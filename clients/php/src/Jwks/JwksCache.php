<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

use TinySesam\Gate\ErrorClass;
use TinySesam\Gate\GateError;
use TinySesam\Gate\KeySet;
use TinySesam\Gate\KeySource;

/**
 * Fetching the key set (spec section 5): a deadline, a body limit, a freshness window, a rate limit, a stale limit, and
 * one fetch for requests that need keys at the same time. No request waits longer than one fetch deadline for keys.
 */
final class JwksCache implements KeySource
{
    /** One fetch in total — connect, TLS, headers, body — in seconds. */
    public const float FETCH_TIMEOUT = 5.0;
    /** The largest body of a key set document. */
    public const int MAX_JWKS_BYTES = 65536;

    private const int DEFAULT_FRESH = 300; // when Cache-Control has no readable max-age
    private const int MIN_FRESH = 60;
    private const int MAX_FRESH = 3600;
    private const int STALE_MAX = 3600; // a set more than this past its freshness is no longer used
    private const int MIN_INTERVAL = 10; // at most one fetch attempt per this many seconds

    private readonly Store $store;
    /** @var \Closure(): int */
    private readonly \Closure $clock;
    private readonly float $timeout;

    /** The last parsed document, so a request does not parse the same key set twice. */
    private ?string $parsedDocument = null;
    private ?KeySet $parsed = null;

    /**
     * @param ?Store $store where the state lives; a {@see MemoryStore} when not given
     * @param ?\Closure(): int $clock seconds, for tests; the store's clock when not given
     */
    public function __construct(
        private readonly Fetcher $fetcher,
        ?Store $store = null,
        ?\Closure $clock = null,
        float $timeoutSeconds = self::FETCH_TIMEOUT,
    ) {
        $this->store = $store ?? new MemoryStore();
        $this->clock = $clock ?? $this->store->now(...);
        $this->timeout = min($timeoutSeconds, self::FETCH_TIMEOUT);
    }

    /**
     * The key for $kid now (spec section 5, rule 6).
     *
     * @throws GateError of the class `key_unavailable` or `kid`
     */
    public function lookup(string $kid): string
    {
        $now = ($this->clock)();
        $state = $this->sane($this->store->load(), $now);
        $fetched = false;
        if ($this->keys($state) === null || $now >= $state->freshUntil) {
            [$fetched, $state] = $this->maybeFetch($state, $now);
        }
        $keys = $this->keys($state);
        if ($keys === null || $now >= $state->freshUntil + self::STALE_MAX) {
            throw new GateError(ErrorClass::KeyUnavailable, 'no usable key set', $kid);
        }
        $key = $keys->get($kid);
        if ($key !== null) {
            return $key;
        }
        if (!$fetched) {
            [$fetched, $state] = $this->maybeFetch($state, $now);
            $again = $fetched ? $this->keys($state)?->get($kid) : null;
            if ($again !== null) {
                return $again;
            }
        }
        throw new GateError(ErrorClass::Kid, 'kid not in the key set', $kid);
    }

    /**
     * A state with timestamps in the future (a clock that stepped back, a copied file) is not trusted: the attempt is
     * forgotten and the freshness capped, so the cache fetches again instead of keeping a set too long.
     */
    private function sane(State $s, int $now): State
    {
        $lastAttempt = $s->lastAttempt !== null && $s->lastAttempt > $now ? null : $s->lastAttempt;
        $freshUntil = min($s->freshUntil, $now + self::MAX_FRESH);

        return $lastAttempt === $s->lastAttempt && $freshUntil === $s->freshUntil
            ? $s : new State($s->document, $freshUntil, $lastAttempt);
    }

    /**
     * Fetches if the rate allows it, under the store's lock. When a fetch elsewhere holds the lock, waits for it at
     * most one deadline and takes its result. Reports whether this request fetched or shared a fetch, and the state
     * after.
     *
     * @return array{0: bool, 1: State}
     */
    private function maybeFetch(State $before, int $now): array
    {
        // The lock comes first, also when the rate forbids a fetch of our own: a request that arrives while another
        // one fetches waits for that fetch (at most one deadline) instead of failing at once with an empty cache.
        if (!$this->store->lock($this->timeout)) {
            // A fetch elsewhere is still running after one deadline: go on with what is cached.
            return [true, $this->sane($this->store->load(), $now)];
        }
        try {
            $state = $this->sane($this->store->load(), $now);
            if ($state->lastAttempt !== $before->lastAttempt) {
                return [true, $state]; // another request fetched while this one waited for the lock: share its result
            }
            if ($state->lastAttempt !== null && $now - $state->lastAttempt < self::MIN_INTERVAL) {
                return [false, $state];
            }
            // The attempt is recorded before the fetch, so even a fetch that never returns counts against the rate.
            $state = new State($state->document, $state->freshUntil, $now);
            $this->store->save($state);
            $fresh = $this->fetchOnce();
            if ($fresh !== null) {
                $state = new State($fresh[0], $now + $fresh[1], $now);
                $this->store->save($state);
            }

            return [true, $state];
        } finally {
            $this->store->unlock();
        }
    }

    /**
     * One fetch: the document and its freshness in seconds, or null for a failed fetch (rule 4) — a network error, an
     * answer after the deadline, a status other than 200, a body above 64 KiB, no strict JSON, `jwks_invalid`, or no
     * usable entry.
     *
     * @return array{0: string, 1: int}|null
     */
    private function fetchOnce(): ?array
    {
        $start = hrtime(true);
        try {
            $r = $this->fetcher->fetch($this->timeout);
        } catch (\Throwable) {
            return null;
        }
        if ((hrtime(true) - $start) / 1e9 > $this->timeout) {
            return null;
        }
        if ($r->status !== 200 || \strlen($r->body) > self::MAX_JWKS_BYTES) {
            return null;
        }
        try {
            $keys = KeySet::fromJwks($r->body);
        } catch (GateError) {
            return null;
        }
        if ($keys->count() === 0) {
            return null;
        }
        $this->parsedDocument = $r->body;
        $this->parsed = $keys;

        return [$r->body, self::freshness($r->cacheControl ?? '')];
    }

    /** The key set of a state's document, parsed once. */
    private function keys(State $state): ?KeySet
    {
        if ($state->document === null) {
            return null;
        }
        if ($state->document !== $this->parsedDocument) {
            try {
                $keys = KeySet::fromJwks($state->document);
            } catch (GateError) {
                return null;
            }
            $this->parsedDocument = $state->document;
            $this->parsed = $keys->count() > 0 ? $keys : null;
        }

        return $this->parsed;
    }

    /**
     * Reads max-age from Cache-Control (default 300 s), clamped to 60-3600 s; no-cache and no-store do not shorten it
     * below 60 s.
     */
    public static function freshness(string $cacheControl): int
    {
        $fresh = preg_match('/(?:^|,)\s*max-age\s*=\s*([0-9]+)\s*(?:,|$)/i', $cacheControl, $m) === 1
            ? (int) min((float) $m[1], (float) self::MAX_FRESH) : self::DEFAULT_FRESH;

        return min(max($fresh, self::MIN_FRESH), self::MAX_FRESH);
    }
}
