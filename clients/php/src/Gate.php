<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use Psr\Log\LoggerInterface;
use TinySesam\Gate\Internal\IpPrefix;
use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\Internal\Token;
use TinySesam\Gate\Jwks\CurlFetcher;
use TinySesam\Gate\Jwks\Fetcher;
use TinySesam\Gate\Jwks\JwksCache;
use TinySesam\Gate\Jwks\Store;

/**
 * Identifies requests in one explicitly configured mode (spec section 1). Build it with {@see Gate::headerMode()} or
 * {@see Gate::tokenMode()}; a contradictory or incomplete configuration throws a {@see ConfigError} there, so the
 * application stops at start-up instead of failing open later.
 */
final readonly class Gate
{
    /** The default name of the gate cookie (TinySesam's gate_cookie_name). */
    public const string DEFAULT_GATE_COOKIE = '__Host-tinysesam_gate';
    /** The largest configurable clock leeway in seconds. */
    public const int MAX_LEEWAY = Token::MAX_LEEWAY;

    /**
     * @param list<IpPrefix> $proxies
     * @param \Closure(): int $now
     */
    private function __construct(
        public string $mode,
        private HeaderNames $names,
        private array $proxies,
        private string $issuer,
        private string $audience,
        private int $leeway,
        private ?KeySource $keys,
        private string $cookie,
        private string $tokenHeader,
        private ?LoggerInterface $logger,
        private \Closure $now,
    ) {
    }

    /**
     * Header mode: trust the Remote-* headers the proxy sets. Only safe when the proxy fulfils spec section 2.1.
     *
     * @param ?list<string> $trustedProxies the peer addresses the proxy connects from (`127.0.0.1`, `198.51.100.0/24`,
     *                                      `::1`); a request from any other peer is refused with `untrusted_peer`.
     *                                      Recommended; the peer is the socket address, never X-Forwarded-For
     * @param ?HeaderNames $headerNames renamed headers when TinySesam's forward_headers renames them
     * @param ?LoggerInterface $logger receives one line per refused request: the class and the kid, never a value
     *
     * @throws ConfigError
     */
    public static function headerMode(
        ?array $trustedProxies = null,
        ?HeaderNames $headerNames = null,
        ?LoggerInterface $logger = null,
    ): self {
        $proxies = [];
        if ($trustedProxies !== null) {
            if ($trustedProxies === []) {
                throw new ConfigError('trustedProxies must be a non-empty list when given');
            }
            foreach ($trustedProxies as $p) {
                $prefix = IpPrefix::parse($p);
                if ($prefix === null) {
                    throw new ConfigError('invalid trusted proxy address or prefix');
                }
                $proxies[] = $prefix;
            }
        }

        return new self(
            'header',
            $headerNames ?? new HeaderNames(),
            $proxies,
            '',
            '',
            0,
            null,
            self::DEFAULT_GATE_COOKIE,
            '',
            $logger,
            time(...),
        );
    }

    /**
     * Token mode: verify the gate token itself and ignore every Remote-* header. Exactly one of $gateKeys, $jwksUrl
     * and $keySource is required.
     *
     * @param string $issuer TinySesam's base_url without a trailing slash, exactly
     * @param string $audience the exact string the proxy names in audience_whitelist, including `|roles=...` when the
     *                         route requires roles; never derived from the request
     * @param ?list<string> $gateKeys fixed public keys, each the output of `tinysesam gate-key` (standard Base64)
     * @param ?string $jwksUrl the key set address, normally `https://<auth host>/auth/gate/jwks.json`; https, or http
     *                         to a loopback address only
     * @param int $leewaySeconds clock leeway, 0 (the default) to 60
     * @param ?string $cookieName the gate cookie; `__Host-tinysesam_gate` when neither it nor $tokenHeader is given
     * @param ?string $tokenHeader read the token from this request header instead of the cookie
     * @param ?Fetcher $fetcher fetches the key set (only with $jwksUrl); a {@see CurlFetcher} when not given
     * @param ?Store $store where the key set cache lives (only with $jwksUrl); see {@see Store} — under PHP-FPM give a
     *                      {@see Jwks\FileStore}
     * @param ?KeySource $keySource a key source of your own
     * @param ?\Closure(): int $clock the current time in seconds since the epoch, for tests
     *
     * @throws ConfigError
     */
    public static function tokenMode(
        string $issuer,
        string $audience,
        ?array $gateKeys = null,
        ?string $jwksUrl = null,
        int $leewaySeconds = 0,
        ?string $cookieName = null,
        ?string $tokenHeader = null,
        ?Fetcher $fetcher = null,
        ?Store $store = null,
        ?KeySource $keySource = null,
        ?LoggerInterface $logger = null,
        ?\Closure $clock = null,
    ): self {
        if ($issuer === '' || $audience === '') {
            throw new ConfigError('token mode needs issuer and audience');
        }
        if ($leewaySeconds < 0 || $leewaySeconds > self::MAX_LEEWAY) {
            throw new ConfigError('leewaySeconds must be an integer from 0 to ' . self::MAX_LEEWAY);
        }
        if ($cookieName !== null && $tokenHeader !== null) {
            throw new ConfigError('give either cookieName or tokenHeader, not both');
        }
        $cookie = $cookieName ?? self::DEFAULT_GATE_COOKIE;
        if (!Strict::isToken($cookie)) {
            throw new ConfigError('invalid cookieName');
        }
        if ($tokenHeader !== null && !Strict::isToken($tokenHeader)) {
            throw new ConfigError('invalid tokenHeader');
        }
        if (!\function_exists('sodium_crypto_sign_verify_detached')) {
            throw new ConfigError('token mode needs ext-sodium');
        }
        $given = ($gateKeys !== null ? 1 : 0) + ($jwksUrl !== null ? 1 : 0) + ($keySource !== null ? 1 : 0);
        if ($given !== 1) {
            throw new ConfigError('token mode needs exactly one of gateKeys, jwksUrl and keySource');
        }
        if ($jwksUrl === null && ($fetcher !== null || $store !== null)) {
            throw new ConfigError('fetcher and store belong to jwksUrl');
        }
        if ($gateKeys !== null) {
            $keySource = new StaticKeys(KeySet::fromGateKeys($gateKeys));
        } elseif ($jwksUrl !== null) {
            self::checkJwksUrl($jwksUrl);
            if ($fetcher === null && !\function_exists('curl_init')) {
                throw new ConfigError('jwksUrl needs ext-curl, or a Fetcher of your own');
            }
            $keySource = new JwksCache($fetcher ?? new CurlFetcher($jwksUrl), $store);
        }
        \assert($keySource !== null);

        return new self(
            'token',
            new HeaderNames(),
            [],
            $issuer,
            $audience,
            $leewaySeconds,
            $keySource,
            $cookie,
            $tokenHeader ?? '',
            $logger,
            $clock ?? time(...),
        );
    }

    /**
     * @internal shared with {@see ApprovalVerifier} and {@see Account}
     *
     * @throws ConfigError
     */
    public static function checkJwksUrl(string $url): void
    {
        $u = parse_url($url);
        if (
            $u === false || !isset($u['scheme'], $u['host']) || $u['host'] === '' || Strict::hasControl($url)
            || preg_match('/\s/', $url) === 1
        ) {
            throw new ConfigError('jwksUrl is not an absolute URL');
        }
        if (isset($u['user']) || isset($u['pass']) || isset($u['fragment'])) {
            throw new ConfigError('jwksUrl must not carry credentials or a fragment');
        }
        $scheme = strtolower($u['scheme']);
        if ($scheme === 'https') {
            return;
        }
        if ($scheme === 'http') {
            $host = strtolower(trim($u['host'], '[]'));
            $address = IpPrefix::address($host);
            $loopback = $host === 'localhost'
                || ($address !== null && \strlen($address) === 4 && $address[0] === "\x7F")
                || $address === str_repeat("\0", 15) . "\1";
            if ($loopback) {
                return;
            }
            throw new ConfigError('jwksUrl over plain http is allowed to a loopback address only');
        }
        throw new ConfigError('jwksUrl must use https');
    }

    /**
     * The identity of a request. Every error — an unexpected one inside the client included — means not authenticated.
     *
     * @throws GateError whose class says why not
     */
    public function identify(GateRequest $request): Identity
    {
        try {
            if ($this->mode === 'header') {
                if ($this->proxies !== [] && !$this->trustedPeer($request->peer)) {
                    throw new GateError(ErrorClass::UntrustedPeer);
                }

                return Headers::identity($request->fields, $this->names);
            }

            return $this->verify($this->token($request->fields))->identity;
        } catch (GateError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new GateError(ErrorClass::Internal, 'unexpected failure');
        }
    }

    /** As {@see identify()}, but null instead of an error; a refusal goes to the logger (not `unauthenticated`). */
    public function identifyOrNull(GateRequest $request): ?Identity
    {
        try {
            return $this->identify($request);
        } catch (GateError $e) {
            $this->log($e);

            return null;
        }
    }

    /**
     * Checks a gate token in the order of spec section 4.4. Only for a gate in token mode.
     *
     * @throws GateError
     */
    public function verify(#[\SensitiveParameter] string $jws): Verified
    {
        try {
            if ($this->keys === null) {
                throw new GateError(ErrorClass::Internal, 'verify needs token mode');
            }
            $now = ($this->now)();
            $token = Token::parse($jws);
            $key = $this->keys->lookup($token->kid);
            $claims = Token::finish($token, $key, $this->issuer, $this->audience, $this->leeway, $now);

            return new Verified(Token::identity($claims), $claims);
        } catch (GateError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new GateError(ErrorClass::Internal, 'unexpected failure');
        }
    }

    private function trustedPeer(?string $peer): bool
    {
        $address = $peer === null ? null : IpPrefix::address($peer);
        if ($address === null) {
            return false;
        }
        foreach ($this->proxies as $p) {
            if ($p->contains($address)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The gate token from the one configured source.
     *
     * @param list<array{0: string, 1: string}> $fields
     *
     * @throws GateError
     */
    private function token(array $fields): string
    {
        if ($this->tokenHeader !== '') {
            $values = Headers::values($fields, $this->tokenHeader);
            if (\count($values) > 1) {
                throw new GateError(ErrorClass::Malformed, 'more than one token header');
            }
            if ($values === [] || $values[0] === '') {
                throw new GateError(ErrorClass::Unauthenticated, 'no token');
            }

            return $values[0];
        }
        $found = [];
        foreach (Headers::values($fields, 'Cookie') as $line) {
            foreach (explode(';', $line) as $pair) {
                $eq = strpos($pair, '=');
                if ($eq !== false && trim(substr($pair, 0, $eq)) === $this->cookie) {
                    $found[] = trim(substr($pair, $eq + 1));
                }
            }
        }
        if (\count($found) > 1) {
            throw new GateError(ErrorClass::Malformed, 'more than one gate cookie');
        }
        if ($found === [] || $found[0] === '') {
            throw new GateError(ErrorClass::Unauthenticated, 'no token');
        }

        return $found[0];
    }

    private function log(GateError $e): void
    {
        if ($this->logger === null || $e->errorClass === ErrorClass::Unauthenticated) {
            return;
        }
        $context = ['class' => $e->errorClass->value];
        if ($e->kid !== null) {
            $context['kid'] = $e->kid;
        }
        try {
            $this->logger->notice('tinysesam gate: request refused ({class})', $context);
        } catch (\Throwable) {
            // A failing logger must not change the answer.
        }
    }
}
