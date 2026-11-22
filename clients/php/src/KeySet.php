<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\Strict;

/**
 * Maps kid to a 32-byte Ed25519 public key (spec section 4.3). It comes from configuration — fixed gate keys or a
 * JWKS document — never from a token.
 */
final readonly class KeySet
{
    /** The largest number of entries a key set document may have. */
    public const int MAX_JWKS_KEYS = 32;

    private const array FORBIDDEN_JWK_MEMBERS = ['d', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'jku'];

    /** @var array<string, string> kid => raw public key */
    private array $keys;

    /** @var list<string> The kids in the order of the source. */
    public array $kids;

    /**
     * @param list<array{0: string, 1: string}> $entries [kid, 32 raw key bytes]
     */
    private function __construct(array $entries)
    {
        $keys = [];
        $kids = [];
        foreach ($entries as [$kid, $raw]) {
            $keys[$kid] = $raw;
            $kids[] = $kid;
        }
        $this->keys = $keys;
        $this->kids = $kids;
    }

    /** The raw key of a kid, or null. */
    public function get(string $kid): ?string
    {
        return $this->keys[$kid] ?? null;
    }

    /** The number of usable keys. */
    public function count(): int
    {
        return \count($this->keys);
    }

    /** Whether a kid has the format of spec section 4.1: 16 lowercase hexadecimal digits. */
    public static function isValidKid(string $kid): bool
    {
        return preg_match('/\A[0-9a-f]{16}\z/', $kid) === 1;
    }

    /** The kid of a public key: the first 16 hex digits of SHA-256 over its 32 raw bytes. */
    public static function keyId(string $raw): string
    {
        return substr(hash('sha256', $raw), 0, 16);
    }

    /** Reads the output of `tinysesam gate-key`: 32 raw bytes in standard Base64 (the proxy's sign_key). */
    public static function parseGateKey(string $b64): ?string
    {
        $raw = Strict::decodeStandardBase64(trim($b64));

        return $raw !== null && \strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ? $raw : null;
    }

    /**
     * Builds a key set from one or more gate keys (before and after a rotation).
     *
     * @param list<string> $gateKeys
     *
     * @throws ConfigError for no key or a key that is not 32 bytes in standard Base64
     */
    public static function fromGateKeys(array $gateKeys): self
    {
        if ($gateKeys === []) {
            throw new ConfigError('no gate key');
        }
        $entries = [];
        $seen = [];
        foreach ($gateKeys as $b64) {
            $raw = self::parseGateKey($b64);
            if ($raw === null) {
                throw new ConfigError(
                    'a gate key must be 32 bytes in standard Base64 (the output of `tinysesam gate-key`)',
                );
            }
            $kid = self::keyId($raw);
            if (!isset($seen[$kid])) {
                $seen[$kid] = true;
                $entries[] = [$kid, $raw];
            }
        }

        return new self($entries);
    }

    /**
     * Reads a key set document (spec section 4.3). Unusable entries are skipped, two usable entries with the same kid
     * make that kid unusable; a document that is not strict JSON, not an object, has no keys array or more than
     * {@see self::MAX_JWKS_KEYS} entries is the error `jwks_invalid`. The result may be empty.
     *
     * @throws GateError of the class `jwks_invalid`
     */
    public static function fromJwks(string $document): self
    {
        [$ok, $doc] = Strict::parseJson($document);
        if (!$ok) {
            throw new GateError(ErrorClass::JwksInvalid, 'not strict JSON');
        }
        if (!$doc instanceof \stdClass) {
            throw new GateError(ErrorClass::JwksInvalid, 'not an object');
        }
        $entries = Strict::member($doc, 'keys');
        if (!\is_array($entries) || \count($entries) > self::MAX_JWKS_KEYS) {
            throw new GateError(ErrorClass::JwksInvalid, 'no keys array or too many entries');
        }
        $usable = [];
        $count = [];
        foreach ($entries as $e) {
            $found = self::jwkEntry($e);
            if ($found !== null) {
                $usable[] = $found;
                $count[$found[0]] = ($count[$found[0]] ?? 0) + 1;
            }
        }

        return new self(array_values(array_filter($usable, static fn (array $u): bool => $count[$u[0]] === 1)));
    }

    /**
     * The kid and key of a usable JWKS entry, or null.
     *
     * @return array{0: string, 1: string}|null
     */
    private static function jwkEntry(mixed $e): ?array
    {
        if (
            !$e instanceof \stdClass
            || Strict::member($e, 'kty') !== 'OKP'
            || Strict::member($e, 'crv') !== 'Ed25519'
        ) {
            return null;
        }
        foreach (self::FORBIDDEN_JWK_MEMBERS as $name) {
            if (property_exists($e, $name)) {
                return null;
            }
        }
        if (property_exists($e, 'alg') && $e->alg !== 'EdDSA') {
            return null;
        }
        if (property_exists($e, 'use') && $e->use !== 'sig') {
            return null;
        }
        if (property_exists($e, 'key_ops') && (!\is_array($e->key_ops) || !\in_array('verify', $e->key_ops, true))) {
            return null;
        }
        $x = Strict::member($e, 'x');
        $kid = Strict::member($e, 'kid');
        if (!\is_string($x) || !\is_string($kid)) {
            return null;
        }
        $raw = Strict::decodeSegment($x);
        if ($raw === null || \strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || $kid !== self::keyId($raw)) {
            return null;
        }

        return [$kid, $raw];
    }
}
