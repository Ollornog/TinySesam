<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests\Support;

use TinySesam\Gate\Gate;
use TinySesam\Gate\GateError;
use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\KeySet;
use TinySesam\Gate\StaticKeys;

/**
 * Shared helpers of the test suites: the vectors (read from this repository, never a copy), the test keys and a minter
 * for tokens with exactly one defect.
 */
final class Vectors
{
    /** spec/vectors/ relative to this file: clients/php/tests/Support -> the repository root. */
    public const string DIR = __DIR__ . '/../../../../spec/vectors/';

    public const int JSON_FLAGS = JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        | JSON_PRESERVE_ZERO_FRACTION;

    /** @return list<string> */
    public static function files(): array
    {
        $found = glob(self::DIR . '*.json');
        $files = array_map('basename', $found === false ? [] : $found);
        sort($files);

        return $files;
    }

    /** A vector file as decoded JSON (objects as \stdClass, so `{}` and `[]` stay apart). */
    public static function load(string $name): \stdClass
    {
        $text = file_get_contents(self::DIR . $name);
        if ($text === false) {
            throw new \RuntimeException("{$name}: unreadable");
        }
        $doc = json_decode($text, false, 512, JSON_THROW_ON_ERROR);
        if (!$doc instanceof \stdClass) {
            throw new \RuntimeException("{$name}: not an object");
        }
        // Spec version 2 (Remote-Kind, ts_kind, menu_links), approval version 1 (spec/approval-token.md): vectors of
        // another version must not pass unseen.
        if (($doc->format ?? null) !== ($name === 'approval.json' ? 1 : 2)) {
            throw new \RuntimeException("{$name}: unknown vector format");
        }

        return $doc;
    }

    /** A JSON value of a vector as text again. */
    public static function encode(mixed $value): string
    {
        return json_encode($value, self::JSON_FLAGS);
    }

    /** Decoded JSON (or an array built from it) as plain arrays with sorted keys, for exact comparison. */
    /**
     * The expected fields of an approval vector, as the application would hold them.
     *
     * @return array<array-key, string|int|bool>
     */
    public static function fields(\stdClass $fields): array
    {
        $out = [];
        foreach (get_object_vars($fields) as $name => $value) {
            if (!\is_string($value) && !\is_int($value) && !\is_bool($value)) {
                throw new \RuntimeException("field {$name}: not a string, an integer or a boolean");
            }
            $out[$name] = $value;
        }

        return $out;
    }

    public static function normalize(mixed $value): mixed
    {
        if ($value instanceof \stdClass) {
            $value = get_object_vars($value);
            $out = [];
            foreach ($value as $k => $v) {
                $out[(string) $k] = self::normalize($v);
            }
            ksort($out, SORT_STRING);

            return ['{}' => $out];
        }
        if (\is_array($value)) {
            if (array_is_list($value)) {
                return array_map(self::normalize(...), $value);
            }
            $out = [];
            foreach ($value as $k => $v) {
                $out[(string) $k] = self::normalize($v);
            }
            ksort($out, SORT_STRING);

            return ['{}' => $out];
        }

        return $value;
    }

    /** The octets of a vector header value: one code point U+0000-U+00FF per byte (Latin-1). */
    public static function latin1(string $utf8): string
    {
        $out = '';
        $chars = preg_split('//u', $utf8, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($chars === false ? [] : $chars as $ch) {
            $cp = match (\strlen($ch)) {
                1 => \ord($ch),
                2 => ((\ord($ch[0]) & 0x1F) << 6) | (\ord($ch[1]) & 0x3F),
                default => throw new \RuntimeException('a header value above U+00FF'),
            };
            if ($cp > 0xFF) {
                throw new \RuntimeException('a header value above U+00FF');
            }
            $out .= \chr($cp);
        }

        return $out;
    }

    /**
     * The field lines of a vector's headers: each value as octets; a list means a repeated field.
     *
     * @return list<array{0: string, 1: string}>
     */
    public static function headerFields(\stdClass $headers): array
    {
        $fields = [];
        foreach (get_object_vars($headers) as $name => $value) {
            foreach (\is_array($value) ? $value : [$value] as $item) {
                \assert(\is_string($item));
                $fields[] = [(string) $name, self::latin1($item)];
            }
        }

        return $fields;
    }

    /** A token-mode gate with a fixed key set and a fixed clock, as the token vectors describe. */
    public static function tokenGate(mixed $jwks, string $issuer, string $audience, int $leeway, int $now): Gate
    {
        return Gate::tokenMode(
            issuer: $issuer,
            audience: $audience,
            leewaySeconds: $leeway,
            keySource: new StaticKeys(KeySet::fromJwks(self::encode($jwks))),
            clock: static fn (): int => $now,
        );
    }

    /** The class of a refused call, or 'ok'. */
    public static function outcome(callable $call): string
    {
        try {
            $call();

            return 'ok';
        } catch (GateError $e) {
            return $e->errorClass->value;
        }
    }

    public static function keys(): \stdClass
    {
        $keys = self::load('keys.json')->keys;
        \assert($keys instanceof \stdClass);

        return $keys;
    }

    /** @return array{issuer: string, audience: string, now: int} */
    public static function defaults(): array
    {
        $d = self::load('keys.json')->defaults;

        return ['issuer' => $d->issuer, 'audience' => $d->audience, 'now' => $d->now];
    }

    /** The public key of a test key in the gate-key form (standard Base64). */
    public static function signKey(string $name): string
    {
        return self::keys()->{$name}->sign_key_base64;
    }

    public static function kidOf(string $name): string
    {
        return self::keys()->{$name}->public_jwk->kid;
    }

    public static function publicJwk(string $name): \stdClass
    {
        return self::keys()->{$name}->public_jwk;
    }

    /** The secret key of a test key (public test material of spec/vectors/keys.json). */
    public static function secretKey(string $name): string
    {
        $seed = Strict::decodeSegment(self::keys()->{$name}->d);
        \assert($seed !== null && $seed !== '');

        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    }

    /**
     * A token signed with a test key over the given payload bytes (and header, by default the right one).
     *
     * @param array<string, mixed>|string $payload claims, or the exact payload bytes
     * @param array<string, mixed>|string|null $header header members, or the exact header bytes
     */
    public static function mint(string $name, array|string $payload, array|string|null $header = null): string
    {
        $header ??= ['alg' => 'EdDSA', 'typ' => 'tinysesam-gate+jwt', 'kid' => self::kidOf($name)];
        $h = Strict::encodeSegment(\is_string($header) ? $header : self::encode($header));
        $p = Strict::encodeSegment(\is_string($payload) ? $payload : self::encode($payload));
        $secret = self::secretKey($name);
        \assert($secret !== '');
        $sig = sodium_crypto_sign_detached($h . '.' . $p, $secret);

        return $h . '.' . $p . '.' . Strict::encodeSegment($sig);
    }

    /**
     * The claims TinySesam issues for a session.
     *
     * @return array<string, mixed>
     */
    public static function sessionClaims(string $groups, int $now): array
    {
        $d = self::defaults();

        return [
            'iss' => $d['issuer'],
            'aud' => $d['audience'],
            'sub' => '1',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + 300,
            'jti' => 'jti-test',
            'ts_user' => 'anna',
            'ts_name' => 'Anna Berg',
            'ts_email' => 'anna@example.com',
            'ts_groups' => $groups,
            'ts_id' => '1',
            'ts_auth' => 'session',
            'ts_kind' => 'user',
        ];
    }
}
