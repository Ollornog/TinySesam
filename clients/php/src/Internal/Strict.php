<?php

declare(strict_types=1);

namespace TinySesam\Gate\Internal;

/**
 * Strict decoders for spec section 4.4: base64url, UTF-8 and JSON. The decoding itself is done by PHP (base64_decode,
 * PCRE's UTF-8 check, json_decode); this class adds what those are too lenient for — the alphabet and canonical form of
 * base64url, the byte order mark, and repeated member names (json_decode keeps the last of two).
 *
 * @internal
 */
final class Strict
{
    private function __construct()
    {
    }

    /**
     * Decodes strict base64url (RFC 7515): only `A-Z a-z 0-9 - _`, no padding, no whitespace or line break, and
     * canonical — re-encoding the bytes gives the same text, so the unused low bits are zero.
     */
    public static function decodeSegment(string $s): ?string
    {
        // \z, not $: `$` would also match before a trailing line break.
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $s) !== 1 || \strlen($s) % 4 === 1) {
            return null;
        }
        $raw = base64_decode(strtr($s, '-_', '+/'), true);
        if ($raw === false || self::encodeSegment($raw) !== $s) {
            return null;
        }

        return $raw;
    }

    /** Encodes bytes as base64url without padding. */
    public static function encodeSegment(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Decodes strict standard Base64 with padding (the output of `tinysesam gate-key`), canonical only. */
    public static function decodeStandardBase64(string $s): ?string
    {
        if (preg_match('/\A[A-Za-z0-9+\/]*={0,2}\z/', $s) !== 1 || \strlen($s) % 4 !== 0) {
            return null;
        }
        $raw = base64_decode($s, true);
        if ($raw === false || base64_encode($raw) !== $s) {
            return null;
        }

        return $raw;
    }

    /** Whether bytes are strict UTF-8: PCRE refuses invalid and overlong sequences, surrogates and values above U+10FFFF. */
    public static function isUtf8(string $bytes): bool
    {
        return preg_match('//u', $bytes) === 1;
    }

    /**
     * Parses one JSON value from UTF-8 bytes the way the specification demands: strict UTF-8, no byte order mark, no
     * member name twice in any object, no NaN or Infinity, no lone surrogate escape, nothing after the value. Objects
     * become \stdClass (so `{}` and `[]` stay apart), integers int, numbers with a fraction or exponent float.
     *
     * @return array{0: bool, 1: mixed} [true, value] or [false, null]
     */
    public static function parseJson(string $bytes): array
    {
        if (str_starts_with($bytes, "\xEF\xBB\xBF") || !self::isUtf8($bytes)) {
            return [false, null];
        }
        try {
            // json_decode refuses NaN, Infinity, lone surrogate escapes and trailing text itself. A member name that
            // starts with NUL cannot be a property of \stdClass; json_decode refuses it, which fails closed.
            $value = json_decode($bytes, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [false, null];
        }
        if (!self::noRepeatedNames($bytes)) {
            return [false, null];
        }

        return [true, $value];
    }

    /**
     * Walks JSON text that json_decode has accepted and refuses a repeated member name in any object. Names are
     * compared decoded, so `"a"` and `"a"` are the same name.
     */
    private static function noRepeatedNames(string $text): bool
    {
        /** @var list<array{object: bool, names: array<string, true>, expectName: bool}> $stack */
        $stack = [];
        $n = \strlen($text);
        $i = 0;
        while ($i < $n) {
            $c = $text[$i];
            if ($c === '"') {
                $j = $i + 1;
                $escaped = false;
                while ($text[$j] !== '"') {
                    if ($text[$j] === '\\') {
                        $escaped = true;
                        $j += 2;
                    } else {
                        $j++;
                    }
                }
                $top = array_key_last($stack);
                if ($top !== null && $stack[$top]['object'] && $stack[$top]['expectName']) {
                    $name = $escaped ? json_decode(substr($text, $i, $j - $i + 1), false, 2, JSON_THROW_ON_ERROR)
                        : substr($text, $i + 1, $j - $i - 1);
                    if (!\is_string($name)) {
                        return false;
                    }
                    // A key of the form "123" becomes the integer 123 in a PHP array — the same for both spellings,
                    // so the comparison stays exact.
                    if (isset($stack[$top]['names'][$name])) {
                        return false;
                    }
                    $stack[$top]['names'][$name] = true;
                    $stack[$top]['expectName'] = false;
                }
                $i = $j + 1;
            } elseif ($c === '{' || $c === '[') {
                $stack[] = ['object' => $c === '{', 'names' => [], 'expectName' => $c === '{'];
                $i++;
            } elseif ($c === '}' || $c === ']') {
                array_pop($stack);
                $i++;
            } elseif ($c === ',') {
                $top = array_key_last($stack);
                if ($top !== null && $stack[$top]['object']) {
                    $stack[$top]['expectName'] = true;
                }
                $i++;
            } else {
                $i++; // whitespace, ':', numbers and the letters of true, false, null
            }
        }

        return true;
    }

    /** A C0 control character (U+0000-U+001F, tab included) or DEL. */
    public static function hasControl(string $s): bool
    {
        return preg_match('/[\x00-\x1F\x7F]/', $s) === 1;
    }

    /** Compares s with an ASCII lower-case reference, ignoring ASCII case only (no Unicode case folding). */
    public static function asciiEqualFold(string $s, string $lower): bool
    {
        return \strlen($s) === \strlen($lower) && strtolower($s) === $lower;
    }

    /** A valid HTTP field name or cookie name (an RFC 9110 token). */
    public static function isToken(string $s): bool
    {
        return preg_match('/\A[!#$%&\'*+\-.^_`|~0-9A-Za-z]+\z/', $s) === 1;
    }

    /**
     * An own member of a decoded JSON object, or null (with $present false) when it is absent.
     *
     * @param-out bool $present
     */
    public static function member(\stdClass $o, string $name, ?bool &$present = null): mixed
    {
        $present = property_exists($o, $name);

        return $present ? $o->{$name} : null;
    }
}
