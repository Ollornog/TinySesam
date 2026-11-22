<?php

declare(strict_types=1);

namespace TinySesam\Gate\Internal;

/**
 * An address prefix of the trusted proxy list. IPv4 addresses (also IPv4-mapped IPv6 such as ::ffff:127.0.0.1) match
 * IPv4 prefixes only.
 *
 * @internal
 */
final readonly class IpPrefix
{
    private function __construct(private string $address, private int $bits)
    {
    }

    /** `127.0.0.1`, `198.51.100.0/24`, `::1`, `2001:db8::/32`; null when invalid. */
    public static function parse(string $s): ?self
    {
        $slash = strpos($s, '/');
        $addressText = $slash === false ? $s : substr($s, 0, $slash);
        $address = self::address($addressText);
        if ($address === null) {
            return null;
        }
        $max = \strlen($address) * 8;
        if ($slash === false) {
            return new self($address, $max);
        }
        $bitsText = substr($s, $slash + 1);
        if (preg_match('/\A(0|[1-9][0-9]{0,2})\z/', $bitsText) !== 1 || (int) $bitsText > $max) {
            return null;
        }

        return new self($address, (int) $bitsText);
    }

    /** The packed address (4 or 16 bytes); an IPv4-mapped IPv6 address becomes IPv4; null when invalid. */
    public static function address(string $s): ?string
    {
        if ($s === '' || str_contains($s, '%')) {
            return null;
        }
        $packed = @inet_pton($s);
        if ($packed === false) {
            return null;
        }
        if (\strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10) . "\xFF\xFF")) {
            return substr($packed, 12);
        }

        return $packed;
    }

    /** Whether the packed address lies in this prefix. */
    public function contains(string $address): bool
    {
        if (\strlen($address) !== \strlen($this->address)) {
            return false;
        }
        $full = intdiv($this->bits, 8);
        if (substr($address, 0, $full) !== substr($this->address, 0, $full)) {
            return false;
        }
        $rest = $this->bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;

        return (\ord($address[$full]) & $mask) === (\ord($this->address[$full]) & $mask);
    }
}
