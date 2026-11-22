<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\Strict;

/**
 * Header mode (spec sections 2.2 and 2.3): the identity from the Remote-* headers.
 *
 * Header fields are given as field lines, one `[name, value]` pair per line as it arrived; a value is a string of
 * octets (PHP strings are bytes). {@see GateRequest} builds them from a PSR-7 request or from `$_SERVER`.
 */
final class Headers
{
    private function __construct()
    {
    }

    /**
     * Every value of the field $name (compared ignoring ASCII case), in order.
     *
     * @param iterable<array{0: string, 1: string}> $fields
     *
     * @return list<string>
     */
    public static function values(iterable $fields, string $name): array
    {
        $out = [];
        foreach ($fields as [$key, $value]) {
            // strcasecmp ignores ASCII case only (locale-independent since PHP 8.2).
            if (strcasecmp($key, $name) === 0) {
                $out[] = $value;
            }
        }

        return $out;
    }

    /**
     * Reads the identity from the Remote-* headers (spec section 2.2). It does not check where the request came from:
     * use it only behind a proxy that fulfils the duties of spec section 2.1, or use a {@see Gate} in header mode with
     * trusted proxies.
     *
     * @param iterable<array{0: string, 1: string}> $fields
     *
     * @throws GateError of the class `unauthenticated` or `header`
     */
    public static function identity(iterable $fields, ?HeaderNames $names = null): Identity
    {
        $names ??= new HeaderNames();
        $pairs = \is_array($fields) ? $fields : iterator_to_array($fields, false);
        $values = ['user' => '', 'name' => '', 'email' => '', 'groups' => '', 'id' => '', 'auth' => '', 'kind' => ''];
        foreach ($names->slots() as $slot => $headerName) {
            $found = self::values($pairs, $headerName);
            if ($found === []) {
                continue;
            }
            if (\count($found) > 1) {
                throw new GateError(ErrorClass::Header, 'a header occurs more than once');
            }
            $value = $found[0];
            if (!Strict::isUtf8($value)) {
                throw new GateError(ErrorClass::Header, 'a header is not UTF-8');
            }
            if (Strict::hasControl($value)) {
                throw new GateError(ErrorClass::Header, 'control character in a header');
            }
            $values[$slot] = $value;
        }
        if ($values['user'] === '') {
            throw new GateError(ErrorClass::Unauthenticated, 'no user header');
        }
        if ($values['id'] !== '' && preg_match('/\A[0-9]+\z/', $values['id']) !== 1) {
            throw new GateError(ErrorClass::Header, 'the id header is not a number');
        }
        $problem = AccountKind::problem($values['kind'], $values['auth']);
        if ($problem !== null) {
            throw new GateError(ErrorClass::Header, $problem);
        }

        return new Identity(
            $values['user'],
            $values['name'],
            $values['email'],
            $values['groups'],
            $values['id'],
            $values['auth'],
            $values['kind'],
        );
    }
}
