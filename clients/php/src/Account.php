<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\Internal\Token;
use TinySesam\Gate\Jwks\CurlFetcher;
use TinySesam\Gate\Jwks\Fetcher;
use TinySesam\Gate\Jwks\JwksCache;

/**
 * Account overview data (spec section 8a): the person's own security state as TinySesam's account page shows it,
 * reduced to what an application may render on its own settings page. The result is a plain array: signed out,
 * every group is null; signed in, `account`, `sign_in`, `sessions`, `programs` and `links` are always arrays and a
 * null inside them means "missing, of the wrong type or not offered". Every string is text, never markup — escape
 * it. Changes happen on TinySesam's account page, which the links lead to. Do not cache the result across sessions.
 */
final class Account
{
    private const array LINKS = ['account', 'sessions', 'totp', 'passkeys', 'devices', 'app_passwords', 'services',
        'approvals'];

    private function __construct()
    {
    }

    /**
     * The overview of a signed-out request (also the answer to anything doubtful).
     *
     * @return array{signed_in: false, account: null, sign_in: null, sessions: null, programs: null, approvals: null,
     *     links: null}
     */
    public static function signedOut(): array
    {
        return ['signed_in' => false, 'account' => null, 'sign_in' => null, 'sessions' => null, 'programs' => null,
            'approvals' => null, 'links' => null];
    }

    /**
     * Normalizes the body of a 200 answer of `/.tinysesam/account.json` or `/auth/account.json`. Anything but a JSON
     * object with `signed_in` true (the boolean) counts as signed out; a member of the wrong type reads as missing
     * (null), an unsafe href as null, unknown members are dropped.
     *
     * @return array<string, mixed>
     */
    public static function parse(string $body): array
    {
        [$ok, $data] = Strict::parseJson($body);
        if (!$ok || !$data instanceof \stdClass || Strict::member($data, 'signed_in') !== true) {
            return self::signedOut();
        }
        $account = self::group($data, 'account');
        $signIn = self::group($data, 'sign_in');
        $sessions = self::group($data, 'sessions');
        $programs = self::group($data, 'programs');
        $links = self::group($data, 'links');
        $totp = Strict::member($signIn, 'totp');
        $passkeys = Strict::member($signIn, 'passkeys');
        $approvals = Strict::member($data, 'approvals');
        $pending = $approvals instanceof \stdClass ? self::count($approvals, 'pending') : null;
        $appPasswords = Strict::member($programs, 'app_passwords');
        $hrefs = [];
        foreach (self::LINKS as $name) {
            $hrefs[$name] = self::href($links, $name);
        }

        return [
            'signed_in' => true,
            'account' => ['username' => self::text($account, 'username'),
                'display_name' => self::text($account, 'display_name')],
            'sign_in' => [
                'password' => self::text($signIn, 'password'),
                'totp' => $totp instanceof \stdClass ? ['enabled' => self::flag($totp, 'enabled'),
                    'recovery_left' => self::count($totp, 'recovery_left'),
                    'recovery_low' => self::flag($totp, 'recovery_low')] : null,
                'passkeys' => $passkeys instanceof \stdClass ? ['count' => self::count($passkeys, 'count'),
                    'items' => self::uses(Strict::member($passkeys, 'items'))] : null,
                'pin' => self::flag($signIn, 'pin'),
            ],
            'sessions' => [
                'count' => self::count($sessions, 'count'),
                'items' => array_map(static fn (\stdClass $e): array => [
                    'created_at' => self::count($e, 'created_at'),
                    'last_seen' => self::count($e, 'last_seen'),
                    'method' => self::text($e, 'method'),
                    'device' => self::text($e, 'device'),
                    'current' => self::flag($e, 'current'),
                ], self::objects(Strict::member($sessions, 'items'))),
            ],
            'programs' => [
                'oauth' => \is_array(Strict::member($programs, 'oauth'))
                    ? self::uses(Strict::member($programs, 'oauth')) : null,
                'services' => \is_array(Strict::member($programs, 'services'))
                    ? self::uses(Strict::member($programs, 'services')) : null,
                'app_passwords' => \is_array($appPasswords) ? array_map(static fn (\stdClass $e): array => [
                    'name' => self::text($e, 'name'),
                    'created_at' => self::count($e, 'created_at'),
                    'last_used' => self::count($e, 'last_used'),
                    'expires_at' => self::count($e, 'expires_at'),
                ], self::objects($appPasswords)) : null,
                'api_keys_active' => self::count($programs, 'api_keys_active'),
            ],
            'approvals' => $pending === null ? null : ['pending' => $pending],
            'links' => $hrefs,
        ];
    }

    /**
     * Fetches the own account overview server-side: a GET to $url (normally `https://<auth host>/auth/account.json`, or
     * `/.tinysesam/account.json` on the application's host) carrying only TinySesam's cookies of $cookieHeader, with a
     * deadline of 5 seconds, a body limit of 64 KiB and no redirects. Any failure — a 401 (no full browser session), a
     * 404, a 429 included — gives the signed-out overview.
     *
     * @param ?\Closure(string $url, list<string> $headers): Fetcher $fetcher builds the fetcher for one request
     *     (tests); a {@see CurlFetcher} when not given
     *
     * @throws ConfigError a URL that is not https (plain http only to a loopback address)
     *
     * @return array<string, mixed>
     */
    public static function fetch(string $url, string $cookieHeader = '', ?\Closure $fetcher = null): array
    {
        Gate::checkJwksUrl($url);
        $cookies = self::tinysesamCookies($cookieHeader);
        $headers = $cookies === '' ? [] : ['Cookie: ' . $cookies];
        try {
            $f = $fetcher !== null ? $fetcher($url, $headers) : new CurlFetcher($url, $headers);
            $result = $f->fetch(JwksCache::FETCH_TIMEOUT);
        } catch (\Throwable) {
            return self::signedOut();
        }
        if ($result->status !== 200 || \strlen($result->body) > JwksCache::MAX_JWKS_BYTES) {
            return self::signedOut();
        }

        return self::parse($result->body);
    }

    /** Only TinySesam's cookies of a Cookie header (`tinysesam_*`, `__Host-tinysesam_*`), joined again. */
    public static function tinysesamCookies(string $cookieHeader): string
    {
        $kept = [];
        foreach (explode(';', $cookieHeader) as $part) {
            $part = trim($part);
            if (str_starts_with($part, 'tinysesam_') || str_starts_with($part, '__Host-tinysesam_')) {
                $kept[] = $part;
            }
        }

        return implode('; ', $kept);
    }

    /** A member that is always an object in the answer: anything else reads as an empty one. */
    private static function group(\stdClass $data, string $name): \stdClass
    {
        $v = Strict::member($data, $name);

        return $v instanceof \stdClass ? $v : new \stdClass();
    }

    private static function text(\stdClass $m, string $name): ?string
    {
        $v = Strict::member($m, $name);

        return \is_string($v) ? $v : null;
    }

    private static function flag(\stdClass $m, string $name): ?bool
    {
        $v = Strict::member($m, $name);

        return \is_bool($v) ? $v : null;
    }

    /** A count or a time: a JSON integer from 0 to 2^53 - 1 (json_decode gives a float for 1.0). */
    private static function count(\stdClass $m, string $name): ?int
    {
        $v = Strict::member($m, $name);

        return \is_int($v) && $v >= 0 && $v <= Token::MAX_SAFE ? $v : null;
    }

    private static function href(\stdClass $m, string $name): ?string
    {
        $v = Strict::member($m, $name);

        return \is_string($v) && Topbar::isSafeHref($v) ? $v : null;
    }

    /**
     * The object entries of a list; anything that is no list counts as none.
     *
     * @return list<\stdClass>
     */
    private static function objects(mixed $v): array
    {
        return \is_array($v) ? array_values(array_filter($v, static fn (mixed $e): bool => $e instanceof \stdClass))
            : [];
    }

    /** @return list<array{name: ?string, created_at: ?int, last_used: ?int}> */
    private static function uses(mixed $v): array
    {
        return array_map(static fn (\stdClass $e): array => [
            'name' => self::text($e, 'name'),
            'created_at' => self::count($e, 'created_at'),
            'last_used' => self::count($e, 'last_used'),
        ], self::objects($v));
    }
}
