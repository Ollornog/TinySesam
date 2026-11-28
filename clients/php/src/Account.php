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
 * every group is null; signed in, `account`, `sign_in`, `sessions`, `programs`, `links` and `actions` are always
 * arrays and a null inside them means "missing, of the wrong type or not offered". Every string is text, never markup
 * — escape it. Changes happen on TinySesam's account page and its action pages (spec section 8c), which the links and
 * `actions` lead to; {@see Account::actionUrl()} builds the address with the way back. Do not cache the result across
 * sessions.
 */
final class Account
{
    private const array LINKS = ['account', 'sessions', 'totp', 'passkeys', 'devices', 'app_passwords', 'services',
        'approvals'];
    /** The own action pages of spec section 8c, the members of `actions`. */
    private const array ACTIONS = ['username', 'email', 'password', 'pin', 'totp', 'recovery_codes', 'passkeys',
        'api_keys', 'app_passwords', 'sessions', 'programs', 'services'];
    /** The longest `state` an action page carries back (spec section 8c). */
    public const int ACTION_STATE_MAX = 128;

    private function __construct()
    {
    }

    /**
     * The overview of a signed-out request (also the answer to anything doubtful).
     *
     * @return array{signed_in: false, account: null, sign_in: null, sessions: null, programs: null, approvals: null,
     *     permissions: null, links: null, actions: null}
     */
    public static function signedOut(): array
    {
        return ['signed_in' => false, 'account' => null, 'sign_in' => null, 'sessions' => null, 'programs' => null,
            'approvals' => null, 'permissions' => null, 'links' => null, 'actions' => null];
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
        $actions = self::group($data, 'actions');
        $totp = Strict::member($signIn, 'totp');
        $passkeys = Strict::member($signIn, 'passkeys');
        $approvals = Strict::member($data, 'approvals');
        $pending = $approvals instanceof \stdClass ? self::count($approvals, 'pending') : null;
        $appPasswords = Strict::member($programs, 'app_passwords');
        $hrefs = [];
        foreach (self::LINKS as $name) {
            $hrefs[$name] = self::href($links, $name);
        }
        $pages = [];
        foreach (self::ACTIONS as $name) {
            $pages[$name] = self::href($actions, $name);
        }

        return [
            'signed_in' => true,
            'account' => ['username' => self::text($account, 'username'),
                'display_name' => self::text($account, 'display_name'),
                // Where the account comes from: local, oidc, saml, ldap (two or more = mixed); null when no list.
                'source' => self::texts($account, 'source')],
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
                    // The session handle (opaque text) and the action page that ends exactly this session.
                    'handle' => self::text($e, 'handle'),
                    'end' => self::href($e, 'end'),
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
            'permissions' => self::permissions(Strict::member($data, 'permissions')),
            'links' => $hrefs,
            'actions' => $pages,
        ];
    }

    /**
     * The address of an action page with the way back (spec section 8c): $href is a member of `actions` or a session's
     * `end` (ending exactly that session), $returnTo the absolute http(s) URL on the application's own host to come
     * back to, $state an optional value of the application (null or '' for none; printable ASCII, at most
     * {@see self::ACTION_STATE_MAX} characters). Send the person there by navigation; the page leads back with
     * `ts_action`, `ts_result` and `state`.
     *
     * @throws ConfigError an href that fails the rule of spec section 8 or carries a fragment, a $returnTo that is no
     *     absolute http(s) URL of printable ASCII, a $state outside the rule
     */
    public static function actionUrl(string $href, string $returnTo, ?string $state = null): string
    {
        if (!Topbar::isSafeHref($href) || str_contains($href, '#')) {
            throw new ConfigError('actionUrl: the href is no action page address');
        }
        if (preg_match('~^https?://[\x21-\x7e]*$~iD', $returnTo) !== 1) {
            throw new ConfigError('actionUrl: returnTo must be an absolute http(s) URL in printable ASCII');
        }
        $state ??= '';
        if (\strlen($state) > self::ACTION_STATE_MAX || preg_match('~^[\x21-\x7e]*$~D', $state) !== 1) {
            throw new ConfigError('actionUrl: state is printable ASCII of at most 128 characters');
        }
        // rawurlencode keeps exactly A-Z a-z 0-9 - . _ ~ (RFC 3986) and writes upper-case hex digits.
        $url = $href . (str_contains($href, '?') ? '&' : '?') . 'return=' . rawurlencode($returnTo);

        return $state === '' ? $url : $url . '&state=' . rawurlencode($state);
    }

    /**
     * Spec section 8a `permissions`: an object gives `app` (text or null) and `names` (the strings of a list, [] for no
     * list); anything else null — the host belongs to no application.
     *
     * @return array{app: ?string, names: list<string>}|null
     */
    private static function permissions(mixed $value): ?array
    {
        if (!$value instanceof \stdClass) {
            return null;
        }
        $names = Strict::member($value, 'names');

        return [
            'app' => self::text($value, 'app'),
            'names' => \is_array($names) ? array_values(array_filter($names, 'is_string')) : [],
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

    /**
     * The string entries of a list, in order; null when it is no list.
     *
     * @return list<string>|null
     */
    private static function texts(\stdClass $m, string $name): ?array
    {
        $v = Strict::member($m, $name);

        return \is_array($v) ? array_values(array_filter($v, static fn (mixed $e): bool => \is_string($e))) : null;
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
