<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\Internal\Token;

/**
 * Top bar data (spec section 8): TinySesam's topbar.json reduced to what an application may render. Every href is an
 * absolute http(s) URL or a path starting with exactly one slash; titles and the name are text, never markup — escape
 * them (htmlspecialchars). Do not cache it across sessions (TinySesam sends no-store).
 */
final readonly class Topbar
{
    /**
     * @param list<array{title: string, href: string}> $links
     * @param list<array{title: string, href: string}> $menuLinks the account menu (spec version 2); empty when none
     */
    public function __construct(
        public string $brand = '',
        public bool $signedIn = false,
        public ?string $name = null,
        public array $links = [],
        public array $menuLinks = [],
        public ?string $account = null,
        public ?string $adminPanel = null,
        public ?string $logout = null,
        /**
         * The approvals waiting for this account, when TinySesam has approvals switched on and the answer carries a
         * count of at least 0 and a safe link. Show the number with a word ("Approvals (2)"), never as a coloured
         * dot alone.
         *
         * @var ?array{pending: int, href: string}
         */
        public ?array $approvals = null,
    ) {
    }

    /**
     * Normalizes the body of `/.tinysesam/topbar.json` or `/auth/topbar.json`. Anything but a JSON object with
     * `signed_in` true (the boolean) and a string `name` counts as signed out; unsafe links are dropped.
     */
    public static function parse(string $body): self
    {
        [$ok, $data] = Strict::parseJson($body);
        if (!$ok || !$data instanceof \stdClass) {
            return new self();
        }
        $brandValue = Strict::member($data, 'brand');
        $brand = \is_string($brandValue) ? $brandValue : '';
        $name = Strict::member($data, 'name');
        if (Strict::member($data, 'signed_in') !== true || !\is_string($name)) {
            return new self($brand);
        }
        $shown = static function (string $slot) use ($data): ?string {
            $m = Strict::member($data, $slot);
            if (!$m instanceof \stdClass || Strict::member($m, 'shown') !== true) {
                return null;
            }
            $href = Strict::member($m, 'href');

            return \is_string($href) && self::isSafeHref($href) ? $href : null;
        };
        $logoutSlot = Strict::member($data, 'logout');
        $logoutHref = $logoutSlot instanceof \stdClass ? Strict::member($logoutSlot, 'href') : null;

        return new self(
            $brand,
            true,
            $name,
            self::links(Strict::member($data, 'links')),
            self::links(Strict::member($data, 'menu_links')),
            $shown('account'),
            $shown('admin_panel'),
            \is_string($logoutHref) && self::isSafeHref($logoutHref) ? $logoutHref : null,
            self::approvals(Strict::member($data, 'approvals')),
        );
    }

    /**
     * `approvals` of spec section 8: a count of at least 0 and a safe href, or nothing at all.
     *
     * @return ?array{pending: int, href: string}
     */
    private static function approvals(mixed $raw): ?array
    {
        if (!$raw instanceof \stdClass) {
            return null;
        }
        $pending = Strict::member($raw, 'pending');
        $href = Strict::member($raw, 'href');
        if (!\is_int($pending) || $pending < 0 || $pending > Token::MAX_SAFE) {
            return null;
        }

        return \is_string($href) && self::isSafeHref($href) ? ['pending' => $pending, 'href' => $href] : null;
    }

    /**
     * Whether an href may be rendered: an absolute http/https URL or a path that starts with exactly one slash (not
     * `//`, not `/\`), without whitespace or control characters.
     */
    public static function isSafeHref(string $href): bool
    {
        if (!Strict::isUtf8($href) || Strict::hasControl($href) || preg_match('/\p{White_Space}/u', $href) !== 0) {
            return false;
        }
        if (
            Strict::asciiEqualFold(substr($href, 0, 8), 'https://')
            || Strict::asciiEqualFold(substr($href, 0, 7), 'http://')
        ) {
            return true;
        }

        return str_starts_with($href, '/') && !str_starts_with($href, '//') && !str_starts_with($href, '/\\');
    }

    /**
     * The safe {title, href} entries of a link list; anything that is no list counts as none.
     *
     * @return list<array{title: string, href: string}>
     */
    private static function links(mixed $raw): array
    {
        $links = [];
        foreach (\is_array($raw) ? $raw : [] as $l) {
            if (!$l instanceof \stdClass) {
                continue;
            }
            $title = Strict::member($l, 'title');
            $href = Strict::member($l, 'href');
            if (\is_string($title) && \is_string($href) && self::isSafeHref($href)) {
                $links[] = ['title' => $title, 'href' => $href];
            }
        }

        return $links;
    }

    /**
     * The normalized result as the vectors spell it.
     *
     * @return array{
     *     brand: string,
     *     signed_in: bool,
     *     name: ?string,
     *     links: list<array{title: string, href: string}>,
     *     menu_links: list<array{title: string, href: string}>,
     *     account: ?string,
     *     admin_panel: ?string,
     *     logout: ?string,
     *     approvals: ?array{pending: int, href: string},
     * }
     */
    public function toArray(): array
    {
        return [
            'brand' => $this->brand,
            'signed_in' => $this->signedIn,
            'name' => $this->name,
            'links' => $this->links,
            'menu_links' => $this->menuLinks,
            'account' => $this->account,
            'admin_panel' => $this->adminPanel,
            'logout' => $this->logout,
            'approvals' => $this->approvals,
        ];
    }
}
