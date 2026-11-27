<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * Who made the request, the same in both modes (spec section 1). Key your own records by {@see Identity::$id}: it is
 * the only value that survives a rename. `user`, `name` and `email` may hold any character except controls —
 * bidirectional overrides and zero-width characters included — so escape them for HTML (htmlspecialchars) and isolate
 * them as bidi text.
 */
final readonly class Identity
{
    private const array AUTH_VALUES = ['session', 'oauth', 'apikey', 'app-password'];

    /** The account name (sign-in identifier). */
    public string $user;
    /** The display name, may be empty. */
    public string $name;
    /** May be empty. */
    public string $email;
    /** @var list<string> The roles (spec section 3.3); incomplete on purpose for a token request. */
    public array $groups;
    /** The account ID, decimal digits. */
    public string $id;
    /** session, oauth, apikey, app-password, or empty. */
    public string $auth;
    /** `session` only when auth is exactly `session`. */
    public Kind $kind;
    /** `user` or `service`, never empty (spec version 2). */
    public AccountKind $accountKind;
    /**
     * @var list<string> The account's permissions for this application (spec section 3.4, Remote-Permissions or
     *     ts_perms); empty when TinySesam sends none — which means "holds none", never "unknown".
     */
    public array $permissions;

    /**
     * @param string $groups the raw Remote-Groups or ts_groups value
     * @param string $accountKind the raw Remote-Kind or ts_kind value
     * @param string $permissions the raw Remote-Permissions or ts_perms value
     *
     * @throws GateError when the account kind is missing or invalid — an identity never exists without one
     */
    public function __construct(
        string $user,
        string $name,
        string $email,
        string $groups,
        string $id,
        string $auth,
        string $accountKind,
        string $permissions = '',
    ) {
        $problem = AccountKind::problem($accountKind, $auth);
        if ($problem !== null) {
            throw new GateError(ErrorClass::Header, $problem);
        }
        $this->user = $user;
        $this->name = $name;
        $this->email = $email;
        $this->groups = self::parseGroups($groups);
        $this->id = $id;
        $this->auth = \in_array($auth, self::AUTH_VALUES, true) ? $auth : '';
        $this->kind = $this->auth === 'session' ? Kind::Session : Kind::Token;
        $this->accountKind = AccountKind::from($accountKind);
        $this->permissions = self::parseGroups($permissions);
    }

    /**
     * Whether $permission is one of the permissions, compared exactly (spec section 3.4): no case folding, no wildcard,
     * and neither `admin` nor a role implies one.
     */
    public function hasPermission(string $permission): bool
    {
        return \in_array($permission, $this->permissions, true);
    }

    /**
     * Whether $role is one of the groups, compared exactly: no case folding, no normalization, and no role implied by
     * `admin`. Whether an admin passes every role check is the application's decision.
     */
    public function hasRole(string $role): bool
    {
        return \in_array($role, $this->groups, true);
    }

    /**
     * Whether the request came from a browser session. The groups of a token request are incomplete on purpose (a token
     * never carries admin): never conclude from a missing group that the account lacks it.
     */
    public function isSession(): bool
    {
        return $this->kind === Kind::Session;
    }

    /** Whether the account is a service account (Remote-Kind or ts_kind exactly `service`). */
    public function isService(): bool
    {
        return $this->accountKind === AccountKind::Service;
    }

    /**
     * The plain fields, as the vectors of the specification spell them.
     *
     * @return array{
     *     user: string,
     *     name: string,
     *     email: string,
     *     groups: list<string>,
     *     id: string,
     *     auth: string,
     *     kind: string,
     *     account_kind: string,
     *     permissions: list<string>,
     * }
     */
    public function toArray(): array
    {
        return [
            'user' => $this->user,
            'name' => $this->name,
            'email' => $this->email,
            'groups' => $this->groups,
            'id' => $this->id,
            'auth' => $this->auth,
            'kind' => $this->kind->value,
            'account_kind' => $this->accountKind->value,
            'permissions' => $this->permissions,
        ];
    }

    /**
     * Reads Remote-Groups or ts_groups (spec section 3.3): split at every comma, remove leading and trailing spaces
     * (U+0020 only), drop empty and repeated entries, keep the order. There is no escape mechanism.
     *
     * @return list<string>
     */
    public static function parseGroups(string $s): array
    {
        $out = [];
        foreach (explode(',', $s) as $part) {
            $g = trim($part, ' ');
            if ($g !== '' && !\in_array($g, $out, true)) {
                $out[] = $g;
            }
        }

        return $out;
    }
}
