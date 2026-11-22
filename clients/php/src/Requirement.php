<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * What a route requires: any identity, a role (compared exactly), a browser session, or an account kind (`user` for a
 * route only people may use, `service` for one only service accounts may use).
 */
final readonly class Requirement
{
    private function __construct(
        private string $what,
        private string $role = '',
        private ?AccountKind $accountKind = null,
    ) {
    }

    /** Any identity. */
    public static function signedIn(): self
    {
        return new self('signed-in');
    }

    /** A browser session (`Remote-Auth: session`); a token request is 403. */
    public static function session(): self
    {
        return new self('session');
    }

    /** The role, compared exactly; no role is implied by `admin`. */
    public static function role(string $role): self
    {
        return new self('role', $role);
    }

    /** The account kind of spec version 2. */
    public static function accountKind(AccountKind $kind): self
    {
        return new self('account-kind', '', $kind);
    }

    /** Whether the identity meets this requirement. */
    public function isMetBy(Identity $identity): bool
    {
        return match ($this->what) {
            'signed-in' => true,
            'session' => $identity->isSession(),
            'role' => $identity->hasRole($this->role),
            'account-kind' => $identity->accountKind === $this->accountKind,
            default => false,
        };
    }
}
