<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** The outcome of a guard: allowed, 401 (not authenticated) or 403 (authenticated, requirement not met). */
enum Decision: int
{
    case Allow = 200;
    case Unauthorized = 401;
    case Forbidden = 403;

    /**
     * Decides a request against requirements. No identity is 401; an identity that misses a requirement is 403 —
     * never why (spec section 6).
     *
     * @param list<Requirement> $requirements
     */
    public static function of(?Identity $identity, array $requirements = []): self
    {
        if ($identity === null) {
            return self::Unauthorized;
        }
        foreach ($requirements as $r) {
            if (!$r->isMetBy($identity)) {
                return self::Forbidden;
            }
        }

        return self::Allow;
    }
}
