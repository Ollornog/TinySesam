<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * What the account is (spec version 2): a person (`user`) or a service account (`service`). Independent of {@see Kind}:
 * a paired service acting as a person is `token` and `user`.
 */
enum AccountKind: string
{
    case User = 'user';
    case Service = 'service';

    /**
     * The account-kind rules of spec version 2 (section 2.2 rules 6-8, section 4.4 step 9): $kind is the value of
     * Remote-Kind or ts_kind (null or empty when missing), $auth that of Remote-Auth or ts_auth. Returns the reason for
     * a refusal, or null — a missing or unknown kind is never taken as `user`, and a service account has no session.
     */
    public static function problem(mixed $kind, mixed $auth): ?string
    {
        if ($kind === null || $kind === '') {
            return 'Remote-Kind/ts_kind missing (TinySesam or proxy older than spec v2?)';
        }
        if ($kind !== 'user' && $kind !== 'service') {
            return 'Remote-Kind/ts_kind is not exactly user or service';
        }
        if ($kind === 'service' && $auth === 'session') {
            return 'a service account has no session';
        }

        return null;
    }
}
