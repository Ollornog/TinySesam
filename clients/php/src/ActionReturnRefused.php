<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * {@see Account::parseActionReturn()} refused the way back of an action page. `reason` is `invalid` (not a way back an
 * action page gives: an unknown action or result, one of the three names twice or missing, a value outside printable
 * ASCII, a broken escape, a `state` outside the rule) or `state` (a `state` the application did not issue). Show no
 * message for it; the application reads the account overview again anyway.
 */
final class ActionReturnRefused extends \RuntimeException
{
    /** @param 'invalid'|'state' $reason */
    public function __construct(public readonly string $reason)
    {
        parent::__construct('tinysesam: action page way back refused: ' . $reason);
    }
}
