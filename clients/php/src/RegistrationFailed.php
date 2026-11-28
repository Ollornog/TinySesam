<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** TinySesam did not take the manifest: not reachable (`status` 0) or any answer but 200. */
final class RegistrationFailed extends \RuntimeException
{
    public function __construct(string $message, public readonly int $status = 0)
    {
        parent::__construct($message);
    }
}
