<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** A contradictory or incomplete configuration: thrown at start-up instead of failing open later (spec section 6). */
final class ConfigError extends \InvalidArgumentException
{
    public function __construct(string $message)
    {
        parent::__construct('tinysesam: configuration: ' . $message);
    }
}
