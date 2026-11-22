<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** Fixed keys from configuration. */
final readonly class StaticKeys implements KeySource
{
    public function __construct(private KeySet $keys)
    {
    }

    public function lookup(string $kid): string
    {
        return $this->keys->get($kid) ?? throw new GateError(ErrorClass::Kid, 'kid not in the key set', $kid);
    }
}
