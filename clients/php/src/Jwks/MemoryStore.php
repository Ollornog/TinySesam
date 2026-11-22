<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

/**
 * The state in the memory of this PHP process, on a monotonic clock (hrtime), so a step of the wall clock can neither
 * stall nor flood the cache. In a runtime with coroutines or fibers a second request that needs keys while a fetch runs
 * does not wait: it goes on with the cached set (spec section 5, rule 2).
 */
final class MemoryStore implements Store
{
    private State $state;
    private bool $locked = false;

    public function __construct()
    {
        $this->state = new State();
    }

    public function load(): State
    {
        return $this->state;
    }

    public function save(State $state): void
    {
        $this->state = $state;
    }

    public function lock(float $timeoutSeconds): bool
    {
        if ($this->locked) {
            return false;
        }
        $this->locked = true;

        return true;
    }

    public function unlock(): void
    {
        $this->locked = false;
    }

    public function now(): int
    {
        return intdiv(hrtime(true), 1_000_000_000);
    }
}
