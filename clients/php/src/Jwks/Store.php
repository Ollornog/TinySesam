<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

/**
 * Where the key set cache keeps its {@see State}, and the lock that lets one fetch serve every request.
 *
 * - {@see MemoryStore} (the default) lives as long as the PHP process: right for long-running workers (RoadRunner,
 *   FrankenPHP's worker mode, Swoole, ReactPHP) and the CLI.
 * - {@see FileStore} is shared by every process of one host: needed under PHP-FPM, mod_php or CGI, where nothing of
 *   PHP survives a request — without it every request would fetch the key set (spec section 7).
 */
interface Store
{
    /** The current state; an empty State when there is none or it is unreadable. */
    public function load(): State;

    /** Replaces the state. */
    public function save(State $state): void;

    /**
     * Takes the fetch lock, waiting at most $timeoutSeconds for a fetch elsewhere to finish. Returns false when the
     * lock could not be had in time; the request then goes on with the cached set.
     */
    public function lock(float $timeoutSeconds): bool;

    /** Releases the fetch lock. */
    public function unlock(): void;

    /** Now, in whole seconds on the clock this store's timestamps use. */
    public function now(): int;
}
