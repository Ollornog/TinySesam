<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

/**
 * What the cache remembers between requests: the last good key set document, until when it is fresh, and when the last
 * fetch was attempted — all in seconds on the clock of the {@see Store}.
 */
final readonly class State
{
    public function __construct(
        /** The last good key set document (as fetched), or null when there has never been one. */
        public ?string $document = null,
        public int $freshUntil = 0,
        /** The time of the last fetch attempt, or null when there has been none. */
        public ?int $lastAttempt = null,
    ) {
    }
}
