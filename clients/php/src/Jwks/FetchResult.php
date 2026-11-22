<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

/** The answer of one fetch attempt. */
final readonly class FetchResult
{
    public function __construct(
        public int $status,
        public ?string $cacheControl,
        public string $body,
    ) {
    }
}
