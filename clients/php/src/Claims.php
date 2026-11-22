<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * The claims of a valid gate token. {@see Claims::$raw} holds every claim as decoded (objects as \stdClass); unknown
 * claims are ignored by the checks but kept there.
 */
final readonly class Claims
{
    /**
     * @param list<string> $aud
     * @param array<array-key, mixed> $raw every claim; a name of decimal digits is an int key, as in any PHP array
     */
    public function __construct(
        public string $iss,
        public array $aud,
        public string $sub,
        public int $iat,
        public int $nbf,
        public int $exp,
        public string $jti,
        public array $raw,
    ) {
    }
}
