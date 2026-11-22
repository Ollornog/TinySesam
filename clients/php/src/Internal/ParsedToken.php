<?php

declare(strict_types=1);

namespace TinySesam\Gate\Internal;

/**
 * What steps 1-5 of the checking order decide before a key is chosen.
 *
 * @internal
 */
final readonly class ParsedToken
{
    public function __construct(
        /** The ASCII bytes `header-segment.payload-segment`. */
        public string $signingInput,
        public string $payload,
        public string $signature,
        /** The kid, format-checked (16 lowercase hex digits): safe to log. */
        public string $kid,
    ) {
    }
}
