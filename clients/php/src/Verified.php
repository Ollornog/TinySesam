<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** A verified gate token: the identity and the claims it came from. */
final readonly class Verified
{
    public function __construct(
        public Identity $identity,
        public Claims $claims,
    ) {
    }
}
