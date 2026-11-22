<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** Where a verifier gets the key for a kid: fixed keys ({@see StaticKeys}) or a key set URL ({@see Jwks\JwksCache}). */
interface KeySource
{
    /**
     * The 32 raw bytes of the Ed25519 public key for $kid.
     *
     * @throws GateError of the class `kid` or `key_unavailable`
     */
    public function lookup(string $kid): string;
}
