<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * The claims of a valid approval confirmation. {@see ApprovalClaims::$raw} holds every claim as decoded (objects as
 * \stdClass), unknown ones included.
 */
final readonly class ApprovalClaims
{
    /**
     * @param list<string> $amr how the person stepped up (RFC 8176 values)
     * @param array<array-key, string|int|bool> $fields the fields of the action, without `type`
     * @param array<array-key, mixed> $raw every claim
     */
    public function __construct(
        public string $iss,
        public string $aud,
        public string $sub,
        public int $iat,
        public int $nbf,
        public int $exp,
        public int $authTime,
        public string $jti,
        public array $amr,
        /** `act.sub`: `app:<application id>`. */
        public string $actor,
        public string $type,
        public array $fields,
        public ?string $nonce,
        public array $raw,
    ) {
    }
}
