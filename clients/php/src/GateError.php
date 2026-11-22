<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * A refusal. It carries the class and, once the kid has passed the format check of spec section 4.4, the kid — never
 * the token, a claim value or a header value, so it is safe to log.
 */
final class GateError extends \RuntimeException
{
    public function __construct(
        public readonly ErrorClass $errorClass,
        string $detail = '',
        /** The format-checked kid of the token, if the check got that far. */
        public readonly ?string $kid = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct(
            $detail === '' ? 'tinysesam: ' . $errorClass->value : 'tinysesam: ' . $errorClass->value . ': ' . $detail,
            0,
            $previous,
        );
    }

    /** The same refusal, carrying the kid. */
    public function withKid(string $kid): self
    {
        return new self($this->errorClass, '', $kid);
    }
}
