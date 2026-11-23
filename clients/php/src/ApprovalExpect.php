<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** The action the application stored when it asked — never taken from the confirmation. */
final readonly class ApprovalExpect
{
    /**
     * @param string $type the action type (`authorization_details[0].type`)
     * @param array<array-key, string|int|bool> $fields the fields exactly as sent: names, JSON types and values (`1`,
     *     `"1"` and `true` are three different values)
     * @param string $sub the account the application acts for (a decimal id as a string, for example Remote-Id)
     * @param ?string $nonce the state kept in the person's session (browser entry); null when the application sent none
     */
    public function __construct(
        public string $type,
        public array $fields,
        public string $sub,
        public ?string $nonce = null,
    ) {
    }
}
