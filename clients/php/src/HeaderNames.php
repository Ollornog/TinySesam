<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\Strict;

/**
 * The seven headers of header mode. TinySesam's forward_headers can rename them; a slot left out keeps its default.
 */
final readonly class HeaderNames
{
    /**
     * @throws ConfigError when a name is no valid field name or two slots share a name
     */
    public function __construct(
        public string $user = 'Remote-User',
        public string $name = 'Remote-Name',
        public string $email = 'Remote-Email',
        public string $groups = 'Remote-Groups',
        public string $id = 'Remote-Id',
        public string $auth = 'Remote-Auth',
        public string $kind = 'Remote-Kind',
    ) {
        $seen = [];
        foreach ($this->slots() as $n) {
            $lower = strtolower($n);
            if (!Strict::isToken($n) || isset($seen[$lower])) {
                throw new ConfigError('invalid or repeated header name');
            }
            $seen[$lower] = true;
        }
    }

    /**
     * The names by slot, in the order of the specification.
     *
     * @return array{user: string, name: string, email: string, groups: string, id: string, auth: string, kind: string}
     */
    public function slots(): array
    {
        return [
            'user' => $this->user,
            'name' => $this->name,
            'email' => $this->email,
            'groups' => $this->groups,
            'id' => $this->id,
            'auth' => $this->auth,
            'kind' => $this->kind,
        ];
    }
}
