<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** The request {@see Permissions::register()} sends: PUT `<base>/auth/api/apps/<app>/permissions` with `$body` as JSON. */
final readonly class PermissionRequest
{
    /**
     * @param non-empty-string $method
     * @param non-empty-string $url
     * @param array{permissions: list<mixed>} $body
     */
    public function __construct(public string $method, public string $url, public array $body)
    {
    }
}
