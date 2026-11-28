<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\Strict;

/**
 * Registering the application's permissions with TinySesam (spec section 3.4, T-101). Registering grants nothing: an
 * administrator assigns permissions to roles, and the proxy then sends the account's permissions for this application
 * ({@see Identity::hasPermission()}).
 */
final class Permissions
{
    /** The largest manifest TinySesam takes per application. */
    public const int MAX_PERMISSIONS = 200;
    private const string APP_ID = '/\A[a-z][a-z0-9_]{0,31}\z/';
    private const string NAME = '/\A[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}\z/';

    /**
     * Checks a manifest the way spec section 3.4 asks and builds the request, without sending it.
     *
     * @throws ConfigError a base URL that is not https (plain http only to a loopback address), an application id
     *     outside the rule, a manifest that is no list or has more than 200 entries, an entry that is no object or
     *     whose name breaks the rule, a name twice
     */
    public static function request(string $baseUrl, string $app, mixed $permissions): PermissionRequest
    {
        try {
            Gate::checkJwksUrl($baseUrl);
        } catch (ConfigError) {
            throw new ConfigError('the base URL must be https (plain http only to a loopback address)');
        }
        if (preg_match(self::APP_ID, $app) !== 1) {
            throw new ConfigError('the application id must match ^[a-z][a-z0-9_]{0,31}$');
        }
        if (!\is_array($permissions) || !array_is_list($permissions) || \count($permissions) > self::MAX_PERMISSIONS) {
            throw new ConfigError('the manifest is a list of at most ' . self::MAX_PERMISSIONS . ' permissions');
        }
        $seen = [];
        foreach ($permissions as $entry) {
            $name = match (true) {
                $entry instanceof \stdClass => $entry->name ?? null,
                \is_array($entry) && !array_is_list($entry) => $entry['name'] ?? null,
                default => null,
            };
            if (!\is_string($name) || preg_match(self::NAME, $name) !== 1) {
                throw new ConfigError('every permission is an object whose name matches the rule of spec section 3.4');
            }
            if (isset($seen[$name])) {
                throw new ConfigError('a permission name twice');
            }
            $seen[$name] = true;
        }

        return new PermissionRequest(
            'PUT',
            rtrim($baseUrl, '/') . '/auth/api/apps/' . $app . '/permissions',
            ['permissions' => $permissions],
        );
    }

    /**
     * Registers the application's whole manifest with TinySesam (PUT /auth/api/apps/{id}/permissions) with an
     * automation key of the application's service account (scope `permissions:register`), straight to TinySesam,
     * never through the proxy. Returns TinySesam's answer (`added`, `updated`, `returned`, `orphaned`). Deadline
     * 5 seconds; the key goes in `X-Api-Key` and never into an exception.
     *
     * @param list<mixed> $permissions
     *
     * @return array<string, mixed>
     *
     * @throws ConfigError a manifest {@see request()} refuses (nothing is sent) or a missing key
     * @throws RegistrationFailed TinySesam not reachable or any answer but 200
     */
    public static function register(string $baseUrl, string $app, array $permissions, string $apiKey): array
    {
        $req = self::request($baseUrl, $app, $permissions);
        if ($apiKey === '' || Strict::hasControl($apiKey)) {
            throw new ConfigError('an API key is required');
        }
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $req->url,
            CURLOPT_CUSTOMREQUEST => $req->method,
            CURLOPT_POSTFIELDS => json_encode($req->body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json',
                'X-Api-Key: ' . $apiKey],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_TIMEOUT_MS => 5000,
            CURLOPT_CONNECTTIMEOUT_MS => 5000,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if (!\is_string($body)) {
            throw new RegistrationFailed('TinySesam not reachable');
        }
        if ($status !== 200) {
            throw new RegistrationFailed('TinySesam refused the manifest (' . $status . ')', $status);
        }
        [$ok, $data] = Strict::parseJson($body);
        if (!$ok || !$data instanceof \stdClass) {
            throw new RegistrationFailed('an answer that is no JSON object', $status);
        }

        $out = [];
        foreach (get_object_vars($data) as $key => $value) {
            $out[(string) $key] = $value;
        }

        return $out;
    }
}
