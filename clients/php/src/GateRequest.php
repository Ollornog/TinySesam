<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The request as the gate sees it: the header field lines and the socket address of the peer.
 *
 * What PHP hands an application decides what the gate can see. Under PHP-FPM, mod_php and CGI the web server turns
 * every header into a variable `HTTP_<NAME>`: a repeated field arrives joined into one value, and `Remote-User` and
 * `Remote_User` become the same variable. The gate then cannot refuse a repeated Remote-* field (spec section 2.2 rule
 * 1) — the proxy's duty to remove them (section 2.1) has to hold, and the web server must drop header names with an
 * underscore (nginx and Apache do by default). PHP's built-in server also cuts a value at a NUL byte. A long-running
 * server (RoadRunner, ReactPHP, AMPHP, Swoole) usually keeps the field lines; its PSR-7 request then carries each line
 * as its own value.
 */
final readonly class GateRequest
{
    /**
     * @param list<array{0: string, 1: string}> $fields one [name, value] pair per field line, values as octets
     * @param ?string $peer the peer's socket address (REMOTE_ADDR, never X-Forwarded-For); needed with trusted proxies
     */
    public function __construct(
        public array $fields,
        public ?string $peer = null,
    ) {
    }

    /** From a PSR-7 server request: every value of every header as a field line, the peer from `REMOTE_ADDR`. */
    public static function fromPsr7(ServerRequestInterface $request): self
    {
        $fields = [];
        foreach ($request->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                $fields[] = [(string) $name, $value];
            }
        }
        $peer = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return new self($fields, \is_string($peer) ? $peer : null);
    }

    /**
     * From `$_SERVER` of a classic SAPI (PHP-FPM, mod_php, CGI): each `HTTP_*` variable as a field line named with
     * dashes. Read the gate cookie from here too, never from `$_COOKIE`: PHP keeps only one of two equal cookie names
     * and rewrites dots and spaces in them.
     *
     * @param array<array-key, mixed> $server usually `$_SERVER`
     */
    public static function fromGlobals(array $server): self
    {
        $fields = [];
        foreach ($server as $key => $value) {
            if (\is_string($key) && str_starts_with($key, 'HTTP_') && \is_string($value)) {
                $fields[] = [str_replace('_', '-', substr($key, 5)), $value];
            }
        }
        $peer = $server['REMOTE_ADDR'] ?? null;

        return new self($fields, \is_string($peer) ? $peer : null);
    }
}
