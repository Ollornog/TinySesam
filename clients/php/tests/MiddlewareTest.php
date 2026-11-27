<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TinySesam\Gate\AccountKind;
use TinySesam\Gate\Gate;
use TinySesam\Gate\Identity;
use TinySesam\Gate\Psr15\GateMiddleware;
use TinySesam\Gate\Psr15\RequireMiddleware;
use TinySesam\Gate\Requirement;
use TinySesam\Gate\Tests\Support\Server;
use TinySesam\Gate\Tests\Support\Vectors;

/**
 * The PSR-15 middleware with a real PSR-7 implementation (nyholm/psr7), every header vector through it, the guards —
 * and every header vector through PHP's built-in server and `$_SERVER`, the way PHP-FPM hands a request over.
 */
final class MiddlewareTest extends TestCase
{
    /** The handler at the end of the chain: answers 200 with the identity the middleware attached. */
    private static function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $id = GateMiddleware::identityOf($request);
                if ($id === null) {
                    return new Response(200, [], 'null');
                }
                // The identity as headers.json lists it: without permissions (permissions.json checks those).
                $plain = $id->toArray();
                unset($plain['permissions']);

                return new Response(200, [], Vectors::encode($plain));
            }
        };
    }

    /** @param list<array{0: string, 1: string}> $fields */
    private static function request(array $fields, string $peer = '127.0.0.1'): ServerRequestInterface
    {
        $r = new ServerRequest('GET', 'https://app.example.com/', [], null, '1.1', ['REMOTE_ADDR' => $peer]);
        foreach ($fields as [$name, $value]) {
            $r = $r->withAddedHeader($name, $value);
        }

        return $r;
    }

    public function testEveryHeaderVectorThroughTheMiddleware(): void
    {
        $mw = new GateMiddleware(Gate::headerMode(trustedProxies: ['127.0.0.1']), new Psr17Factory());
        $problems = [];
        foreach (Vectors::load('headers.json')->vectors as $v) {
            try {
                $response = $mw->process(self::request(Vectors::headerFields($v->input->headers)), self::handler());
                $body = (string) $response->getBody();
            } catch (\InvalidArgumentException) {
                $body = 'null'; // the PSR-7 implementation refusing a header value is a refusal too
            }
            if ($v->expected->ok === true) {
                $want = Vectors::normalize($v->expected->identity);
                if ($body === 'null' || Vectors::normalize(json_decode($body, false)) !== $want) {
                    $problems[] = "{$v->id}: {$body}";
                }
            } elseif ($body !== 'null') {
                $problems[] = "{$v->id}: accepted ({$body}), want {$v->expected->error}";
            }
        }
        self::assertSame([], $problems);
    }

    public function testTheMiddlewareGuardsAnswer401And403WithoutDetail(): void
    {
        $factory = new Psr17Factory();
        $gate = Gate::headerMode();
        $mw = new GateMiddleware($gate, $factory, [Requirement::role('editors'), Requirement::session()]);
        $session = [
            ['Remote-User', 'anna'],
            ['Remote-Groups', 'editors'],
            ['Remote-Auth', 'session'],
            ['Remote-Kind', 'user'],
        ];
        $ok = $mw->process(self::request($session), self::handler());
        self::assertSame(200, $ok->getStatusCode());
        $none = $mw->process(self::request([['Remote-User', 'anna']]), self::handler());
        self::assertSame(
            [401, 'Unauthorized', 'no-store'],
            [$none->getStatusCode(), (string) $none->getBody(), $none->getHeaderLine('Cache-Control')],
        );
        $apiKey = $session;
        $apiKey[2] = ['Remote-Auth', 'apikey'];
        $forbidden = $mw->process(self::request($apiKey), self::handler());
        self::assertSame([403, 'Forbidden'], [$forbidden->getStatusCode(), (string) $forbidden->getBody()]);
        self::assertStringNotContainsString('anna', Vectors::encode($forbidden->getHeaders()) . $forbidden->getBody());
        // Identify only, then a route guard.
        $identify = new GateMiddleware($gate, $factory);
        $passed = $identify->process(self::request([]), self::handler());
        self::assertSame([200, 'null'], [$passed->getStatusCode(), (string) $passed->getBody()]);
        $route = new RequireMiddleware($factory, [Requirement::accountKind(AccountKind::Service)]);
        $chain = new class ($route) implements RequestHandlerInterface {
            public function __construct(private readonly RequireMiddleware $route)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->route->process($request, MiddlewareTest::endHandler());
            }
        };
        self::assertSame(403, $identify->process(self::request($session), $chain)->getStatusCode());
        $service = [['Remote-User', 'bot'], ['Remote-Auth', 'oauth'], ['Remote-Kind', 'service']];
        self::assertSame(200, $identify->process(self::request($service), $chain)->getStatusCode());
        $alone = $route->process(self::request($service), self::handler());
        self::assertSame(401, $alone->getStatusCode(), 'no GateMiddleware ran');
        // An attribute that is not an Identity counts as none.
        self::assertNull(GateMiddleware::identityOf(self::request([])->withAttribute(Identity::class, 'anna')));
    }

    public static function endHandler(): RequestHandlerInterface
    {
        return self::handler();
    }

    /**
     * Through PHP's built-in server: the SAPI turns headers into `$_SERVER['HTTP_*']`. Every vector holds except two
     * kinds the SAPI changes before the gate sees the request — it joins a repeated field into one value ("anna, boss")
     * and cuts a value at a NUL byte — which is why spec section 2.1 duty 1 (the proxy removes every Remote-* field of
     * the client) carries header mode here. Both are measured, not assumed.
     */
    public function testEveryHeaderVectorThroughTheBuiltInServerAndServerGlobals(): void
    {
        $server = new Server();
        try {
            $problems = [];
            $joined = [];
            $cutAtNul = [];
            foreach (Vectors::load('headers.json')->vectors as $v) {
                $head = "GET /identify HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n";
                foreach (Vectors::headerFields($v->input->headers) as [$name, $value]) {
                    $head .= "{$name}: {$value}\r\n";
                }
                [$status, $body] = $server->raw($head . "\r\n");
                $answer = json_decode($body, false);
                $identity = $status === 200 && $answer instanceof \stdClass ? ($answer->identity ?? null) : null;
                if ($identity instanceof \stdClass) {
                    unset($identity->permissions); // headers.json lists the identity without them
                }
                if ($v->expected->ok === true) {
                    $want = Vectors::normalize($v->expected->identity);
                    if ($identity === null || Vectors::normalize($identity) !== $want) {
                        $problems[] = "{$v->id}: {$status} {$body}";
                    }
                } elseif ($identity !== null) {
                    $values = array_column(Vectors::headerFields($v->input->headers), 1);
                    $names = array_map('strtolower', array_column(Vectors::headerFields($v->input->headers), 0));
                    if (\count($names) !== \count(array_unique($names))) {
                        $joined[] = $v->id;
                    } elseif (array_any($values, static fn (string $x): bool => str_contains($x, "\0"))) {
                        $cutAtNul[] = $v->id;
                    } else {
                        $problems[] = "{$v->id}: accepted ({$body}), want {$v->expected->error}";
                    }
                }
            }
            self::assertSame([], $problems);
            // If the SAPI ever keeps the lines apart or the NUL, these lists shrink: then update the README.
            self::assertNotEmpty($joined, 'the built-in server kept repeated fields apart: update the README');
            self::assertSame(['kind-control'], $cutAtNul, 'the built-in server changed at NUL: update the README');
        } finally {
            $server->stop();
        }
    }
}
