<?php

declare(strict_types=1);

namespace TinySesam\Gate\Psr15;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TinySesam\Gate\Gate;
use TinySesam\Gate\GateRequest;
use TinySesam\Gate\Identity;
use TinySesam\Gate\Requirement;

/**
 * PSR-15 middleware: identifies the request with the gate and puts the {@see Identity} (or null) into the request
 * attribute {@see GateMiddleware::ATTRIBUTE}. With requirements it is also the guard: no identity answers 401, a
 * missing requirement 403 — the status text only, never the token, the claims or why (spec section 6). Without
 * requirements every request passes on, and a {@see RequireMiddleware} on a route decides later.
 */
final readonly class GateMiddleware implements MiddlewareInterface
{
    /** The request attribute that holds the identity (Identity or null). */
    public const string ATTRIBUTE = Identity::class;

    /**
     * @param ?list<Requirement> $require null: identify only; a list (empty: signed in): identify and guard
     */
    public function __construct(
        private Gate $gate,
        private ResponseFactoryInterface $responses,
        private ?array $require = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identity = $this->gate->identifyOrNull(GateRequest::fromPsr7($request));
        $request = $request->withAttribute(self::ATTRIBUTE, $identity);
        if ($this->require !== null) {
            $denied = RequireMiddleware::deny($this->responses, $identity, $this->require);
            if ($denied !== null) {
                return $denied;
            }
        }

        return $handler->handle($request);
    }

    /** The identity a {@see GateMiddleware} put on the request, or null. */
    public static function identityOf(ServerRequestInterface $request): ?Identity
    {
        $identity = $request->getAttribute(self::ATTRIBUTE);

        return $identity instanceof Identity ? $identity : null;
    }
}
