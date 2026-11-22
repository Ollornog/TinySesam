<?php

declare(strict_types=1);

namespace TinySesam\Gate\Psr15;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TinySesam\Gate\Decision;
use TinySesam\Gate\Identity;
use TinySesam\Gate\Requirement;

/**
 * PSR-15 guard for a route behind a {@see GateMiddleware}: reads the identity from the request attribute and answers
 * 401 or 403 when the requirements are not met. A request that no GateMiddleware has seen has no identity: 401.
 */
final readonly class RequireMiddleware implements MiddlewareInterface
{
    /**
     * @param list<Requirement> $require an empty list means signed in
     */
    public function __construct(
        private ResponseFactoryInterface $responses,
        private array $require = [],
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return self::deny($this->responses, GateMiddleware::identityOf($request), $this->require)
            ?? $handler->handle($request);
    }

    /**
     * The refusal for an identity, or null when it may pass.
     *
     * @param list<Requirement> $require
     */
    public static function deny(
        ResponseFactoryInterface $responses,
        ?Identity $identity,
        array $require,
    ): ?ResponseInterface {
        $decision = Decision::of($identity, $require);
        if ($decision === Decision::Allow) {
            return null;
        }
        $text = $decision === Decision::Unauthorized ? 'Unauthorized' : 'Forbidden';
        $response = $responses->createResponse($decision->value, $text)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Content-Type', 'text/plain; charset=utf-8');
        $response->getBody()->write($text);

        return $response;
    }
}
