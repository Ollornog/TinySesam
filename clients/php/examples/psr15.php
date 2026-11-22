<?php

declare(strict_types=1);

// The PSR-15 middleware in any PSR-15 framework (Slim, Mezzio, a RoadRunner worker, ...): one GateMiddleware for the
// whole application identifies every request, a RequireMiddleware per route decides. The PSR-17 factory comes from any
// PSR-7 implementation; nyholm/psr7 here.

require __DIR__ . '/../vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use TinySesam\Gate\AccountKind;
use TinySesam\Gate\Gate;
use TinySesam\Gate\Psr15\GateMiddleware;
use TinySesam\Gate\Psr15\RequireMiddleware;
use TinySesam\Gate\Requirement;

$factory = new Psr17Factory();

// Header mode (the default and the recommended way).
$gate = Gate::headerMode(trustedProxies: ['127.0.0.1', '::1']);

// Token mode with the key set URL instead — under PHP-FPM with a FileStore in a directory only the application can
// write, so one fetch serves every process:
//
//   $gate = Gate::tokenMode(
//       issuer: 'https://auth.example.com',
//       audience: 'app.example.com',
//       jwksUrl: 'https://auth.example.com/auth/gate/jwks.json',
//       store: new \TinySesam\Gate\Jwks\FileStore('/var/lib/example/tinysesam-jwks.json'),
//   );

$identify = new GateMiddleware($gate, $factory);                                   // every route: identity or null
$editorsOnly = new RequireMiddleware($factory, [Requirement::role('editors')]);     // 401 or 403 otherwise
$browserOnly = new RequireMiddleware($factory, [Requirement::session()]);           // no API key, no OAuth token
$peopleOnly = new RequireMiddleware($factory, [Requirement::accountKind(AccountKind::User)]);

// In a handler:
//
//   $identity = GateMiddleware::identityOf($request);   // TinySesam\Gate\Identity or null
//   $identity?->id;                                      // the key for your own records
