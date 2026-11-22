<?php

declare(strict_types=1);

// A classic PHP page under PHP-FPM or mod_php behind TinySesam's gate, in header mode: the proxy (Caddy with
// Caddyfile.gate, or /auth/forward) has checked the sign-in and set the Remote-* headers. Only safe when the proxy
// fulfils spec section 2.1 and the application is reachable through it alone.

require __DIR__ . '/../vendor/autoload.php';

use TinySesam\Gate\Decision;
use TinySesam\Gate\Gate;
use TinySesam\Gate\GateRequest;
use TinySesam\Gate\Requirement;

// Built once per request (PHP keeps nothing between requests). A wrong setting throws a ConfigError here, before any
// request is answered.
$gate = Gate::headerMode(trustedProxies: ['127.0.0.1', '::1']);

$identity = $gate->identifyOrNull(GateRequest::fromGlobals($_SERVER));
$decision = Decision::of($identity, [Requirement::role('editors')]);
if ($decision !== Decision::Allow || $identity === null) {
    http_response_code($decision->value);
    header('Cache-Control: no-store');
    header('Content-Type: text/plain; charset=utf-8');
    echo $decision === Decision::Unauthorized ? 'Unauthorized' : 'Forbidden';

    exit;
}

header('Content-Type: text/html; charset=utf-8');
// Names may hold any character but controls — escape them, and isolate them as bidi text.
echo '<p>Hello, <bdi>' . htmlspecialchars($identity->name !== '' ? $identity->name : $identity->user) . '</bdi></p>';
// Key your own records by $identity->id: it is the only value that survives a rename.
