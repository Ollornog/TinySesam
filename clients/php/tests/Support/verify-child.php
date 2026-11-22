<?php

declare(strict_types=1);

// One "request" in a process of its own, as PHP-FPM runs them: a token-mode gate with a key set URL and a FileStore,
// verifying one token. Prints the outcome class. Used by JwksHttpTest to start many processes at once.
//
//   php verify-child.php <jwks url> <state file> <token>

require __DIR__ . '/../../vendor/autoload.php';

use TinySesam\Gate\Gate;
use TinySesam\Gate\GateError;
use TinySesam\Gate\Jwks\FileStore;

$args = $_SERVER['argv'] ?? [];
\assert(\is_array($args) && \count($args) === 4);
[, $url, $state, $token] = array_map(static fn (mixed $a): string => \is_string($a) ? $a : '', $args);
$gate = Gate::tokenMode(
    issuer: 'https://auth.example.com',
    audience: 'app.example.com',
    jwksUrl: $url,
    store: new FileStore($state),
);
try {
    $gate->verify($token);
    echo 'ok';
} catch (GateError $e) {
    echo $e->errorClass->value;
}
