<?php

declare(strict_types=1);

// Loads the INSTALLED package through an application's autoloader (not the source tree the suite runs) and identifies
// requests through it: the classes resolve without any dev dependency, the PSR interfaces are there, and the client
// applies spec v2 (Remote-Kind) and verifies a vector token with ext-sodium.
//
//   php tests/package-smoke.php <application>/vendor/autoload.php
//
// Run by clients/php/ci.sh, which the CI workflow client-php and scripts/check.sh both run.

$args = $_SERVER['argv'] ?? [];
$autoload = is_array($args) ? ($args[1] ?? '') : '';
if (!is_string($autoload) || !is_file($autoload)) {
    fwrite(STDERR, "usage: php package-smoke.php <vendor/autoload.php>\n");
    exit(2);
}
require $autoload;

use Psr\Http\Server\MiddlewareInterface;
use TinySesam\Gate\Gate;
use TinySesam\Gate\GateError;
use TinySesam\Gate\GateRequest;
use TinySesam\Gate\Psr15\GateMiddleware;

$fail = static function (string $why): never {
    fwrite(STDERR, "package smoke: {$why}\n");
    exit(1);
};

if (class_exists('PHPUnit\Framework\TestCase') || class_exists('Nyholm\Psr7\Response')) {
    $fail('a dev dependency is installed with --no-dev');
}
$implements = class_implements(GateMiddleware::class);
if ($implements === false || !in_array(MiddlewareInterface::class, $implements, true)) {
    $fail('the PSR-15 middleware does not load');
}
$gate = Gate::headerMode();
$id = $gate->identify(new GateRequest([['Remote-User', 'anna'], ['Remote-Auth', 'session'], ['Remote-Kind', 'user']]));
if ($id->user !== 'anna' || !$id->isSession() || $id->accountKind->value !== 'user') {
    $fail('the installed package does not identify the request as expected');
}
try {
    $gate->identify(new GateRequest([['Remote-User', 'anna']]));
    $fail('the installed package accepts a request without Remote-Kind (spec v2)');
} catch (GateError $e) {
    if ($e->errorClass->value !== 'header') {
        $fail('a request without Remote-Kind is not a header error');
    }
}
$vectors = __DIR__ . '/../../../spec/vectors/';
/** @var array{keys: array{A: array{sign_key_base64: string}}} $keys */
$keys = json_decode((string) file_get_contents($vectors . 'keys.json'), true, 512, JSON_THROW_ON_ERROR);
/** @var array{vectors: list<array{id: string, input: array{issuer: string, audience: string, now: int, jws: string}}>} $tokens */
$tokens = json_decode((string) file_get_contents($vectors . 'token.json'), true, 512, JSON_THROW_ON_ERROR);
$valid = $tokens['vectors'][0] ?? $fail('no token vectors');
if ($valid['id'] !== 'valid-session') {
    $fail('the first token vector is no longer valid-session');
}
$tokenGate = Gate::tokenMode(
    issuer: $valid['input']['issuer'],
    audience: $valid['input']['audience'],
    gateKeys: [$keys['keys']['A']['sign_key_base64']],
    clock: static fn (): int => $valid['input']['now'],
);
if ($tokenGate->verify($valid['input']['jws'])->identity->user !== 'anna') {
    $fail('the installed package does not verify the vector token');
}
echo "the installed package loads and identifies ({$autoload})\n";
