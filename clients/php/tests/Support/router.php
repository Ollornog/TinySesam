<?php

declare(strict_types=1);

// Router for PHP's built-in server (`php -S`) in the HTTP tests: a key set endpoint with misbehaving variants and an
// application endpoint that identifies a request from $_SERVER, the way PHP-FPM and mod_php hand it over. Every
// request appends its path to the file named by TS_HITS, so a test can count the fetches.

require __DIR__ . '/../../vendor/autoload.php';

use TinySesam\Gate\Gate;
use TinySesam\Gate\GateError;
use TinySesam\Gate\GateRequest;

$path = parse_url(is_string($_SERVER['REQUEST_URI'] ?? null) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH);
$hits = getenv('TS_HITS');
if (is_string($hits) && $hits !== '') {
    file_put_contents($hits, $path . "\n", FILE_APPEND | LOCK_EX);
}
$jwks = getenv('TS_JWKS');
$jwks = is_string($jwks) ? $jwks : '{"keys":[]}';

/** The key set document padded with spaces to exactly $bytes bytes. */
$padded = static function (int $bytes) use ($jwks): string {
    return substr($jwks, 0, -1) . str_repeat(' ', max(0, $bytes - strlen($jwks))) . '}';
};

switch ($path) {
    case '/jwks':
        header('Content-Type: application/json');
        header('Cache-Control: max-age=300');
        echo $jwks;
        break;
    case '/slow':
        usleep(1_000_000);
        header('Content-Type: application/json');
        echo $jwks;
        break;
    case '/hang':
        // Accepts the connection and never answers within any deadline of the client.
        sleep(30);
        break;
    case '/exact-limit':
        header('Content-Type: application/json');
        echo $padded(65536);
        break;
    case '/above-limit':
        header('Content-Type: application/json');
        echo $padded(65537);
        break;
    case '/redirect':
        header('Location: /jwks', true, 302);
        break;
    case '/status-500':
        http_response_code(500);
        header('Content-Type: application/json');
        echo $jwks;
        break;
    case '/account':
        // The account overview (spec section 8a): the body of TS_JWKS, and the Cookie header it saw in TS_HITS.
        if (is_string($hits) && $hits !== '') {
            $cookie = $_SERVER['HTTP_COOKIE'] ?? '';
            file_put_contents($hits, 'cookie:' . (is_string($cookie) ? $cookie : '') . "\n", FILE_APPEND | LOCK_EX);
        }
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo $jwks;
        break;
    case '/account-401':
        http_response_code(401);
        header('Content-Type: application/json');
        echo '{"authenticated":false,"signed_in":false}';
        break;
    case '/identify':
        header('Content-Type: application/json');
        try {
            $identity = Gate::headerMode()->identify(GateRequest::fromGlobals($_SERVER));
            echo json_encode(['identity' => $identity->toArray()]);
        } catch (GateError $e) {
            echo json_encode(['error' => $e->errorClass->value]);
        }
        break;
    default:
        http_response_code(404);
}
