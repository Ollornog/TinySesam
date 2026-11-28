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
    case '/topbar':
        // The account overview (spec section 8a): the body of TS_JWKS, and the Cookie header it saw in TS_HITS.
        if (is_string($hits) && $hits !== '') {
            $cookie = $_SERVER['HTTP_COOKIE'] ?? '';
            file_put_contents($hits, 'cookie:' . (is_string($cookie) ? $cookie : '') . "\n", FILE_APPEND | LOCK_EX);
        }
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo $jwks;
        break;
    case '/topbar-204':
        http_response_code(204);
        break;
    case '/account-401':
        http_response_code(401);
        header('Content-Type: application/json');
        echo '{"authenticated":false,"signed_in":false}';
        break;
    case '/auth/api/apps/docs/permissions':
    case '/auth/api/apps/deny/permissions':
    case '/auth/api/apps/text/permissions':
    case '/auth/api/apps/hang/permissions':
        // The permission registration (spec section 3.4): method, API key, content type and body go to TS_HITS.
        if (is_string($hits) && $hits !== '') {
            $text = static fn (string $name): string => is_string($_SERVER[$name] ?? null) ? $_SERVER[$name] : '';
            $seen = ['method:' . $text('REQUEST_METHOD'), 'key:' . $text('HTTP_X_API_KEY'),
                'type:' . $text('CONTENT_TYPE'), 'body:' . file_get_contents('php://input')];
            file_put_contents($hits, implode("\n", $seen) . "\n", FILE_APPEND | LOCK_EX);
        }
        header('Content-Type: application/json');
        if (str_contains($path, '/deny/')) {
            http_response_code(403);
            echo '{"detail":"missing scope permissions:register"}';
        } elseif (str_contains($path, '/text/')) {
            echo 'registered';
        } elseif (str_contains($path, '/hang/')) {
            sleep(30);
        } else {
            echo '{"added":["docs.read"],"updated":[],"returned":[],"orphaned":[]}';
        }
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
