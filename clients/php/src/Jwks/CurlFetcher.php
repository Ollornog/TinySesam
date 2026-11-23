<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

/**
 * Fetches the configured key set URL with ext-curl: one deadline over everything (DNS, connect, TLS, headers, body),
 * no redirects (a redirect is a failed fetch, its status is not 200), only https (http only where the configuration
 * allowed it: to a loopback address), the body read up to {@see JwksCache::MAX_JWKS_BYTES} and the transfer aborted
 * above it, certificate and host name verified.
 */
final readonly class CurlFetcher implements Fetcher
{
    /** @param list<string> $headers further request header lines (the account overview: its Cookie line) */
    public function __construct(private string $url, private array $headers = [])
    {
    }

    public function fetch(float $timeoutSeconds): FetchResult
    {
        $ms = max(1, (int) ($timeoutSeconds * 1000));
        $body = '';
        $tooLarge = false;
        /** @var list<string> $cacheControl */
        $cacheControl = [];
        $ch = curl_init();
        $ok = curl_setopt_array($ch, [
            CURLOPT_URL => $this->url,
            CURLOPT_HTTPGET => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_TIMEOUT_MS => $ms,
            CURLOPT_CONNECTTIMEOUT_MS => $ms,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/json', ...$this->headers],
            CURLOPT_MAXFILESIZE => JwksCache::MAX_JWKS_BYTES,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$cacheControl): int {
                if (str_starts_with($line, 'HTTP/')) {
                    $cacheControl = []; // a new response (after 100 Continue): only the last one counts
                } elseif (preg_match('/\ACache-Control:(.*)\z/is', rtrim($line, "\r\n"), $m) === 1) {
                    $cacheControl[] = trim($m[1]);
                }

                return \strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$tooLarge): int {
                if (\strlen($body) + \strlen($chunk) > JwksCache::MAX_JWKS_BYTES) {
                    $tooLarge = true;

                    return 0; // aborts the transfer
                }
                $body .= $chunk;

                return \strlen($chunk);
            },
        ]);
        if (!$ok) {
            throw new \RuntimeException('curl refused an option');
        }
        $done = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($done === false || $tooLarge) {
            throw new \RuntimeException('key set fetch failed');
        }

        return new FetchResult($status, $cacheControl === [] ? null : implode(', ', $cacheControl), $body);
    }
}
