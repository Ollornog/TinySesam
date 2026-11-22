<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

/**
 * Performs one fetch of the key set document. {@see CurlFetcher} is the default; write your own only when curl is not
 * available, and keep its rules: no redirects, the deadline over everything (connect, TLS, headers, body), the body
 * read up to {@see JwksCache::MAX_JWKS_BYTES} — PHP cannot interrupt a call that ignores its deadline, so the cache can
 * only discard a late answer, not stop waiting for it.
 */
interface Fetcher
{
    /**
     * @param float $timeoutSeconds the deadline of this attempt in seconds
     *
     * @throws \Throwable for a network error, a timeout or a body above the limit (a failed fetch)
     */
    public function fetch(float $timeoutSeconds): FetchResult;
}
