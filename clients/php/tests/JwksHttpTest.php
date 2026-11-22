<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\TestCase;
use TinySesam\Gate\Gate;
use TinySesam\Gate\Jwks\CurlFetcher;
use TinySesam\Gate\Jwks\Fetcher;
use TinySesam\Gate\Jwks\FetchResult;
use TinySesam\Gate\Jwks\FileStore;
use TinySesam\Gate\Jwks\JwksCache;
use TinySesam\Gate\Jwks\MemoryStore;
use TinySesam\Gate\Jwks\State;
use TinySesam\Gate\Tests\Support\Server;
use TinySesam\Gate\Tests\Support\Vectors;

/**
 * What the vectors cannot carry (spec section 5), against a real HTTP server (PHP's built-in one): a server that
 * accepts and never answers, a body above 64 KiB, no redirects, and concurrent requests — processes, as under PHP-FPM —
 * that share one fetch through a FileStore.
 */
final class JwksHttpTest extends TestCase
{
    /** @var list<Server> */
    private array $servers = [];
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->servers as $s) {
            $s->stop();
        }
        foreach ($this->dirs as $d) {
            $files = glob($d . '/{,.}*', GLOB_BRACE);
            foreach ($files === false ? [] : $files as $f) {
                if (is_file($f)) {
                    unlink($f);
                }
            }
            rmdir($d);
        }
    }

    private function server(): Server
    {
        $s = new Server(Vectors::encode(['keys' => [Vectors::publicJwk('A')]]));
        $this->servers[] = $s;

        return $s;
    }

    private function dir(): string
    {
        $d = sys_get_temp_dir() . '/tinysesam-gate-state-' . bin2hex(random_bytes(6));
        mkdir($d, 0o700);
        $this->dirs[] = $d;

        return $d;
    }

    private static function token(): string
    {
        return Vectors::mint('A', Vectors::sessionClaims('editors', time()));
    }

    private static function gate(string $url, ?\TinySesam\Gate\Jwks\Store $store = null): Gate
    {
        $d = Vectors::defaults();

        return Gate::tokenMode(issuer: $d['issuer'], audience: $d['audience'], jwksUrl: $url, store: $store);
    }

    private static function outcomeAt(string $url, ?\TinySesam\Gate\Jwks\Store $store = null): string
    {
        return Vectors::outcome(static fn () => self::gate($url, $store)->verify(self::token()));
    }

    public function testAServerThatNeverAnswersCostsOneDeadlineThenNothing(): void
    {
        $s = $this->server();
        $gate = self::gate($s->base . '/hang');
        $start = microtime(true);
        self::assertSame('key_unavailable', Vectors::outcome(static fn () => $gate->verify(self::token())));
        $took = microtime(true) - $start;
        self::assertGreaterThan(4.5, $took, 'returned before the deadline: did it wait at all?');
        self::assertLessThan(6.5, $took, 'waited longer than the 5-second deadline');
        // The next request within 10 s does not try again and returns at once.
        $start = microtime(true);
        self::assertSame('key_unavailable', Vectors::outcome(static fn () => $gate->verify(self::token())));
        self::assertLessThan(0.5, microtime(true) - $start);
        self::assertSame(['/hang'], $s->hits());
    }

    public function testTheBodyLimitIs64KiB(): void
    {
        $s = $this->server();
        self::assertSame('ok', self::outcomeAt($s->base . '/exact-limit'));
        self::assertSame('key_unavailable', self::outcomeAt($s->base . '/above-limit'));
        // The fetcher itself stops above the limit instead of returning the body.
        $this->expectException(\RuntimeException::class);
        new CurlFetcher($s->base . '/above-limit')->fetch(5.0);
    }

    public function testNoRedirectsAndNoStatusButTwoHundred(): void
    {
        $s = $this->server();
        self::assertSame('key_unavailable', self::outcomeAt($s->base . '/redirect'));
        self::assertSame('key_unavailable', self::outcomeAt($s->base . '/status-500'));
        self::assertSame(['/redirect', '/status-500'], $s->hits(), 'the redirect was followed');
        $r = new CurlFetcher($s->base . '/jwks')->fetch(5.0);
        self::assertSame([200, 'max-age=300'], [$r->status, $r->cacheControl]);
    }

    public function testConcurrentProcessesShareOneFetchThroughAFileStore(): void
    {
        $s = $this->server();
        $state = $this->dir() . '/jwks-state.json';
        $token = self::token();
        $children = [];
        for ($i = 0; $i < 8; $i++) {
            $p = proc_open(
                [PHP_BINARY, __DIR__ . '/Support/verify-child.php', $s->base . '/slow', $state, $token],
                [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
            );
            self::assertNotFalse($p);
            $children[] = [$p, $pipes];
        }
        $outcomes = [];
        foreach ($children as [$p, $pipes]) {
            $outcomes[] = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($p);
        }
        self::assertSame(array_fill(0, 8, 'ok'), $outcomes);
        self::assertSame(['/slow'], $s->hits(), 'more than one fetch for eight concurrent requests');
        // A later process reads the shared state and does not fetch either.
        $later = self::gate($s->base . '/slow', new FileStore($state));
        self::assertSame('ok', Vectors::outcome(static fn () => $later->verify($token)));
        self::assertSame(['/slow'], $s->hits());
    }

    public function testAFileStoreDoesNotTrustTimestampsInTheFuture(): void
    {
        $s = $this->server();
        $state = $this->dir() . '/jwks-state.json';
        $store = new FileStore($state);
        // A copied or stale file: an attempt "in the future" would block every fetch, an empty set would answer kid.
        $store->save(new State('{"keys":[]}', time() + 100000, time() + 100000));
        self::assertSame('ok', self::outcomeAt($s->base . '/jwks', $store));
        self::assertSame(['/jwks'], $s->hits());
        $reread = $store->load();
        self::assertNotNull($reread->document);
        self::assertLessThanOrEqual(time() + 300, $reread->freshUntil);
    }

    public function testAFileStoreNeedsAWritableDirectory(): void
    {
        $this->expectException(\TinySesam\Gate\ConfigError::class);
        new FileStore('/nonexistent-' . bin2hex(random_bytes(4)) . '/state.json');
    }

    public function testASecondLookupWhileAFetchRunsDoesNotFetchAgain(): void
    {
        // A runtime with fibers or coroutines: the fetch suspends, another request needs keys in the meantime.
        $fetcher = new class implements Fetcher {
            public int $calls = 0;

            public function fetch(float $timeoutSeconds): FetchResult
            {
                $this->calls++;
                \Fiber::suspend();

                return new FetchResult(200, null, Vectors::encode(['keys' => [Vectors::publicJwk('A')]]));
            }
        };
        $cache = new JwksCache($fetcher, new MemoryStore());
        $first = new \Fiber(static fn (): string => $cache->lookup(Vectors::kidOf('A')));
        $first->start();
        self::assertTrue($first->isSuspended());
        self::assertSame('key_unavailable', Vectors::outcome(static fn () => $cache->lookup(Vectors::kidOf('A'))));
        $first->resume();
        self::assertTrue($first->isTerminated());
        $key = $first->getReturn();
        self::assertIsString($key);
        self::assertSame(32, \strlen($key));
        self::assertSame(1, $fetcher->calls);
    }

    public function testTheCacheRefusesABodyAbove64KiBFromAnyFetcher(): void
    {
        // The limit holds in the cache too, not only in CurlFetcher: a Fetcher of one's own may return more.
        $jwks = Vectors::encode(['keys' => [Vectors::publicJwk('A')]]);
        foreach ([65536 => 32, 65537 => 'key_unavailable'] as $size => $want) {
            $body = substr($jwks, 0, -1) . str_repeat(' ', $size - \strlen($jwks)) . '}';
            self::assertSame($size, \strlen($body));
            $fetcher = new class ($body) implements Fetcher {
                public function __construct(private readonly string $body)
                {
                }

                public function fetch(float $timeoutSeconds): FetchResult
                {
                    return new FetchResult(200, null, $this->body);
                }
            };
            $cache = new JwksCache($fetcher, new MemoryStore());
            $got = Vectors::outcome(static fn () => $cache->lookup(Vectors::kidOf('A')));
            self::assertSame($want === 32 ? 'ok' : $want, $got, "{$size} bytes");
        }
    }

    public function testALateAnswerOfAFetcherIsAFailedFetch(): void
    {
        $fetcher = new class implements Fetcher {
            public function fetch(float $timeoutSeconds): FetchResult
            {
                usleep((int) ($timeoutSeconds * 1e6) + 100_000);

                return new FetchResult(200, null, Vectors::encode(['keys' => [Vectors::publicJwk('A')]]));
            }
        };
        $cache = new JwksCache($fetcher, new MemoryStore(), null, 0.2);
        self::assertSame('key_unavailable', Vectors::outcome(static fn () => $cache->lookup(Vectors::kidOf('A'))));
    }
}
