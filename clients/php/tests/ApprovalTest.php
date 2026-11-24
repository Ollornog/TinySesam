<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\TestCase;
use TinySesam\Gate\Account;
use TinySesam\Gate\ApprovalExpect;
use TinySesam\Gate\ApprovalVerifier;
use TinySesam\Gate\ConfigError;
use TinySesam\Gate\ErrorClass;
use TinySesam\Gate\GateError;
use TinySesam\Gate\Jwks\FetchResult;
use TinySesam\Gate\Jwks\Fetcher;
use TinySesam\Gate\JtiStore;
use TinySesam\Gate\KeySet;
use TinySesam\Gate\Tests\Support\Server;
use TinySesam\Gate\Tests\Support\Vectors;
use TinySesam\Gate\Topbar;

/**
 * The approval check and the account overview beyond the vectors: configuration errors, the jti store, the key set
 * fetched from TinySesam, the server-side account fetch.
 */
final class ApprovalTest extends TestCase
{
    private static function input(string $id): \stdClass
    {
        foreach (Vectors::load('approval.json')->vectors as $v) {
            if ($v->id === $id) {
                return $v->input;
            }
        }
        throw new \RuntimeException("no approval vector {$id}");
    }

    private static function expectOf(\stdClass $in, ?string $sub = null): ApprovalExpect
    {
        return new ApprovalExpect($in->expect->type, Vectors::fields($in->expect->fields), $sub ?? $in->expect->sub);
    }

    private static function verifier(\stdClass $in): ApprovalVerifier
    {
        $now = $in->now;

        return ApprovalVerifier::create(
            $in->issuer,
            $in->app_id,
            keys: KeySet::fromJwks(Vectors::encode($in->jwks)),
            clock: static fn (): int => $now,
        );
    }

    private static function classOf(callable $call): string
    {
        try {
            $call();
        } catch (GateError $e) {
            return $e->errorClass->value;
        }

        return 'ok';
    }

    public function testConfigurationErrorsStopTheStart(): void
    {
        $keys = KeySet::fromJwks(Vectors::encode(self::input('valid-basic')->jwks));
        $empty = KeySet::fromJwks('{"keys":[]}');
        $iss = 'https://auth.example.com';
        ApprovalVerifier::create($iss, 'example', keys: $keys);
        ApprovalVerifier::create($iss, 'example', jwksUrl: "{$iss}/auth/approvals/jwks.json", leewaySeconds: 30);
        $bad = [
            'no issuer' => static fn () => ApprovalVerifier::create('', 'example', keys: $keys),
            'no app id' => static fn () => ApprovalVerifier::create($iss, '', keys: $keys),
            'no keys' => static fn () => ApprovalVerifier::create($iss, 'example'),
            'empty key set' => static fn () => ApprovalVerifier::create($iss, 'example', keys: $empty),
            'both' => static fn () => ApprovalVerifier::create(
                $iss,
                'example',
                keys: $keys,
                jwksUrl: "{$iss}/auth/approvals/jwks.json"
            ),
            'leeway 31' => static fn () => ApprovalVerifier::create($iss, 'example', keys: $keys, leewaySeconds: 31),
            'leeway -1' => static fn () => ApprovalVerifier::create($iss, 'example', keys: $keys, leewaySeconds: -1),
            'gate key set' => static fn () => ApprovalVerifier::create(
                $iss,
                'example',
                jwksUrl: "{$iss}/auth/gate/jwks.json"
            ),
            'gate key set /' => static fn () => ApprovalVerifier::create(
                $iss,
                'example',
                jwksUrl: "{$iss}/auth/gate/jwks.json/"
            ),
            'plain http' => static fn () => ApprovalVerifier::create(
                $iss,
                'example',
                jwksUrl: 'http://auth.example.com/auth/approvals/jwks.json'
            ),
        ];
        foreach ($bad as $name => $call) {
            try {
                $call();
                self::fail("{$name}: accepted");
            } catch (ConfigError) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testOneStoreTheSecondUseIsAReplay(): void
    {
        $in = self::input('valid-basic');
        $verifier = self::verifier($in);
        $store = new class implements JtiStore {
            /** @var array<string, int> */
            public array $rows = [];

            public function remember(string $jti, int $until): bool
            {
                if (isset($this->rows[$jti])) {
                    return false;
                }
                $this->rows[$jti] = $until;

                return true;
            }
        };
        $c = $verifier->verify($in->jws, self::expectOf($in), $store);
        self::assertSame([$c->jti => $c->exp], $store->rows);
        self::assertSame('app:example', $c->actor);
        self::assertSame('example.collection.delete_permanently', $c->type);
        self::assertSame(Vectors::fields($in->expect->fields), $c->fields);
        $again = static fn () => $verifier->verify($in->jws, self::expectOf($in), $store);
        self::assertSame('replay', self::classOf($again));
        $failing = static function (): bool {
            throw new \RuntimeException('database gone');
        };
        $broken = static fn () => $verifier->verify($in->jws, self::expectOf($in), $failing);
        self::assertSame('internal', self::classOf($broken));
        $touched = false;
        $spy = static function () use (&$touched): bool {
            $touched = true;

            return true;
        };
        $other = static fn () => $verifier->verify($in->jws, self::expectOf($in, '1002'), $spy);
        self::assertSame('subject', self::classOf($other));
        self::assertFalse($touched, 'the store was written for a refused confirmation');
    }

    public function testExpectedFieldsCompareByTypeAndValue(): void
    {
        $in = self::input('valid-escapes-int-bool');
        $verifier = self::verifier($in);
        $fields = Vectors::fields($in->expect->fields);
        foreach (['-1', true, 1] as $quota) {
            $expect = new ApprovalExpect($in->expect->type, ['quota' => $quota] + $fields, $in->expect->sub);
            self::assertSame(
                ErrorClass::ApprovalFields->value,
                self::classOf(static fn () => $verifier->verify($in->jws, $expect, static fn (): bool => true)),
                var_export($quota, true),
            );
        }
    }

    public function testTheApprovalKeySetIsFetchedOnce(): void
    {
        $in = self::input('valid-basic');
        $server = new Server(Vectors::encode($in->jwks));
        try {
            $now = $in->now;
            $verifier = ApprovalVerifier::create(
                $in->issuer,
                $in->app_id,
                jwksUrl: $server->base . '/jwks',
                clock: static fn (): int => $now,
            );
            $verifier->verify($in->jws, self::expectOf($in), static fn (): bool => true);
            $verifier->verify($in->jws, self::expectOf($in), static fn (): bool => true);
            self::assertSame('malformed', self::classOf(static fn () => $verifier->verify(
                'a.b',
                self::expectOf($in),
                static fn (): bool => true
            )));
            self::assertSame(['/jwks'], $server->hits());
            $missing = ApprovalVerifier::create(
                $in->issuer,
                $in->app_id,
                jwksUrl: $server->base . '/missing',
                clock: static fn (): int => $now,
            );
            self::assertSame('key_unavailable', self::classOf(static fn () => $missing->verify(
                $in->jws,
                self::expectOf($in),
                static fn (): bool => true
            )));
        } finally {
            $server->stop();
        }
    }

    public function testTheCanonicalForm(): void
    {
        self::assertSame(
            '{"a":-12,"b":true,"s":"q\"\\\\é\n\u0001","type":"t"}',
            str_replace("\n", '\n', ApprovalVerifier::canonical(['type' => 't', 'b' => true, 'a' => -12,
                's' => "q\"\\é\n\x01"])),
        );
    }

    public function testTheAccountIsFetchedWithOnlyTinySesamCookies(): void
    {
        $full = Vectors::load('account.json')->vectors[0]->input->account;
        $server = new Server(Vectors::encode($full));
        try {
            $got = Account::fetch($server->base . '/account', 'app=private; tinysesam_session=s; x=1');
            self::assertSame(Vectors::normalize($full), Vectors::normalize($got));
            self::assertContains('cookie:tinysesam_session=s', $server->hits());
            foreach (['/account-401', '/status-500', '/nowhere', '/above-limit'] as $path) {
                $got = Account::fetch($server->base . $path, 'tinysesam_session=s');
                self::assertSame(Account::signedOut(), $got, $path);
            }
        } finally {
            $server->stop();
        }
        self::assertSame(Account::signedOut(), Account::fetch('http://127.0.0.1:1/none'));
        // A plain-http URL to another host stops the start (the check runs before any request).
        $plainHttp = 'http://auth.example.com/auth/account.json';
        $this->expectException(ConfigError::class);
        Account::fetch($plainHttp);
    }

    public function testTheTopbarIsFetchedWithOnlyTinySesamCookiesThroughEveryVector(): void
    {
        foreach (Vectors::load('topbar.json')->vectors as $v) {
            $server = new Server(Vectors::encode($v->input->topbar));
            try {
                $got = Topbar::fetch($server->base . '/topbar', 'app=private; tinysesam_session=s; x=1');
                self::assertSame(
                    Vectors::normalize($v->expected->topbar),
                    Vectors::normalize($got->toArray()),
                    $v->id,
                );
                self::assertContains('cookie:tinysesam_session=s', $server->hits(), $v->id);
            } finally {
                $server->stop();
            }
        }
    }

    public function testAnythingButA200IsNoTopbar(): void
    {
        $signedIn = null;
        foreach (Vectors::load('topbar.json')->vectors as $v) {
            if (($v->expected->topbar->signed_in ?? false) === true) {
                $signedIn = $v;
                break;
            }
        }
        self::assertNotNull($signedIn);
        $server = new Server(Vectors::encode($signedIn->input->topbar));
        try {
            self::assertTrue(Topbar::fetch($server->base . '/topbar')->signedIn);
            // 204, 404, 401, 500 and a body above 64 KiB: the signed-out value, never an exception.
            foreach (['/topbar-204', '/nowhere', '/account-401', '/status-500', '/above-limit'] as $path) {
                self::assertEquals(new Topbar(), Topbar::fetch($server->base . $path, 'tinysesam_session=s'), $path);
            }
        } finally {
            $server->stop();
        }
        self::assertEquals(new Topbar(), Topbar::fetch('http://127.0.0.1:1/none'));
    }

    public function testTheTopbarFetchKeepsItsDeadlineAndAFailedTransferIsNoBar(): void
    {
        $seen = new \stdClass();
        $seen->timeout = null;
        $seen->headers = null;
        $make = static fn (string $body, bool $throw): \Closure => self::spyFactory($seen, $body, $throw);
        $body = '{"brand":"Example","signed_in":true,"name":"Anna","links":[]}';
        $url = 'https://auth.example.com/auth/topbar.json';
        $bar = Topbar::fetch($url, 'a=1; __Host-tinysesam_gate=g', $make($body, false));
        self::assertTrue($bar->signedIn);
        self::assertSame(5.0, $seen->timeout, 'the deadline of one fetch is 5 seconds');
        self::assertSame(['Cookie: __Host-tinysesam_gate=g'], $seen->headers);
        self::assertEquals(new Topbar(), Topbar::fetch($url, '', $make($body, true)));
        // The body limit is 64 KiB: a signed-in answer padded to exactly that is a bar, one byte more is none.
        $atLimit = $body . str_repeat(' ', 65536 - \strlen($body));
        self::assertTrue(Topbar::fetch($url, '', $make($atLimit, false))->signedIn);
        self::assertEquals(new Topbar(), Topbar::fetch($url, '', $make($atLimit . ' ', false)));
        $this->expectException(ConfigError::class);
        $plainHttp = 'http://auth.example.com/auth/topbar.json';
        Topbar::fetch($plainHttp);
    }

    /** @return \Closure(string, list<string>): Fetcher a fetcher factory that records headers and deadline */
    private static function spyFactory(\stdClass $seen, string $body, bool $throw): \Closure
    {
        return static function (string $url, array $headers) use ($seen, $body, $throw): Fetcher {
            $seen->headers = $headers;

            return new class ($seen, $body, $throw) implements Fetcher {
                public function __construct(private \stdClass $seen, private string $body, private bool $throw)
                {
                }

                public function fetch(float $timeoutSeconds): FetchResult
                {
                    $this->seen->timeout = $timeoutSeconds;
                    if ($this->throw) {
                        throw new \RuntimeException('transfer failed');
                    }

                    return new FetchResult(200, null, $this->body);
                }
            };
        };
    }
}
