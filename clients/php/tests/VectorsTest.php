<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\TestCase;
use TinySesam\Gate\Account;
use TinySesam\Gate\ApprovalClaims;
use TinySesam\Gate\ApprovalExpect;
use TinySesam\Gate\ApprovalVerifier;
use TinySesam\Gate\Gate;
use TinySesam\Gate\GateRequest;
use TinySesam\Gate\Headers;
use TinySesam\Gate\Identity;
use TinySesam\Gate\Jwks\Fetcher;
use TinySesam\Gate\Jwks\FetchResult;
use TinySesam\Gate\Jwks\JwksCache;
use TinySesam\Gate\Jwks\MemoryStore;
use TinySesam\Gate\KeySet;
use TinySesam\Gate\Topbar;
use TinySesam\Gate\Tests\Support\Vectors;

/** Every vector of spec/vectors/, read from this repository, checked exactly (clients/README.md). */
final class VectorsTest extends TestCase
{
    /** Every file in spec/vectors/ must be run by one of these tests; a new file without a runner fails the suite. */
    private const array RUNNERS = ['account.json', 'approval.json', 'headers.json', 'jwks.json', 'keys.json',
        'token.json', 'topbar.json'];

    public function testEveryVectorFileHasARunnerAndItsFormat(): void
    {
        $expected = self::RUNNERS;
        sort($expected);
        self::assertSame($expected, Vectors::files(), 'add a runner for the new vector file');
        foreach (self::RUNNERS as $file) {
            self::assertSame($file === 'approval.json' ? 1 : 2, Vectors::load($file)->format, $file);
        }
    }

    public function testAccountVectors(): void
    {
        $vectors = Vectors::load('account.json')->vectors;
        self::assertNotEmpty($vectors, 'no account vectors');
        foreach ($vectors as $v) {
            $got = Account::parse(Vectors::encode($v->input->account));
            self::assertSame(Vectors::normalize($v->expected->account), Vectors::normalize($got), $v->id);
        }
    }

    public function testApprovalVectors(): void
    {
        $doc = Vectors::load('approval.json');
        self::assertSame('spec/approval-token.md', $doc->spec);
        self::assertGreaterThanOrEqual(40, \count($doc->vectors));
        $problems = [];
        foreach ($doc->vectors as $v) {
            $in = $v->input;
            $now = $in->now;
            $verifier = ApprovalVerifier::create(
                $in->issuer,
                $in->app_id,
                keys: KeySet::fromJwks(Vectors::encode($in->jwks)),
                leewaySeconds: $in->leeway,
                clock: static fn (): int => $now,
            );
            $e = $in->expect;
            $expect = new ApprovalExpect($e->type, Vectors::fields($e->fields), $e->sub, $e->nonce ?? null);
            $seen = array_fill_keys($in->seen, true);
            $store = static function (string $jti) use (&$seen): bool {
                if (isset($seen[$jti])) {
                    return false;
                }
                $seen[$jti] = true;

                return true;
            };
            $claims = null;
            $got = Vectors::outcome(static function () use ($verifier, $in, $expect, $store, &$claims): void {
                $claims = $verifier->verify($in->jws, $expect, $store);
            });
            if ($v->expected->ok !== true) {
                if ($got !== $v->expected->error) {
                    $problems[] = "{$v->id}: {$got}, want {$v->expected->error}";
                }
                continue;
            }
            if ($got !== 'ok' || !$claims instanceof ApprovalClaims) {
                $problems[] = "{$v->id}: refused with {$got}";
            } elseif (Vectors::normalize($claims->raw) !== Vectors::normalize($v->expected->claims)) {
                $problems[] = "{$v->id}: claims differ";
            }
        }
        self::assertSame([], $problems);
    }

    /**
     * Compares an identity (and has_role) with the expected value of a vector.
     *
     * @return list<string> the differences
     */
    private static function identityProblems(string $id, Identity $identity, \stdClass $expected): array
    {
        $problems = [];
        if (
            property_exists($expected, 'identity')
            && Vectors::normalize($identity->toArray()) !== Vectors::normalize($expected->identity)
        ) {
            $problems[] = "{$id}: identity " . Vectors::encode($identity->toArray())
                . ', want ' . Vectors::encode($expected->identity);
        }
        foreach (get_object_vars($expected->has_role ?? new \stdClass()) as $role => $want) {
            if ($identity->hasRole((string) $role) !== $want) {
                $problems[] = "{$id}: hasRole({$role}) wrong";
            }
        }

        return $problems;
    }

    public function testTokenVectors(): void
    {
        $vectors = Vectors::load('token.json')->vectors;
        self::assertNotEmpty($vectors, 'no token vectors');
        $problems = [];
        foreach ($vectors as $v) {
            $in = $v->input;
            $gate = Vectors::tokenGate($in->jwks, $in->issuer, $in->audience, $in->leeway, $in->now);
            $result = null;
            $got = Vectors::outcome(static function () use ($gate, $in, &$result): void {
                $result = $gate->verify($in->jws);
            });
            if ($v->expected->ok !== true) {
                if ($got !== $v->expected->error) {
                    $problems[] = "{$v->id}: {$got}, want {$v->expected->error}";
                }
                continue;
            }
            if ($got !== 'ok' || $result === null) {
                $problems[] = "{$v->id}: refused ({$got}), want ok";
                continue;
            }
            if (Vectors::normalize($result->claims->raw) !== Vectors::normalize($v->expected->claims)) {
                $problems[] = "{$v->id}: claims " . Vectors::encode($result->claims->raw);
            }
            array_push($problems, ...self::identityProblems($v->id, $result->identity, $v->expected));
        }
        self::assertSame([], $problems);
        self::assertGreaterThan(100, \count($vectors));
    }

    public function testHeaderVectors(): void
    {
        $vectors = Vectors::load('headers.json')->vectors;
        self::assertNotEmpty($vectors, 'no header vectors');
        $gate = Gate::headerMode();
        $problems = [];
        foreach ($vectors as $v) {
            $fields = Vectors::headerFields($v->input->headers);
            $runs = [
                'Headers::identity' => static fn (): Identity => Headers::identity($fields),
                'Gate::identify' => static fn (): Identity => $gate->identify(new GateRequest($fields)),
            ];
            foreach ($runs as $how => $run) {
                $identity = null;
                $got = Vectors::outcome(static function () use ($run, &$identity): void {
                    $identity = $run();
                });
                if ($v->expected->ok !== true) {
                    if ($got !== $v->expected->error) {
                        $problems[] = "{$v->id} ({$how}): {$got}, want {$v->expected->error}";
                    }
                } elseif ($got !== 'ok' || $identity === null) {
                    $problems[] = "{$v->id} ({$how}): refused ({$got}), want ok";
                } else {
                    array_push($problems, ...self::identityProblems("{$v->id} ({$how})", $identity, $v->expected));
                }
            }
        }
        self::assertSame([], $problems);
    }

    public function testKeySetVectors(): void
    {
        $sets = Vectors::load('jwks.json')->sets;
        self::assertNotEmpty($sets, 'no key set vectors');
        $problems = [];
        foreach ($sets as $v) {
            $kids = [];
            $got = Vectors::outcome(static function () use ($v, &$kids): void {
                $kids = KeySet::fromJwks(Vectors::encode($v->input->jwks))->kids;
            });
            if ($v->expected->ok !== true) {
                if ($got !== $v->expected->error) {
                    $problems[] = "{$v->id}: {$got}, want {$v->expected->error}";
                }
            } elseif ($got !== 'ok') {
                $problems[] = "{$v->id}: refused ({$got})";
            } elseif ($kids !== $v->expected->kids) {
                $problems[] = "{$v->id}: kids " . Vectors::encode($kids)
                    . ', want ' . Vectors::encode($v->expected->kids);
            }
        }
        self::assertSame([], $problems);
    }

    public function testCacheScenarioVectors(): void
    {
        $doc = Vectors::load('jwks.json');
        self::assertNotEmpty($doc->scenarios, 'no cache scenarios');
        $problems = [];
        $steps = 0;
        foreach ($doc->scenarios as $sc) {
            $now = 0;
            $fetcher = new class implements Fetcher {
                public ?\stdClass $answer = null;
                private int $calls = 0;
                private bool $unexpected = false;

                /** Starts a step: its answer, no call so far. */
                public function step(?\stdClass $answer): void
                {
                    $this->answer = $answer;
                    $this->calls = 0;
                    $this->unexpected = false;
                }

                /** @return array{0: int, 1: bool} the calls of this step, and whether one came without an answer */
                public function seen(): array
                {
                    return [$this->calls, $this->unexpected];
                }

                public function fetch(float $timeoutSeconds): FetchResult
                {
                    $this->calls++;
                    if ($this->answer === null) {
                        $this->unexpected = true;
                        throw new \RuntimeException('no fetch in this step');
                    }
                    $a = $this->answer;
                    if (property_exists($a, 'error')) {
                        throw new \RuntimeException((string) $a->error);
                    }
                    $body = property_exists($a, 'body') ? Vectors::encode($a->body) : (string) ($a->body_text ?? '');
                    $cacheControl = isset($a->cache_control) ? (string) $a->cache_control : null;

                    return new FetchResult((int) $a->status, $cacheControl, $body);
                }
            };
            $clock = static function () use (&$now): int {
                return $now;
            };
            $gate = Gate::tokenMode(
                issuer: $doc->defaults->issuer,
                audience: $doc->defaults->audience,
                keySource: new JwksCache($fetcher, new MemoryStore(), $clock),
                clock: $clock,
            );
            foreach ($sc->steps as $i => $step) {
                $now = $step->now;
                $fetcher->step($step->fetch ?? null);
                $got = Vectors::outcome(static fn () => $gate->verify($step->jws));
                [$calls, $unexpected] = $fetcher->seen();
                $steps++;
                $where = "{$sc->id} step {$i}";
                if ($unexpected) {
                    $problems[] = "{$where}: fetched although the step gives no answer";
                }
                if ($calls > 1) {
                    $problems[] = "{$where}: {$calls} fetches in one request";
                }
                if (($calls === 1) !== $step->expect->fetched) {
                    $problems[] = "{$where}: fetched " . var_export($calls === 1, true);
                }
                $want = $step->expect->ok === true ? 'ok' : $step->expect->error;
                if ($got !== $want) {
                    $problems[] = "{$where}: {$got}, want {$want}";
                }
            }
        }
        self::assertSame([], $problems);
        self::assertGreaterThan(40, $steps);
    }

    public function testTopBarVectors(): void
    {
        $vectors = Vectors::load('topbar.json')->vectors;
        self::assertNotEmpty($vectors, 'no top bar vectors');
        foreach ($vectors as $v) {
            $got = Topbar::parse(Vectors::encode($v->input->topbar))->toArray();
            self::assertSame(Vectors::normalize($v->expected->topbar), Vectors::normalize($got), $v->id);
        }
    }

    public function testAnUnknownTopBarMemberIsIgnored(): void
    {
        // The answer may grow; a member this client does not know leaves the normalized form as it is, and an
        // `approvals` of the wrong shape is no approvals.
        $answer = ['brand' => 'Example', 'signed_in' => true, 'name' => 'Anna', 'links' => [], 'approvals' => [1, 2],
            'unknown' => ['nested' => true]];
        $plain = $answer;
        unset($plain['approvals'], $plain['unknown']);
        $want = Topbar::parse(Vectors::encode($plain))->toArray();
        self::assertSame($want, Topbar::parse(Vectors::encode($answer))->toArray());
        self::assertTrue(Topbar::parse(Vectors::encode($answer))->signedIn);
    }

    public function testTestKeysMatchTheirSignKeyFormAndTheSeedSignsForThem(): void
    {
        $d = Vectors::defaults();
        foreach (['A', 'B', 'X'] as $name) {
            $raw = KeySet::parseGateKey(Vectors::signKey($name));
            self::assertNotNull($raw, "{$name}: sign_key_base64 unreadable");
            self::assertSame(Vectors::kidOf($name), KeySet::keyId($raw), "{$name}: kid");
            $set = KeySet::fromJwks(Vectors::encode(['keys' => [Vectors::publicJwk($name)]]));
            self::assertSame([Vectors::kidOf($name)], $set->kids, "{$name}: public JWK not usable");
            $jwks = ['keys' => [Vectors::publicJwk($name)]];
            $gate = Vectors::tokenGate($jwks, $d['issuer'], $d['audience'], 0, $d['now']);
            $token = Vectors::mint($name, Vectors::sessionClaims('editors', $d['now']));
            $got = Vectors::outcome(static fn () => $gate->verify($token));
            self::assertSame('ok', $got, "{$name}: the seed does not sign for the public key");
        }
    }

    public function testTheLatin1ConversionOfHeaderValues(): void
    {
        // A vector header value is one code point per octet; the client reads octets the same way.
        self::assertSame("\xC3\xBC", Vectors::latin1('Ã¼'));
    }
}
