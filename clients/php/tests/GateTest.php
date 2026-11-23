<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use TinySesam\Gate\AccountKind;
use TinySesam\Gate\ConfigError;
use TinySesam\Gate\Decision;
use TinySesam\Gate\ErrorClass;
use TinySesam\Gate\Gate;
use TinySesam\Gate\GateError;
use TinySesam\Gate\GateRequest;
use TinySesam\Gate\HeaderNames;
use TinySesam\Gate\Identity;
use TinySesam\Gate\Jwks\MemoryStore;
use TinySesam\Gate\KeySource;
use TinySesam\Gate\Requirement;
use TinySesam\Gate\Tests\Support\Vectors;

/** Configuration errors, token sources, trusted proxies, logging, guards and failing closed. */
final class GateTest extends TestCase
{
    private const string COOKIE = '__Host-tinysesam_gate=';

    /** @var list<array{level: mixed, message: string, context: array<mixed>}> */
    private static array $logged = [];

    private static function token(string $groups = 'editors'): string
    {
        return Vectors::mint('A', Vectors::sessionClaims($groups, Vectors::defaults()['now']));
    }

    /**
     * A token-mode gate at the vectors' clock with test key A.
     *
     * @param array<string, mixed> $options named arguments of Gate::tokenMode
     */
    private static function tokenGate(array $options = []): Gate
    {
        $d = Vectors::defaults();
        $options += ['gateKeys' => [Vectors::signKey('A')], 'clock' => static fn (): int => $d['now']];

        return self::build($options);
    }

    /**
     * A token-mode gate built from exactly the given options (issuer and audience of the vectors). The options go in
     * by name and unchecked: the tests pass wrong ones on purpose.
     *
     * @param array<string, mixed> $options named arguments of Gate::tokenMode
     */
    private static function build(array $options = []): Gate
    {
        $d = Vectors::defaults();
        // The settings come from tables of test cases, so their types are mixed here; each call is checked at runtime.
        return Gate::tokenMode($d['issuer'], $d['audience'], ...$options); // @phpstan-ignore argument.type
    }

    /**
     * The outcome of identifying a request with these field lines (and peer).
     *
     * @param list<array{0: string, 1: string}> $fields
     */
    private static function outcome(Gate $gate, array $fields, ?string $peer = null): string
    {
        return Vectors::outcome(static fn () => $gate->identify(new GateRequest($fields, $peer)));
    }

    /** @return iterable<string, array{0: \Closure(): mixed}> */
    public static function badConfigurations(): iterable
    {
        $d = Vectors::defaults();
        $key = Vectors::signKey('A');
        yield 'no issuer' => [static fn () => Gate::tokenMode('', $d['audience'], gateKeys: [$key])];
        yield 'no audience' => [static fn () => Gate::tokenMode($d['issuer'], '', gateKeys: [$key])];
        yield 'leeway 61' => [static fn () => self::build(['gateKeys' => [$key], 'leewaySeconds' => 61])];
        yield 'leeway -1' => [static fn () => self::build(['gateKeys' => [$key], 'leewaySeconds' => -1])];
        yield 'no key' => [static fn () => self::build()];
        yield 'empty key list' => [static fn () => self::build(['gateKeys' => []])];
        yield 'key not Base64' => [static fn () => self::build(['gateKeys' => ['not base64!']])];
        $short = base64_encode(str_repeat('k', 31));
        yield 'key of 31 bytes' => [static fn () => self::build(['gateKeys' => [$short]])];
        $urlSafe = strtr($key, '+/', '-_') . '-';
        yield 'key in base64url' => [static fn () => self::build(['gateKeys' => [$urlSafe]])];
        $withKey = static fn (array $more): Gate => self::build(['gateKeys' => [$key], ...$more]);
        yield 'keys and URL' => [static fn () => $withKey(['jwksUrl' => 'https://auth.example.com/j'])];
        yield 'cookie and header' => [static fn () => $withKey(['cookieName' => 'a', 'tokenHeader' => 'b'])];
        yield 'invalid cookie name' => [static fn () => self::build(['gateKeys' => [$key], 'cookieName' => 'a b'])];
        yield 'invalid token header' => [static fn () => self::build(['gateKeys' => [$key], 'tokenHeader' => 'X:Y'])];
        yield 'store without URL' => [static fn () => $withKey(['store' => new MemoryStore()])];
        $urls = [
            'http://auth.example.com/jwks.json',
            'ftp://auth.example.com/jwks.json',
            'https://user:pw@auth.example.com/j',
            'https://auth.example.com/j#x',
            'auth.example.com/jwks.json',
            'https:///jwks.json',
            "https://auth.example.com/j\n",
            'http://127.0.0.1.example.com/j',
            'http://[::2]/j',
            'https://auth.example.com/auth/approvals/jwks.json',
            'https://auth.example.com/auth/approvals/jwks.json/',
        ];
        foreach ($urls as $url) {
            yield "jwksUrl {$url}" => [static fn () => self::build(['jwksUrl' => $url])];
        }
        yield 'empty trusted proxy list' => [static fn () => Gate::headerMode(trustedProxies: [])];
        foreach (['127.0.0.1/33', '::1/129', '1.2.3', 'example.com', '10.0.0.0/08', 'fe80::1%eth0', ''] as $p) {
            yield "trusted proxy {$p}" => [static fn () => Gate::headerMode(trustedProxies: [$p])];
        }
        yield 'header name with a space' => [static fn () => new HeaderNames(user: 'Remote User')];
        yield 'two slots one name' => [static fn () => new HeaderNames(name: 'remote-user')];
    }

    /** @param \Closure(): mixed $build */
    #[DataProvider('badConfigurations')]
    public function testAContradictoryConfigurationStopsTheStart(\Closure $build): void
    {
        $this->expectException(ConfigError::class);
        $build();
    }

    public function testGoodConfigurations(): void
    {
        $urls = [
            'https://auth.example.com/auth/gate/jwks.json',
            'http://127.0.0.1:8080/j',
            'http://localhost/j',
            'http://[::1]:9/j',
            'HTTPS://auth.example.com/j',
        ];
        foreach ($urls as $url) {
            self::assertSame('token', self::build(['jwksUrl' => $url])->mode, $url);
        }
        $keys = [Vectors::signKey('A'), Vectors::signKey('B'), Vectors::signKey('A')];
        self::assertSame('token', self::build(['gateKeys' => $keys, 'leewaySeconds' => 60])->mode);
        $proxies = ['127.0.0.1', '198.51.100.0/24', '::1', '2001:db8::/32', '0.0.0.0/0'];
        self::assertSame('header', Gate::headerMode(trustedProxies: $proxies)->mode);
    }

    public function testTheTokenComesFromTheConfiguredCookieOnly(): void
    {
        $gate = self::tokenGate();
        $t = self::token();
        $id = $gate->identify(new GateRequest([['Cookie', 'a=b; ' . self::COOKIE . $t . '; c=d']]));
        self::assertSame('anna', $id->user);
        // A second Cookie field line (HTTP/2 splits cookies) is read too.
        $split = [['cookie', 'a=b'], ['COOKIE', self::COOKIE . $t]];
        self::assertSame('anna', $gate->identify(new GateRequest($split))->user);
        $twice = self::COOKIE . $t;
        self::assertSame('malformed', self::outcome($gate, [['Cookie', "{$twice}; {$twice}"]]));
        self::assertSame('malformed', self::outcome($gate, [['Cookie', $twice], ['Cookie', $twice]]));
        self::assertSame('unauthenticated', self::outcome($gate, []));
        self::assertSame('unauthenticated', self::outcome($gate, [['Cookie', self::COOKIE]]));
        $lower = [['Cookie', strtolower(self::COOKIE) . $t]];
        self::assertSame('unauthenticated', self::outcome($gate, $lower), 'cookie names are case-sensitive');
        self::assertSame('unauthenticated', self::outcome($gate, [['Authorization', 'Bearer ' . $t], ['X-Gate', $t]]));
        // Token mode never reads identity from Remote-* headers, and never falls back to header mode.
        $remote = [['Remote-User', 'boss'], ['Remote-Kind', 'user'], ['Remote-Auth', 'session']];
        self::assertSame('unauthenticated', self::outcome($gate, $remote));
        $both = [['Remote-User', 'boss'], ['Remote-Groups', 'admin'], ['Cookie', self::COOKIE . $t]];
        $withHeaders = $gate->identify(new GateRequest($both));
        self::assertSame(['anna', ['editors']], [$withHeaders->user, $withHeaders->groups]);
    }

    public function testATokenHeaderOrACookieOfAnotherName(): void
    {
        $t = self::token();
        $gate = self::tokenGate(['tokenHeader' => 'X-Gate']);
        self::assertSame('anna', $gate->identify(new GateRequest([['x-gate', $t]]))->user);
        self::assertSame('malformed', self::outcome($gate, [['X-Gate', $t], ['X-Gate', $t]]));
        self::assertSame('unauthenticated', self::outcome($gate, [['Cookie', self::COOKIE . $t]]));
        $gate = self::tokenGate(['cookieName' => 'gate']);
        self::assertSame('anna', $gate->identify(new GateRequest([['Cookie', 'gate=' . $t]]))->user);
    }

    public function testTrustedProxies(): void
    {
        $gate = Gate::headerMode(trustedProxies: ['127.0.0.1', '198.51.100.0/25', '2001:db8::/32']);
        $fields = [['Remote-User', 'anna'], ['Remote-Kind', 'user']];
        $peers = [
            '127.0.0.1' => 'ok',
            '::ffff:127.0.0.1' => 'ok',
            '198.51.100.127' => 'ok',
            '198.51.100.128' => 'untrusted_peer',
            '2001:db8:1::5' => 'ok',
            '2001:db9::1' => 'untrusted_peer',
            '127.0.0.2' => 'untrusted_peer',
            '::1' => 'untrusted_peer',
            'localhost' => 'untrusted_peer',
            '' => 'untrusted_peer',
        ];
        foreach ($peers as $peer => $want) {
            self::assertSame($want, self::outcome($gate, $fields, $peer), $peer);
        }
        self::assertSame('untrusted_peer', self::outcome($gate, $fields));
        // Without a list, the peer is not looked at.
        self::assertSame('ok', self::outcome(Gate::headerMode(), $fields));
    }

    public function testRenamedHeaders(): void
    {
        $gate = Gate::headerMode(headerNames: new HeaderNames(user: 'X-User', kind: 'X-Account-Kind'));
        $fields = [['X-User', 'anna'], ['X-Account-Kind', 'service'], ['Remote-User', 'boss']];
        $id = $gate->identify(new GateRequest($fields));
        self::assertSame(['anna', AccountKind::Service], [$id->user, $id->accountKind]);
        self::assertSame('header', self::outcome($gate, [['X-User', 'anna'], ['Remote-Kind', 'user']]));
    }

    public function testFromGlobalsReadsTheHttpVariablesAndThePeer(): void
    {
        $request = GateRequest::fromGlobals([
            'HTTP_REMOTE_USER' => 'anna',
            'HTTP_REMOTE_KIND' => 'user',
            'HTTP_COOKIE' => 'a=b',
            'REMOTE_ADDR' => '127.0.0.1',
            'REMOTE_USER' => 'boss',
            'PHP_AUTH_USER' => 'boss',
            'HTTP_X' => ['not', 'a', 'string'],
            7 => 'x',
        ]);
        self::assertSame([['REMOTE-USER', 'anna'], ['REMOTE-KIND', 'user'], ['COOKIE', 'a=b']], $request->fields);
        self::assertSame('127.0.0.1', $request->peer);
        self::assertSame('anna', Gate::headerMode(trustedProxies: ['127.0.0.1'])->identify($request)->user);
    }

    public function testAnUnexpectedFailureInsideFailsClosedAsInternal(): void
    {
        $broken = new class implements KeySource {
            public function lookup(string $kid): string
            {
                throw new \LogicException('boom: ' . $kid);
            }
        };
        $gate = self::build(['keySource' => $broken, 'clock' => static fn (): int => Vectors::defaults()['now']]);
        try {
            $gate->verify(self::token());
            self::fail('accepted');
        } catch (GateError $e) {
            self::assertSame(ErrorClass::Internal, $e->errorClass);
            self::assertStringNotContainsString('boom', $e->getMessage());
            self::assertNull($e->getPrevious(), 'the cause would carry details into a log');
        }
        self::assertNull($gate->identifyOrNull(new GateRequest([['Cookie', self::COOKIE . self::token()]])));
        // A failure in identify() itself (here a field line that is not two strings) fails closed too.
        $odd = new GateRequest([['Remote-User', 5], ['Remote-Kind', 'user']]); // @phpstan-ignore argument.type
        self::assertSame('internal', Vectors::outcome(static fn () => Gate::headerMode()->identify($odd)));
        self::assertNull(Gate::headerMode()->identifyOrNull($odd));
        // verify() on a header-mode gate is a refusal, not an exception of another kind.
        self::assertSame('internal', Vectors::outcome(static fn () => Gate::headerMode()->verify(self::token())));
    }

    public function testTheLoggerGetsTheClassAndTheKidButNoValue(): void
    {
        self::$logged = [];
        $logger = new class extends AbstractLogger {
            public function log($level, \Stringable|string $message, array $context = []): void
            {
                GateTest::record($level, (string) $message, $context);
            }
        };
        $t = self::token();
        $gate = self::tokenGate(['logger' => $logger]);
        $tampered = substr($t, 0, -2) . (substr($t, -2, 1) === 'A' ? 'B' : 'A') . substr($t, -1);
        self::assertNull($gate->identifyOrNull(new GateRequest([['Cookie', self::COOKIE . $tampered]])));
        self::assertNull($gate->identifyOrNull(new GateRequest([])));
        self::assertNotNull($gate->identifyOrNull(new GateRequest([['Cookie', self::COOKIE . $t]])));
        self::assertCount(1, self::$logged, 'one line per refusal; unauthenticated and accepted requests log nothing');
        $line = self::logged()[0];
        self::assertSame(['class' => 'signature', 'kid' => Vectors::kidOf('A')], $line['context']);
        self::assertStringNotContainsString(substr($t, 0, 20), Vectors::encode($line));
        // A logger that throws does not change the answer.
        $throwing = new class extends AbstractLogger {
            public function log($level, \Stringable|string $message, array $context = []): void
            {
                throw new \RuntimeException('log down');
            }
        };
        $request = new GateRequest([['Cookie', self::COOKIE . 'x']]);
        self::assertNull(self::tokenGate(['logger' => $throwing])->identifyOrNull($request));
    }

    /** @return list<array{level: mixed, message: string, context: array<mixed>}> */
    private static function logged(): array
    {
        return self::$logged;
    }

    /** @param array<mixed> $context */
    public static function record(mixed $level, string $message, array $context): void
    {
        self::$logged[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }

    public function testGuards(): void
    {
        $session = new Identity('anna', '', '', 'editors, admin', '1', 'session', 'user');
        $token = new Identity('anna', '', '', 'editors', '1', 'apikey', 'user');
        $service = new Identity('bot', '', '', 'Editors', '2', 'oauth', 'service');
        $all = [Requirement::signedIn(), Requirement::session(), Requirement::role('admin')];
        self::assertSame(Decision::Unauthorized, Decision::of(null));
        self::assertSame(Decision::Unauthorized, Decision::of(null, [Requirement::role('editors')]));
        self::assertSame(Decision::Allow, Decision::of($token));
        self::assertSame(Decision::Allow, Decision::of($session, $all));
        self::assertSame(Decision::Forbidden, Decision::of($token, [Requirement::session()]));
        self::assertSame(Decision::Forbidden, Decision::of($token, [Requirement::role('admin')]), 'not implied');
        self::assertSame(Decision::Forbidden, Decision::of($service, [Requirement::role('editors')]), 'exact');
        self::assertSame(Decision::Forbidden, Decision::of($session, [Requirement::role('Admin')]));
        self::assertSame(Decision::Allow, Decision::of($service, [Requirement::accountKind(AccountKind::Service)]));
        self::assertSame(Decision::Forbidden, Decision::of($service, [Requirement::accountKind(AccountKind::User)]));
        self::assertSame(Decision::Forbidden, Decision::of($session, [Requirement::accountKind(AccountKind::Service)]));
        self::assertSame(['editors', 'admin'], $session->groups);
        self::assertTrue($service->isService());
        self::assertFalse($token->isSession());
    }

    public function testAnIdentityNeverExistsWithoutAValidAccountKind(): void
    {
        $make = static fn (string $auth, string $kind): string
            => Vectors::outcome(static fn () => new Identity('anna', '', '', '', '1', $auth, $kind));
        foreach (['', 'User', 'person', ' user'] as $kind) {
            self::assertSame('header', $make('session', $kind), $kind);
        }
        self::assertSame('header', $make('session', 'service'));
        self::assertSame('ok', $make('Session', 'service'));
    }
}
