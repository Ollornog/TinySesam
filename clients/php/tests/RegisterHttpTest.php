<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\TestCase;
use TinySesam\Gate\Permissions;
use TinySesam\Gate\RegistrationFailed;
use TinySesam\Gate\Tests\Support\Server;

/**
 * Permissions::register() over a real HTTP connection (T-140): the vectors cover the request it builds, this test the
 * sending — method, path, `X-Api-Key`, body, the deadline, and the refusal of any answer but 200 without the key in
 * the error.
 */
final class RegisterHttpTest extends TestCase
{
    private const string KEY = 'tsk_registerkey_8f2c41d07b9e4a1f';
    private const array MANIFEST = [['name' => 'docs.read', 'label' => ['en' => 'Read documents']],
        ['name' => 'docs.delete', 'danger' => true]];

    /** @var list<Server> */
    private array $servers = [];

    protected function tearDown(): void
    {
        foreach ($this->servers as $s) {
            $s->stop();
        }
        $this->servers = [];
    }

    private function server(): Server
    {
        $s = new Server();
        $this->servers[] = $s;

        return $s;
    }

    /** The refusal of a call, which must never carry the key. */
    private static function refusal(callable $call): RegistrationFailed
    {
        try {
            $call();
        } catch (RegistrationFailed $e) {
            self::assertStringNotContainsString(self::KEY, $e->getMessage());
            self::assertStringNotContainsString(substr(self::KEY, 0, 12), $e->getMessage());
            self::assertStringNotContainsString(self::KEY, (string) $e);

            return $e;
        }
        self::fail('no RegistrationFailed');
    }

    public function testTheManifestGoesOutAsAPutWithTheKeyInItsHeader(): void
    {
        $s = $this->server();
        $answer = Permissions::register($s->base, 'docs', self::MANIFEST, self::KEY);
        self::assertSame(['added' => ['docs.read'], 'updated' => [], 'returned' => [], 'orphaned' => []], $answer);
        self::assertSame([
            '/auth/api/apps/docs/permissions',
            'method:PUT',
            'key:' . self::KEY,
            'type:application/json',
            'body:{"permissions":[{"name":"docs.read","label":{"en":"Read documents"}},'
                . '{"name":"docs.delete","danger":true}]}',
        ], $s->hits());
    }

    public function testAnyAnswerButA200IsRefusedWithoutTheKey(): void
    {
        $s = $this->server();
        $e = self::refusal(static fn () => Permissions::register($s->base, 'deny', self::MANIFEST, self::KEY));
        self::assertSame(403, $e->status);
        $e = self::refusal(static fn () => Permissions::register($s->base, 'text', self::MANIFEST, self::KEY));
        self::assertSame(200, $e->status, 'an answer that is no JSON object');
        $s->stop();
        $e = self::refusal(static fn () => Permissions::register($s->base, 'docs', self::MANIFEST, self::KEY));
        self::assertSame(0, $e->status, 'not reachable');
    }

    public function testTheDeadlineIsFiveSeconds(): void
    {
        $s = $this->server();
        $start = microtime(true);
        $e = self::refusal(static fn () => Permissions::register($s->base, 'hang', self::MANIFEST, self::KEY));
        $took = microtime(true) - $start;
        self::assertSame(0, $e->status);
        self::assertGreaterThan(4.5, $took, 'returned before the deadline: did it wait at all?');
        self::assertLessThan(6.5, $took, 'waited longer than the 5-second deadline');
    }
}
