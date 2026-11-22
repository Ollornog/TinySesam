<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\TestCase;
use TinySesam\Gate\GateError;
use TinySesam\Gate\Headers;
use TinySesam\Gate\Identity;
use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\KeySet;
use TinySesam\Gate\Topbar;
use TinySesam\Gate\Tests\Support\Vectors;

/**
 * Properties over generated input, with a fixed seed so every run checks the same cases: no input throws anything but
 * a GateError past the API, a changed or inserted character never verifies, and the group, control-character and JSON
 * rules hold.
 */
final class PropsTest extends TestCase
{
    private const int RUNS = 1500;

    private \Random\Randomizer $rng;

    protected function setUp(): void
    {
        $this->rng = new \Random\Randomizer(new \Random\Engine\Mt19937(20261122));
    }

    private function pick(string $alphabet, int $max): string
    {
        $n = $this->rng->getInt(0, $max);
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $out .= $alphabet[$this->rng->getInt(0, \strlen($alphabet) - 1)];
        }

        return $out;
    }

    public function testNoInputThrowsAnythingButAGateError(): void
    {
        $d = Vectors::defaults();
        $gate = Vectors::tokenGate(['keys' => [Vectors::publicJwk('A')]], $d['issuer'], $d['audience'], 0, $d['now']);
        $valid = Vectors::mint('A', Vectors::sessionClaims('editors', $d['now']));
        $refused = 0;
        for ($i = 0; $i < self::RUNS; $i++) {
            $input = match ($i % 3) {
                0 => $this->rng->getBytes($this->rng->getInt(1, 300)),
                1 => $this->pick('ABCabc019-_.=+/ {}"', 200),
                default => substr_replace(
                    $valid,
                    $this->rng->getBytes($this->rng->getInt(1, 4)),
                    $this->rng->getInt(0, \strlen($valid)),
                    $this->rng->getInt(0, 3),
                ),
            };
            try {
                $gate->verify($input);
                self::assertSame($valid, $input, 'a generated token verified');
            } catch (GateError) {
                $refused++; // a refusal is the expected answer
            }
            try {
                KeySet::fromJwks($input);
            } catch (GateError) {
            }
            self::assertFalse(Topbar::parse($input)->signedIn);
        }
        self::assertGreaterThan(self::RUNS - 10, $refused);
    }

    public function testAChangedOrInsertedCharacterNeverVerifies(): void
    {
        $d = Vectors::defaults();
        $gate = Vectors::tokenGate(['keys' => [Vectors::publicJwk('A')]], $d['issuer'], $d['audience'], 0, $d['now']);
        $valid = Vectors::mint('A', Vectors::sessionClaims('editors', $d['now']));
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.';
        for ($i = 0; $i < self::RUNS; $i++) {
            $at = $this->rng->getInt(0, \strlen($valid) - 1);
            $c = $alphabet[$this->rng->getInt(0, \strlen($alphabet) - 1)];
            $changed = $i % 2 === 0 ? substr_replace($valid, $c, $at, 1) : substr_replace($valid, $c, $at, 0);
            if ($changed === $valid) {
                continue;
            }
            self::assertNotSame('ok', Vectors::outcome(static fn () => $gate->verify($changed)), "position {$at}");
        }
    }

    public function testTheGroupRules(): void
    {
        for ($i = 0; $i < self::RUNS; $i++) {
            $s = $this->pick('aAb ,\\"%', 24);
            $groups = Identity::parseGroups($s);
            self::assertSame($groups, array_values(array_unique($groups)), 'repeated entry');
            foreach ($groups as $g) {
                self::assertNotSame('', $g);
                self::assertSame($g, trim($g, ' '));
                self::assertStringNotContainsString(',', $g);
            }
            $trimmed = array_map(static fn (string $p): string => trim($p, ' '), explode(',', $s));
            $expected = array_values(array_unique(array_filter($trimmed, static fn (string $p): bool => $p !== '')));
            self::assertSame($expected, $groups);
        }
    }

    public function testAControlCharacterAnywhereInAHeaderIsRefusedNeverStripped(): void
    {
        for ($i = 0; $i < self::RUNS; $i++) {
            $control = \chr($this->rng->getInt(0, 1) === 0 ? $this->rng->getInt(0, 0x1F) : 0x7F);
            $value = $this->pick('ab', 6) . $control . $this->pick('ab', 6);
            $slot = ['Remote-User', 'Remote-Name', 'Remote-Email', 'Remote-Groups', 'Remote-Auth'][$i % 5];
            $fields = ['Remote-User' => 'anna', 'Remote-Kind' => 'user', $slot => $value];
            $pairs = [];
            foreach ($fields as $k => $v) {
                $pairs[] = [$k, $v];
            }
            self::assertSame('header', Vectors::outcome(static fn () => Headers::identity($pairs)), bin2hex($value));
        }
    }

    public function testStrictJsonAgreesWithJsonDecodeWithoutRepeats(): void
    {
        for ($i = 0; $i < self::RUNS; $i++) {
            $doc = $this->document(3);
            $text = Vectors::encode($doc);
            [$ok, $value] = Strict::parseJson($text);
            self::assertTrue($ok, $text);
            self::assertSame(Vectors::normalize(json_decode($text, false)), Vectors::normalize($value));
            // One repeated member name anywhere makes it refuse.
            if ($doc instanceof \stdClass && get_object_vars($doc) !== []) {
                $name = (string) array_key_first(get_object_vars($doc));
                $repeated = '{' . json_encode($name, Vectors::JSON_FLAGS) . ':0,' . substr($text, 1);
                self::assertFalse(Strict::parseJson($repeated)[0], $repeated);
            }
        }
    }

    private function document(int $depth): mixed
    {
        $kind = $depth === 0 ? $this->rng->getInt(2, 5) : $this->rng->getInt(0, 5);

        return match ($kind) {
            0 => (function () use ($depth): \stdClass {
                $o = new \stdClass();
                for ($n = $this->rng->getInt(0, 4); $n > 0; $n--) {
                    $name = $this->pick('ab"\\/1', 4) . ['', 'é', '€', '😀'][$this->rng->getInt(0, 3)];
                    $o->{$name} = $this->document($depth - 1);
                }

                return $o;
            })(),
            1 => array_map(fn (): mixed => $this->document($depth - 1), range(1, $this->rng->getInt(1, 3))),
            2 => $this->pick('xy"\\/', 6) . ['', 'ü', "\u{202E}", '😀'][$this->rng->getInt(0, 3)],
            3 => $this->rng->getInt(-1000, 1000),
            4 => $this->rng->getInt(0, 1) === 1,
            default => null,
        };
    }
}
