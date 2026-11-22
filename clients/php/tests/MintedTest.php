<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TinySesam\Gate\Gate;
use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\Tests\Support\Vectors;

/**
 * Tokens signed with the public test key A, each with exactly one defect that no vector isolates — or one a client in
 * PHP is likely to miss (json_decode keeps the last of two members, integers versus floats).
 */
final class MintedTest extends TestCase
{
    private static function gate(): Gate
    {
        $d = Vectors::defaults();

        return Vectors::tokenGate(['keys' => [Vectors::publicJwk('A')]], $d['issuer'], $d['audience'], 0, $d['now']);
    }

    /** The JSON text of the session claims with $replace substituted into it. */
    private static function claimsText(string $search = '', string $replace = ''): string
    {
        $text = Vectors::encode(Vectors::sessionClaims('editors', Vectors::defaults()['now']));
        if ($search !== '') {
            self::assertStringContainsString($search, $text);
            $text = str_replace($search, $replace, $text);
        }

        return $text;
    }

    public function testTheBaseTokenIsValid(): void
    {
        $token = Vectors::mint('A', self::claimsText());
        self::assertSame('ok', Vectors::outcome(static fn () => self::gate()->verify($token)));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function payloads(): iterable
    {
        $now = Vectors::defaults()['now'];
        foreach (
            ['ff' => "\xFF", 'overlong' => "\xC0\xAF", 'surrogate' => "\xED\xA0\x80", 'truncated' => "\xE2\x82",
            'above-max' => "\xF4\x90\x80\x80"] as $how => $bytes
        ) {
            yield "invalid UTF-8 ({$how})" => [self::claimsText('"Anna Berg"', '"Anna' . $bytes . '"'), 'malformed'];
        }
        yield 'byte order mark' => ["\xEF\xBB\xBF" . self::claimsText(), 'malformed'];
        yield 'repeated claim sub' => [self::claimsText('"sub":"1"', '"sub":"1","sub":"2"'), 'malformed'];
        $escaped = '"ts_user":"anna","ts_\\u0075ser":"boss"';
        yield 'repeated claim ts_user, escaped' => [self::claimsText('"ts_user":"anna"', $escaped), 'malformed'];
        $nested = '"jti":"jti-test","x":{"a":1,"a":2}';
        yield 'repeated member in a nested object' => [self::claimsText('"jti":"jti-test"', $nested), 'malformed'];
        yield 'NaN' => [self::claimsText('"iat":' . $now, '"iat":NaN'), 'malformed'];
        yield 'Infinity' => [self::claimsText('"iat":' . $now, '"iat":Infinity'), 'malformed'];
        yield 'lone surrogate escape' => [self::claimsText('"Anna Berg"', '"Anna \ud800"'), 'malformed'];
        yield 'trailing text' => [self::claimsText() . ' x', 'malformed'];
        yield 'iat 1.0 form' => [self::claimsText('"iat":' . $now, '"iat":' . $now . '.0'), 'claims'];
        yield 'iat exponent form' => [self::claimsText('"iat":' . $now, '"iat":1.7e9'), 'claims'];
        yield 'iat 2^53' => [self::claimsText('"iat":' . $now, '"iat":9007199254740992'), 'claims'];
        yield 'iat -1' => [self::claimsText('"iat":' . $now, '"iat":-1'), 'claims'];
        yield 'iat as string' => [self::claimsText('"iat":' . $now, '"iat":"' . $now . '"'), 'claims'];
        yield 'iat true' => [self::claimsText('"iat":' . $now, '"iat":true'), 'claims'];
        yield 'control character in ts_name' => [self::claimsText('"Anna Berg"', '"Anna\u0007Berg"'), 'claims'];
        $noTsId = str_replace(',"ts_id":"1"', '', self::claimsText('"sub":"1"', '"sub":"1\u0000"'));
        yield 'control character in sub without ts_id' => [$noTsId, 'claims'];
        yield 'empty sub' => [self::claimsText('"sub":"1"', '"sub":""'), 'claims'];
        $aud = '"aud":"app.example.com"';
        yield 'aud as an object' => [self::claimsText($aud, '"aud":{"0":"app.example.com"}'), 'claims'];
        yield 'aud as an empty array' => [self::claimsText('"aud":"app.example.com"', '"aud":[]'), 'claims'];
        yield 'ts_kind missing' => [self::claimsText(',"ts_kind":"user"', ''), 'claims'];
        yield 'ts_kind service, session' => [self::claimsText('"ts_kind":"user"', '"ts_kind":"service"'), 'claims'];
        yield 'payload is an array' => ['[]', 'malformed'];
    }

    #[DataProvider('payloads')]
    public function testOneDefectInThePayload(string $payload, string $want): void
    {
        self::assertSame($want, Vectors::outcome(static fn () => self::gate()->verify(Vectors::mint('A', $payload))));
    }

    public function testAnUnknownClaimIsIgnoredAlsoWithADigitName(): void
    {
        $token = Vectors::mint('A', self::claimsText('"jti":"jti-test"', '"jti":"jti-test","123":1,"x":{"y":[1,{}]}'));
        self::assertSame('ok', Vectors::outcome(static fn () => self::gate()->verify($token)));
    }

    public function testAWrongLengthSignatureWithAnUnknownKidIsASignatureError(): void
    {
        // Step 5 (length) comes before step 6 (key): a kid outside the set must not hide the short signature.
        $header = ['alg' => 'EdDSA', 'typ' => 'tinysesam-gate+jwt', 'kid' => '0123456789abcdef'];
        $token = Strict::encodeSegment(Vectors::encode($header)) . '.' . Strict::encodeSegment(self::claimsText())
            . '.' . Strict::encodeSegment(str_repeat("\1", 63));
        self::assertSame('signature', Vectors::outcome(static fn () => self::gate()->verify($token)));
    }

    public function testHeaderMembersWithADigitNameOrAnUnusualSpellingAreRefused(): void
    {
        $kid = Vectors::kidOf('A');
        foreach (
            ['{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"' . $kid . '","0":1}' => 'header',
            '{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"' . $kid . '","alg":"EdDSA"}' => 'malformed',
            '{"alg":"EdDSA","typ":"TinySesam-Gate+JWT","kid":"' . $kid . '"}' => 'ok',
            '{"alg":"EdDSA","typ":"tinysesam-gate+jwt ","kid":"' . $kid . '"}' => 'header',
            '{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"' . strtoupper($kid) . '"}' => 'kid',
            ] as $header => $want
        ) {
            $token = Vectors::mint('A', self::claimsText(), $header);
            self::assertSame($want, Vectors::outcome(static fn () => self::gate()->verify($token)), $header);
        }
    }

    public function testATokenAboveTheSizeLimitIsMalformedBeforeAnythingElse(): void
    {
        self::assertSame('malformed', Vectors::outcome(static fn () => self::gate()->verify(str_repeat('a', 4097))));
        $big = Vectors::mint('A', self::claimsText('"jti":"jti-test"', '"jti":"' . str_repeat('j', 3000) . '"'));
        self::assertGreaterThan(4096, \strlen($big));
        self::assertSame('malformed', Vectors::outcome(static fn () => self::gate()->verify($big)));
    }

    public function testATrailingLineBreakInASegmentIsMalformed(): void
    {
        // PCRE's `$` matches before a final line break; the segment check must not.
        [$h, $p, $s] = explode('.', Vectors::mint('A', self::claimsText()));
        foreach (["{$h}\n.{$p}.{$s}", "{$h}.{$p}\n.{$s}", "{$h}.{$p}.{$s}\n"] as $token) {
            self::assertSame('malformed', Vectors::outcome(static fn () => self::gate()->verify($token)));
        }
    }
}
