<?php

declare(strict_types=1);

namespace TinySesam\Gate\Internal;

use TinySesam\Gate\AccountKind;
use TinySesam\Gate\Claims;
use TinySesam\Gate\ErrorClass;
use TinySesam\Gate\GateError;
use TinySesam\Gate\Identity;
use TinySesam\Gate\KeySet;

/**
 * Token mode: the checking order of spec section 4.4, step by step.
 *
 * @internal
 */
final class Token
{
    /** A larger token is malformed (step 1). */
    public const int MAX_TOKEN_BYTES = 4096;
    /** The largest configurable clock leeway in seconds. */
    public const int MAX_LEEWAY = 60;
    /** The largest exp - nbf in seconds. */
    public const int MAX_LIFETIME = 3600;

    /** The algorithm is this client's constant; the header may only confirm it (spec section 7). */
    private const string ALGORITHM = 'EdDSA';
    private const string TYPE = 'tinysesam-gate+jwt';
    private const array ALLOWED_HEADER_MEMBERS = ['alg', 'typ', 'kid'];
    private const array IDENTITY_CLAIMS = [
        'ts_user', 'ts_name', 'ts_email', 'ts_groups', 'ts_id', 'ts_auth', 'ts_kind',
    ];
    private const int MAX_SAFE = 9007199254740991; // 2^53 - 1

    private function __construct()
    {
    }

    /**
     * Steps 1-5: size, structure, header JSON, header members, signature length.
     *
     * @throws GateError
     */
    public static function parse(#[\SensitiveParameter] string $jws): ParsedToken
    {
        if (\strlen($jws) > self::MAX_TOKEN_BYTES) {
            throw new GateError(ErrorClass::Malformed, 'token too large');
        }
        $parts = explode('.', $jws);
        if (\count($parts) !== 3 || $parts[0] === '' || $parts[1] === '') {
            throw new GateError(ErrorClass::Malformed, 'not three segments');
        }
        [$h, $p, $s] = $parts;
        $head = Strict::decodeSegment($h);
        $payload = Strict::decodeSegment($p);
        $signature = Strict::decodeSegment($s);
        if ($head === null || $payload === null || $signature === null) {
            throw new GateError(ErrorClass::Malformed, 'not strict base64url');
        }
        [$ok, $header] = Strict::parseJson($head);
        if (!$ok) {
            throw new GateError(ErrorClass::Malformed, 'header is not strict JSON');
        }
        if (!$header instanceof \stdClass) {
            throw new GateError(ErrorClass::Malformed, 'header is not a JSON object');
        }
        foreach (array_keys(get_object_vars($header)) as $name) {
            if (!\in_array($name, self::ALLOWED_HEADER_MEMBERS, true)) {
                throw new GateError(ErrorClass::Header, 'forbidden header member');
            }
        }
        if (Strict::member($header, 'alg') !== self::ALGORITHM) {
            throw new GateError(ErrorClass::Header, 'alg is not EdDSA');
        }
        $typ = Strict::member($header, 'typ');
        if (!\is_string($typ) || !Strict::asciiEqualFold($typ, self::TYPE)) {
            throw new GateError(ErrorClass::Header, 'wrong typ');
        }
        $kid = Strict::member($header, 'kid');
        if (!\is_string($kid) || !KeySet::isValidKid($kid)) {
            throw new GateError(ErrorClass::Kid, 'kid missing or not 16 lowercase hex digits');
        }
        if (\strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new GateError(ErrorClass::Signature, 'signature is not 64 bytes', $kid);
        }

        return new ParsedToken($h . '.' . $p, $payload, $signature, $kid);
    }

    /**
     * Steps 7-10: the signature, then (only then) the payload, its claims and their values.
     *
     * @param string $key 32 raw bytes of an Ed25519 public key
     *
     * @throws GateError
     */
    public static function finish(
        ParsedToken $token,
        string $key,
        string $issuer,
        string $audience,
        int $leeway,
        int $now,
    ): Claims {
        if (
            \strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || $token->signature === ''
            || !sodium_crypto_sign_verify_detached($token->signature, $token->signingInput, $key)
        ) {
            throw new GateError(ErrorClass::Signature, 'verification failed', $token->kid);
        }
        [$ok, $payload] = Strict::parseJson($token->payload);
        if (!$ok) {
            throw new GateError(ErrorClass::Malformed, 'payload is not strict JSON', $token->kid);
        }
        if (!$payload instanceof \stdClass) {
            throw new GateError(ErrorClass::Malformed, 'payload is not a JSON object', $token->kid);
        }
        try {
            return self::checkClaims($payload, $issuer, $audience, $leeway, $now);
        } catch (GateError $e) {
            throw $e->withKid($token->kid);
        }
    }

    /** An integer claim: a JSON number without fraction or exponent from 0 to 2^53 - 1; not a boolean, not a string. */
    private static function intClaim(mixed $value): ?int
    {
        // json_decode gives an int only for a number written without fraction or exponent (1.0 and 1e3 are floats).
        return \is_int($value) && $value >= 0 && $value <= self::MAX_SAFE ? $value : null;
    }

    /** @throws GateError */
    private static function checkClaims(\stdClass $m, string $issuer, string $audience, int $leeway, int $now): Claims
    {
        $iss = Strict::member($m, 'iss');
        if (!\is_string($iss)) {
            throw new GateError(ErrorClass::Claims, 'iss');
        }
        $sub = Strict::member($m, 'sub');
        if (!\is_string($sub)) {
            throw new GateError(ErrorClass::Claims, 'sub');
        }
        $audValue = Strict::member($m, 'aud');
        if (\is_string($audValue)) {
            $aud = [$audValue];
        } elseif (
            \is_array($audValue)
            && $audValue !== []
            && array_all($audValue, static fn (mixed $a): bool => \is_string($a))
        ) {
            /** @var list<string> $aud */
            $aud = $audValue;
        } else {
            throw new GateError(ErrorClass::Claims, 'aud');
        }
        $iat = self::intClaim(Strict::member($m, 'iat'));
        $nbf = self::intClaim(Strict::member($m, 'nbf'));
        $exp = self::intClaim(Strict::member($m, 'exp'));
        if ($iat === null || $nbf === null || $exp === null) {
            throw new GateError(ErrorClass::Claims, 'iat, nbf or exp');
        }
        $jti = '';
        $v = Strict::member($m, 'jti', $present);
        if ($present) {
            if (!\is_string($v)) {
                throw new GateError(ErrorClass::Claims, 'jti');
            }
            $jti = $v;
        }
        foreach (self::IDENTITY_CLAIMS as $name) {
            $v = Strict::member($m, $name, $present);
            if ($present) {
                if (!\is_string($v)) {
                    throw new GateError(ErrorClass::Claims, 'identity claim type');
                }
                if (Strict::hasControl($v)) {
                    throw new GateError(ErrorClass::Claims, 'control character in an identity claim');
                }
            }
        }
        if ($sub === '' || Strict::hasControl($sub)) {
            throw new GateError(ErrorClass::Claims, 'sub');
        }
        $tsId = Strict::member($m, 'ts_id', $present);
        if ($present && $tsId !== $sub) {
            throw new GateError(ErrorClass::Claims, 'ts_id differs from sub');
        }
        if ($iat > $nbf) {
            throw new GateError(ErrorClass::Claims, 'iat later than nbf');
        }
        // Spec v2: ts_kind present and exactly user or service, never service with a session (its type was checked
        // above).
        $kindProblem = AccountKind::problem(Strict::member($m, 'ts_kind'), Strict::member($m, 'ts_auth'));
        if ($kindProblem !== null) {
            throw new GateError(ErrorClass::Claims, $kindProblem);
        }
        if ($iss !== $issuer) {
            throw new GateError(ErrorClass::Issuer);
        }
        if (!\in_array($audience, $aud, true)) {
            throw new GateError(ErrorClass::Audience);
        }
        if ($exp <= $nbf || $exp - $nbf > self::MAX_LIFETIME) {
            throw new GateError(ErrorClass::Lifetime);
        }
        if ($nbf > $now + $leeway) {
            throw new GateError(ErrorClass::NotYetValid);
        }
        if ($exp + $leeway <= $now) {
            throw new GateError(ErrorClass::Expired);
        }

        return new Claims($iss, $aud, $sub, $iat, $nbf, $exp, $jti, get_object_vars($m));
    }

    /**
     * Maps the claims of a valid token to the identity (spec section 4.1); a missing claim gives an empty value —
     * except ts_kind, which checkClaims has required (the Identity constructor refuses an invalid one again).
     */
    public static function identity(Claims $c): Identity
    {
        $str = static fn (string $name): string => \is_string($c->raw[$name] ?? null) ? $c->raw[$name] : '';

        return new Identity(
            $str('ts_user'),
            $str('ts_name'),
            $str('ts_email'),
            $str('ts_groups'),
            $c->sub,
            $str('ts_auth'),
            $str('ts_kind'),
        );
    }
}
