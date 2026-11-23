<?php

declare(strict_types=1);

namespace TinySesam\Gate;

use TinySesam\Gate\Internal\ParsedToken;
use TinySesam\Gate\Internal\Strict;
use TinySesam\Gate\Internal\Token;
use TinySesam\Gate\Jwks\CurlFetcher;
use TinySesam\Gate\Jwks\Fetcher;
use TinySesam\Gate\Jwks\JwksCache;
use TinySesam\Gate\Jwks\Store;

/**
 * Checks approval confirmations (spec/approval-token.md): the proof an application receives after a person confirmed
 * one of its sensitive actions in TinySesam with a fresh step-up — this account has just confirmed exactly this
 * action, for this application, once. Build it once with {@see ApprovalVerifier::create()}.
 */
final readonly class ApprovalVerifier
{
    /** The typ of a confirmation — never `tinysesam-gate+jwt`. */
    public const string TOKEN_TYPE = 'tinysesam-approval+jwt';
    /** The longest lifetime exp - nbf of a confirmation, in seconds. */
    public const int MAX_LIFETIME = 300;
    /** The largest clock leeway an application may allow, in seconds. */
    public const int MAX_LEEWAY = 30;

    private const int MAX_TEXT = 128;
    private const int MAX_SUB = 1000;
    private const int MAX_AMR = 32;
    private const int MAX_TYPE = 100;
    private const array REQUIRED = [
        'iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'jti', 'auth_time', 'amr', 'act', 'authorization_details',
        'ts_payload_sha256',
    ];

    /** @param \Closure(): int $clock */
    private function __construct(
        private string $issuer,
        private string $appId,
        private int $leeway,
        private KeySource $keys,
        private \Closure $clock,
    ) {
    }

    /**
     * Exactly one key source: $keys (a fixed approval key set, {@see KeySet::fromJwks()} of
     * `/auth/approvals/jwks.json`) or $jwksUrl (normally `https://<auth host>/auth/approvals/jwks.json`, fetched under
     * the rules of spec/gate-client.md section 5) — never the gate key set: a path ending in `/gate/jwks.json` is
     * refused.
     *
     * @param string $issuer TinySesam's base_url without a trailing slash
     * @param string $appId the application's own id (`apps.<id>` in TinySesam's configuration)
     * @param ?Fetcher $fetcher fetches the key set (only with $jwksUrl); a {@see CurlFetcher} when not given
     * @param ?Store $store where the key set cache lives (only with $jwksUrl), see {@see Gate::tokenMode()}
     * @param ?\Closure(): int $clock Unix seconds, for tests
     *
     * @throws ConfigError a configuration that must stop the start
     */
    public static function create(
        string $issuer,
        string $appId,
        ?KeySet $keys = null,
        ?string $jwksUrl = null,
        int $leewaySeconds = 0,
        ?Fetcher $fetcher = null,
        ?Store $store = null,
        ?\Closure $clock = null,
    ): self {
        if ($issuer === '' || $appId === '') {
            throw new ConfigError('approvals need issuer and appId');
        }
        if ($leewaySeconds < 0 || $leewaySeconds > self::MAX_LEEWAY) {
            throw new ConfigError('leewaySeconds must be 0 to ' . self::MAX_LEEWAY . ' for approvals');
        }
        if (!\function_exists('sodium_crypto_sign_verify_detached')) {
            throw new ConfigError('ext-sodium is required');
        }
        if (($keys === null) === ($jwksUrl === null)) {
            throw new ConfigError('approvals need exactly one of keys and jwksUrl');
        }
        if ($jwksUrl === null && ($fetcher !== null || $store !== null)) {
            throw new ConfigError('fetcher and store belong to jwksUrl');
        }
        if ($keys !== null) {
            if ($keys->count() === 0) {
                throw new ConfigError('the approval key set has no usable key');
            }
            $source = new StaticKeys($keys);
        } else {
            \assert($jwksUrl !== null);
            Gate::checkJwksUrl($jwksUrl);
            $path = parse_url($jwksUrl, PHP_URL_PATH);
            if (\is_string($path) && str_ends_with(rtrim($path, '/'), '/gate/jwks.json')) {
                throw new ConfigError(
                    'jwksUrl is the GATE key set; confirmations have their own '
                    . '(https://<auth host>/auth/approvals/jwks.json)',
                );
            }
            if ($fetcher === null && !\function_exists('curl_init')) {
                throw new ConfigError('jwksUrl needs ext-curl, or a Fetcher of your own');
            }
            $source = new JwksCache($fetcher ?? new CurlFetcher($jwksUrl), $store);
        }

        return new self($issuer, $appId, $leewaySeconds, $source, $clock ?? time(...));
    }

    /**
     * Checks a confirmation in the order of spec/approval-token.md section 4 and, as the last step, writes its jti into
     * $store. Any GateError means: do not carry the action out — log its class, never the token. Afterwards run the
     * application's own rules again (still the owner? does the thing still exist?), then act.
     *
     * @param JtiStore|callable(string, int): bool $store
     *
     * @throws GateError
     */
    public function verify(
        #[\SensitiveParameter] string $token,
        ApprovalExpect $expect,
        JtiStore|callable $store,
    ): ApprovalClaims {
        $now = ($this->clock)();
        $parsed = Token::parse($token, self::TOKEN_TYPE);
        $key = $this->keys->lookup($parsed->kid);
        $payload = self::verifiedPayload($parsed, $key);
        try {
            $c = self::claims($payload);
            $this->values($c, $now);
            if ($c->type !== $expect->type) {
                throw new GateError(ErrorClass::ApprovalType);
            }
            if (!self::sameFields($c->fields, $expect->fields)) {
                throw new GateError(ErrorClass::ApprovalFields);
            }
            if ($c->sub !== $expect->sub) {
                throw new GateError(ErrorClass::Subject);
            }
            if ($expect->nonce !== null && $c->nonce !== $expect->nonce) {
                throw new GateError(ErrorClass::Nonce);
            }
            try {
                $first = $store instanceof JtiStore ? $store->remember($c->jti, $c->exp + $this->leeway)
                    : $store($c->jti, $c->exp + $this->leeway);
            } catch (\Throwable) {
                throw new GateError(ErrorClass::Internal, 'the jti store failed');
            }
            if ($first !== true) {
                throw new GateError(ErrorClass::Replay);
            }

            return $c;
        } catch (GateError $e) {
            throw $e->withKid($parsed->kid);
        }
    }

    /** Steps 7-8: the signature, then (only then) the payload. */
    private static function verifiedPayload(ParsedToken $token, string $key): \stdClass
    {
        if (
            \strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || $token->signature === ''
            || !sodium_crypto_sign_verify_detached($token->signature, $token->signingInput, $key)
        ) {
            throw new GateError(ErrorClass::Signature, 'verification failed', $token->kid);
        }
        [$ok, $payload] = Strict::parseJson($token->payload);
        if (!$ok || !$payload instanceof \stdClass) {
            throw new GateError(ErrorClass::Malformed, 'payload is not a strict JSON object', $token->kid);
        }

        return $payload;
    }

    /** A non-empty string of at most $limit code points without a C0 control character or DEL. */
    private static function isText(mixed $v, int $limit): bool
    {
        return \is_string($v) && $v !== '' && !Strict::hasControl($v) && preg_match_all('/./su', $v) <= $limit;
    }

    private static function intClaim(mixed $v): ?int
    {
        // json_decode gives an int only for a number written without fraction or exponent.
        return \is_int($v) && $v >= 0 && $v <= Token::MAX_SAFE ? $v : null;
    }

    private static function isFieldValue(mixed $v): bool
    {
        return \is_string($v) || \is_bool($v) || (\is_int($v) && abs($v) <= Token::MAX_SAFE);
    }

    /** Step 9: presence, types, aud as one string, exactly one entry, the digest, the order of the times. */
    private static function claims(\stdClass $m): ApprovalClaims
    {
        $bad = static fn (string $detail): GateError => new GateError(ErrorClass::Claims, $detail);
        foreach (self::REQUIRED as $name) {
            if (!property_exists($m, $name)) {
                throw $bad("{$name} missing");
            }
        }
        $iss = $m->iss;
        $sub = $m->sub;
        if (!\is_string($iss) || !\is_string($sub) || !self::isText($sub, self::MAX_SUB)) {
            throw $bad('iss or sub');
        }
        $iat = self::intClaim($m->iat);
        $nbf = self::intClaim($m->nbf);
        $exp = self::intClaim($m->exp);
        $authTime = self::intClaim($m->auth_time);
        if ($iat === null || $nbf === null || $exp === null || $authTime === null) {
            throw $bad('iat, nbf, exp or auth_time');
        }
        $jti = $m->jti;
        if (!\is_string($jti) || !self::isText($jti, self::MAX_TEXT)) {
            throw $bad('jti');
        }
        $amr = $m->amr;
        if (!\is_array($amr) || $amr === [] || !array_is_list($amr)) {
            throw $bad('amr');
        }
        $methods = [];
        foreach ($amr as $a) {
            if (!\is_string($a) || !self::isText($a, self::MAX_AMR)) {
                throw $bad('amr');
            }
            $methods[] = $a;
        }
        $act = $m->act;
        $actor = $act instanceof \stdClass ? Strict::member($act, 'sub') : null;
        if (!\is_string($actor) || !self::isText($actor, self::MAX_TEXT)) {
            throw $bad('act');
        }
        $digest = $m->ts_payload_sha256;
        if (!\is_string($digest)) {
            throw $bad('ts_payload_sha256');
        }
        $nonce = Strict::member($m, 'nonce', $hasNonce);
        if ($hasNonce && (!\is_string($nonce) || !self::isText($nonce, self::MAX_TEXT))) {
            throw $bad('nonce');
        }
        // aud is ONE string, the application's id — never an array, which could name several applications.
        $aud = $m->aud;
        if (!\is_string($aud)) {
            throw $bad('aud is not a string');
        }
        $details = $m->authorization_details;
        if (!\is_array($details) || \count($details) !== 1 || !array_is_list($details)) {
            throw $bad('authorization_details is not one entry');
        }
        $entry = $details[0];
        if (!$entry instanceof \stdClass) {
            throw $bad('authorization_details[0]');
        }
        $type = Strict::member($entry, 'type');
        if (!\is_string($type) || !self::isText($type, self::MAX_TYPE)) {
            throw $bad('authorization_details[0].type');
        }
        $members = get_object_vars($entry);
        $fields = [];
        foreach ($members as $name => $value) {
            if (!self::isFieldValue($value)) {
                throw $bad('a field value of an unsupported type');
            }
            if ((string) $name !== 'type') {
                \assert(\is_string($value) || \is_int($value) || \is_bool($value));
                $fields[$name] = $value;
            }
        }
        /** @var array<array-key, string|int|bool> $members */
        if (!hash_equals(self::payloadDigest($members), $digest)) {
            throw $bad('ts_payload_sha256 does not match the entry');
        }
        if ($iat > $nbf || $authTime > $iat) {
            throw $bad('iat, nbf and auth_time out of order');
        }

        return new ApprovalClaims(
            $iss,
            $aud,
            $sub,
            $iat,
            $nbf,
            $exp,
            $authTime,
            $jti,
            $methods,
            $actor,
            $type,
            $fields,
            \is_string($nonce) ? $nonce : null,
            get_object_vars($m),
        );
    }

    /** Step 10: issuer, the application's id, lifetime, not before, expiry. */
    private function values(ApprovalClaims $c, int $now): void
    {
        if ($c->iss !== $this->issuer) {
            throw new GateError(ErrorClass::Issuer);
        }
        if ($c->aud !== $this->appId) {
            throw new GateError(ErrorClass::Audience);
        }
        if ($c->exp <= $c->nbf || $c->exp - $c->nbf > self::MAX_LIFETIME) {
            throw new GateError(ErrorClass::Lifetime);
        }
        if ($c->nbf > $now + $this->leeway) {
            throw new GateError(ErrorClass::NotYetValid);
        }
        if ($c->exp + $this->leeway <= $now) {
            throw new GateError(ErrorClass::Expired);
        }
    }

    /**
     * Names, JSON types and values exactly: 1, "1" and true are three different values.
     *
     * @param array<array-key, string|int|bool> $got
     * @param array<array-key, mixed> $want
     */
    private static function sameFields(array $got, array $want): bool
    {
        if (\count($got) !== \count($want)) {
            return false;
        }
        foreach ($want as $name => $w) {
            if (!\array_key_exists($name, $got) || !self::isFieldValue($w) || $got[$name] !== $w) {
                return false;
            }
        }

        return true;
    }

    /**
     * ts_payload_sha256 of an entry: SHA-256 over its canonical form (RFC 8785 for string, integer and boolean values,
     * spec/approval-token.md section 6), base64url without padding.
     *
     * @param array<array-key, string|int|bool> $entry
     */
    public static function payloadDigest(array $entry): string
    {
        return Strict::encodeSegment(hash('sha256', self::canonical($entry), true));
    }

    /**
     * Members sorted by name (byte order of UTF-8, which is code point order), no whitespace, strings with only the
     * escapes of RFC 8785, integers in plain decimal, true and false.
     *
     * @param array<array-key, string|int|bool> $entry
     */
    public static function canonical(array $entry): string
    {
        uksort($entry, static fn (int|string $a, int|string $b): int => strcmp((string) $a, (string) $b));
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS
            | JSON_THROW_ON_ERROR;
        $parts = [];
        foreach ($entry as $name => $value) {
            $text = match (true) {
                \is_string($value) => json_encode($value, $flags),
                \is_bool($value) => $value ? 'true' : 'false',
                default => (string) $value,
            };
            $parts[] = json_encode((string) $name, $flags) . ':' . $text;
        }

        return '{' . implode(',', $parts) . '}';
    }
}
