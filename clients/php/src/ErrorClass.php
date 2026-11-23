<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * Why a request was refused. The classes of the specification (spec/gate-client.md, sections 2.4, 4.3 and 4.5) exist
 * for logs and tests; to the application every one of them means the same: not authenticated.
 */
enum ErrorClass: string
{
    /** Header mode: no or empty Remote-User; token mode: no token in the configured source. */
    case Unauthenticated = 'unauthenticated';
    /** A malformed Remote-* header, or a forbidden JWS header member, a wrong alg or typ. */
    case Header = 'header';
    /** Size, structure, base64url, JSON, more than one gate cookie. */
    case Malformed = 'malformed';
    /** The kid is missing, malformed or not in the key set. */
    case Kid = 'kid';
    /** Wrong length or verification failed. */
    case Signature = 'signature';
    /** No key set could be obtained. */
    case KeyUnavailable = 'key_unavailable';
    /** Wrong claim type, control character, inconsistency, a missing or malformed ts_kind. */
    case Claims = 'claims';
    /** Wrong iss. */
    case Issuer = 'issuer';
    /** Wrong aud. */
    case Audience = 'audience';
    /** exp - nbf not in (0, 3600]. */
    case Lifetime = 'lifetime';
    /** Before nbf - leeway. */
    case NotYetValid = 'not_yet_valid';
    /** At or after exp + leeway. */
    case Expired = 'expired';
    /** A key set document of the wrong shape. */
    case JwksInvalid = 'jwks_invalid';
    /** Approval check (spec/approval-token.md section 5): another action — do not carry it out. */
    case ApprovalType = 'approval_type';
    /** Approval check: other fields (a name, a JSON type or a value). */
    case ApprovalFields = 'approval_fields';
    /** Approval check: another account. */
    case Subject = 'subject';
    /** Approval check: another browser session (browser entry). */
    case Nonce = 'nonce';
    /** Approval check: the confirmation was used before. */
    case Replay = 'replay';
    /** Beyond the specification — header mode: the request did not come from a trusted proxy. */
    case UntrustedPeer = 'untrusted_peer';
    /** Beyond the specification — an unexpected failure inside the client (fails closed). */
    case Internal = 'internal';
}
