/**
 * Why a request was refused. The classes of the specification (spec/gate-client.md, sections 2.4, 4.3 and 4.5) exist
 * for logs and tests; to the application every one of them means the same: not authenticated.
 */
export type ErrorClass =
  | 'unauthenticated' // header mode: no or empty Remote-User; token mode: no token in the configured source
  | 'header' // a malformed Remote-* header, or a forbidden JWS header member, a wrong alg or typ
  | 'malformed' // size, structure, base64url, JSON, more than one gate cookie
  | 'kid' // kid missing, malformed or not in the key set
  | 'signature' // wrong length or verification failed
  | 'key_unavailable' // no key set could be obtained
  | 'claims' // wrong claim type, control character, inconsistency
  | 'issuer' // wrong iss
  | 'audience' // wrong aud
  | 'lifetime' // exp - nbf not in (0, 3600]
  | 'not_yet_valid' // before nbf - leeway
  | 'expired' // at or after exp + leeway
  | 'jwks_invalid' // a key set document of the wrong shape
  // Classes of the approval check (spec/approval-token.md section 5): do not carry the action out.
  | 'approval_type' // another action
  | 'approval_fields' // other fields: a name, a JSON type or a value
  | 'subject' // another account
  | 'nonce' // another browser session (browser entry)
  | 'replay' // the confirmation was used before
  // Classes of this client beyond the specification:
  | 'untrusted_peer' // header mode: the request did not come from a trusted proxy
  | 'internal'; // an unexpected failure inside the client (fails closed)

/** Every class, in the order of the type above. */
export const ERROR_CLASSES: readonly ErrorClass[] = Object.freeze([
  'unauthenticated',
  'header',
  'malformed',
  'kid',
  'signature',
  'key_unavailable',
  'claims',
  'issuer',
  'audience',
  'lifetime',
  'not_yet_valid',
  'expired',
  'jwks_invalid',
  'approval_type',
  'approval_fields',
  'subject',
  'nonce',
  'replay',
  'untrusted_peer',
  'internal',
]);

/**
 * A refusal. It carries the class and, once the kid has passed the format check of spec section 4.4, the kid — never
 * the token, a claim value or a header value, so it is safe to log.
 */
export class GateError extends Error {
  /** The error class. */
  readonly code: ErrorClass;
  /** The format-checked kid of the token, if the check got that far. */
  readonly kid: string | undefined;

  constructor(code: ErrorClass, detail?: string, kid?: string) {
    super(detail ? `tinysesam: ${code}: ${detail}` : `tinysesam: ${code}`);
    this.name = 'GateError';
    this.code = code;
    this.kid = kid;
  }
}

/** A contradictory or incomplete configuration: thrown at start-up instead of failing open later (spec section 6). */
export class ConfigError extends Error {
  constructor(message: string) {
    super(`tinysesam: configuration: ${message}`);
    this.name = 'ConfigError';
  }
}

/** The class of an error, or `internal` for anything that did not come from this library. */
export function errorClassOf(err: unknown): ErrorClass {
  return err instanceof GateError ? err.code : 'internal';
}

/** Whether err is a refusal of this library, optionally of the given class. */
export function isGateError(err: unknown, code?: ErrorClass): err is GateError {
  return err instanceof GateError && (code === undefined || err.code === code);
}
