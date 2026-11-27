// Token mode: the checking order of spec section 4.4, step by step.

import { GateError } from './errors.ts';
import { accountKindProblem, Identity } from './identity.ts';
import { isValidKid } from './keys.ts';
import { asciiEqualFold, decodeSegment, hasControl, isObject, own, parseStrictJson } from './strict.ts';

/** A larger token is malformed (spec section 4.4, step 1). */
export const MAX_TOKEN_BYTES = 4096;
/** The largest configurable clock leeway in seconds. */
export const MAX_LEEWAY = 60;
/** The largest exp - nbf in seconds. */
export const MAX_LIFETIME = 3600;

const TOKEN_ALGORITHM = 'EdDSA';
const TOKEN_TYPE = 'tinysesam-gate+jwt';
const ALLOWED_HEADER_MEMBERS: ReadonlySet<string> = new Set(['alg', 'typ', 'kid']);
const IDENTITY_CLAIMS = [
  'ts_user',
  'ts_name',
  'ts_email',
  'ts_groups',
  'ts_id',
  'ts_auth',
  'ts_kind',
  'ts_perms',
] as const;
const SIGNATURE_BYTES = 64;
const MAX_SAFE = 2n ** 53n - 1n;
const INTEGER_TEXT = /^-?[0-9]+$/;

/**
 * The claims of a valid gate token. `raw` holds every claim as decoded; unknown claims are ignored by the checks but
 * kept there.
 */
export interface Claims {
  readonly iss: string;
  readonly aud: readonly string[];
  readonly sub: string;
  readonly iat: number;
  readonly nbf: number;
  readonly exp: number;
  readonly jti: string;
  readonly raw: Readonly<Record<string, unknown>>;
}

/** What steps 1-5 of the checking order decide before a key is chosen. */
export interface ParsedToken {
  readonly signingInput: Uint8Array;
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
  /** The kid, format-checked (16 lowercase hex digits): safe to log. */
  readonly kid: string;
}

/** The values the claims are checked against; all come from configuration, never from the request. */
export interface TokenRules {
  readonly issuer: string;
  readonly audience: string;
  readonly leeway: number;
}

const encoder = new TextEncoder();

/**
 * Steps 1-5 of spec section 4.4: size, structure, header JSON, header members, signature length. `typ` is the gate
 * token's by default; the approval confirmation (spec/approval-token.md section 4) runs the same steps with its own.
 */
export function parseToken(jws: string, typ: string = TOKEN_TYPE): ParsedToken {
  if (typeof jws !== 'string' || jws.length > MAX_TOKEN_BYTES || encoder.encode(jws).length > MAX_TOKEN_BYTES) {
    throw new GateError('malformed', 'token too large');
  }
  const parts = jws.split('.');
  if (parts.length !== 3 || parts[0] === '' || parts[1] === '') {
    throw new GateError('malformed', 'not three segments');
  }
  const [h = '', p = '', s = ''] = parts;
  const head = decodeSegment(h);
  const payload = decodeSegment(p);
  const signature = decodeSegment(s);
  if (head === null || payload === null || signature === null) {
    throw new GateError('malformed', 'not strict base64url');
  }
  const parsed = parseStrictJson(head);
  if (parsed === null) {
    throw new GateError('malformed', 'header is not strict JSON');
  }
  const header = parsed.value;
  if (!isObject(header)) {
    throw new GateError('malformed', 'header is not a JSON object');
  }
  for (const name of Object.keys(header)) {
    if (!ALLOWED_HEADER_MEMBERS.has(name)) {
      throw new GateError('header', 'forbidden header member');
    }
  }
  // The algorithm is this client's constant; the header may only confirm it.
  if (own(header, 'alg') !== TOKEN_ALGORITHM) {
    throw new GateError('header', 'alg is not EdDSA');
  }
  const gotTyp = own(header, 'typ');
  if (typeof gotTyp !== 'string' || !asciiEqualFold(gotTyp, typ)) {
    throw new GateError('header', 'wrong typ');
  }
  const kid = own(header, 'kid');
  if (typeof kid !== 'string' || !isValidKid(kid)) {
    throw new GateError('kid', 'kid missing or not 16 lowercase hex digits');
  }
  if (signature.length !== SIGNATURE_BYTES) {
    throw new GateError('signature', 'signature is not 64 bytes', kid);
  }
  return { signingInput: encoder.encode(`${h}.${p}`), payload, signature, kid };
}

/** Steps 7-10: the signature, then (only then) the payload, its claims and their values. */
export async function finishToken(token: ParsedToken, key: CryptoKey, rules: TokenRules, now: number): Promise<Claims> {
  const valid = await crypto.subtle.verify(
    { name: 'Ed25519' },
    key,
    token.signature as Uint8Array<ArrayBuffer>,
    token.signingInput as Uint8Array<ArrayBuffer>,
  );
  if (!valid) {
    throw new GateError('signature', 'verification failed', token.kid);
  }
  const parsed = parseStrictJson(token.payload);
  if (parsed === null) {
    throw new GateError('malformed', 'payload is not strict JSON', token.kid);
  }
  if (!isObject(parsed.value)) {
    throw new GateError('malformed', 'payload is not a JSON object', token.kid);
  }
  try {
    return checkClaims(parsed.value, parsed.numbers, rules, now);
  } catch (err) {
    throw err instanceof GateError ? new GateError(err.code, undefined, token.kid) : err;
  }
}

/** An integer claim: a JSON number without fraction or exponent from 0 to 2^53 - 1; not a boolean, not a string. */
export function intClaim(value: unknown, text: string | undefined): number | null {
  if (typeof value !== 'number' || text === undefined || !INTEGER_TEXT.test(text)) {
    return null;
  }
  const n = BigInt(text);
  return n >= 0n && n <= MAX_SAFE ? Number(n) : null;
}

function checkClaims(
  m: Record<string, unknown>,
  numbers: ReadonlyMap<string, string>,
  rules: TokenRules,
  now: number,
): Claims {
  const bad = (detail: string): never => {
    throw new GateError('claims', detail);
  };
  const iss = own(m, 'iss');
  if (typeof iss !== 'string') {
    bad('iss');
  }
  const sub = own(m, 'sub');
  if (typeof sub !== 'string') {
    bad('sub');
  }
  const audValue = own(m, 'aud');
  let aud: string[] = [];
  if (typeof audValue === 'string') {
    aud = [audValue];
  } else if (Array.isArray(audValue) && audValue.length > 0 && audValue.every((a) => typeof a === 'string')) {
    aud = audValue as string[];
  } else {
    bad('aud');
  }
  const iat = intClaim(own(m, 'iat'), numbers.get('iat'));
  const nbf = intClaim(own(m, 'nbf'), numbers.get('nbf'));
  const exp = intClaim(own(m, 'exp'), numbers.get('exp'));
  if (iat === null || nbf === null || exp === null) {
    return bad('iat, nbf or exp');
  }
  let jti = '';
  if (Object.hasOwn(m, 'jti')) {
    const v = own(m, 'jti');
    if (typeof v !== 'string') {
      bad('jti');
    }
    jti = v as string;
  }
  for (const name of IDENTITY_CLAIMS) {
    if (Object.hasOwn(m, name)) {
      const v = own(m, name);
      if (typeof v !== 'string') {
        bad('identity claim type');
      }
      if (hasControl(v as string)) {
        bad('control character in an identity claim');
      }
    }
  }
  const subject = sub as string;
  if (subject === '' || hasControl(subject)) {
    bad('sub');
  }
  if (Object.hasOwn(m, 'ts_id') && own(m, 'ts_id') !== subject) {
    bad('ts_id differs from sub');
  }
  if (iat > nbf) {
    bad('iat later than nbf');
  }
  // Spec v2: ts_kind present and exactly user or service, never service with a session (its type was checked above).
  const kindProblem = accountKindProblem(own(m, 'ts_kind'), own(m, 'ts_auth'));
  if (kindProblem !== null) {
    bad(kindProblem);
  }
  if (iss !== rules.issuer) {
    throw new GateError('issuer');
  }
  if (!aud.includes(rules.audience)) {
    throw new GateError('audience');
  }
  if (exp <= nbf || exp - nbf > MAX_LIFETIME) {
    throw new GateError('lifetime');
  }
  if (nbf > now + rules.leeway) {
    throw new GateError('not_yet_valid');
  }
  if (exp + rules.leeway <= now) {
    throw new GateError('expired');
  }
  return Object.freeze({
    iss: iss as string,
    aud: Object.freeze([...aud]),
    sub: subject,
    iat,
    nbf,
    exp,
    jti,
    raw: m,
  });
}

/**
 * Maps the claims of a valid token to the identity (spec section 4.1); a missing claim gives an empty value — except
 * ts_kind, which checkClaims has required (the Identity constructor refuses an invalid one again).
 */
export function identityFromClaims(c: Claims): Identity {
  const str = (name: string): string => {
    const v = own(c.raw as Record<string, unknown>, name);
    return typeof v === 'string' ? v : '';
  };
  return new Identity({
    user: str('ts_user'),
    name: str('ts_name'),
    email: str('ts_email'),
    groups: str('ts_groups'),
    id: c.sub,
    auth: str('ts_auth'),
    accountKind: str('ts_kind'),
    permissions: str('ts_perms'),
  });
}
