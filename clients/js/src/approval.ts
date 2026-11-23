// Approval confirmations (spec/approval-token.md): the proof an application receives after a person confirmed one of
// its sensitive actions in TinySesam with a fresh step-up.

import { ConfigError, GateError } from './errors.ts';
import { checkJwksUrl } from './gate.ts';
import { type FetchFunction, httpFetcher, JwksCache, type KeySource, StaticKeys } from './jwks.ts';
import type { KeySet } from './keys.ts';
import { encodeSegment, hasControl, isObject, own, parseStrictJson } from './strict.ts';
import { intClaim, parseToken } from './token.ts';

/** The `typ` of a confirmation — never `tinysesam-gate+jwt`. */
export const APPROVAL_TOKEN_TYPE = 'tinysesam-approval+jwt';
/** The longest lifetime `exp - nbf` of a confirmation, in seconds. */
export const MAX_APPROVAL_LIFETIME = 300;
/** The largest clock leeway an application may allow, in seconds. */
export const MAX_APPROVAL_LEEWAY = 30;

const MAX_TEXT = 128;
const MAX_SUB = 1000;
const MAX_AMR = 32;
const MAX_TYPE = 100;
const REQUIRED = [
  'iss',
  'aud',
  'sub',
  'iat',
  'nbf',
  'exp',
  'jti',
  'auth_time',
  'amr',
  'act',
  'authorization_details',
  'ts_payload_sha256',
] as const;

/** A field value of an action: a string, a boolean or a safe integer. */
export type FieldValue = string | number | boolean;

/**
 * The `jti` store of spec/approval-token.md section 7: writes the id atomically (one INSERT into a table with a unique
 * key, shared by every process of the application) and answers true only the first time. It may forget the entry
 * after `until` (Unix seconds). A thrown error refuses the confirmation (`internal`).
 */
export type JtiStore = (jti: string, until: number) => boolean | Promise<boolean>;

/** The configuration; issuer and appId come from configuration, never from the request. */
export interface ApprovalConfig {
  /** TinySesam's base_url without a trailing slash, exactly. */
  readonly issuer: string;
  /** The application's own id (`apps.<id>` in TinySesam's configuration). */
  readonly appId: string;
  /** A fixed approval key set (`parseJwks` of `/auth/approvals/jwks.json`). */
  readonly keys?: KeySet;
  /**
   * The approval key set to fetch, normally `https://<auth host>/auth/approvals/jwks.json` — never the gate key set,
   * a path ending in `/gate/jwks.json` is refused. Exactly one of keys and jwksUrl.
   */
  readonly jwksUrl?: string;
  /** The fetch function for the key set (optional; the global fetch by default). Only with jwksUrl. */
  readonly fetch?: FetchFunction;
  /** Clock leeway in seconds, 0 (the default) to 30. */
  readonly leewaySeconds?: number;
  /** The clock in Unix seconds (tests); the system clock by default. */
  readonly now?: () => number;
}

/** The action the application stored when it asked — never taken from the confirmation. */
export interface ApprovalExpect {
  /** The action type (`authorization_details[0].type`). */
  readonly type: string;
  /** The fields exactly as sent: names, JSON types and values (`1`, `"1"` and `true` are three different values). */
  readonly fields: Readonly<Record<string, FieldValue>>;
  /** The account the application acts for (a decimal id as a string). */
  readonly sub: string;
  /** The state kept in the person's session (browser entry); undefined when the application sent none. */
  readonly nonce?: string;
}

/** The claims of a valid confirmation. `raw` holds every claim as decoded, unknown ones included. */
export interface ApprovalClaims {
  readonly iss: string;
  readonly aud: string;
  readonly sub: string;
  readonly iat: number;
  readonly nbf: number;
  readonly exp: number;
  readonly authTime: number;
  readonly jti: string;
  readonly amr: readonly string[];
  /** `act.sub`: `app:<application id>`. */
  readonly actor: string;
  readonly type: string;
  readonly fields: Readonly<Record<string, FieldValue>>;
  readonly nonce: string | undefined;
  readonly raw: Readonly<Record<string, unknown>>;
}

const KEYS = new Set(['issuer', 'appId', 'keys', 'jwksUrl', 'fetch', 'leewaySeconds', 'now']);

/** A non-empty string of at most `limit` code points without a C0 control character or DEL. */
function isText(v: unknown, limit: number): v is string {
  return typeof v === 'string' && v !== '' && [...v].length <= limit && !hasControl(v);
}

function isFieldValue(v: unknown): v is FieldValue {
  return typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isSafeInteger(v));
}

function codePointCompare(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = (x[i]?.codePointAt(0) ?? 0) - (y[i]?.codePointAt(0) ?? 0);
    if (d !== 0) {
      return d;
    }
  }
  return x.length - y.length;
}

function canonicalString(s: string): string {
  let out = '"';
  for (const c of s) {
    const code = c.codePointAt(0) ?? 0;
    if (c === '"') out += '\\"';
    else if (c === '\\') out += '\\\\';
    else if (c === '\b') out += '\\b';
    else if (c === '\t') out += '\\t';
    else if (c === '\n') out += '\\n';
    else if (c === '\f') out += '\\f';
    else if (c === '\r') out += '\\r';
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += c;
  }
  return `${out}"`;
}

/**
 * The canonical form of an entry (RFC 8785 for string, integer and boolean values, spec/approval-token.md section 6):
 * members sorted by name in code point order, no whitespace, only the escapes of RFC 8785.
 */
export function canonicalEntry(entry: Readonly<Record<string, unknown>>): string {
  const names = Object.keys(entry).sort(codePointCompare);
  return `{${names.map((n) => `${canonicalString(n)}:${valueText(own(entry as Record<string, unknown>, n))}`).join(',')}}`;
}

function valueText(v: unknown): string {
  if (typeof v === 'string') {
    return canonicalString(v);
  }
  return String(v);
}

/** `ts_payload_sha256` of an entry: SHA-256 over its canonical form, base64url without padding. */
export async function payloadDigest(entry: Readonly<Record<string, unknown>>): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalEntry(entry)));
  return encodeSegment(new Uint8Array(digest));
}

/** Names, JSON types and values exactly. */
function sameFields(got: Record<string, FieldValue>, want: Readonly<Record<string, FieldValue>>): boolean {
  const names = Object.keys(want);
  if (names.length !== Object.keys(got).length) {
    return false;
  }
  return names.every((n) => {
    if (!Object.hasOwn(got, n)) {
      return false;
    }
    const g = got[n];
    const w = want[n];
    return isFieldValue(w) && typeof g === typeof w && g === w;
  });
}

/** Checks approval confirmations (spec/approval-token.md section 4). Build it with {@link createApprovalVerifier}. */
export class ApprovalVerifier {
  readonly #issuer: string;
  readonly #appId: string;
  readonly #leeway: number;
  readonly #keys: KeySource;
  readonly #now: () => number;

  /** @internal Use {@link createApprovalVerifier}. */
  constructor(issuer: string, appId: string, leeway: number, keys: KeySource, now: () => number) {
    this.#issuer = issuer;
    this.#appId = appId;
    this.#leeway = leeway;
    this.#keys = keys;
    this.#now = now;
  }

  /**
   * Checks a confirmation in the order of spec/approval-token.md section 4 and, as the last step, writes its `jti`
   * into `store`. Throws a {@link GateError} whose class is the first failing step; every class means: do not carry
   * the action out. Log the class, never the token. Afterwards run the application's own rules again, then act.
   */
  async verify(token: string, expect: ApprovalExpect, store: JtiStore): Promise<ApprovalClaims> {
    if (typeof store !== 'function') {
      throw new GateError('internal', 'no jti store');
    }
    const now = this.#now();
    const parsed = parseToken(token, APPROVAL_TOKEN_TYPE);
    const key = await this.#keys.lookup(parsed.kid);
    const valid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      parsed.signature as Uint8Array<ArrayBuffer>,
      parsed.signingInput as Uint8Array<ArrayBuffer>,
    );
    if (!valid) {
      throw new GateError('signature', 'verification failed', parsed.kid);
    }
    const payload = parseStrictJson(parsed.payload);
    if (payload === null || !isObject(payload.value)) {
      throw new GateError('malformed', 'payload is not a strict JSON object', parsed.kid);
    }
    try {
      const c = await claimsOf(payload.value, payload.numbers, payload.fractional);
      this.#values(c, now);
      if (c.type !== expect.type) {
        throw new GateError('approval_type');
      }
      if (!isObject(expect.fields) || !sameFields(c.fields as Record<string, FieldValue>, expect.fields)) {
        throw new GateError('approval_fields');
      }
      if (c.sub !== expect.sub) {
        throw new GateError('subject');
      }
      if (expect.nonce !== undefined && c.nonce !== expect.nonce) {
        throw new GateError('nonce');
      }
      let first: boolean;
      try {
        first = (await store(c.jti, c.exp + this.#leeway)) === true;
      } catch {
        throw new GateError('internal', 'the jti store failed');
      }
      if (!first) {
        throw new GateError('replay');
      }
      return c;
    } catch (err) {
      throw err instanceof GateError ? new GateError(err.code, undefined, parsed.kid) : err;
    }
  }

  /** Step 10: issuer, the application's id, lifetime, not before, expiry. */
  #values(c: ApprovalClaims, now: number): void {
    if (c.iss !== this.#issuer) {
      throw new GateError('issuer');
    }
    if (c.aud !== this.#appId) {
      throw new GateError('audience');
    }
    if (c.exp <= c.nbf || c.exp - c.nbf > MAX_APPROVAL_LIFETIME) {
      throw new GateError('lifetime');
    }
    if (c.nbf > now + this.#leeway) {
      throw new GateError('not_yet_valid');
    }
    if (c.exp + this.#leeway <= now) {
      throw new GateError('expired');
    }
  }
}

/** Step 9: presence, types, aud as one string, exactly one entry, the digest, the order of the times. */
async function claimsOf(
  m: Record<string, unknown>,
  numbers: ReadonlyMap<string, string>,
  fractional: boolean,
): Promise<ApprovalClaims> {
  const bad = (detail: string): never => {
    throw new GateError('claims', detail);
  };
  for (const name of REQUIRED) {
    if (!Object.hasOwn(m, name)) {
      bad(`${name} missing`);
    }
  }
  const iss = own(m, 'iss');
  if (typeof iss !== 'string') bad('iss');
  const sub = own(m, 'sub');
  if (!isText(sub, MAX_SUB)) bad('sub');
  const [iat, nbf, exp, authTime] = (['iat', 'nbf', 'exp', 'auth_time'] as const).map((n) =>
    intClaim(own(m, n), numbers.get(n)),
  );
  if (iat == null || nbf == null || exp == null || authTime == null) {
    return bad('iat, nbf, exp or auth_time');
  }
  const jti = own(m, 'jti');
  if (!isText(jti, MAX_TEXT)) bad('jti');
  const amr = own(m, 'amr');
  if (!Array.isArray(amr) || amr.length === 0 || !amr.every((a) => isText(a, MAX_AMR))) bad('amr');
  const act = own(m, 'act');
  const actor = isObject(act) ? own(act, 'sub') : undefined;
  if (!isText(actor, MAX_TEXT)) bad('act');
  const digest = own(m, 'ts_payload_sha256');
  if (typeof digest !== 'string') bad('ts_payload_sha256');
  const nonce = own(m, 'nonce');
  if (Object.hasOwn(m, 'nonce') && !isText(nonce, MAX_TEXT)) bad('nonce');
  // aud is ONE string, the application's id — never an array, which could name several applications.
  const aud = own(m, 'aud');
  if (typeof aud !== 'string') bad('aud is not a string');
  const details = own(m, 'authorization_details');
  if (!Array.isArray(details) || details.length !== 1) {
    return bad('authorization_details is not one entry');
  }
  const entry: unknown = details[0];
  if (!isObject(entry)) {
    return bad('authorization_details[0]');
  }
  const type = own(entry, 'type');
  if (!isText(type, MAX_TYPE)) bad('authorization_details[0].type');
  // JSON.parse reads 1.0 as 1: a fraction or an exponent anywhere in the payload refuses it (TinySesam writes none).
  if (fractional || !Object.values(entry).every(isFieldValue)) bad('a field value of an unsupported type');
  if (digest !== (await payloadDigest(entry))) bad('ts_payload_sha256 does not match the entry');
  if (iat > nbf || authTime > iat) bad('iat, nbf and auth_time out of order');
  const fields: Record<string, FieldValue> = {};
  for (const [k, v] of Object.entries(entry)) {
    if (k !== 'type') {
      Object.defineProperty(fields, k, { value: v, enumerable: true });
    }
  }
  return Object.freeze({
    iss: iss as string,
    aud: aud as string,
    sub: sub as string,
    iat,
    nbf,
    exp,
    authTime,
    jti: jti as string,
    amr: Object.freeze([...(amr as string[])]),
    actor: actor as string,
    type: type as string,
    fields: Object.freeze(fields),
    nonce: typeof nonce === 'string' ? nonce : undefined,
    raw: m,
  });
}

/** Checks the configuration and builds the verifier; a ConfigError here must stop the start. */
export function createApprovalVerifier(config: ApprovalConfig): ApprovalVerifier {
  for (const key of Object.keys(config)) {
    if (!KEYS.has(key)) {
      throw new ConfigError(`"${key}" is not a setting of the approval check`);
    }
  }
  const { issuer, appId } = config;
  if (typeof issuer !== 'string' || issuer === '' || typeof appId !== 'string' || appId === '') {
    throw new ConfigError('approvals need issuer and appId');
  }
  const leeway = config.leewaySeconds ?? 0;
  if (!Number.isInteger(leeway) || leeway < 0 || leeway > MAX_APPROVAL_LEEWAY) {
    throw new ConfigError(`leewaySeconds must be an integer from 0 to ${MAX_APPROVAL_LEEWAY} for approvals`);
  }
  let keys: KeySource;
  if (config.keys !== undefined && config.jwksUrl !== undefined) {
    throw new ConfigError('give either keys or jwksUrl, not both');
  } else if (config.keys !== undefined) {
    if (config.fetch !== undefined) {
      throw new ConfigError('fetch without jwksUrl');
    }
    if (config.keys.kids.length === 0) {
      throw new ConfigError('the approval key set has no usable key');
    }
    keys = new StaticKeys(config.keys);
  } else if (typeof config.jwksUrl === 'string') {
    checkJwksUrl(config.jwksUrl);
    if (new URL(config.jwksUrl).pathname.replace(/\/+$/, '').endsWith('/gate/jwks.json')) {
      throw new ConfigError(
        'jwksUrl is the GATE key set; confirmations have their own (https://<auth host>/auth/approvals/jwks.json)',
      );
    }
    if (config.fetch !== undefined && typeof config.fetch !== 'function') {
      throw new ConfigError('fetch must be a function');
    }
    keys = new JwksCache(httpFetcher(config.jwksUrl, config.fetch));
  } else {
    throw new ConfigError('approvals need keys or jwksUrl');
  }
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  return new ApprovalVerifier(issuer, appId, leeway, keys, now);
}
