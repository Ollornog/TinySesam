// Key sets (spec section 4.3): fixed gate keys from configuration or a JWKS document, reduced to kid -> Ed25519 key.

import { ConfigError, GateError } from './errors.ts';
import { decodeSegment, decodeStandardBase64, isObject, own, parseStrictJson, parseStrictJsonText } from './strict.ts';

/** The largest number of entries a key set document may have. */
export const MAX_JWKS_KEYS = 32;

const ED25519 = { name: 'Ed25519' } as const;
const KID_FORMAT = /^[0-9a-f]{16}$/;
const FORBIDDEN_JWK_MEMBERS = ['d', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'jku'];

/** Whether a kid has the format of spec section 4.1: 16 lowercase hexadecimal digits. */
export function isValidKid(kid: string): boolean {
  return KID_FORMAT.test(kid);
}

/** The kid of a public key: the first 16 hex digits of SHA-256 over its 32 raw bytes. */
export async function keyId(raw: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw as Uint8Array<ArrayBuffer>));
  let hex = '';
  for (const b of digest.subarray(0, 8)) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/** Imports 32 raw bytes as an Ed25519 public key for verification; null when the runtime or the bytes refuse. */
export async function importPublicKey(raw: Uint8Array): Promise<CryptoKey | null> {
  if (raw.length !== 32) {
    return null;
  }
  try {
    return await crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, ED25519, false, ['verify']);
  } catch {
    return null;
  }
}

/**
 * Maps kid to an Ed25519 public key. It comes from configuration (fixed keys or a JWKS URL), never from a token.
 */
export class KeySet {
  readonly #keys: ReadonlyMap<string, CryptoKey>;
  /** The kids in the order of the source. */
  readonly kids: readonly string[];

  constructor(entries: readonly (readonly [string, CryptoKey])[]) {
    this.#keys = new Map(entries);
    this.kids = Object.freeze(entries.map(([kid]) => kid));
  }

  /** The key of a kid, or undefined. */
  get(kid: string): CryptoKey | undefined {
    return this.#keys.get(kid);
  }

  /** The number of usable keys. */
  get size(): number {
    return this.#keys.size;
  }
}

/** Reads the output of `tinysesam gate-key`: 32 raw bytes in standard Base64 (the proxy's sign_key). */
export function parseGateKey(b64: string): Uint8Array | null {
  const raw = decodeStandardBase64(b64.trim());
  return raw !== null && raw.length === 32 ? raw : null;
}

/** Builds a key set from one or more gate keys (before and after a rotation); a bad key is a ConfigError. */
export async function staticKeySet(gateKeys: readonly string[]): Promise<KeySet> {
  if (gateKeys.length === 0) {
    throw new ConfigError('no gate key');
  }
  const entries: [string, CryptoKey][] = [];
  for (const b64 of gateKeys) {
    const raw = typeof b64 === 'string' ? parseGateKey(b64) : null;
    if (raw === null) {
      throw new ConfigError('a gate key must be 32 bytes in standard Base64 (the output of `tinysesam gate-key`)');
    }
    const key = await importPublicKey(raw);
    if (key === null) {
      throw new ConfigError('a gate key is no Ed25519 public key, or this runtime has no WebCrypto Ed25519');
    }
    const kid = await keyId(raw);
    if (!entries.some(([k]) => k === kid)) {
      entries.push([kid, key]);
    }
  }
  return new KeySet(entries);
}

/**
 * Reads a key set document (spec section 4.3). Unusable entries are skipped, two usable entries with the same kid make
 * that kid unusable; a document that is not strict JSON, not an object, has no keys array or more than
 * {@link MAX_JWKS_KEYS} entries is the error `jwks_invalid`. The result may be empty.
 */
export async function parseJwks(doc: Uint8Array | string): Promise<KeySet> {
  const parsed = typeof doc === 'string' ? parseStrictJsonText(doc) : parseStrictJson(doc);
  if (parsed === null) {
    throw new GateError('jwks_invalid', 'not strict JSON');
  }
  if (!isObject(parsed.value)) {
    throw new GateError('jwks_invalid', 'not an object');
  }
  const entries = own(parsed.value, 'keys');
  if (!Array.isArray(entries) || entries.length > MAX_JWKS_KEYS) {
    throw new GateError('jwks_invalid', 'no keys array or too many entries');
  }
  const usable: [string, CryptoKey][] = [];
  const count = new Map<string, number>();
  for (const e of entries) {
    const found = await jwkEntry(e);
    if (found !== null) {
      usable.push(found);
      count.set(found[0], (count.get(found[0]) ?? 0) + 1);
    }
  }
  return new KeySet(usable.filter(([kid]) => count.get(kid) === 1));
}

/** The kid and key of a usable JWKS entry, or null. */
async function jwkEntry(e: unknown): Promise<[string, CryptoKey] | null> {
  if (!isObject(e) || own(e, 'kty') !== 'OKP' || own(e, 'crv') !== 'Ed25519') {
    return null;
  }
  if (FORBIDDEN_JWK_MEMBERS.some((name) => Object.hasOwn(e, name))) {
    return null;
  }
  if (Object.hasOwn(e, 'alg') && own(e, 'alg') !== 'EdDSA') {
    return null;
  }
  if (Object.hasOwn(e, 'use') && own(e, 'use') !== 'sig') {
    return null;
  }
  if (Object.hasOwn(e, 'key_ops')) {
    const ops = own(e, 'key_ops');
    if (!Array.isArray(ops) || !ops.includes('verify')) {
      return null;
    }
  }
  const x = own(e, 'x');
  const kid = own(e, 'kid');
  if (typeof x !== 'string' || typeof kid !== 'string') {
    return null;
  }
  const raw = decodeSegment(x);
  if (raw === null || raw.length !== 32 || kid !== (await keyId(raw))) {
    return null;
  }
  const key = await importPublicKey(raw);
  return key === null ? null : [kid, key];
}
