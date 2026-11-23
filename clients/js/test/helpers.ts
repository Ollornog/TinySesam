// Shared helpers of the test suites: the vectors (read from this repository, never a copy), the test keys and a
// minter for tokens with exactly one defect.

import { readdirSync, readFileSync } from 'node:fs';
import { errorClassOf } from '../src/errors.ts';
import { Gate } from '../src/gate.ts';
import { StaticKeys } from '../src/jwks.ts';
import { parseJwks } from '../src/keys.ts';
import { encodeSegment } from '../src/strict.ts';

/** spec/vectors/ relative to this file: clients/js/test -> the repository root. */
export const VECTOR_DIR = new URL('../../../spec/vectors/', import.meta.url);

// biome-ignore lint/suspicious/noExplicitAny: vector documents are free-form JSON, checked field by field
export type Json = any;

export function vectorFiles(): string[] {
  return readdirSync(VECTOR_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort();
}

export function loadVectors(name: string): Json {
  const doc = JSON.parse(readFileSync(new URL(name, VECTOR_DIR), 'utf8'));
  // Spec version 2 (Remote-Kind, ts_kind, menu_links), approval version 1 (spec/approval-token.md): vectors of another
  // version must not pass unseen.
  if (doc.format !== (name === 'approval.json' ? 1 : 2)) {
    throw new Error(`${name}: unknown vector format ${doc.format}`);
  }
  return doc;
}

/** A token-mode gate with a fixed key set and a fixed clock, as the token vectors describe. */
export async function tokenGate(
  jwks: Json,
  issuer: string,
  audience: string,
  leeway: number,
  now: number,
): Promise<Gate> {
  const keys = new StaticKeys(await parseJwks(JSON.stringify(jwks)));
  return new Gate({ mode: 'token', rules: { issuer, audience, leeway }, keys, now: () => now });
}

/** The class of a rejected promise, or 'ok'. */
export async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (err) {
    return errorClassOf(err);
  }
}

/** A string of octets (one code point U+0000-U+00FF per byte) from bytes. */
export function latin1(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}

const keysDoc = loadVectors('keys.json');
export const DEFAULTS: { issuer: string; audience: string; now: number } = keysDoc.defaults;

/** The public key of a test key in the gate-key form (standard Base64). */
export function signKey(name: 'A' | 'B' | 'X'): string {
  return keysDoc.keys[name].sign_key_base64;
}

/** The kid of a test key. */
export function kidOf(name: 'A' | 'B' | 'X'): string {
  return keysDoc.keys[name].public_jwk.kid;
}

/** The public JWK of a test key. */
export function publicJwk(name: 'A' | 'B' | 'X'): Json {
  return keysDoc.keys[name].public_jwk;
}

/** The private test key (public test material of spec/vectors/keys.json). */
export async function privateKey(name: 'A' | 'B' | 'X'): Promise<CryptoKey> {
  const k = keysDoc.keys[name];
  return crypto.subtle.importKey('jwk', { ...k.public_jwk, d: k.d, key_ops: ['sign'] }, { name: 'Ed25519' }, false, [
    'sign',
  ]);
}

const enc = new TextEncoder();

/** A correctly signed token over the raw header and payload bytes. */
export async function mintRaw(name: 'A' | 'B' | 'X', header: Uint8Array, payload: Uint8Array): Promise<string> {
  const input = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, await privateKey(name), enc.encode(input)));
  return `${input}.${encodeSegment(sig)}`;
}

/** A correctly signed gate token with the standard header and the given claims. */
export async function mint(name: 'A' | 'B' | 'X', claims: Record<string, unknown>): Promise<string> {
  const header = { alg: 'EdDSA', typ: 'tinysesam-gate+jwt', kid: kidOf(name) };
  return mintRaw(name, enc.encode(JSON.stringify(header)), enc.encode(JSON.stringify(claims)));
}

/** The claims of a session token at DEFAULTS.now. */
export function sessionClaims(groups = 'editors', now = DEFAULTS.now): Record<string, unknown> {
  return {
    iss: DEFAULTS.issuer,
    aud: DEFAULTS.audience,
    sub: '1',
    iat: now,
    nbf: now,
    exp: now + 300,
    jti: 'test',
    ts_user: 'anna',
    ts_name: 'Anna Berg',
    ts_email: 'anna@example.com',
    ts_groups: groups,
    ts_id: '1',
    ts_auth: 'session',
    ts_kind: 'user',
  };
}
