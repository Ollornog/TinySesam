// Tokens minted with the public test key A of spec/vectors/keys.json, each with exactly ONE defect in a correctly
// signed payload. A vector that combines two defects lets a client pass that checks only one of them
// (`attack-payload-invalid-utf8` also repeats `ts_name`); these isolate every rule of spec section 4.4 step 8 and 9.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createGate } from '../src/gate.ts';
import { DEFAULTS, kidOf, mintRaw, outcome, publicJwk, signKey, tokenGate } from './helpers.ts';

const enc = new TextEncoder();
const HEADER = enc.encode(`{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"${kidOf('A')}"}`);

function concat(...parts: (Uint8Array | string)[]): Uint8Array {
  const bytes = parts.map((p) => (typeof p === 'string' ? enc.encode(p) : p));
  const out = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
  let i = 0;
  for (const b of bytes) {
    out.set(b, i);
    i += b.length;
  }
  return out;
}

/** The payload of a valid session token with the raw bytes of ts_name spliced in, and an optional tail. */
function payload(name: Uint8Array | string, tail = '', head = ''): Uint8Array {
  const { now } = DEFAULTS;
  return concat(
    head,
    `{"iss":"${DEFAULTS.issuer}","aud":"${DEFAULTS.audience}","sub":"1","iat":${now},"nbf":${now},"exp":${now + 300},`,
    `"ts_user":"anna","ts_name":"`,
    name,
    `","ts_auth":"session","ts_kind":"user"${tail}}`,
  );
}

/** Through a gate built by createGate: its clock is the wall clock. */
async function check(body: Uint8Array): Promise<string> {
  const gate = await createGate({
    mode: 'token',
    issuer: DEFAULTS.issuer,
    audience: DEFAULTS.audience,
    gateKeys: [signKey('A')],
  });
  return outcome(gate.verify(await mintRaw('A', HEADER, body)));
}

/** Through a gate whose clock stands at DEFAULTS.now. */
async function checkAtNow(body: Uint8Array): Promise<string> {
  const gate = await tokenGate({ keys: [publicJwk('A')] }, DEFAULTS.issuer, DEFAULTS.audience, 0, DEFAULTS.now);
  return outcome(gate.verify(await mintRaw('A', HEADER, body)));
}

test('the control token verifies', async () => {
  assert.equal(await checkAtNow(payload('Jürgen')), 'ok');
  // Through a gate on the wall clock the same token is long expired: the clock is read, not assumed.
  assert.equal(await check(payload('Jürgen')), 'expired');
});

test('invalid UTF-8 alone is malformed', async () => {
  for (const bad of [
    [0x4a, 0xfc, 0x72, 0x67, 0x65, 0x6e], // Latin-1 ü
    [0xff],
    [0xc0, 0xaf], // overlong /
    [0xed, 0xa0, 0x80], // an encoded surrogate
    [0x61, 0xe2, 0x82], // truncated
  ]) {
    assert.equal(await checkAtNow(payload(new Uint8Array(bad))), 'malformed', JSON.stringify(bad));
  }
});

test('a byte order mark alone is malformed', async () => {
  assert.equal(await checkAtNow(payload('Anna', '', '﻿')), 'malformed');
});

test('a repeated claim alone is malformed, also when spelled with an escape', async () => {
  assert.equal(await checkAtNow(payload('Anna', ',"ts_user":"admin"')), 'malformed');
  assert.equal(await checkAtNow(payload('Anna', ',"ts\\u005fuser":"admin"')), 'malformed');
});

test('NaN, Infinity and a lone surrogate escape are malformed', async () => {
  assert.equal(await checkAtNow(payload('Anna', ',"x":NaN')), 'malformed');
  assert.equal(await checkAtNow(payload('Anna', ',"x":Infinity')), 'malformed');
  assert.equal(await checkAtNow(payload('\\ud800')), 'malformed');
  assert.equal(await checkAtNow(payload('\\udc00x')), 'malformed');
  // A paired surrogate escape is an ordinary character.
  assert.equal(await checkAtNow(payload('\\ud83d\\ude00')), 'ok');
});

test('integer claims: fraction, exponent, sign and range are refused exactly', async () => {
  const { now } = DEFAULTS;
  const withExp = (exp: string) =>
    concat(
      `{"iss":"${DEFAULTS.issuer}","aud":"${DEFAULTS.audience}","sub":"1","iat":${now},"nbf":${now},"exp":${exp},"ts_kind":"user"}`,
    );
  assert.equal(await checkAtNow(withExp(String(now + 300))), 'ok');
  assert.equal(await checkAtNow(withExp(`${now + 300}.0`)), 'claims');
  assert.equal(await checkAtNow(withExp(`${(now + 300) / 100}e2`)), 'claims');
  assert.equal(await checkAtNow(withExp('9007199254740992')), 'claims');
  assert.equal(await checkAtNow(withExp('-1')), 'claims');
  assert.equal(await checkAtNow(withExp(`"${now + 300}"`)), 'claims');
  assert.equal(await checkAtNow(withExp('true')), 'claims');
  // A nested member named like a claim does not stand in for it.
  assert.equal(
    await checkAtNow(
      concat(
        `{"iss":"${DEFAULTS.issuer}","aud":"${DEFAULTS.audience}","sub":"1","x":{"iat":1},"iat":${now}.0,"nbf":${now},"exp":${now + 300},"ts_kind":"user"}`,
      ),
    ),
    'claims',
  );
});

test('a control character in one identity claim alone is claims', async () => {
  for (const c of ['\\u0000', '\\t', '\\r\\n', '\\u007f', '\\u001f']) {
    assert.equal(await checkAtNow(payload(`boss${c}`)), 'claims', c);
  }
  // C1 controls and bidi overrides are characters, not refused (spec section 3.2).
  assert.equal(await checkAtNow(payload('\\u0085\\u202e')), 'ok');
});

test('ts_kind (spec v2): missing, of another type or case, unknown, or service with a session alone is claims', async () => {
  const { now } = DEFAULTS;
  const withKind = (kind: string, auth = '"session"') =>
    concat(
      `{"iss":"${DEFAULTS.issuer}","aud":"${DEFAULTS.audience}","sub":"1","iat":${now},"nbf":${now},"exp":${now + 300},"ts_auth":${auth}${kind}}`,
    );
  assert.equal(await checkAtNow(withKind(',"ts_kind":"user"')), 'ok');
  assert.equal(await checkAtNow(withKind(',"ts_kind":"service"', '"apikey"')), 'ok');
  for (const bad of [
    '',
    ',"ts_kind":""',
    ',"ts_kind":1',
    ',"ts_kind":"User"',
    ',"ts_kind":"admin"',
    ',"ts_kind":null',
  ]) {
    assert.equal(await checkAtNow(withKind(bad)), 'claims', bad);
  }
  assert.equal(await checkAtNow(withKind(',"ts_kind":"service"')), 'claims', 'service with a session');
});

test('a payload that is not an object is malformed', async () => {
  assert.equal(await checkAtNow(enc.encode('[1]')), 'malformed');
  assert.equal(await checkAtNow(enc.encode('"x"')), 'malformed');
  assert.equal(await checkAtNow(enc.encode('null')), 'malformed');
});

test('a header member __proto__ is a forbidden member, not the prototype', async () => {
  const gate = await tokenGate({ keys: [publicJwk('A')] }, DEFAULTS.issuer, DEFAULTS.audience, 0, DEFAULTS.now);
  const header = enc.encode(`{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"${kidOf('A')}","__proto__":{"x":1}}`);
  assert.equal(await outcome(gate.verify(await mintRaw('A', header, payload('Anna')))), 'header');
});

test('sub: empty or with a control character alone is claims (without ts_id, which would also catch it)', async () => {
  const { now } = DEFAULTS;
  const withSub = (sub: string) =>
    concat(
      `{"iss":"${DEFAULTS.issuer}","aud":"${DEFAULTS.audience}","sub":${sub},"iat":${now},"nbf":${now},"exp":${now + 300},"ts_kind":"user"}`,
    );
  assert.equal(await checkAtNow(withSub('"7"')), 'ok');
  assert.equal(await checkAtNow(withSub('""')), 'claims');
  assert.equal(await checkAtNow(withSub('"7\\u0000"')), 'claims');
  assert.equal(await checkAtNow(withSub('"7\\u007f"')), 'claims');
});

test('a short or long signature is signature before the key is looked up (step 5 before step 6)', async () => {
  const token = await mintRaw('A', HEADER, payload('Anna'));
  const [h, p] = token.split('.');
  // A kid that is not in the set: the length check must still come first.
  const foreign = await mintRaw(
    'X',
    enc.encode(`{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"${kidOf('X')}"}`),
    payload('Anna'),
  );
  const [fh, fp] = foreign.split('.');
  for (const sig of ['AAAAAAAAAAAAAA', `${'A'.repeat(86)}AAAA`]) {
    const gate = await tokenGate({ keys: [publicJwk('A')] }, DEFAULTS.issuer, DEFAULTS.audience, 0, DEFAULTS.now);
    assert.equal(await outcome(gate.verify(`${h}.${p}.${sig}`)), 'signature', `own kid, ${sig.length} chars`);
    assert.equal(await outcome(gate.verify(`${fh}.${fp}.${sig}`)), 'signature', `foreign kid, ${sig.length} chars`);
  }
});
