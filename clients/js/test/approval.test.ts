// The approval check and the account overview beyond the vectors: configuration errors, the jti store, the key set
// fetched from TinySesam, the server-side account fetch.

import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { fetchAccount, signedOutAccount } from '../src/account.ts';
import { canonicalEntry, createApprovalVerifier, type JtiStore, payloadDigest } from '../src/approval.ts';
import { ConfigError, errorClassOf } from '../src/errors.ts';
import { parseJwks } from '../src/keys.ts';
import { type Json, loadVectors } from './helpers.ts';

function vector(id: string): Json {
  const v = loadVectors('approval.json').vectors.find((x: Json) => x.id === id);
  assert.ok(v, id);
  return v.input;
}

async function serve(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const always: JtiStore = () => true;

test('approval: configuration errors stop the start', async () => {
  const keys = await parseJwks(JSON.stringify(vector('valid-basic').jwks));
  const empty = await parseJwks('{"keys":[]}');
  const good = { issuer: 'https://auth.example.com', appId: 'example' };
  createApprovalVerifier({ ...good, keys });
  createApprovalVerifier({ ...good, jwksUrl: 'https://auth.example.com/auth/approvals/jwks.json', leewaySeconds: 30 });
  const bad: Json[] = [
    { appId: 'example', keys },
    { issuer: 'https://auth.example.com', keys },
    { ...good },
    { ...good, keys: empty },
    { ...good, keys, jwksUrl: 'https://auth.example.com/auth/approvals/jwks.json' },
    { ...good, keys, leewaySeconds: 31 },
    { ...good, keys, leewaySeconds: -1 },
    { ...good, keys, leewaySeconds: 1.5 },
    { ...good, keys, fetch: globalThis.fetch },
    { ...good, jwksUrl: 'https://auth.example.com/auth/gate/jwks.json' },
    { ...good, jwksUrl: 'https://auth.example.com/auth/gate/jwks.json/' },
    { ...good, jwksUrl: 'http://auth.example.com/auth/approvals/jwks.json' },
    { ...good, keys, audience: 'example' },
  ];
  for (const config of bad) {
    assert.throws(() => createApprovalVerifier(config), ConfigError, JSON.stringify(Object.keys(config)));
  }
});

test('approval: one store, the second use is a replay; a failing store refuses; another subject spends nothing', async () => {
  const input = vector('valid-basic');
  const verifier = createApprovalVerifier({
    issuer: input.issuer,
    appId: input.app_id,
    keys: await parseJwks(JSON.stringify(input.jwks)),
    now: () => input.now,
  });
  const seen = new Map<string, number>();
  const store: JtiStore = async (jti, until) => {
    if (seen.has(jti)) {
      return false;
    }
    seen.set(jti, until);
    return true;
  };
  const c = await verifier.verify(input.jws, input.expect, store);
  assert.equal(seen.get(c.jti), c.exp);
  assert.equal(c.actor, 'app:example');
  assert.equal(c.type, 'example.collection.delete_permanently');
  assert.deepEqual({ ...c.fields }, input.expect.fields);
  await assert.rejects(verifier.verify(input.jws, input.expect, store), (e) => errorClassOf(e) === 'replay');
  const failing: JtiStore = () => {
    throw new Error('database gone');
  };
  await assert.rejects(verifier.verify(input.jws, input.expect, failing), (e) => errorClassOf(e) === 'internal');
  const spent: string[] = [];
  const counting: JtiStore = (jti) => {
    spent.push(jti);
    return true;
  };
  await assert.rejects(
    verifier.verify(input.jws, { ...input.expect, sub: '1002' }, counting),
    (e) => errorClassOf(e) === 'subject',
  );
  assert.deepEqual(spent, []);
  for (const quota of ['-1', -1.5, true, null]) {
    const mixed = vector('valid-escapes-int-bool');
    const v = createApprovalVerifier({
      issuer: mixed.issuer,
      appId: mixed.app_id,
      keys: await parseJwks(JSON.stringify(mixed.jwks)),
      now: () => mixed.now,
    });
    const expect = { ...mixed.expect, fields: { ...mixed.expect.fields, quota } };
    await assert.rejects(v.verify(mixed.jws, expect, always), (e) => errorClassOf(e) === 'approval_fields');
  }
});

test('approval: the key set is fetched from TinySesam once, never for a malformed token', async () => {
  const input = vector('valid-basic');
  let hits = 0;
  const server = await serve((req, res) => {
    hits++;
    if (req.url !== '/auth/approvals/jwks.json') {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=300' });
    res.end(JSON.stringify(input.jwks));
  });
  try {
    const verifier = createApprovalVerifier({
      issuer: input.issuer,
      appId: input.app_id,
      jwksUrl: `${server.url}/auth/approvals/jwks.json`,
      now: () => input.now,
    });
    await verifier.verify(input.jws, input.expect, always);
    await verifier.verify(input.jws, input.expect, always);
    await assert.rejects(verifier.verify('a.b', input.expect, always), (e) => errorClassOf(e) === 'malformed');
    assert.equal(hits, 1);
    const missing = createApprovalVerifier({
      issuer: input.issuer,
      appId: input.app_id,
      jwksUrl: `${server.url}/auth/approvals/missing.json`,
      now: () => input.now,
    });
    await assert.rejects(missing.verify(input.jws, input.expect, always), (e) => errorClassOf(e) === 'key_unavailable');
  } finally {
    await server.close();
  }
});

test('approval: the canonical form sorts by code point and escapes only what RFC 8785 escapes', () => {
  assert.equal(
    canonicalEntry({ type: 't', b: true, a: -12, s: 'q"\\é\n\u0001', '\u{1F680}': 1, '\uFB01': 2 }),
    '{"a":-12,"b":true,"s":"q\\"\\\\é\\n\\u0001","type":"t","\uFB01":2,"\u{1F680}":1}',
  );
});

test('account: fetched server-side with only TinySesam cookies; anything but 200 is signed out', async () => {
  // The server's answer (input) and what the helper makes of it (expected): members it does not normalize are dropped.
  const signedIn = loadVectors('account.json').vectors[0];
  const full = signedIn.input.account;
  const normal = signedIn.expected.account;
  let cookie: string | undefined;
  const server = await serve((req, res) => {
    cookie = req.headers.cookie;
    const status = req.url === '/auth/account.json' ? 200 : Number(req.url?.slice(1));
    if (req.url === '/big') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(`{"signed_in":true,"pad":"${'x'.repeat(64 * 1024)}"}`);
      return;
    }
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(status === 200 ? full : { authenticated: false, signed_in: false }));
  });
  try {
    const account = await fetchAccount(`${server.url}/auth/account.json`, 'app=private; tinysesam_session=s');
    assert.deepEqual(account, normal);
    assert.equal(cookie, 'tinysesam_session=s');
    for (const path of ['/401', '/404', '/429', '/big']) {
      assert.deepEqual(await fetchAccount(`${server.url}${path}`, 'tinysesam_session=s'), signedOutAccount(), path);
    }
    assert.deepEqual(await fetchAccount('http://127.0.0.1:1/none', null), signedOutAccount());
  } finally {
    await server.close();
  }
});

test('approval: a field written as 1.0 is no integer, as in the other clients (JSON.parse alone reads it as 1)', async () => {
  const doc = loadVectors('approval.json');
  const input = vector('valid-basic');
  const p = doc.keys.P;
  const key = await crypto.subtle.importKey(
    'jwk',
    { ...p.public_jwk, d: p.d, key_ops: ['sign'] },
    { name: 'Ed25519' },
    false,
    ['sign'],
  );
  const b64 = (s: string): string => Buffer.from(s).toString('base64url');
  const claims = JSON.parse(Buffer.from(input.jws.split('.')[1], 'base64url').toString());
  const entry = { ...claims.authorization_details[0], count: 1 };
  claims.authorization_details = [entry];
  claims.ts_payload_sha256 = await payloadDigest(entry);
  const head = b64(JSON.stringify({ alg: 'EdDSA', typ: 'tinysesam-approval+jwt', kid: p.public_jwk.kid }));
  const sign = async (body: string): Promise<string> => {
    const signing = `${head}.${b64(body)}`;
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(signing));
    return `${signing}.${Buffer.from(sig).toString('base64url')}`;
  };
  const verifier = createApprovalVerifier({
    issuer: input.issuer,
    appId: input.app_id,
    keys: await parseJwks(JSON.stringify(input.jwks)),
    now: () => input.now,
  });
  const expect = { ...input.expect, fields: { ...input.expect.fields, count: 1 } };
  const plain = JSON.stringify(claims);
  await verifier.verify(await sign(plain), expect, always);
  const fraction = plain.replace('"count":1', '"count":1.0');
  assert.notEqual(fraction, plain);
  await assert.rejects(verifier.verify(await sign(fraction), expect, always), (e) => errorClassOf(e) === 'claims');
});
