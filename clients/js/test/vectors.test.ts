// Every vector of spec/vectors/, read from this repository, checked exactly (clients/README.md).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Gate } from '../src/gate.ts';
import { identityFromHeaders } from '../src/identity.ts';
import { type FetchResult, JwksCache } from '../src/jwks.ts';
import { keyId, parseGateKey, parseJwks } from '../src/keys.ts';
import { parseTopbar } from '../src/topbar.ts';
import {
  type Json,
  kidOf,
  latin1,
  loadVectors,
  mint,
  outcome,
  privateKey,
  sessionClaims,
  signKey,
  tokenGate,
  vectorFiles,
} from './helpers.ts';

// Every file in spec/vectors/ must be run by one of these tests; a new file without a runner fails the suite.
const RUNNERS = ['headers.json', 'jwks.json', 'keys.json', 'token.json', 'topbar.json'];

test('every vector file has a runner', () => {
  assert.deepEqual(vectorFiles(), RUNNERS, 'add a runner for the new vector file');
});

/** Compares an identity (and has_role) with the expected value of a vector; returns the differences. */
function identityProblems(id: string, identity: Json, expected: Json): string[] {
  const problems: string[] = [];
  if (expected.identity !== undefined) {
    try {
      assert.deepStrictEqual(identity.toJSON(), expected.identity);
    } catch {
      problems.push(`${id}: identity ${JSON.stringify(identity)}, want ${JSON.stringify(expected.identity)}`);
    }
  }
  for (const [role, want] of Object.entries(expected.has_role ?? {})) {
    if (identity.hasRole(role) !== want) {
      problems.push(`${id}: hasRole(${JSON.stringify(role)}) = ${identity.hasRole(role)}, want ${want}`);
    }
  }
  return problems;
}

test('token vectors', async (t) => {
  const vectors: Json[] = loadVectors('token.json').vectors;
  assert.ok(vectors.length > 0, 'no token vectors');
  const problems: string[] = [];
  for (const v of vectors) {
    const { input, expected } = v;
    const gate = await tokenGate(input.jwks, input.issuer, input.audience, input.leeway, input.now);
    let result: Json;
    let got = 'ok';
    try {
      result = await gate.verify(input.jws);
    } catch (err) {
      got = (err as { code?: string }).code ?? 'not a GateError';
    }
    if (expected.ok !== true) {
      if (got !== expected.error) {
        problems.push(`${v.id}: ${got}, want ${expected.error}`);
      }
      continue;
    }
    if (got !== 'ok') {
      problems.push(`${v.id}: refused (${got}), want ok`);
      continue;
    }
    try {
      assert.deepStrictEqual({ ...result.claims.raw }, expected.claims);
    } catch {
      problems.push(`${v.id}: claims ${JSON.stringify(result.claims.raw)}, want ${JSON.stringify(expected.claims)}`);
    }
    problems.push(...identityProblems(v.id, result.identity, expected));
  }
  assert.deepEqual(problems, []);
  t.diagnostic(`${vectors.length} token vectors`);
});

/** The header pairs of a vector: each value converted to octets with Latin-1; a list means a repeated field. */
function headerPairs(headers: Record<string, string | string[]>): [string, string][] {
  const pairs: [string, string][] = [];
  for (const [name, value] of Object.entries(headers)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      pairs.push([name, item]);
    }
  }
  return pairs;
}

test('header vectors', async (t) => {
  const vectors: Json[] = loadVectors('headers.json').vectors;
  assert.ok(vectors.length > 0, 'no header vectors');
  const problems: string[] = [];
  const gate = new Gate({ mode: 'header' });
  for (const v of vectors) {
    const pairs = headerPairs(v.input.headers);
    for (const [how, run] of [
      ['identityFromHeaders', async () => identityFromHeaders(pairs)],
      ['Gate.identify', () => gate.identify({ headers: pairs })],
    ] as const) {
      let identity: Json;
      let got = 'ok';
      try {
        identity = await run();
      } catch (err) {
        got = (err as { code?: string }).code ?? 'not a GateError';
      }
      if (v.expected.ok !== true) {
        if (got !== v.expected.error) {
          problems.push(`${v.id} (${how}): ${got}, want ${v.expected.error}`);
        }
      } else if (got !== 'ok') {
        problems.push(`${v.id} (${how}): refused (${got}), want ok`);
      } else {
        problems.push(...identityProblems(`${v.id} (${how})`, identity, v.expected));
      }
    }
  }
  assert.deepEqual(problems, []);
  t.diagnostic(`${vectors.length} header vectors`);
});

test('key set vectors', async (t) => {
  const sets: Json[] = loadVectors('jwks.json').sets;
  assert.ok(sets.length > 0, 'no key set vectors');
  const problems: string[] = [];
  for (const v of sets) {
    let got: Json = 'ok';
    let kids: readonly string[] = [];
    try {
      kids = (await parseJwks(JSON.stringify(v.input.jwks))).kids;
    } catch (err) {
      got = (err as { code?: string }).code;
    }
    if (v.expected.ok !== true) {
      if (got !== v.expected.error) {
        problems.push(`${v.id}: ${got}, want ${v.expected.error}`);
      }
    } else if (got !== 'ok') {
      problems.push(`${v.id}: refused (${got})`);
    } else if (JSON.stringify(kids) !== JSON.stringify(v.expected.kids)) {
      problems.push(`${v.id}: kids ${JSON.stringify(kids)}, want ${JSON.stringify(v.expected.kids)}`);
    }
  }
  assert.deepEqual(problems, []);
  t.diagnostic(`${sets.length} key set vectors`);
});

/** The fetch answer of a scenario step as the cache sees it; an `error` answer is a failed fetch (a rejection). */
function fetchAnswer(answer: Json): Promise<FetchResult> {
  if (answer.error !== undefined) {
    return Promise.reject(new Error(answer.error));
  }
  const body = answer.body !== undefined ? JSON.stringify(answer.body) : (answer.body_text ?? '');
  return Promise.resolve({ status: answer.status, cacheControl: answer.cache_control ?? null, body });
}

test('cache scenario vectors', async (t) => {
  const doc = loadVectors('jwks.json');
  const scenarios: Json[] = doc.scenarios;
  assert.ok(scenarios.length > 0, 'no cache scenarios');
  const problems: string[] = [];
  let steps = 0;
  for (const sc of scenarios) {
    let now = 0;
    let answer: Json;
    let calls = 0;
    let unexpected = false;
    const cache = new JwksCache(
      () => {
        calls++;
        if (answer === undefined) {
          unexpected = true;
          return Promise.reject(new Error('no fetch in this step'));
        }
        return fetchAnswer(answer);
      },
      { clock: () => now },
    );
    const gate = new Gate({
      mode: 'token',
      rules: { issuer: doc.defaults.issuer, audience: doc.defaults.audience, leeway: 0 },
      keys: cache,
      now: () => now,
    });
    for (const [i, step] of sc.steps.entries()) {
      now = step.now;
      answer = step.fetch;
      calls = 0;
      unexpected = false;
      const got = await outcome(gate.verify(step.jws));
      steps++;
      const where = `${sc.id} step ${i}`;
      if (unexpected) {
        problems.push(`${where}: fetched although the step gives no answer`);
      }
      if (calls > 1) {
        problems.push(`${where}: ${calls} fetches in one request`);
      }
      if ((calls === 1) !== step.expect.fetched) {
        problems.push(`${where}: fetched ${calls === 1}, want ${step.expect.fetched}`);
      }
      const want = step.expect.ok === true ? 'ok' : step.expect.error;
      if (got !== want) {
        problems.push(`${where}: ${got}, want ${want}`);
      }
    }
  }
  assert.deepEqual(problems, []);
  t.diagnostic(`${scenarios.length} cache scenarios, ${steps} steps`);
});

test('top bar vectors', (t) => {
  const vectors: Json[] = loadVectors('topbar.json').vectors;
  assert.ok(vectors.length > 0, 'no top bar vectors');
  for (const v of vectors) {
    const body = JSON.stringify(v.input.topbar);
    assert.deepStrictEqual(parseTopbar(body), v.expected.topbar, v.id);
    assert.deepStrictEqual(parseTopbar(new TextEncoder().encode(body)), v.expected.topbar, `${v.id} (bytes)`);
  }
  t.diagnostic(`${vectors.length} top bar vectors`);
});

test('test keys: the public JWK matches the sign_key form, and the seed signs for that key', async () => {
  const keys = loadVectors('keys.json').keys;
  assert.ok(Object.keys(keys).length >= 3, 'expected the test keys A, B and X');
  for (const name of Object.keys(keys) as ('A' | 'B' | 'X')[]) {
    const raw = parseGateKey(signKey(name));
    assert.ok(raw, `${name}: sign_key_base64 unreadable`);
    assert.equal(await keyId(raw), kidOf(name), `${name}: kid`);
    const set = await parseJwks(JSON.stringify({ keys: [keys[name].public_jwk] }));
    assert.deepEqual(set.kids, [kidOf(name)], `${name}: public JWK not usable`);
    await privateKey(name);
    const gate = await tokenGate(
      { keys: [keys[name].public_jwk] },
      'https://auth.example.com',
      'app.example.com',
      0,
      1767225600,
    );
    const token = await mint(name, sessionClaims('editors', 1767225600));
    assert.equal(await outcome(gate.verify(token)), 'ok', `${name}: the seed does not sign for the public key`);
  }
});

test('the vector suite carries a latin1 conversion for header values', () => {
  // A vector header value is one code point per octet; the client reads octets the same way.
  assert.equal(latin1(new TextEncoder().encode('ü')), 'Ã¼');
});
