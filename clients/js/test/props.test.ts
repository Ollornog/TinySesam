// Property tests (fast-check): no input throws past the API, a changed token never verifies, the group and control
// character rules hold for generated input.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import fc from 'fast-check';
import { GateError } from '../src/errors.ts';
import { identityFromHeaders, parseGroups } from '../src/identity.ts';
import { parseJwks } from '../src/keys.ts';
import { hasControl, parseStrictJsonText } from '../src/strict.ts';
import { parseToken } from '../src/token.ts';
import { parseTopbar } from '../src/topbar.ts';
import { DEFAULTS, mint, outcome, publicJwk, sessionClaims, tokenGate } from './helpers.ts';

const RUNS = { numRuns: 300 };

test('verify: any string ends in a GateError, never an exception of another kind', async () => {
  const gate = await tokenGate({ keys: [publicJwk('A')] }, DEFAULTS.issuer, DEFAULTS.audience, 0, DEFAULTS.now);
  const segment = fc.stringMatching(/^[A-Za-z0-9_\-=+/. ]{0,40}$/);
  await fc.assert(
    fc.asyncProperty(
      fc.oneof(
        fc.string(),
        fc.tuple(segment, segment, segment).map((p) => p.join('.')),
      ),
      async (s) => {
        try {
          await gate.verify(s);
          return false;
        } catch (err) {
          return err instanceof GateError && err.code !== 'internal';
        }
      },
    ),
    RUNS,
  );
});

test('a valid token with one character changed or inserted never verifies', async () => {
  const gate = await tokenGate({ keys: [publicJwk('A')] }, DEFAULTS.issuer, DEFAULTS.audience, 0, DEFAULTS.now);
  const token = await mint('A', sessionClaims());
  assert.equal(await outcome(gate.verify(token)), 'ok');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=';
  await fc.assert(
    fc.asyncProperty(fc.nat(token.length - 1), fc.constantFrom(...alphabet), fc.boolean(), async (i, c, insert) => {
      const changed = insert ? token.slice(0, i) + c + token.slice(i) : token.slice(0, i) + c + token.slice(i + 1);
      fc.pre(changed !== token);
      return (await outcome(gate.verify(changed))) !== 'ok';
    }),
    RUNS,
  );
});

test('parsers never throw: token structure, strict JSON, key sets, top bar', async () => {
  fc.assert(
    fc.property(fc.string(), (s) => {
      try {
        parseToken(s);
      } catch (err) {
        if (!(err instanceof GateError)) {
          return false;
        }
      }
      parseStrictJsonText(s);
      parseTopbar(s);
      return true;
    }),
    RUNS,
  );
  await fc.assert(
    fc.asyncProperty(fc.oneof(fc.string(), fc.json()), async (s) => {
      try {
        await parseJwks(s);
        return true;
      } catch (err) {
        return err instanceof GateError && err.code === 'jwks_invalid';
      }
    }),
    RUNS,
  );
});

test('strict JSON agrees with JSON.parse on every document without repeated names or lone surrogates', () => {
  fc.assert(
    fc.property(fc.json(), (text) => {
      const parsed = parseStrictJsonText(text);
      assert.ok(parsed !== null, text);
      assert.deepStrictEqual(parsed.value, JSON.parse(text));
    }),
    RUNS,
  );
});

test('groups: no entry is empty, repeated or padded with spaces; order of first occurrence', () => {
  fc.assert(
    fc.property(fc.array(fc.stringMatching(/^[ a-zA-Z,]{0,6}$/), { maxLength: 8 }), (parts) => {
      const groups = parseGroups(parts.join(','));
      assert.equal(new Set(groups).size, groups.length);
      for (const g of groups) {
        assert.ok(g !== '' && !g.startsWith(' ') && !g.endsWith(' ') && !g.includes(','));
      }
      const expected: string[] = [];
      for (const p of parts.join(',').split(',')) {
        const g = p.trim();
        if (g !== '' && !expected.includes(g)) {
          expected.push(g);
        }
      }
      assert.deepEqual(groups, expected);
    }),
    RUNS,
  );
});

test('a control character anywhere in a header value is refused, never stripped', () => {
  fc.assert(
    fc.property(
      fc.stringMatching(/^[a-z]{0,8}$/),
      fc.integer({ min: 0, max: 0x20 }).map((c) => (c === 0x20 ? 0x7f : c)),
      fc.stringMatching(/^[a-z]{0,8}$/),
      fc.constantFrom('Remote-User', 'Remote-Name', 'Remote-Email', 'Remote-Groups', 'Remote-Auth'),
      (before, control, after, header) => {
        const value = before + String.fromCharCode(control) + after;
        const pairs: [string, string][] = [
          ['Remote-User', 'anna'],
          [header, value],
        ];
        if (header === 'Remote-User') {
          pairs.shift();
        }
        try {
          identityFromHeaders(pairs);
          return false;
        } catch (err) {
          return err instanceof GateError && err.code === 'header';
        }
      },
    ),
    RUNS,
  );
});

test('header values: well-formed UTF-8 round-trips exactly', () => {
  fc.assert(
    fc.property(fc.string({ unit: 'grapheme', minLength: 1 }), (name) => {
      fc.pre(!hasControl(name) && name.trim() === name);
      const octets = String.fromCharCode(...new TextEncoder().encode(name));
      const id = identityFromHeaders([['Remote-User', octets]]);
      return id.user === name;
    }),
    RUNS,
  );
});
