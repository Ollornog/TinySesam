// Unit tests of the building blocks: strict decoders, IP prefixes, freshness, key parsing, the core's portability.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parseGroups } from '../src/identity.ts';
import { parseAddress, parsePrefix, prefixContains } from '../src/ip.ts';
import { freshness, interpretFetch, MAX_JWKS_BYTES } from '../src/jwks.ts';
import { parseGateKey } from '../src/keys.ts';
import { decodeSegment, decodeStandardBase64, parseStrictJson, parseStrictJsonText } from '../src/strict.ts';
import { isSafeHref } from '../src/topbar.ts';
import { publicJwk, signKey } from './helpers.ts';

test('strict JSON: refused and accepted documents', () => {
  const bytes = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
  const refused = [
    '{"a":"\xff"}',
    '{"a":"\xc0\xaf"}',
    '{"\xed\xa0\x80":1}',
    '\xef\xbb\xbf{}',
    '{"a":1,"a":1}',
    '{"a":1,"\\u0061":2}',
    '{"a":{"b":1,"b":2}}',
    '[{"a":1,"a":2}]',
    '{"a":NaN}',
    '{"a":Infinity}',
    '{"a":1} {}',
    '{"a":1}x',
    '{"a":"\\ud800"}',
    '',
  ];
  for (const s of refused) {
    assert.equal(parseStrictJson(bytes(s)), null, JSON.stringify(s));
  }
  assert.equal(parseStrictJsonText('﻿{}'), null);
  for (const s of ['{}', ' {"a":[1,{"b":null}]} \n', '{"a":"\xc3\xbc","b":"\xc3\xbc"}', '[]', '"x"', '1e400']) {
    assert.notEqual(parseStrictJson(bytes(s)), null, JSON.stringify(s));
  }
  // Same name in sibling objects is fine; the number texts of the top-level members are kept exactly.
  const parsed = parseStrictJsonText('{"a":{"x":1},"b":{"x":2},"n":1.0,"m":-0,"e":1E3}');
  assert.ok(parsed);
  assert.deepEqual(
    [...parsed.numbers],
    [
      ['n', '1.0'],
      ['m', '-0'],
      ['e', '1E3'],
    ],
  );
});

test('strict base64url: alphabet, padding, whitespace, canonical form', () => {
  assert.deepEqual(decodeSegment('AQID'), new Uint8Array([1, 2, 3]));
  assert.deepEqual(decodeSegment(''), new Uint8Array(0));
  for (const bad of ['AQID=', 'AQ==', 'A', 'AQ+D', 'AQ/D', 'AQ D', 'AQ\nID', 'AR', 'AQJ']) {
    assert.equal(decodeSegment(bad), null, JSON.stringify(bad));
  }
  assert.deepEqual(decodeSegment('AQ'), new Uint8Array([1]));
  assert.deepEqual(decodeSegment('AQI'), new Uint8Array([1, 2]));
  assert.equal(decodeStandardBase64('AQ'), null, 'standard Base64 needs its padding');
  assert.equal(decodeStandardBase64('AR=='), null, 'non-zero trailing bits');
  assert.deepEqual(decodeStandardBase64('AQ=='), new Uint8Array([1]));
  assert.ok(parseGateKey(` ${signKey('A')}\n`), 'surrounding whitespace of a pasted key is fine');
  assert.equal(parseGateKey(signKey('A').replace('=', '')), null);
});

test('IP addresses and prefixes', () => {
  const contains = (p: string, a: string) => {
    const prefix = parsePrefix(p);
    const address = parseAddress(a);
    assert.ok(prefix && address, `${p} ${a}`);
    return prefixContains(prefix, address);
  };
  assert.ok(contains('198.51.100.0/24', '198.51.100.77'));
  assert.ok(!contains('198.51.100.0/24', '198.51.101.1'));
  assert.ok(contains('127.0.0.1', '::ffff:127.0.0.1'));
  assert.ok(contains('2001:db8:1::/48', '2001:db8:1::5'));
  assert.ok(!contains('2001:db8:1::/48', '2001:db8:2::1'));
  assert.ok(contains('::1', '0:0:0:0:0:0:0:1'));
  assert.ok(contains('fe80::/10', 'fe80::1%eth0'));
  assert.ok(!contains('::/0', '127.0.0.1'), 'an IPv6 prefix does not contain IPv4');
  assert.ok(contains('0.0.0.0/0', '1.2.3.4'));
  assert.ok(contains('2001:db8::/32', '2001:db8:0:0:0:0:0:1'));
  assert.ok(contains('::ffff:0.0.0.0/0'.replace('::ffff:', ''), '::ffff:1.2.3.4'));
  for (const bad of [
    '1.2.3',
    '1.2.3.4.5',
    '01.2.3.4',
    '256.1.1.1',
    '1::2::3',
    ':1',
    '1:2:3:4:5:6:7:8:9',
    'g::1',
    'localhost',
    '',
  ]) {
    assert.equal(parseAddress(bad), null, bad);
  }
  for (const bad of ['198.51.100.0/33', '::/129', '198.51.100.0/024', '198.51.100.0/', 'fe80::1%eth0', '[::1]']) {
    assert.equal(parsePrefix(bad), null, bad);
  }
});

test('freshness: max-age clamped to 60-3600 s, 300 s without one', () => {
  assert.equal(freshness(''), 300);
  assert.equal(freshness('max-age=600'), 600);
  assert.equal(freshness('public, MAX-AGE = 120 , must-revalidate'), 120);
  assert.equal(freshness('max-age=5'), 60);
  assert.equal(freshness('no-store'), 300);
  assert.equal(freshness('no-cache, max-age=0'), 60);
  assert.equal(freshness('max-age=99999999999999999999999'), 3600);
  assert.equal(freshness('s-maxage=10'), 300);
  assert.equal(freshness('max-age=1x'), 300);
});

test('top bar hrefs', () => {
  for (const ok of ['https://a.example.com/x', 'HTTP://a.example.com', '/files/', '/']) {
    assert.ok(isSafeHref(ok), ok);
  }
  for (const bad of [
    'javascript:alert(1)',
    'data:text/html,x',
    '//evil.example',
    '/\\evil.example',
    'files/',
    '/a b',
    '/a b',
    '/a\u0085b',
    '/a b',
    '/a\u0000',
    'https://a\tb',
    '',
  ]) {
    assert.ok(!isSafeHref(bad), JSON.stringify(bad));
  }
});

test('the core uses web standards only: no Node module, no Buffer, no process outside src/node.ts', () => {
  const dir = new URL('../src/', import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith('.ts') && f !== 'node.ts');
  assert.ok(files.length >= 10);
  for (const f of files) {
    const text = readFileSync(new URL(f, dir), 'utf8');
    assert.ok(!/from ['"]node:/.test(text) && !/require\(/.test(text), `${f} imports a Node module`);
    assert.ok(!/\bBuffer\b|\bprocess\./.test(text), `${f} uses a Node global`);
  }
  // The Node adapter imports Node's types only — no Node module is loaded at runtime.
  const node = readFileSync(new URL('node.ts', dir), 'utf8');
  const nodeImports = node.split('\n').filter((l) => /^import .* from ['"]node:/.test(l));
  assert.ok(nodeImports.length > 0);
  for (const line of nodeImports) {
    assert.ok(line.startsWith('import type '), line);
  }
});

test('groups: only U+0020 is trimmed — no other whitespace', () => {
  assert.deepEqual(parseGroups(' editors , 　a ,b '), ['editors ', '　a', 'b ']);
  assert.deepEqual(parseGroups('  a  ,a, ,'), ['a']);
});

test('a fetch result: status other than 200, or a body above 64 KiB, is a failed fetch', async () => {
  const jwks = JSON.stringify({ keys: [publicJwk('A')] });
  assert.notEqual(await interpretFetch({ status: 200, body: jwks }), null);
  for (const status of [201, 204, 301, 404, 500]) {
    assert.equal(await interpretFetch({ status, body: jwks }), null, String(status));
  }
  const big = jwks + ' '.repeat(MAX_JWKS_BYTES - jwks.length);
  assert.notEqual(await interpretFetch({ status: 200, body: big }), null, 'exactly 64 KiB');
  assert.equal(await interpretFetch({ status: 200, body: `${big} ` }), null, 'one byte more (text)');
  assert.equal(await interpretFetch({ status: 200, body: new TextEncoder().encode(`${big} `) }), null, '(bytes)');
});
