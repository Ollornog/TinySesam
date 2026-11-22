// Strict decoders for spec section 4.4: base64url, UTF-8 and JSON. The decoding itself is done by the platform
// (atob, TextDecoder, JSON.parse); this module adds what those are too lenient for — the alphabet and canonical form
// of base64url, the byte order mark, repeated member names, lone surrogates and the exact form of integers.

const BASE64URL = /^[A-Za-z0-9_-]*$/;
const BASE64_STD = /^[A-Za-z0-9+/]*={0,2}$/;

function binaryToBytes(binary: string): Uint8Array {
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function bytesToBinary(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) {
    s += String.fromCharCode(b);
  }
  return s;
}

/**
 * Decodes strict base64url (RFC 7515): only `A-Z a-z 0-9 - _`, no padding, no whitespace or line break, and
 * canonical — re-encoding the bytes gives the same text, so the unused low bits are zero. `atob` alone would skip
 * whitespace and accept non-zero trailing bits; the checks around it refuse both.
 */
export function decodeSegment(s: string): Uint8Array | null {
  if (!BASE64URL.test(s) || s.length % 4 === 1) {
    return null;
  }
  const std = s.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (s.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(std);
  } catch {
    return null;
  }
  if (encodeSegment(binaryToBytes(binary)) !== s) {
    return null;
  }
  return binaryToBytes(binary);
}

/** Encodes bytes as base64url without padding. */
export function encodeSegment(bytes: Uint8Array): string {
  const std = btoa(bytesToBinary(bytes));
  const pad = std.endsWith('==') ? 2 : std.endsWith('=') ? 1 : 0;
  return std
    .slice(0, std.length - pad)
    .replaceAll('+', '-')
    .replaceAll('/', '_');
}

/** Decodes strict standard Base64 with padding (the output of `tinysesam gate-key`), canonical only. */
export function decodeStandardBase64(s: string): Uint8Array | null {
  if (!BASE64_STD.test(s) || s.length % 4 !== 0) {
    return null;
  }
  let binary: string;
  try {
    binary = atob(s);
  } catch {
    return null;
  }
  const bytes = binaryToBytes(binary);
  return btoa(bytesToBinary(bytes)) === s ? bytes : null;
}

/** Bytes from a string of octets, one code unit U+0000-U+00FF per byte; null when a code unit is above U+00FF. */
export function octetsToBytes(octets: string): Uint8Array | null {
  const out = new Uint8Array(octets.length);
  for (let i = 0; i < octets.length; i++) {
    const c = octets.charCodeAt(i);
    if (c > 0xff) {
      return null;
    }
    out[i] = c;
  }
  return out;
}

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Decodes strict UTF-8 (invalid, overlong and surrogate sequences refused); null on failure. */
export function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return utf8.decode(bytes);
  } catch {
    return null;
  }
}

/** A lone surrogate: in a `u` regular expression only an unpaired surrogate is a code point of category Cs. */
const LONE_SURROGATE = /\p{Cs}/u;

/** A strictly parsed JSON value and, for an object at the top, the source text of each member that is a number. */
export interface StrictJson {
  readonly value: unknown;
  readonly numbers: ReadonlyMap<string, string>;
}

/**
 * Parses one JSON value from UTF-8 bytes the way the specification demands: strict UTF-8, no byte order mark, no
 * member name twice in any object, no NaN or Infinity (JSON.parse refuses those), no lone surrogate escape, nothing
 * after the value. JSON.parse keeps the last of two equal member names, so a scan over the text — which JSON.parse
 * has already accepted — refuses repeats first; member names are decoded by JSON.parse itself, so `"a"` and `"a"`
 * are the same name.
 */
export function parseStrictJson(bytes: Uint8Array): StrictJson | null {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return null;
  }
  const text = decodeUtf8(bytes);
  if (text === null) {
    return null;
  }
  return parseStrictJsonText(text);
}

/** As {@link parseStrictJson}, for text that is already a string. */
export function parseStrictJsonText(text: string): StrictJson | null {
  if (text.charCodeAt(0) === 0xfeff) {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  const numbers = scan(text);
  return numbers === null ? null : { value, numbers };
}

interface Frame {
  readonly object: boolean;
  readonly names: Set<string>;
  expectName: boolean;
  lastName: string;
}

const NUMBER_CHAR = /[0-9eE.+-]/;

/**
 * Walks JSON text that JSON.parse has accepted. Refuses a repeated member name in any object and a lone surrogate in
 * any string; returns the source text of the numbers that are members of a top-level object.
 */
function scan(text: string): Map<string, string> | null {
  const numbers = new Map<string, string>();
  const stack: Frame[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') {
        j += text[j] === '\\' ? 2 : 1;
      }
      const s = JSON.parse(text.slice(i, j + 1)) as string;
      if (LONE_SURROGATE.test(s)) {
        return null;
      }
      const top = stack[stack.length - 1];
      if (top?.object && top.expectName) {
        if (top.names.has(s)) {
          return null;
        }
        top.names.add(s);
        top.expectName = false;
        top.lastName = s;
      }
      i = j + 1;
    } else if (c === '{' || c === '[') {
      stack.push({ object: c === '{', names: new Set(), expectName: c === '{', lastName: '' });
      i++;
    } else if (c === '}' || c === ']') {
      stack.pop();
      i++;
    } else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top?.object) {
        top.expectName = true;
      }
      i++;
    } else if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
      let j = i;
      while (j < text.length && NUMBER_CHAR.test(text[j] ?? '')) {
        j++;
      }
      const root = stack[0];
      if (stack.length === 1 && root?.object) {
        numbers.set(root.lastName, text.slice(i, j));
      }
      i = j;
    } else {
      i++; // whitespace, ':' and the letters of true, false, null
    }
  }
  return numbers;
}

/** A plain JSON object (not an array, not null). */
export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** An own member of a parsed object — never one inherited from Object.prototype. */
export function own(o: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(o, name) ? o[name] : undefined;
}

/** A C0 control character (U+0000-U+001F, tab included) or DEL. */
export function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) {
      return true;
    }
  }
  return false;
}

/** Compares s with an ASCII lower-case reference, ignoring ASCII case only (no Unicode case folding). */
export function asciiEqualFold(s: string, lower: string): boolean {
  if (s.length !== lower.length) {
    return false;
  }
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0x80) {
      return false;
    }
    if (c >= 0x41 && c <= 0x5a) {
      c += 0x20;
    }
    if (c !== lower.charCodeAt(i)) {
      return false;
    }
  }
  return true;
}

/** Compares two ASCII strings (header field names), ignoring ASCII case only. */
export function asciiEqualFoldBoth(a: string, b: string): boolean {
  return asciiEqualFold(a, asciiLower(b));
}

/** Lower-cases ASCII letters only. */
export function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0x20));
}

const TOKEN_CHARS = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** A valid HTTP field name or cookie name (an RFC 9110 token). */
export function isToken(s: string): boolean {
  return TOKEN_CHARS.test(s);
}
