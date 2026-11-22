// IP addresses and prefixes for the trusted proxy list of header mode — without Node's `net`, so the core runs on
// every runtime. IPv4 addresses (also IPv4-mapped IPv6 such as ::ffff:127.0.0.1) match IPv4 prefixes only.

/** An address: 4 bytes for IPv4, 16 for IPv6. */
export type Address = Uint8Array;

/** A prefix: an address and the number of leading bits that must match. */
export interface Prefix {
  readonly address: Address;
  readonly bits: number;
}

const V4 = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/;
const HEXTET = /^[0-9a-fA-F]{1,4}$/;

function parseV4(s: string): Address | null {
  const m = V4.exec(s);
  if (m === null) {
    return null;
  }
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(m[i + 1]);
    if (n > 255) {
      return null;
    }
    out[i] = n;
  }
  return out;
}

function parseHextets(s: string): number[] | null {
  if (s === '') {
    return [];
  }
  const out: number[] = [];
  const parts = s.split(':');
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? '';
    if (i === parts.length - 1 && part.includes('.')) {
      const v4 = parseV4(part);
      if (v4 === null) {
        return null;
      }
      out.push(((v4[0] ?? 0) << 8) | (v4[1] ?? 0), ((v4[2] ?? 0) << 8) | (v4[3] ?? 0));
    } else if (HEXTET.test(part)) {
      out.push(Number.parseInt(part, 16));
    } else {
      return null;
    }
  }
  return out;
}

function parseV6(s: string): Address | null {
  const halves = s.split('::');
  if (halves.length > 2) {
    return null;
  }
  const head = parseHextets(halves[0] ?? '');
  const tail = halves.length === 2 ? parseHextets(halves[1] ?? '') : [];
  if (head === null || tail === null) {
    return null;
  }
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    return null;
  }
  const words = [...head, ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...tail];
  const out = new Uint8Array(16);
  words.forEach((w, i) => {
    out[2 * i] = w >> 8;
    out[2 * i + 1] = w & 0xff;
  });
  return out;
}

/** Turns an IPv4-mapped IPv6 address into its IPv4 address. */
function unmap(a: Address): Address {
  if (a.length === 16 && a.subarray(0, 10).every((b) => b === 0) && a[10] === 0xff && a[11] === 0xff) {
    return a.slice(12);
  }
  return a;
}

/**
 * Parses an IPv4 or IPv6 address (brackets and a zone such as `%eth0` allowed, as a peer address may carry them);
 * null when it is none. IPv4-mapped IPv6 comes back as IPv4.
 */
export function parseAddress(input: string): Address | null {
  let s = input;
  if (s.startsWith('[') && s.endsWith(']')) {
    s = s.slice(1, -1);
  }
  const zone = s.indexOf('%');
  if (zone >= 0 && s.includes(':')) {
    s = s.slice(0, zone);
  }
  if (s.includes(':')) {
    const v6 = parseV6(s);
    return v6 === null ? null : unmap(v6);
  }
  return parseV4(s);
}

/** Parses `address/bits` or a bare address (all bits); null when invalid. */
export function parsePrefix(input: string): Prefix | null {
  if (typeof input !== 'string' || input.includes('%') || input.includes('[')) {
    return null;
  }
  const slash = input.indexOf('/');
  const address = parseAddress(slash < 0 ? input : input.slice(0, slash));
  if (address === null) {
    return null;
  }
  const max = address.length * 8;
  if (slash < 0) {
    return { address, bits: max };
  }
  const bitsText = input.slice(slash + 1);
  if (!/^(0|[1-9][0-9]{0,2})$/.test(bitsText) || Number(bitsText) > max) {
    return null;
  }
  return { address, bits: Number(bitsText) };
}

/** Whether the prefix contains the address (same family only). */
export function prefixContains(prefix: Prefix, address: Address): boolean {
  if (prefix.address.length !== address.length) {
    return false;
  }
  let bits = prefix.bits;
  for (let i = 0; bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if (((prefix.address[i] ?? 0) & mask) !== ((address[i] ?? 0) & mask)) {
      return false;
    }
  }
  return true;
}
