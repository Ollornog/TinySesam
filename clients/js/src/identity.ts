// The identity both modes produce (spec section 1), the group rules (3.3) and header mode (2.2, 2.3).

import { GateError } from './errors.ts';
import { asciiEqualFoldBoth, decodeUtf8, hasControl, isToken, octetsToBytes } from './strict.ts';

/** Whether a request came from a browser session or from a token (OAuth, API key, app password). */
export type Kind = 'session' | 'token';

/** How the request signed in, as TinySesam reports it; empty for a missing or unknown value. */
export type Auth = 'session' | 'oauth' | 'apikey' | 'app-password' | '';

const AUTH_VALUES: ReadonlySet<string> = new Set(['session', 'oauth', 'apikey', 'app-password']);

/**
 * What the account is (spec version 2): a person (`user`) or a service account (`service`). Independent of
 * {@link Kind}: a paired service acting as a person is `token` and `user`.
 */
export type AccountKind = 'user' | 'service';

/**
 * The account-kind rules of spec version 2 (section 2.2 rules 6–8, section 4.4 step 9): `kind` is the value of
 * Remote-Kind or ts_kind (empty when missing), `auth` that of Remote-Auth or ts_auth. Returns the reason for a refusal,
 * or null — a missing or unknown kind is never taken as `user`, and a service account has no session.
 */
export function accountKindProblem(kind: unknown, auth: unknown): string | null {
  if (kind === undefined || kind === null || kind === '') {
    return 'Remote-Kind/ts_kind missing (TinySesam or proxy older than spec v2?)';
  }
  if (kind !== 'user' && kind !== 'service') {
    return 'Remote-Kind/ts_kind is not exactly user or service';
  }
  if (kind === 'service' && auth === 'session') {
    return 'a service account has no session';
  }
  return null;
}

/**
 * Who made the request, the same in both modes. Key your own records by {@link Identity.id}: it is the only value that
 * survives a rename. `user`, `name` and `email` may hold any character except controls — bidirectional overrides and
 * zero-width characters included — so escape them for HTML and isolate them as bidi text.
 */
export class Identity {
  /** The account name (sign-in identifier). */
  readonly user: string;
  /** The display name, may be empty. */
  readonly name: string;
  /** May be empty. */
  readonly email: string;
  /** The roles (spec section 3.3); incomplete on purpose for a token request. */
  readonly groups: readonly string[];
  /** The account ID, decimal digits. */
  readonly id: string;
  /** session, oauth, apikey, app-password, or empty. */
  readonly auth: Auth;
  /** `session` only when auth is exactly `session`. */
  readonly kind: Kind;
  /** `user` or `service`, never empty (spec version 2). */
  readonly accountKind: AccountKind;
  /**
   * The account's permissions for this application (spec section 3.4, Remote-Permissions or ts_perms); empty when
   * TinySesam sends none — which means "holds none", never "unknown".
   */
  readonly permissions: readonly string[];

  constructor(fields: {
    user: string;
    name: string;
    email: string;
    groups: string;
    id: string;
    auth: string;
    accountKind: string;
    permissions?: string;
  }) {
    const problem = accountKindProblem(fields.accountKind, fields.auth);
    if (problem !== null) {
      // Fail closed: an identity never exists without a valid account kind.
      throw new GateError('header', problem);
    }
    const auth = AUTH_VALUES.has(fields.auth) ? (fields.auth as Auth) : '';
    this.user = fields.user;
    this.name = fields.name;
    this.email = fields.email;
    this.groups = Object.freeze(parseGroups(fields.groups));
    this.id = fields.id;
    this.auth = auth;
    this.kind = auth === 'session' ? 'session' : 'token';
    this.accountKind = fields.accountKind as AccountKind;
    this.permissions = Object.freeze(parseGroups(fields.permissions ?? ''));
    Object.freeze(this);
  }

  /**
   * Whether permission is one of the permissions, compared exactly (spec section 3.4): no case folding, no wildcard,
   * and neither `admin` nor a role implies one.
   */
  hasPermission(permission: string): boolean {
    return this.permissions.includes(permission);
  }

  /**
   * Whether role is one of the groups, compared exactly: no case folding, no normalization, and no role implied by
   * `admin`. Whether an admin passes every role check is the application's decision.
   */
  hasRole(role: string): boolean {
    return this.groups.includes(role);
  }

  /**
   * Whether the request came from a browser session. The groups of a token request are incomplete on purpose (a token
   * never carries admin): never conclude from a missing group that the account lacks it.
   */
  isSession(): boolean {
    return this.kind === 'session';
  }

  /** Whether the account is a service account (Remote-Kind or ts_kind exactly `service`). */
  isService(): boolean {
    return this.accountKind === 'service';
  }

  /** The plain fields, as the vectors of the specification spell them. */
  toJSON(): {
    user: string;
    name: string;
    email: string;
    groups: string[];
    id: string;
    auth: Auth;
    kind: Kind;
    account_kind: AccountKind;
    permissions: string[];
  } {
    return {
      user: this.user,
      name: this.name,
      email: this.email,
      groups: [...this.groups],
      id: this.id,
      auth: this.auth,
      kind: this.kind,
      account_kind: this.accountKind,
      permissions: [...this.permissions],
    };
  }
}

/**
 * Reads Remote-Groups or ts_groups (spec section 3.3): split at every comma, remove leading and trailing spaces
 * (U+0020 only), drop empty and repeated entries, keep the order. There is no escape mechanism.
 */
export function parseGroups(s: string): string[] {
  const seen = new Set<string>();
  for (const part of s.split(',')) {
    const g = trimSpaces(part);
    if (g !== '') {
      seen.add(g); // a Set keeps the order of first insertion
    }
  }
  return [...seen];
}

/** Removes leading and trailing U+0020 only (no tab, no other whitespace) — a loop, no backtracking regex. */
function trimSpaces(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && s.charCodeAt(start) === 0x20) {
    start++;
  }
  while (end > start && s.charCodeAt(end - 1) === 0x20) {
    end--;
  }
  return s.slice(start, end);
}

/**
 * The eight headers of header mode. TinySesam's forward_headers can rename them. `perms` (Remote-Permissions) is
 * optional on the wire: missing or empty means none (spec section 3.4).
 */
export interface HeaderNames {
  user: string;
  name: string;
  email: string;
  groups: string;
  id: string;
  auth: string;
  kind: string;
  perms: string;
}

/** The names TinySesam sends unless forward_headers renames them. */
export const DEFAULT_HEADER_NAMES: Readonly<HeaderNames> = Object.freeze({
  user: 'Remote-User',
  name: 'Remote-Name',
  email: 'Remote-Email',
  groups: 'Remote-Groups',
  id: 'Remote-Id',
  auth: 'Remote-Auth',
  kind: 'Remote-Kind',
  perms: 'Remote-Permissions',
});

const SLOTS = ['user', 'name', 'email', 'groups', 'id', 'auth', 'kind', 'perms'] as const;

/** Fills missing names with the defaults and checks them; null when a name is invalid or two are equal. */
export function resolveHeaderNames(names: Partial<HeaderNames> | undefined): Readonly<HeaderNames> | null {
  const out = { ...DEFAULT_HEADER_NAMES };
  for (const slot of SLOTS) {
    const v = names?.[slot];
    if (v !== undefined) {
      out[slot] = v;
    }
  }
  const seen = new Set<string>();
  for (const slot of SLOTS) {
    const n = out[slot];
    if (typeof n !== 'string' || !isToken(n) || seen.has(n.toLowerCase())) {
      return null;
    }
    seen.add(n.toLowerCase());
  }
  return Object.freeze(out);
}

/**
 * Request header fields as name/value pairs, one pair per field line as it arrived. A value is a string of octets:
 * one code unit U+0000-U+00FF per byte, which is what Node's `rawHeaders` and the Fetch `Headers` API hand out.
 */
export type HeaderPairs = Iterable<readonly [string, string]>;

/** Every value of the field `name` (compared ignoring ASCII case), in order. */
export function headerValues(headers: HeaderPairs, name: string): string[] {
  const out: string[] = [];
  for (const [key, value] of headers) {
    if (asciiEqualFoldBoth(key, name)) {
      out.push(value);
    }
  }
  return out;
}

const ASCII_DIGITS = /^[0-9]+$/;

/**
 * Reads the identity from the Remote-* headers (spec section 2.2). It does not check where the request came from:
 * use it only behind a proxy that fulfils the duties of spec section 2.1, or use a gate in header mode with
 * `trustedProxies`. Throws a {@link GateError} of the class `unauthenticated` or `header`.
 */
export function identityFromHeaders(
  headers: HeaderPairs,
  names: Readonly<HeaderNames> = DEFAULT_HEADER_NAMES,
): Identity {
  const pairs = [...headers];
  const values = { user: '', name: '', email: '', groups: '', id: '', auth: '', kind: '', perms: '' };
  for (const slot of SLOTS) {
    const found = headerValues(pairs, names[slot]);
    if (found.length === 0) {
      continue;
    }
    if (found.length > 1) {
      throw new GateError('header', 'a header occurs more than once');
    }
    const bytes = octetsToBytes(found[0] ?? '');
    const value = bytes === null ? null : decodeUtf8(bytes);
    if (value === null) {
      throw new GateError('header', 'a header is not UTF-8');
    }
    if (hasControl(value)) {
      throw new GateError('header', 'control character in a header');
    }
    values[slot] = value;
  }
  if (values.user === '') {
    throw new GateError('unauthenticated', 'no user header');
  }
  if (values.id !== '' && !ASCII_DIGITS.test(values.id)) {
    throw new GateError('header', 'the id header is not a number');
  }
  const problem = accountKindProblem(values.kind, values.auth);
  if (problem !== null) {
    throw new GateError('header', problem);
  }
  return new Identity({ ...values, accountKind: values.kind, permissions: values.perms });
}
