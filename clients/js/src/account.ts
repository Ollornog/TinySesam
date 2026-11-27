// Account overview data (spec section 8a): the person's own security state as TinySesam's account page shows it,
// reduced to what an application may render on its own settings page.

import { FETCH_TIMEOUT_MS, type FetchFunction, MAX_JWKS_BYTES, readLimited } from './jwks.ts';
import { isObject, own, parseStrictJson, parseStrictJsonText } from './strict.ts';
import { isSafeHref, tinysesamCookies } from './topbar.ts';

/** A named thing with its creation and last use (Unix seconds; null = never used). */
export interface AccountUse {
  readonly name: string | null;
  readonly created_at: number | null;
  readonly last_used: number | null;
}

/** A live app password. */
export interface AccountAppPassword extends AccountUse {
  readonly expires_at: number | null;
}

/** One browser session; `current` is null when the answer does not know the request's session. */
export interface AccountSession {
  readonly created_at: number | null;
  readonly last_seen: number | null;
  readonly method: string | null;
  readonly device: string | null;
  readonly current: boolean | null;
}

/** The links to TinySesam's account page and its sections; null when not offered (or not a safe link). */
export interface AccountLinks {
  readonly account: string | null;
  readonly sessions: string | null;
  readonly totp: string | null;
  readonly passkeys: string | null;
  readonly devices: string | null;
  readonly app_passwords: string | null;
  readonly services: string | null;
  readonly approvals: string | null;
}

/** A signed-in account overview: every member present, null for "missing, of the wrong type or not offered". */
export interface SignedInAccount {
  readonly signed_in: true;
  /**
   * `source`: where the account comes from — `local`, `oidc`, `saml`, `ldap` (two or more = a mixed account; an unknown
   * text is for the application to ignore); null when missing or no list.
   */
  readonly account: {
    readonly username: string | null;
    readonly display_name: string | null;
    readonly source: readonly string[] | null;
  };
  readonly sign_in: {
    readonly password: string | null;
    readonly totp: {
      readonly enabled: boolean | null;
      readonly recovery_left: number | null;
      readonly recovery_low: boolean | null;
    } | null;
    readonly passkeys: { readonly count: number | null; readonly items: readonly AccountUse[] } | null;
    readonly pin: boolean | null;
  };
  readonly sessions: { readonly count: number | null; readonly items: readonly AccountSession[] };
  readonly programs: {
    readonly oauth: readonly AccountUse[] | null;
    readonly services: readonly AccountUse[] | null;
    readonly app_passwords: readonly AccountAppPassword[] | null;
    readonly api_keys_active: number | null;
  };
  readonly approvals: { readonly pending: number } | null;
  readonly links: AccountLinks;
}

/** A signed-out account overview: every group null. */
export interface SignedOutAccount {
  readonly signed_in: false;
  readonly account: null;
  readonly sign_in: null;
  readonly sessions: null;
  readonly programs: null;
  readonly approvals: null;
  readonly links: null;
}

/**
 * The normalized account overview (spec section 8a). Every string is text, never markup — render it with textContent
 * or escaped. Changes happen on TinySesam's account page, which the links lead to. Do not cache it across sessions.
 */
export type Account = SignedInAccount | SignedOutAccount;

/** The overview of a signed-out request (also the answer to anything doubtful). */
export function signedOutAccount(): SignedOutAccount {
  return {
    signed_in: false,
    account: null,
    sign_in: null,
    sessions: null,
    programs: null,
    approvals: null,
    links: null,
  };
}

type Obj = Record<string, unknown>;

/** A member that is always an object in the answer: anything else reads as an empty one. */
function group(data: Obj, name: string): Obj {
  const v = own(data, name);
  return isObject(v) ? v : {};
}

function text(m: Obj, name: string): string | null {
  const v = own(m, name);
  return typeof v === 'string' ? v : null;
}

/** The string entries of a list, in order; null when it is no list. */
function texts(m: Obj, name: string): string[] | null {
  const v = own(m, name);
  return Array.isArray(v) ? v.filter((e): e is string => typeof e === 'string') : null;
}

function flag(m: Obj, name: string): boolean | null {
  const v = own(m, name);
  return typeof v === 'boolean' ? v : null;
}

/** A count or a time: an integer from 0 to 2^53 - 1. */
export function count(m: Obj, name: string): number | null {
  const v = own(m, name);
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

function href(m: Obj, name: string): string | null {
  const v = own(m, name);
  return typeof v === 'string' && isSafeHref(v) ? v : null;
}

/** The object entries of a list; anything that is no list counts as none. */
function objects(v: unknown): Obj[] {
  return Array.isArray(v) ? v.filter(isObject) : [];
}

function uses(v: unknown): AccountUse[] {
  return objects(v).map((e) => ({
    name: text(e, 'name'),
    created_at: count(e, 'created_at'),
    last_used: count(e, 'last_used'),
  }));
}

const LINKS = ['account', 'sessions', 'totp', 'passkeys', 'devices', 'app_passwords', 'services', 'approvals'] as const;

/**
 * Normalizes the body of a 200 answer of `/.tinysesam/account.json` or `/auth/account.json` (text or UTF-8 bytes).
 * Anything but a JSON object with `signed_in` true (the boolean) counts as signed out; a member of the wrong type reads
 * as missing (null), an unsafe href as null, unknown members are dropped.
 */
export function parseAccount(body: string | Uint8Array): Account {
  const parsed = typeof body === 'string' ? parseStrictJsonText(body) : parseStrictJson(body);
  if (parsed === null || !isObject(parsed.value) || own(parsed.value, 'signed_in') !== true) {
    return signedOutAccount();
  }
  const data = parsed.value;
  const account = group(data, 'account');
  const signIn = group(data, 'sign_in');
  const sessions = group(data, 'sessions');
  const programs = group(data, 'programs');
  const links = group(data, 'links');
  const totp = own(signIn, 'totp');
  const passkeys = own(signIn, 'passkeys');
  const approvals = own(data, 'approvals');
  const pending = isObject(approvals) ? count(approvals, 'pending') : null;
  const appPasswords = own(programs, 'app_passwords');
  return {
    signed_in: true,
    account: {
      username: text(account, 'username'),
      display_name: text(account, 'display_name'),
      source: texts(account, 'source'),
    },
    sign_in: {
      password: text(signIn, 'password'),
      totp: isObject(totp)
        ? {
            enabled: flag(totp, 'enabled'),
            recovery_left: count(totp, 'recovery_left'),
            recovery_low: flag(totp, 'recovery_low'),
          }
        : null,
      passkeys: isObject(passkeys) ? { count: count(passkeys, 'count'), items: uses(own(passkeys, 'items')) } : null,
      pin: flag(signIn, 'pin'),
    },
    sessions: {
      count: count(sessions, 'count'),
      items: objects(own(sessions, 'items')).map((e) => ({
        created_at: count(e, 'created_at'),
        last_seen: count(e, 'last_seen'),
        method: text(e, 'method'),
        device: text(e, 'device'),
        current: flag(e, 'current'),
      })),
    },
    programs: {
      oauth: Array.isArray(own(programs, 'oauth')) ? uses(own(programs, 'oauth')) : null,
      services: Array.isArray(own(programs, 'services')) ? uses(own(programs, 'services')) : null,
      app_passwords: Array.isArray(appPasswords)
        ? objects(appPasswords).map((e) => ({
            name: text(e, 'name'),
            created_at: count(e, 'created_at'),
            last_used: count(e, 'last_used'),
            expires_at: count(e, 'expires_at'),
          }))
        : null,
      api_keys_active: count(programs, 'api_keys_active'),
    },
    approvals: pending === null ? null : { pending },
    links: Object.fromEntries(LINKS.map((n) => [n, href(links, n)])) as unknown as AccountLinks,
  };
}

/**
 * Fetches the own account overview server-side: a GET to `accountUrl` (normally `https://<auth host>/auth/account.json`,
 * or `/.tinysesam/account.json` on the application's host) carrying only TinySesam's cookies of the request's Cookie
 * header, with a deadline of 5 seconds, a body limit of 64 KiB and no redirects. Any failure — a 401 (no full browser
 * session), a 404, a 429 included — gives the signed-out overview. Do not cache the result across sessions.
 */
export async function fetchAccount(
  accountUrl: string,
  cookieHeader: string | null | undefined,
  options: { fetch?: FetchFunction } = {},
): Promise<Account> {
  const fetchFn = options.fetch ?? globalThis.fetch;
  try {
    const headers: Record<string, string> = { accept: 'application/json' };
    const cookies = tinysesamCookies(cookieHeader);
    if (cookies !== '') {
      headers.cookie = cookies;
    }
    const response = await fetchFn(accountUrl, {
      method: 'GET',
      headers,
      redirect: 'error',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      return signedOutAccount();
    }
    return parseAccount(await readLimited(response, MAX_JWKS_BYTES));
  } catch {
    return signedOutAccount();
  }
}
