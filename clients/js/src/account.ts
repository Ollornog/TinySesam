// Account overview data (spec section 8a): the person's own security state as TinySesam's account page shows it,
// reduced to what an application may render on its own settings page.

import { ConfigError } from './errors.ts';
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

/**
 * One browser session; `current` is null when the answer does not know the request's session. `handle` is the session
 * handle (opaque text, never the token); `end` the action page that ends exactly this session (null for the session of
 * the request) — `actionUrl(session.end, returnTo, state)` is the address to send the person to.
 */
export interface AccountSession {
  readonly created_at: number | null;
  readonly last_seen: number | null;
  readonly method: string | null;
  readonly device: string | null;
  readonly current: boolean | null;
  readonly handle: string | null;
  readonly end: string | null;
}

/** An API key of the account (spec section 8a, T-106): its name, kind and times — never the key or its prefix. */
export interface AccountApiKey {
  readonly name: string | null;
  /** `automation` or `human`; an unknown text is for the application to ignore. */
  readonly kind: string | null;
  readonly created_at: number | null;
  readonly last_used: number | null;
  readonly expires_at: number | null;
}

/**
 * One of the account's own events (spec section 8a, T-106), newest first: when (Unix seconds), TinySesam's event name
 * (text — show it or a word of your own, keep an unknown one as text) and whether another person caused it.
 */
export interface AccountEvent {
  readonly at: number | null;
  readonly event: string | null;
  readonly by_admin: boolean | null;
}

/** The own action pages of spec section 8c; null when not offered to this account (or not a safe link). */
export interface AccountActions {
  readonly username: string | null;
  readonly email: string | null;
  readonly password: string | null;
  readonly pin: string | null;
  readonly totp: string | null;
  readonly recovery_codes: string | null;
  readonly passkeys: string | null;
  readonly api_keys: string | null;
  readonly app_passwords: string | null;
  readonly sessions: string | null;
  readonly programs: string | null;
  readonly services: string | null;
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
    /** The API keys `api_keys_active` counts; null when API keys are not offered. */
    readonly api_keys: readonly AccountApiKey[] | null;
  };
  readonly approvals: { readonly pending: number } | null;
  /** On an application's host the application and the account's permissions for it (spec section 8a); else null. */
  readonly permissions: { readonly app: string | null; readonly names: readonly string[] } | null;
  readonly links: AccountLinks;
  /** The own action pages (spec section 8c); build the address to send the person to with `actionUrl`. */
  readonly actions: AccountActions;
  /** The account's own events, newest first (always a list). */
  readonly events: readonly AccountEvent[];
  /**
   * For a person who administers accounts inside the application's area: where its page reads the administration data
   * (spec section 8b, `parseAdminAccounts`); null for anyone else and on any other host.
   */
  readonly admin: { readonly accounts: string } | null;
}

/** A signed-out account overview: every group null. */
export interface SignedOutAccount {
  readonly signed_in: false;
  readonly account: null;
  readonly sign_in: null;
  readonly sessions: null;
  readonly programs: null;
  readonly approvals: null;
  readonly permissions: null;
  readonly links: null;
  readonly actions: null;
  readonly events: null;
  readonly admin: null;
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
    permissions: null,
    links: null,
    actions: null,
    events: null,
    admin: null,
  };
}

export type Obj = Record<string, unknown>;

/** A member that is always an object in the answer: anything else reads as an empty one. */
export function group(data: Obj, name: string): Obj {
  const v = own(data, name);
  return isObject(v) ? v : {};
}

export function text(m: Obj, name: string): string | null {
  const v = own(m, name);
  return typeof v === 'string' ? v : null;
}

/** The string entries of a list, in order; null when it is no list. */
export function texts(m: Obj, name: string): string[] | null {
  const v = own(m, name);
  return Array.isArray(v) ? v.filter((e): e is string => typeof e === 'string') : null;
}

export function flag(m: Obj, name: string): boolean | null {
  const v = own(m, name);
  return typeof v === 'boolean' ? v : null;
}

/** The string entries of a list, in order; `[]` when it is no list. */
export function strings(m: Obj, name: string): string[] {
  return texts(m, name) ?? [];
}

/** A count or a time: an integer from 0 to 2^53 - 1. */
export function count(m: Obj, name: string): number | null {
  const v = own(m, name);
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

export function href(m: Obj, name: string): string | null {
  const v = own(m, name);
  return typeof v === 'string' && isSafeHref(v) ? v : null;
}

/** The object entries of a list; anything that is no list counts as none. */
export function objects(v: unknown): Obj[] {
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
const ACTIONS = [
  'username',
  'email',
  'password',
  'pin',
  'totp',
  'recovery_codes',
  'passkeys',
  'api_keys',
  'app_passwords',
  'sessions',
  'programs',
  'services',
] as const;

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
  const actions = group(data, 'actions');
  const totp = own(signIn, 'totp');
  const passkeys = own(signIn, 'passkeys');
  const approvals = own(data, 'approvals');
  const pending = isObject(approvals) ? count(approvals, 'pending') : null;
  const appPasswords = own(programs, 'app_passwords');
  const apiKeys = own(programs, 'api_keys');
  const events = own(data, 'events');
  const admin = own(data, 'admin');
  const accounts = isObject(admin) ? href(admin, 'accounts') : null;
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
        handle: text(e, 'handle'),
        end: href(e, 'end'),
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
      api_keys: Array.isArray(apiKeys)
        ? objects(apiKeys).map((e) => ({
            name: text(e, 'name'),
            kind: text(e, 'kind'),
            created_at: count(e, 'created_at'),
            last_used: count(e, 'last_used'),
            expires_at: count(e, 'expires_at'),
          }))
        : null,
    },
    approvals: pending === null ? null : { pending },
    permissions: permissionsView(own(data, 'permissions')),
    links: Object.fromEntries(LINKS.map((n) => [n, href(links, n)])) as unknown as AccountLinks,
    actions: Object.fromEntries(ACTIONS.map((n) => [n, href(actions, n)])) as unknown as AccountActions,
    events: objects(events).map((e) => ({
      at: count(e, 'at'),
      event: text(e, 'event'),
      by_admin: flag(e, 'by_admin'),
    })),
    admin: accounts === null ? null : { accounts },
  };
}

/** The longest `state` an action page carries back (spec section 8c). */
export const ACTION_STATE_MAX = 128;

const PRINTABLE_ASCII = /^[\x21-\x7e]*$/;

/** Every character but `A-Z a-z 0-9 - . _ ~` as `%XX` (upper case); the text is printable ASCII. */
function queryEscape(value: string): string {
  return value.replace(/[^A-Za-z0-9\-._~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`);
}

/**
 * The address of an action page with the way back (spec section 8c): `href` is a member of `actions` or a session's
 * `end` (ending exactly that session), `returnTo` the absolute http(s) URL on the application's own host to come back
 * to, `state` an optional value of the application (null, undefined or empty for none; printable ASCII, at most 128
 * characters). Send the person there by navigation; the page leads back with `ts_action`, `ts_result` and `state`.
 * Throws a `ConfigError` for an href that fails the rule of spec section 8 or carries a fragment, a `returnTo` that is
 * no absolute http(s) URL of printable ASCII, and a `state` outside the rule.
 */
export function actionUrl(href: string, returnTo: string, state?: string | null): string {
  if (typeof href !== 'string' || !isSafeHref(href) || href.includes('#')) {
    throw new ConfigError('actionUrl: the href is no action page address');
  }
  if (typeof returnTo !== 'string' || !/^https?:\/\//i.test(returnTo) || !PRINTABLE_ASCII.test(returnTo)) {
    throw new ConfigError('actionUrl: returnTo must be an absolute http(s) URL in printable ASCII');
  }
  const s = state ?? '';
  if (typeof s !== 'string' || s.length > ACTION_STATE_MAX || !PRINTABLE_ASCII.test(s)) {
    throw new ConfigError(`actionUrl: state is printable ASCII of at most ${ACTION_STATE_MAX} characters`);
  }
  const url = `${href}${href.includes('?') ? '&' : '?'}return=${queryEscape(returnTo)}`;
  return s === '' ? url : `${url}&state=${queryEscape(s)}`;
}

/** §8a `permissions`: an object gives `{app, names}` (non-strings dropped, `names` no list → []), anything else null. */
function permissionsView(value: unknown): { app: string | null; names: string[] } | null {
  if (!isObject(value)) {
    return null;
  }
  const names = own(value, 'names');
  return {
    app: text(value, 'app'),
    names: Array.isArray(names) ? names.filter((n): n is string => typeof n === 'string') : [],
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
