// Administration data (spec section 8b): the accounts a person may administer inside the application's area, as
// TinySesam's `/.tinysesam/admin/accounts.json` answers it on the application's host — with the addresses of the
// administration action pages (section 8c) offered for each account now.

import { flag, group, href, type Obj, objects, strings, text, texts } from './account.ts';
import { isObject, own, parseStrictJson, parseStrictJsonText } from './strict.ts';

/** The administration actions of spec section 8c, each an action page's address or null (not offered now). */
export interface AdminActions {
  readonly admin_totp_reset: string | null;
  readonly admin_lock: string | null;
  readonly admin_unlock: string | null;
  readonly admin_roles: string | null;
  readonly admin_key_revoke: string | null;
  readonly admin_program_revoke: string | null;
  readonly admin_session_end: string | null;
  readonly admin_signin_link: string | null;
}

/** One account the person may administer. */
export interface AdminAccount {
  /** The account id: the claim `ts_id` and the header `Remote-Id`. */
  readonly id: string | null;
  readonly username: string | null;
  readonly display_name: string | null;
  /** Where the account comes from (`local`, `oidc`, `saml`, `ldap`); null when missing or no list. */
  readonly source: readonly string[] | null;
  readonly roles: readonly string[];
  /** The account is locked. */
  readonly disabled: boolean | null;
  /** A confirmed authenticator app; null with TOTP off. */
  readonly totp: boolean | null;
  /** The account's permissions for this application. */
  readonly permissions: readonly string[];
  readonly actions: AdminActions;
}

/** The normalized administration data: `accounts` is always a list. */
export interface AdminAccounts {
  readonly app: string | null;
  readonly links: { readonly panel: string | null };
  readonly accounts: readonly AdminAccount[];
}

const ADMIN_ACTIONS = [
  'admin_totp_reset',
  'admin_lock',
  'admin_unlock',
  'admin_roles',
  'admin_key_revoke',
  'admin_program_revoke',
  'admin_session_end',
  'admin_signin_link',
] as const;

/**
 * Normalizes the body of a 200 answer of `/.tinysesam/admin/accounts.json` (spec section 8b; text or UTF-8 bytes) —
 * fetched same-origin in the browser for a person whose account overview names it (`admin.accounts`). Anything that
 * is no JSON object reads as nothing to show; a member of the wrong type reads as missing, an unsafe href as null,
 * unknown members are dropped. Every string is text — set it with `textContent`. An address is a convenience, not a
 * right: the action page checks the person's rights again.
 */
export function parseAdminAccounts(body: string | Uint8Array): AdminAccounts {
  const parsed = typeof body === 'string' ? parseStrictJsonText(body) : parseStrictJson(body);
  const data: Obj = parsed !== null && isObject(parsed.value) ? parsed.value : {};
  const list = own(data, 'accounts');
  return {
    app: text(data, 'app'),
    links: { panel: href(group(data, 'links'), 'panel') },
    accounts: objects(Array.isArray(list) ? list : []).map((a) => {
      const actions = group(a, 'actions');
      return {
        id: text(a, 'id'),
        username: text(a, 'username'),
        display_name: text(a, 'display_name'),
        source: texts(a, 'source'),
        roles: strings(a, 'roles'),
        disabled: flag(a, 'disabled'),
        totp: flag(a, 'totp'),
        permissions: strings(a, 'permissions'),
        actions: Object.fromEntries(ADMIN_ACTIONS.map((n) => [n, href(actions, n)])) as unknown as AdminActions,
      };
    }),
  };
}
