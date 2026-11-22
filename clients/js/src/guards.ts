// Guards: signed in, a role, a browser session, an account kind — answering 401 or 403 and never why (spec section 6).

import type { AccountKind, Identity } from './identity.ts';

/**
 * What a route requires: any identity, a role (compared exactly), a browser session, or an account kind (`user` for a
 * route only people may use, `service` for one only service accounts may use).
 */
export type Requirement = 'signed-in' | 'session' | { readonly role: string } | { readonly accountKind: AccountKind };

/** The outcome of a guard: allowed, 401 (not authenticated) or 403 (authenticated, requirement not met). */
export type Decision = 'allow' | 401 | 403;

/**
 * Decides a request against requirements. No identity is 401; an identity that misses a role or is no session is 403.
 * An unknown requirement denies (fails closed).
 */
export function authorize(identity: Identity | null | undefined, requirements: readonly Requirement[] = []): Decision {
  if (identity === null || identity === undefined) {
    return 401;
  }
  for (const r of requirements) {
    if (r === 'signed-in') {
      continue;
    }
    if (r === 'session') {
      if (!identity.isSession()) {
        return 403;
      }
      continue;
    }
    if (typeof r === 'object' && r !== null && 'role' in r && typeof r.role === 'string') {
      if (!identity.hasRole(r.role)) {
        return 403;
      }
      continue;
    }
    if (typeof r === 'object' && r !== null && 'accountKind' in r && typeof r.accountKind === 'string') {
      if (identity.accountKind !== r.accountKind) {
        return 403;
      }
      continue;
    }
    return 403;
  }
  return 'allow';
}

/** The body of a refusal: the status text only — never the token, the claims or the error detail. */
export function statusText(status: 401 | 403): string {
  return status === 401 ? 'Unauthorized' : 'Forbidden';
}

/** Headers of a refusal. */
export const DENY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'cache-control': 'no-store',
  'content-type': 'text/plain; charset=utf-8',
});
