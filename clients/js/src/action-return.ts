// The way back of an action page (spec section 8c): the address the person comes back on carries `ts_action`,
// `ts_result` and `state`. Both declarations below are self-contained — they use no import and no other declaration
// of this module but each other —, so a page without a bundler can carry their source as it is (example Ex4 does,
// and the vector test runs that copy too).

/** The way back an action page gave: which action and how it ended — a hint for a message, never a proof. */
export interface ActionReturn {
  /** One of the 21 action names of the register: the own actions and the administration's (`admin_*`). */
  readonly action: string;
  /** `done`, `cancelled` or `unavailable`. */
  readonly result: string;
}

/**
 * `parseActionReturn` refuses the way back. `reason` is `invalid` (not a way back an action page gives: an unknown
 * action or result, a name twice or missing, a broken escape) or `state` (a `state` the application did not issue).
 * Show no message for it; the application reads the account overview again anyway.
 */
export class ActionReturnRefused extends Error {
  readonly reason: 'invalid' | 'state';

  constructor(reason: 'invalid' | 'state') {
    super(`action page way back refused: ${reason}`);
    this.name = 'ActionReturnRefused';
    this.reason = reason;
  }
}

/**
 * Reads the way back of an action page (spec section 8c) from the address the person came back on — an absolute URL,
 * a path with its query or the query alone with its `?` (`location.search`); the query is what lies between the first
 * `?` and the first `#`. `state` is the value the application issued with `actionUrl` (null, undefined or empty for
 * none). Returns `{action, result}`, or null when the address carries neither `ts_action` nor `ts_result` (an ordinary
 * visit). Throws an `ActionReturnRefused`: `invalid` for a way back no action page gives (an unknown action or result,
 * one of the three names twice, one of them missing, a value outside printable ASCII, a broken escape, a `state`
 * outside the rule), `state` when the `state` that came back is not the one issued (compared in constant time). Only
 * the names `ts_action`, `ts_result` and `state` exactly as written count; every other parameter is the application's.
 */
export function parseActionReturn(address: string, state?: string | null): ActionReturn | null {
  const actions = [
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
    'session_end',
    'programs',
    'services',
    'admin_totp_reset',
    'admin_lock',
    'admin_unlock',
    'admin_roles',
    'admin_key_revoke',
    'admin_program_revoke',
    'admin_session_end',
    'admin_signin_link',
  ];
  const results = ['done', 'cancelled', 'unavailable'];
  const printable = /^[\x21-\x7e]*$/;
  // A value as written → its octets as one character each (`+` a space, `%XX` an octet), or null.
  const decode = (raw: string): string | null => {
    if (!printable.test(raw)) {
      return null;
    }
    let out = '';
    for (let i = 0; i < raw.length; i += 1) {
      const c = raw.charAt(i);
      if (c === '%') {
        const hex = raw.slice(i + 1, i + 3);
        if (!/^[0-9A-Fa-f]{2}$/.test(hex)) {
          return null;
        }
        out += String.fromCharCode(Number.parseInt(hex, 16));
        i += 2;
      } else {
        out += c === '+' ? ' ' : c;
      }
    }
    return out;
  };
  const fragment = address.indexOf('#');
  const head = fragment < 0 ? address : address.slice(0, fragment);
  const mark = head.indexOf('?');
  const query = mark < 0 ? '' : head.slice(mark + 1);
  const found: Record<string, string[]> = { ts_action: [], ts_result: [], state: [] };
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    const name = eq < 0 ? pair : pair.slice(0, eq);
    if (name === 'ts_action' || name === 'ts_result' || name === 'state') {
      found[name]?.push(eq < 0 ? '' : pair.slice(eq + 1));
    }
  }
  const [rawAction = [], rawResult = [], rawState = []] = [found.ts_action, found.ts_result, found.state];
  if (rawAction.length === 0 && rawResult.length === 0) {
    return null;
  }
  if (rawAction.length !== 1 || rawResult.length !== 1 || rawState.length > 1) {
    throw new ActionReturnRefused('invalid');
  }
  const action = decode(rawAction[0] ?? '');
  const result = decode(rawResult[0] ?? '');
  const back = rawState.length === 0 ? '' : decode(rawState[0] ?? '');
  if (action === null || result === null || back === null) {
    throw new ActionReturnRefused('invalid');
  }
  if (!actions.includes(action) || !results.includes(result) || back.length > 128 || !printable.test(back)) {
    throw new ActionReturnRefused('invalid');
  }
  // Constant time over the longer of the two: every position is looked at, the lengths count as a difference.
  const issued = state ?? '';
  let diff = back.length ^ issued.length;
  for (let i = 0; i < Math.max(back.length, issued.length); i += 1) {
    diff |= (back.charCodeAt(i) | 0) ^ (issued.charCodeAt(i) | 0);
  }
  if (diff !== 0) {
    throw new ActionReturnRefused('state');
  }
  return { action, result };
}
