// Top bar data (spec section 8): TinySesam's topbar.json reduced to what an application may render.

import { FETCH_TIMEOUT_MS, type FetchFunction, MAX_JWKS_BYTES, readLimited } from './jwks.ts';
import { asciiEqualFold, hasControl, isObject, own, parseStrictJson, parseStrictJsonText } from './strict.ts';

/** One link of the top bar. The title is text, never markup. */
export interface TopbarLink {
  readonly title: string;
  readonly href: string;
}

/**
 * The normalized top bar. Every href is an absolute http(s) URL or a path starting with exactly one slash; titles and
 * the name are text, never markup — render them with textContent or escaped. Do not cache it across sessions.
 */
export interface Topbar {
  readonly brand: string;
  readonly signed_in: boolean;
  readonly name: string | null;
  readonly links: readonly TopbarLink[];
  readonly account: string | null;
  readonly admin_panel: string | null;
  readonly logout: string | null;
}

/** The top bar of a signed-out request (also the answer to anything doubtful). */
export function signedOutTopbar(brand = ''): Topbar {
  return { brand, signed_in: false, name: null, links: [], account: null, admin_panel: null, logout: null };
}

const WHITE_SPACE = /\p{White_Space}/u;

/**
 * Whether an href may be rendered: an absolute http/https URL or a path that starts with exactly one slash (not `//`,
 * not `/\`), without whitespace or control characters.
 */
export function isSafeHref(href: string): boolean {
  if (hasControl(href) || WHITE_SPACE.test(href)) {
    return false;
  }
  if (asciiEqualFold(href.slice(0, 8), 'https://') || asciiEqualFold(href.slice(0, 7), 'http://')) {
    return true;
  }
  return href.startsWith('/') && !href.startsWith('//') && !href.startsWith('/\\');
}

/**
 * Normalizes the body of `/.tinysesam/topbar.json` or `/auth/topbar.json` (text or UTF-8 bytes). Anything but a JSON
 * object with `signed_in` true (the boolean) and a string `name` counts as signed out; unsafe links are dropped.
 */
export function parseTopbar(body: string | Uint8Array): Topbar {
  const parsed = typeof body === 'string' ? parseStrictJsonText(body) : parseStrictJson(body);
  if (parsed === null || !isObject(parsed.value)) {
    return signedOutTopbar();
  }
  const data = parsed.value;
  const brandValue = own(data, 'brand');
  const brand = typeof brandValue === 'string' ? brandValue : '';
  const name = own(data, 'name');
  if (own(data, 'signed_in') !== true || typeof name !== 'string') {
    return signedOutTopbar(brand);
  }
  const links: TopbarLink[] = [];
  const rawLinks = own(data, 'links');
  for (const l of Array.isArray(rawLinks) ? rawLinks : []) {
    if (!isObject(l)) {
      continue;
    }
    const title = own(l, 'title');
    const href = own(l, 'href');
    if (typeof title === 'string' && typeof href === 'string' && isSafeHref(href)) {
      links.push({ title, href });
    }
  }
  const shown = (slot: string): string | null => {
    const m = own(data, slot);
    if (!isObject(m) || own(m, 'shown') !== true) {
      return null;
    }
    const href = own(m, 'href');
    return typeof href === 'string' && isSafeHref(href) ? href : null;
  };
  const logoutSlot = own(data, 'logout');
  const logoutHref = isObject(logoutSlot) ? own(logoutSlot, 'href') : undefined;
  return {
    brand,
    signed_in: true,
    name,
    links,
    account: shown('account'),
    admin_panel: shown('admin_panel'),
    logout: typeof logoutHref === 'string' && isSafeHref(logoutHref) ? logoutHref : null,
  };
}

/** Only TinySesam's cookies of a Cookie header (`tinysesam_*`, `__Host-tinysesam_*`), joined again. */
export function tinysesamCookies(cookieHeader: string | null | undefined): string {
  if (!cookieHeader) {
    return '';
  }
  return cookieHeader
    .split(';')
    .map((c) => c.trim())
    .filter((c) => c.startsWith('tinysesam_') || c.startsWith('__Host-tinysesam_'))
    .join('; ');
}

/**
 * Fetches the top bar server-side: a GET to `topbarUrl` (normally `https://<auth host>/auth/topbar.json`) carrying only
 * TinySesam's cookies of the request's Cookie header, with a deadline of 5 seconds, a body limit of 64 KiB and no
 * redirects. Any failure gives the signed-out top bar. Do not cache the result across sessions.
 */
export async function fetchTopbar(
  topbarUrl: string,
  cookieHeader: string | null | undefined,
  options: { fetch?: FetchFunction } = {},
): Promise<Topbar> {
  const fetchFn = options.fetch ?? globalThis.fetch;
  try {
    const headers: Record<string, string> = { accept: 'application/json' };
    const cookies = tinysesamCookies(cookieHeader);
    if (cookies !== '') {
      headers.cookie = cookies;
    }
    const response = await fetchFn(topbarUrl, {
      method: 'GET',
      headers,
      redirect: 'error',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      return signedOutTopbar();
    }
    return parseTopbar(await readLimited(response, MAX_JWKS_BYTES));
  } catch {
    return signedOutTopbar();
  }
}
