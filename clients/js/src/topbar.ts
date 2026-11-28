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
  /** The links of the account menu (spec version 2); empty when the answer has none. */
  readonly menu_links: readonly TopbarLink[];
  readonly account: string | null;
  readonly admin_panel: string | null;
  readonly logout: string | null;
  /**
   * The approvals waiting for this account, when TinySesam has approvals switched on and the answer carries a count of
   * at least 0 and a safe link. Show the number with a word ("Approvals (2)"), never as a coloured dot alone.
   */
  readonly approvals: TopbarApprovals | null;
  /** What the shell draws on the application's host (spec section 8d); always present. */
  readonly frame: TopbarFrame;
}

/**
 * The part `frame` of the top bar (spec section 8d): `layout` (`top` or `side`), the application's `name` in its app
 * frame, `home` (the way back) and the frame's `links` — the last two only signed in. Without an app frame: the bar on
 * top, nothing else.
 */
export interface TopbarFrame {
  readonly layout: 'top' | 'side';
  readonly name: string | null;
  /** The application's icon: an image address (http(s), a path or a `data:image/…`) — set it as an image `src`. */
  readonly icon: string | null;
  readonly home: string | null;
  readonly links: readonly TopbarLink[];
}

/** How many approvals wait for this account and where to decide them. */
export interface TopbarApprovals {
  readonly pending: number;
  readonly href: string;
}

/** The top bar of a signed-out request (also the answer to anything doubtful). */
export function signedOutTopbar(brand = '', frame: TopbarFrame = topbarFrame(undefined, false)): Topbar {
  return {
    brand,
    signed_in: false,
    name: null,
    links: [],
    menu_links: [],
    account: null,
    admin_panel: null,
    logout: null,
    approvals: null,
    frame,
  };
}

/** `frame.icon` as a data: address: an image type of `apps[id].icon`, then printable ASCII without `"'<>\`. */
const DATA_ICON = /^data:image\/(?:png|gif|jpeg|webp|svg\+xml)[;,][\x21-\x7e]+$/;
const ICON_REFUSED = /["'<>\\]/;

/**
 * `frame` of spec section 8d: layout exactly `side` or else `top`, name text or null; home and links only signed in
 * (a safe href, the safe `{title, href}` entries). Anything that is no object reads as no frame.
 */
function topbarFrame(raw: unknown, signedIn: boolean): TopbarFrame {
  if (!isObject(raw)) {
    return { layout: 'top', name: null, icon: null, home: null, links: [] };
  }
  const name = own(raw, 'name');
  const icon = own(raw, 'icon');
  const home = own(raw, 'home');
  return {
    layout: own(raw, 'layout') === 'side' ? 'side' : 'top',
    name: typeof name === 'string' ? name : null,
    icon:
      typeof icon === 'string' && (isSafeHref(icon) || (DATA_ICON.test(icon) && !ICON_REFUSED.test(icon)))
        ? icon
        : null,
    home: signedIn && typeof home === 'string' && isSafeHref(home) ? home : null,
    links: signedIn ? topbarLinks(own(raw, 'links')) : [],
  };
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

/** The safe `{title, href}` entries of a link list; anything that is no list counts as none. */
function topbarLinks(raw: unknown): TopbarLink[] {
  const links: TopbarLink[] = [];
  for (const l of Array.isArray(raw) ? raw : []) {
    if (!isObject(l)) {
      continue;
    }
    const title = own(l, 'title');
    const href = own(l, 'href');
    if (typeof title === 'string' && typeof href === 'string' && isSafeHref(href)) {
      links.push({ title, href });
    }
  }
  return links;
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
    return signedOutTopbar(brand, topbarFrame(own(data, 'frame'), false));
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
    links: topbarLinks(own(data, 'links')),
    menu_links: topbarLinks(own(data, 'menu_links')),
    account: shown('account'),
    admin_panel: shown('admin_panel'),
    logout: typeof logoutHref === 'string' && isSafeHref(logoutHref) ? logoutHref : null,
    approvals: topbarApprovals(own(data, 'approvals')),
    frame: topbarFrame(own(data, 'frame'), true),
  };
}

/** `approvals` of spec section 8: a count of at least 0 and a safe href, or nothing at all. */
function topbarApprovals(raw: unknown): TopbarApprovals | null {
  if (!isObject(raw)) {
    return null;
  }
  const pending = own(raw, 'pending');
  const href = own(raw, 'href');
  if (typeof pending !== 'number' || !Number.isSafeInteger(pending) || pending < 0) {
    return null;
  }
  return typeof href === 'string' && isSafeHref(href) ? { pending, href } : null;
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
