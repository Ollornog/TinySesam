// Fetching the key set (spec section 5): a deadline, a body limit, a freshness window, a rate limit, a stale limit,
// no redirects, and one shared fetch for concurrent requests. No request waits longer than one fetch deadline.

import { GateError } from './errors.ts';
import { type KeySet, parseJwks } from './keys.ts';

/** One fetch in total — connect, TLS, headers, body — in milliseconds. */
export const FETCH_TIMEOUT_MS = 5000;
/** The largest body of a key set document. */
export const MAX_JWKS_BYTES = 64 * 1024;

const DEFAULT_FRESH = 300; // seconds, when Cache-Control has no readable max-age
const MIN_FRESH = 60;
const MAX_FRESH = 3600;
const STALE_MAX = 3600; // a set more than this past its freshness is no longer used
const MIN_INTERVAL = 10; // at most one fetch attempt per this many seconds

const MAX_AGE = /(?:^|,)\s*max-age\s*=\s*([0-9]+)\s*(?:,|$)/i;

/** The answer of one fetch attempt. A fetcher throws (or rejects) for a network error or a timeout. */
export interface FetchResult {
  readonly status: number;
  readonly cacheControl?: string | null | undefined;
  readonly body: Uint8Array | string;
}

/**
 * Performs one fetch. It receives a signal that aborts at the deadline and must stop then; the cache stops waiting at
 * the deadline in any case.
 */
export type Fetcher = (signal: AbortSignal) => Promise<FetchResult>;

/** Seconds on a clock that only moves forward; only differences matter. */
export type Clock = () => number;

/** Where a verifier gets the key for a kid. */
export interface KeySource {
  lookup(kid: string): Promise<CryptoKey>;
}

/** Fixed keys from configuration. */
export class StaticKeys implements KeySource {
  readonly #keys: KeySet;

  constructor(keys: KeySet) {
    this.#keys = keys;
  }

  async lookup(kid: string): Promise<CryptoKey> {
    const key = this.#keys.get(kid);
    if (key === undefined) {
      throw new GateError('kid', 'kid not in the key set', kid);
    }
    return key;
  }
}

/** A monotonic clock in whole seconds (performance.now, so a wall clock step cannot stall or flood the cache). */
export const monotonicSeconds: Clock = () => Math.floor(performance.now() / 1000);

/** Waits for promise at most ms; resolves either way, never rejects. */
async function within(promise: Promise<unknown>, ms: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms);
  });
  try {
    await Promise.race([promise.then(noop, noop), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

function noop(): void {}

/**
 * Keeps the last good key set and decides when to fetch (spec section 5, rule 6). A request that needs keys while a
 * fetch is running shares its result and waits at most one deadline for it.
 */
export class JwksCache implements KeySource {
  readonly #fetch: Fetcher;
  readonly #clock: Clock;
  readonly #timeoutMs: number;

  #keys: KeySet | null = null;
  #freshUntil = 0;
  #attempted = false;
  #lastAttempt = 0;
  #running: Promise<void> | null = null;

  constructor(fetcher: Fetcher, options: { clock?: Clock; timeoutMs?: number } = {}) {
    this.#fetch = fetcher;
    this.#clock = options.clock ?? monotonicSeconds;
    this.#timeoutMs = Math.min(options.timeoutMs ?? FETCH_TIMEOUT_MS, FETCH_TIMEOUT_MS);
  }

  /** The key for kid now (spec section 5, rule 6); throws `key_unavailable` or `kid`. */
  async lookup(kid: string): Promise<CryptoKey> {
    const now = this.#clock();
    let fetched = false;
    if (this.#keys === null || now >= this.#freshUntil) {
      fetched = await this.#maybeFetch(now);
    }
    const keys = this.#keys as KeySet | null;
    if (keys === null || now >= this.#freshUntil + STALE_MAX) {
      throw new GateError('key_unavailable', 'no usable key set', kid);
    }
    const key = keys.get(kid);
    if (key !== undefined) {
      return key;
    }
    if (!fetched && (await this.#maybeFetch(now))) {
      const again = this.#keys?.get(kid);
      if (again !== undefined) {
        return again;
      }
    }
    throw new GateError('kid', 'kid not in the key set', kid);
  }

  /**
   * Starts a fetch if the rate allows it, or joins the one that runs, and waits for it at most one deadline. Reports
   * whether this request fetched (or shared a fetch).
   */
  async #maybeFetch(now: number): Promise<boolean> {
    if (this.#running !== null) {
      await within(this.#running, this.#timeoutMs);
      return true;
    }
    if (this.#attempted && now - this.#lastAttempt < MIN_INTERVAL) {
      return false;
    }
    this.#attempted = true;
    this.#lastAttempt = now;
    // Cleared in a later microtask, so even a fetcher that throws at once cannot leave a finished fetch marked.
    const run: Promise<void> = this.#run(now).finally(() => {
      if (this.#running === run) {
        this.#running = null;
      }
    });
    this.#running = run;
    await within(run, this.#timeoutMs);
    return true;
  }

  async #run(now: number): Promise<void> {
    try {
      const signal = AbortSignal.timeout(this.#timeoutMs);
      let result: FetchResult | undefined;
      // A fetcher that ignores its signal must not keep the fetch marked as running.
      await within(
        this.#fetch(signal).then((r) => {
          result = r;
        }),
        this.#timeoutMs,
      );
      if (result !== undefined && !signal.aborted) {
        const fresh = await interpretFetch(result);
        if (fresh !== null) {
          this.#keys = fresh.keys;
          this.#freshUntil = now + fresh.seconds;
        }
      }
    } catch {
      // A failed fetch never replaces the cached set (rule 4).
    }
  }
}

/**
 * Turns a fetch result into a key set and its freshness in seconds; null for a failed fetch (rule 4): a status other
 * than 200, a body above 64 KiB, no strict JSON, `jwks_invalid`, or no usable entry.
 */
export async function interpretFetch(r: FetchResult): Promise<{ keys: KeySet; seconds: number } | null> {
  if (r.status !== 200) {
    return null;
  }
  const size = typeof r.body === 'string' ? new TextEncoder().encode(r.body).length : r.body.length;
  if (size > MAX_JWKS_BYTES) {
    return null;
  }
  let keys: KeySet;
  try {
    keys = await parseJwks(r.body);
  } catch {
    return null;
  }
  return keys.size === 0 ? null : { keys, seconds: freshness(r.cacheControl ?? '') };
}

/**
 * Reads max-age from Cache-Control (default 300 s), clamped to 60-3600 s; no-cache and no-store do not shorten it
 * below 60 s.
 */
export function freshness(cacheControl: string): number {
  const m = MAX_AGE.exec(cacheControl);
  const fresh = m?.[1] === undefined ? DEFAULT_FRESH : Number(m[1]);
  return Math.min(Math.max(fresh, MIN_FRESH), MAX_FRESH);
}

/** Reads a response body up to max bytes; throws when it is larger, and stops reading at that point. */
export async function readLimited(response: Response, max: number): Promise<Uint8Array> {
  if (response.body === null) {
    return new Uint8Array(0);
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(noop);
      throw new Error('body larger than the limit');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/** The fetch function a key set or top bar request goes through; the global `fetch` by default. */
export type FetchFunction = (input: string, init: RequestInit) => Promise<Response>;

/**
 * Fetches the configured key set URL with the platform's `fetch`: no redirects (a redirect is a failed fetch), the
 * deadline through the signal, the body read up to 64 KiB.
 */
export function httpFetcher(url: string, fetchFn: FetchFunction = globalThis.fetch): Fetcher {
  return async (signal) => {
    const response = await fetchFn(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal,
    });
    if (response.status !== 200) {
      await response.body?.cancel().catch(noop);
      return { status: response.status, body: '' };
    }
    const body = await readLimited(response, MAX_JWKS_BYTES);
    return { status: response.status, cacheControl: response.headers.get('cache-control'), body };
  };
}
