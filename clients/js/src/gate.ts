// The gate: one explicitly configured mode, the configuration checks that stop the start, and identify().

import { ConfigError, type ErrorClass, GateError } from './errors.ts';
import {
  type HeaderNames,
  type HeaderPairs,
  headerValues,
  type Identity,
  identityFromHeaders,
  resolveHeaderNames,
} from './identity.ts';
import { type Address, type Prefix, parseAddress, parsePrefix, prefixContains } from './ip.ts';
import { type Clock, type FetchFunction, httpFetcher, JwksCache, type KeySource, StaticKeys } from './jwks.ts';
import { importPublicKey, staticKeySet } from './keys.ts';
import { isToken } from './strict.ts';
import { type Claims, finishToken, identityFromClaims, MAX_LEEWAY, parseToken, type TokenRules } from './token.ts';

/** The default name of the gate cookie (TinySesam's gate_cookie_name). */
export const DEFAULT_GATE_COOKIE = '__Host-tinysesam_gate';

/** One line per refused request: the error class and, if format-checked, the kid — never a token or claim value. */
export type RefusalLogger = (event: { readonly code: ErrorClass; readonly kid?: string }) => void;

/** Header mode: trust the Remote-* headers the proxy sets. Only safe when the proxy fulfils spec section 2.1. */
export interface HeaderModeConfig {
  readonly mode: 'header';
  /**
   * The peer addresses the proxy connects from (`127.0.0.1`, `198.51.100.0/24`, `::1`). When set, a request from any other
   * peer is refused with `untrusted_peer`. Recommended; the peer is the socket address, never X-Forwarded-For.
   */
  readonly trustedProxies?: readonly string[];
  /** Renamed headers when TinySesam's forward_headers renames them; a missing slot keeps the default name. */
  readonly headerNames?: Partial<HeaderNames>;
  /** Receives one event per refused request (optional). */
  readonly logger?: RefusalLogger;
}

/** Token mode: verify the gate token itself and ignore every Remote-* header. */
export interface TokenModeConfig {
  readonly mode: 'token';
  /** TinySesam's base_url without a trailing slash, exactly. Required. */
  readonly issuer: string;
  /**
   * The exact string the proxy names in audience_whitelist, including `|roles=...` when the route requires roles.
   * Never derived from the request. Required.
   */
  readonly audience: string;
  /** Fixed public keys, each the output of `tinysesam gate-key` (standard Base64). */
  readonly gateKeys?: readonly string[];
  /**
   * The key set address, normally `https://<auth host>/auth/gate/jwks.json`; https, or http to a loopback address
   * only. Exactly one of gateKeys and jwksUrl is required.
   */
  readonly jwksUrl?: string;
  /** The fetch function for the key set (optional; the global fetch by default). Only with jwksUrl. */
  readonly fetch?: FetchFunction;
  /** Clock leeway in seconds, 0 (the default) to 60. */
  readonly leewaySeconds?: number;
  /** The gate cookie; `__Host-tinysesam_gate` when not given. */
  readonly cookieName?: string;
  /** Read the token from this request header instead of the cookie. */
  readonly tokenHeader?: string;
  /** Receives one event per refused request (optional). */
  readonly logger?: RefusalLogger;
}

/** The configuration of a gate; the mode must be chosen explicitly. */
export type GateConfig = HeaderModeConfig | TokenModeConfig;

/** The request as the gate sees it: the header fields as they arrived and the socket address of the peer. */
export interface GateRequest {
  readonly headers: HeaderPairs;
  /** The peer's socket address (not X-Forwarded-For); needed when trustedProxies is set. */
  readonly peer?: string | null | undefined;
}

/** A verified gate token. */
export interface Verified {
  readonly identity: Identity;
  readonly claims: Claims;
}

const HEADER_KEYS = new Set(['mode', 'trustedProxies', 'headerNames', 'logger']);
const TOKEN_KEYS = new Set([
  'mode',
  'issuer',
  'audience',
  'gateKeys',
  'jwksUrl',
  'fetch',
  'leewaySeconds',
  'cookieName',
  'tokenHeader',
  'logger',
]);

/** A public key of RFC 8032 (test 1): proves at start-up that the runtime has WebCrypto Ed25519. */
const PROBE_KEY = new Uint8Array([
  0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72,
  0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
]);

function checkKeys(config: object, allowed: Set<string>, mode: string): void {
  for (const key of Object.keys(config)) {
    if (!allowed.has(key)) {
      throw new ConfigError(`"${key}" is not a setting of ${mode} mode`);
    }
  }
}

function checkJwksUrl(raw: string): void {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ConfigError('jwksUrl is not an absolute URL');
  }
  if (u.username !== '' || u.password !== '' || u.hash !== '' || u.host === '') {
    throw new ConfigError('jwksUrl must not carry credentials or a fragment');
  }
  if (u.protocol === 'https:') {
    return;
  }
  if (u.protocol === 'http:') {
    const host = u.hostname;
    const address = parseAddress(host);
    const loopback =
      host === 'localhost' ||
      (address?.length === 4 && address[0] === 127) ||
      (address?.length === 16 && address.subarray(0, 15).every((b) => b === 0) && address[15] === 1);
    if (loopback) {
      return;
    }
    throw new ConfigError('jwksUrl over plain http is allowed to a loopback address only');
  }
  throw new ConfigError('jwksUrl must use https');
}

/** Identifies requests in one configured mode. Build it with {@link createGate}. */
export class Gate {
  readonly mode: 'header' | 'token';
  readonly #names: Readonly<HeaderNames> | null;
  readonly #proxies: readonly Prefix[];
  readonly #rules: TokenRules | null;
  readonly #keys: KeySource | null;
  readonly #cookie: string;
  readonly #tokenHeader: string;
  readonly #logger: RefusalLogger | undefined;
  readonly #now: Clock;

  /** @internal Use {@link createGate}. */
  constructor(parts: {
    mode: 'header' | 'token';
    names?: Readonly<HeaderNames>;
    proxies?: readonly Prefix[];
    rules?: TokenRules;
    keys?: KeySource;
    cookie?: string;
    tokenHeader?: string;
    logger?: RefusalLogger | undefined;
    now?: Clock;
  }) {
    this.mode = parts.mode;
    this.#names = parts.names ?? null;
    this.#proxies = parts.proxies ?? [];
    this.#rules = parts.rules ?? null;
    this.#keys = parts.keys ?? null;
    this.#cookie = parts.cookie ?? DEFAULT_GATE_COOKIE;
    this.#tokenHeader = parts.tokenHeader ?? '';
    this.#logger = parts.logger;
    this.#now = parts.now ?? (() => Math.floor(Date.now() / 1000));
    Object.freeze(this);
  }

  /**
   * The identity of a request, or a {@link GateError} whose class says why not. Every error — an unexpected one inside
   * the client included — means not authenticated.
   */
  async identify(request: GateRequest): Promise<Identity> {
    try {
      if (this.mode === 'header') {
        if (this.#proxies.length > 0 && !this.#trustedPeer(request.peer)) {
          throw new GateError('untrusted_peer');
        }
        return identityFromHeaders(request.headers, this.#names ?? undefined);
      }
      const jws = this.#token(request.headers);
      return (await this.verify(jws)).identity;
    } catch (err) {
      throw err instanceof GateError ? err : new GateError('internal', 'unexpected failure');
    }
  }

  /** As {@link identify}, but null instead of an error; a refusal goes to the logger (not `unauthenticated`). */
  async identifyOrNull(request: GateRequest): Promise<Identity | null> {
    try {
      return await this.identify(request);
    } catch (err) {
      this.#log(err);
      return null;
    }
  }

  /** Checks a gate token in the order of spec section 4.4. Only for a gate in token mode. */
  async verify(jws: string): Promise<Verified> {
    try {
      if (this.#rules === null || this.#keys === null) {
        throw new GateError('internal', 'verify needs token mode');
      }
      const now = this.#now();
      const token = parseToken(jws);
      const key = await this.#keys.lookup(token.kid);
      const claims = await finishToken(token, key, this.#rules, now);
      return { identity: identityFromClaims(claims), claims };
    } catch (err) {
      throw err instanceof GateError ? err : new GateError('internal', 'unexpected failure');
    }
  }

  #trustedPeer(peer: string | null | undefined): boolean {
    const address: Address | null = typeof peer === 'string' ? parseAddress(peer) : null;
    return address !== null && this.#proxies.some((p) => prefixContains(p, address));
  }

  /** The gate token from the one configured source. */
  #token(headers: HeaderPairs): string {
    if (this.#tokenHeader !== '') {
      const values = headerValues(headers, this.#tokenHeader);
      if (values.length > 1) {
        throw new GateError('malformed', 'more than one token header');
      }
      if (values.length === 0 || values[0] === '') {
        throw new GateError('unauthenticated', 'no token');
      }
      return values[0] ?? '';
    }
    const found: string[] = [];
    for (const line of headerValues(headers, 'cookie')) {
      for (const pair of line.split(';')) {
        const eq = pair.indexOf('=');
        if (eq >= 0 && pair.slice(0, eq).trim() === this.#cookie) {
          found.push(pair.slice(eq + 1).trim());
        }
      }
    }
    if (found.length > 1) {
      throw new GateError('malformed', 'more than one gate cookie');
    }
    if (found.length === 0 || found[0] === '') {
      throw new GateError('unauthenticated', 'no token');
    }
    return found[0] ?? '';
  }

  #log(err: unknown): void {
    if (this.#logger === undefined || !(err instanceof GateError) || err.code === 'unauthenticated') {
      return;
    }
    try {
      this.#logger(err.kid === undefined ? { code: err.code } : { code: err.code, kid: err.kid });
    } catch {
      // A failing logger must not change the answer.
    }
  }
}

/**
 * Checks the configuration and builds a gate. A contradictory or incomplete configuration throws a
 * {@link ConfigError}, so the application stops at start-up instead of failing open later.
 */
export async function createGate(config: GateConfig): Promise<Gate> {
  if (typeof config !== 'object' || config === null) {
    throw new ConfigError('no configuration');
  }
  const logger = config.logger;
  if (logger !== undefined && typeof logger !== 'function') {
    throw new ConfigError('logger must be a function');
  }
  if (config.mode === 'header') {
    checkKeys(config, HEADER_KEYS, 'header');
    const names = resolveHeaderNames(config.headerNames);
    if (names === null) {
      throw new ConfigError('invalid or repeated header name');
    }
    const proxies: Prefix[] = [];
    if (config.trustedProxies !== undefined) {
      if (!Array.isArray(config.trustedProxies) || config.trustedProxies.length === 0) {
        throw new ConfigError('trustedProxies must be a non-empty list when given');
      }
      for (const p of config.trustedProxies) {
        const prefix = parsePrefix(p);
        if (prefix === null) {
          throw new ConfigError('invalid trusted proxy address or prefix');
        }
        proxies.push(prefix);
      }
    }
    return new Gate({ mode: 'header', names, proxies, logger });
  }
  if (config.mode !== 'token') {
    throw new ConfigError('mode must be "header" or "token"');
  }
  checkKeys(config, TOKEN_KEYS, 'token');
  const { issuer, audience } = config;
  if (typeof issuer !== 'string' || issuer === '' || typeof audience !== 'string' || audience === '') {
    throw new ConfigError('token mode needs issuer and audience');
  }
  const leeway = config.leewaySeconds ?? 0;
  if (!Number.isInteger(leeway) || leeway < 0 || leeway > MAX_LEEWAY) {
    throw new ConfigError(`leewaySeconds must be an integer from 0 to ${MAX_LEEWAY}`);
  }
  if (config.cookieName !== undefined && config.tokenHeader !== undefined) {
    throw new ConfigError('give either cookieName or tokenHeader, not both');
  }
  const cookie = config.cookieName ?? DEFAULT_GATE_COOKIE;
  if (typeof cookie !== 'string' || !isToken(cookie)) {
    throw new ConfigError('invalid cookieName');
  }
  const tokenHeader = config.tokenHeader ?? '';
  if (config.tokenHeader !== undefined && (typeof tokenHeader !== 'string' || !isToken(tokenHeader))) {
    throw new ConfigError('invalid tokenHeader');
  }
  if (typeof crypto === 'undefined' || (await importPublicKey(PROBE_KEY)) === null) {
    throw new ConfigError('this runtime has no WebCrypto Ed25519 (crypto.subtle with the algorithm "Ed25519")');
  }
  let keys: KeySource;
  if (config.gateKeys !== undefined && config.jwksUrl !== undefined) {
    throw new ConfigError('give either gateKeys or jwksUrl, not both');
  } else if (config.gateKeys !== undefined) {
    if (config.fetch !== undefined) {
      throw new ConfigError('fetch without jwksUrl');
    }
    if (!Array.isArray(config.gateKeys)) {
      throw new ConfigError('gateKeys must be a list');
    }
    keys = new StaticKeys(await staticKeySet(config.gateKeys));
  } else if (config.jwksUrl !== undefined) {
    if (typeof config.jwksUrl !== 'string') {
      throw new ConfigError('jwksUrl must be a string');
    }
    checkJwksUrl(config.jwksUrl);
    if (config.fetch !== undefined && typeof config.fetch !== 'function') {
      throw new ConfigError('fetch must be a function');
    }
    keys = new JwksCache(httpFetcher(config.jwksUrl, config.fetch));
  } else {
    throw new ConfigError('token mode needs gateKeys or jwksUrl');
  }
  return new Gate({ mode: 'token', rules: { issuer, audience, leeway }, keys, cookie, tokenHeader, logger });
}
