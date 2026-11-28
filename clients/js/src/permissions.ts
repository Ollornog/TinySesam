import { ConfigError } from './errors.ts';
import { checkJwksUrl } from './gate.ts';
import { FETCH_TIMEOUT_MS, type FetchFunction, MAX_JWKS_BYTES } from './jwks.ts';
import { hasControl, parseStrictJson } from './strict.ts';

/** The application id rule of TinySesam's `apps` and the permission name rule (ADR-17). */
const APP_ID = /^[a-z][a-z0-9_]{0,31}$/;
const PERMISSION_NAME = /^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}$/;

/** The largest manifest TinySesam takes per application. */
export const MAX_PERMISSIONS = 200;

/** The request {@link registerPermissions} sends: PUT `<base>/auth/api/apps/<app>/permissions` with `body` as JSON. */
export interface PermissionRequest {
  readonly method: 'PUT';
  readonly url: string;
  readonly body: { readonly permissions: readonly unknown[] };
}

/** TinySesam did not take the manifest: not reachable (`status` 0) or any answer but 200. */
export class RegistrationFailed extends Error {
  readonly status: number;

  constructor(message: string, status = 0) {
    super(message);
    this.name = 'RegistrationFailed';
    this.status = status;
  }
}

/** The base URL without trailing slashes — a loop, not a regular expression, so its time stays linear. */
function withoutTrailingSlashes(url: string): string {
  let end = url.length;
  while (end > 0 && url[end - 1] === '/') end--;
  return url.slice(0, end);
}

/**
 * Checks a manifest the way spec section 3.4 asks and builds the request, without sending it. Throws a
 * {@link ConfigError} for a base URL that is not https (plain http only to a loopback address), an application id
 * outside the rule, a manifest that is no list or has more than 200 entries, an entry that is no object or whose
 * name breaks the rule, and a name twice. TinySesam checks labels and descriptions itself.
 */
export function registerRequest(baseUrl: string, app: string, permissions: unknown): PermissionRequest {
  try {
    checkJwksUrl(baseUrl);
  } catch {
    throw new ConfigError('baseUrl must be https (plain http only to a loopback address)');
  }
  if (typeof app !== 'string' || !APP_ID.test(app)) {
    throw new ConfigError('the application id must match ^[a-z][a-z0-9_]{0,31}$');
  }
  if (!Array.isArray(permissions) || permissions.length > MAX_PERMISSIONS) {
    throw new ConfigError(`the manifest is a list of at most ${MAX_PERMISSIONS} permissions`);
  }
  const seen = new Set<string>();
  for (const entry of permissions) {
    const name =
      typeof entry === 'object' && entry !== null && !Array.isArray(entry)
        ? (entry as Record<string, unknown>).name
        : undefined;
    if (typeof name !== 'string' || !PERMISSION_NAME.test(name)) {
      throw new ConfigError('every permission is an object whose name matches the rule of spec section 3.4');
    }
    if (seen.has(name)) {
      throw new ConfigError('a permission name twice');
    }
    seen.add(name);
  }
  return {
    method: 'PUT',
    url: `${baseUrl.replace(/\/+$/, '')}/auth/api/apps/${app}/permissions`,
    body: { permissions },
  };
}

/**
 * Registers the application's whole manifest with TinySesam (PUT /auth/api/apps/{id}/permissions) with an automation
 * key of the application's service account (scope `permissions:register`), straight to TinySesam, never through the
 * proxy. Registering grants nothing. Resolves to TinySesam's answer (`added`, `updated`, `returned`, `orphaned`); a
 * manifest {@link registerRequest} refuses is never sent; any answer but 200 rejects with {@link RegistrationFailed}.
 * Deadline 5 seconds; the key goes in `X-Api-Key` and never into an error.
 */
export async function registerPermissions(
  baseUrl: string,
  app: string,
  permissions: unknown,
  apiKey: string,
  options: { fetch?: FetchFunction } = {},
): Promise<Record<string, unknown>> {
  const req = registerRequest(baseUrl, app, permissions);
  if (typeof apiKey !== 'string' || apiKey === '' || hasControl(apiKey)) {
    throw new ConfigError('an API key is required');
  }
  const doFetch: FetchFunction = options.fetch ?? ((input, init) => fetch(input, init));
  let response: Response;
  try {
    response = await doFetch(req.url, {
      method: req.method,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Api-Key': apiKey },
      body: JSON.stringify(req.body),
      redirect: 'error',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch {
    throw new RegistrationFailed('TinySesam not reachable');
  }
  const raw = new Uint8Array(await response.arrayBuffer());
  if (response.status !== 200) {
    throw new RegistrationFailed(`TinySesam refused the manifest (${response.status})`, response.status);
  }
  const parsed = raw.length > MAX_JWKS_BYTES ? null : parseStrictJson(raw);
  if (parsed === null || typeof parsed.value !== 'object' || parsed.value === null || Array.isArray(parsed.value)) {
    throw new RegistrationFailed('an answer that is no JSON object', response.status);
  }
  return parsed.value as Record<string, unknown>;
}

