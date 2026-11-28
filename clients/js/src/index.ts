/**
 * Gate client for applications behind TinySesam (spec/gate-client.md): header mode and token mode, guards, the top
 * bar and account overview helpers, and the approval check (spec/approval-token.md). The core uses web standards only (WebCrypto Ed25519, fetch, TextDecoder), so it runs on Node, Deno, Bun
 * and edge runtimes; the Node/Express adapter lives in the entry point `./node`.
 *
 * @module
 */

export {
  ACTION_STATE_MAX,
  type Account,
  type AccountActions,
  type AccountAppPassword,
  type AccountLinks,
  type AccountSession,
  type AccountUse,
  actionUrl,
  fetchAccount,
  parseAccount,
  type SignedInAccount,
  type SignedOutAccount,
  signedOutAccount,
} from './account.ts';
export { type ActionReturn, ActionReturnRefused, parseActionReturn } from './action-return.ts';
export {
  APPROVAL_TOKEN_TYPE,
  type ApprovalClaims,
  type ApprovalConfig,
  type ApprovalExpect,
  ApprovalVerifier,
  canonicalEntry,
  createApprovalVerifier,
  type FieldValue,
  type JtiStore,
  MAX_APPROVAL_LEEWAY,
  MAX_APPROVAL_LIFETIME,
  payloadDigest,
} from './approval.ts';
export { ConfigError, ERROR_CLASSES, type ErrorClass, errorClassOf, GateError, isGateError } from './errors.ts';
export { denyResponse, fromFetchRequest, guardResponse, identifyRequest, withGate } from './fetch.ts';
export {
  createGate,
  DEFAULT_GATE_COOKIE,
  Gate,
  type GateConfig,
  type GateRequest,
  type HeaderModeConfig,
  type RefusalLogger,
  type TokenModeConfig,
  type Verified,
} from './gate.ts';
export { authorize, type Decision, type Requirement } from './guards.ts';
export {
  type AccountKind,
  type Auth,
  DEFAULT_HEADER_NAMES,
  type HeaderNames,
  type HeaderPairs,
  Identity,
  identityFromHeaders,
  type Kind,
  parseGroups,
} from './identity.ts';
export { FETCH_TIMEOUT_MS, type FetchFunction, MAX_JWKS_BYTES } from './jwks.ts';
export { KeySet, keyId, MAX_JWKS_KEYS, parseGateKey, parseJwks } from './keys.ts';
export {
  MAX_PERMISSIONS,
  type PermissionRequest,
  RegistrationFailed,
  registerPermissions,
  registerRequest,
} from './permissions.ts';
export { type Claims, MAX_LEEWAY, MAX_LIFETIME, MAX_TOKEN_BYTES } from './token.ts';
export {
  fetchTopbar,
  isSafeHref,
  parseTopbar,
  signedOutTopbar,
  type Topbar,
  type TopbarApprovals,
  type TopbarFrame,
  type TopbarLink,
} from './topbar.ts';
