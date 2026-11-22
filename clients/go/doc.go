// Package tinysesam is the gate client for Go applications behind TinySesam's gate.
//
// It answers one question per request: who is this, and may they do this? It never signs anyone in, holds no
// session and issues no token; that stays in TinySesam. The contract is spec/gate-client.md in the TinySesam
// repository, and this package passes every vector in spec/vectors/.
//
// Two operating modes, chosen explicitly by configuration (there is no fallback from one to the other):
//
//   - Header mode reads the Remote-* headers a proxy sets after asking TinySesam. It is only safe when the proxy
//     removes those headers from every client request and the application is reachable through that proxy only.
//   - Token mode verifies a gate token (an Ed25519-signed JWS) against fixed public keys or a JWKS URL.
//
// Both produce the same [Identity]. [Gate.Middleware] puts it into the request context; [RequireAuth],
// [RequireRole] and [RequireSession] guard handlers with 401 and 403 answers that never say why.
package tinysesam
