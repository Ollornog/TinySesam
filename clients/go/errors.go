package tinysesam

import "errors"

// ErrorClass names why a request was refused. The classes of the specification exist for logs and tests; to the
// application every one of them means the same: not authenticated.
type ErrorClass string

// Error classes of the specification (spec/gate-client.md, sections 2.4, 4.5 and 4.3).
const (
	ClassUnauthenticated ErrorClass = "unauthenticated" // header mode: no or empty Remote-User; token mode: no token
	ClassHeader          ErrorClass = "header"          // a malformed Remote-* header, or a forbidden JWS header member
	ClassMalformed       ErrorClass = "malformed"       // size, structure, base64url, JSON, more than one gate cookie
	ClassKid             ErrorClass = "kid"             // kid missing, malformed or not in the key set
	ClassSignature       ErrorClass = "signature"       // wrong length or verification failed
	ClassKeyUnavailable  ErrorClass = "key_unavailable" // no key set could be obtained
	ClassClaims          ErrorClass = "claims"          // wrong claim type, control character, inconsistency
	ClassIssuer          ErrorClass = "issuer"          // wrong iss
	ClassAudience        ErrorClass = "audience"        // wrong aud
	ClassLifetime        ErrorClass = "lifetime"        // exp - nbf not in (0, 3600]
	ClassNotYetValid     ErrorClass = "not_yet_valid"   // before nbf - leeway
	ClassExpired         ErrorClass = "expired"         // at or after exp + leeway
	ClassJWKSInvalid     ErrorClass = "jwks_invalid"    // a key set document of the wrong shape
)

// Classes of this client beyond the specification.
const (
	ClassUntrustedPeer ErrorClass = "untrusted_peer" // header mode: the request did not come from a trusted proxy
	ClassInternal      ErrorClass = "internal"       // an unexpected failure inside the client (fails closed)
)

// Error is a refusal. It carries the class and, once the kid has passed the format check, the kid — never the token,
// a claim value or a header value, so it is safe to log.
type Error struct {
	Class  ErrorClass
	Kid    string
	detail string
}

func (e *Error) Error() string {
	if e.detail == "" {
		return "tinysesam: " + string(e.Class)
	}
	return "tinysesam: " + string(e.Class) + ": " + e.detail
}

// Is reports whether target is a sentinel of the same class, so errors.Is(err, ErrExpired) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Class == e.Class && t.Kid == "" && t.detail == ""
}

// Sentinels for errors.Is.
var (
	ErrUnauthenticated = &Error{Class: ClassUnauthenticated}
	ErrHeader          = &Error{Class: ClassHeader}
	ErrMalformed       = &Error{Class: ClassMalformed}
	ErrKid             = &Error{Class: ClassKid}
	ErrSignature       = &Error{Class: ClassSignature}
	ErrKeyUnavailable  = &Error{Class: ClassKeyUnavailable}
	ErrClaims          = &Error{Class: ClassClaims}
	ErrIssuer          = &Error{Class: ClassIssuer}
	ErrAudience        = &Error{Class: ClassAudience}
	ErrLifetime        = &Error{Class: ClassLifetime}
	ErrNotYetValid     = &Error{Class: ClassNotYetValid}
	ErrExpired         = &Error{Class: ClassExpired}
	ErrJWKSInvalid     = &Error{Class: ClassJWKSInvalid}
	ErrUntrustedPeer   = &Error{Class: ClassUntrustedPeer}
	ErrInternal        = &Error{Class: ClassInternal}
)

// ClassOf returns the class of err, or ClassInternal for an error that did not come from this package.
func ClassOf(err error) ErrorClass {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ClassInternal
}

func refuse(class ErrorClass, detail string) *Error {
	return &Error{Class: class, detail: detail}
}

func refuseKid(class ErrorClass, kid, detail string) *Error {
	return &Error{Class: class, Kid: kid, detail: detail}
}
