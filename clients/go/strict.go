package tinysesam

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// decodeSegment decodes strict base64url (RFC 7515): only A-Z a-z 0-9 - _, no padding, no whitespace or line
// break, and canonical — re-encoding the bytes gives the same text, so the unused low bits are zero. Go's decoder
// skips CR and LF on its own; the alphabet check comes first for that reason.
func decodeSegment(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, false
		}
	}
	if len(s)%4 == 1 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

var errStrictJSON = errors.New("not strict JSON")

// decodeStrictJSON parses one JSON value from UTF-8 bytes the way the specification demands: strict UTF-8, no byte
// order mark, no member name twice in any object, no NaN or Infinity (encoding/json refuses those anyway), nothing
// after the value. Numbers stay json.Number so integers can be checked exactly. encoding/json alone keeps the last
// of two equal member names, so the value is built from a token walk that refuses repeats.
func decodeStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) || !json.Valid(raw) {
		return nil, errStrictJSON
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := walkJSON(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errStrictJSON
	}
	return v, nil
}

func walkJSON(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errStrictJSON
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, errStrictJSON
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errStrictJSON
				}
				if _, dup := obj[key]; dup {
					return nil, errStrictJSON
				}
				val, err := walkJSON(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errStrictJSON
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := walkJSON(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errStrictJSON
			}
			return arr, nil
		}
		return nil, errStrictJSON
	case string, json.Number, bool, nil:
		return t, nil
	}
	return nil, errStrictJSON
}

// hasControl reports a C0 control character (U+0000-U+001F, tab included) or DEL. On valid UTF-8 these are
// exactly the bytes below 0x20 and 0x7F, which never occur inside a multi-byte sequence.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// asciiEqualFold compares s with an ASCII-only lower-case reference, ignoring ASCII case only: a non-ASCII byte in
// s never matches (no Unicode case folding, so the Kelvin sign is not a k).
func asciiEqualFold(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			return false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
