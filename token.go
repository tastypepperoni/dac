package dac

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// DefaultTokenBits is the RECOMMENDED token size (§4.6: SHOULD contain 160 bits).
const DefaultTokenBits = 160

// MinTokenBits is the minimum token size (§4.6: MUST contain at least 128 bits).
const MinTokenBits = 128

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewToken returns a token of the given size from a cryptographically secure
// random source, encoded in base32 (RFC 4648 §6) with lowercase letters and
// without padding (§4.6).  bits must be at least 128 and a multiple of 8.
func NewToken(bits int) (string, error) {
	if bits < MinTokenBits || bits%8 != 0 {
		return "", fmt.Errorf("token size %d: must be at least %d bits, in whole octets", bits, MinTokenBits)
	}
	if bits > 260 {
		return "", fmt.Errorf("token size %d: encodes to more than 52 characters", bits)
	}
	buf := make([]byte, bits/8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random source: %w", err)
	}
	return strings.ToLower(b32.EncodeToString(buf)), nil
}

// IsToken reports whether v matches the ABNF "t-value" rule: 26 to 52
// characters from the lowercase base32 alphabet.  Tokens are opaque and are
// never decoded by verifiers (§4.6).
func IsToken(v string) bool {
	if len(v) < 26 || len(v) > 52 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	return true
}
