// Package dac implements Domain Affiliation Confirmation (DAC) as specified in
// draft-manelidis-dnsop-domain-affiliation-00.
//
// Section references in comments ("§6.2") refer to that document.
package dac

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// ErrName is returned (wrapped) for names that are not acceptable.
var ErrName = errors.New("invalid domain name")

// inputProfile converts user-supplied names containing non-ASCII characters
// to A-labels (§6.1: RFC 5891 conversion; UTS #46 non-transitional processing).
var inputProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

// aLabelProfile validates that an "xn--" label decodes to a valid U-label.
var aLabelProfile = idna.New(
	idna.ValidateLabels(true),
	idna.BidiRule(),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.StrictDomainName(true),
)

// IsCanonical reports whether s is a domain name in the canonical form of §4.1:
// A-labels in lowercase, no trailing dot, at most 253 octets, a last label
// that is not entirely numeric, every label matching the ABNF "label" rule,
// and every label with hyphens in the third and fourth positions a valid A-label.
// Record values are checked with this function and are never repaired.
func IsCanonical(s string) bool {
	return checkCanonical(s) == nil
}

func checkCanonical(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrName)
	}
	if len(s) > 253 {
		return fmt.Errorf("%w: longer than 253 octets", ErrName)
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return err
		}
	}
	last := labels[len(labels)-1]
	if allDigits(last) {
		return fmt.Errorf("%w: last label %q is entirely numeric", ErrName, last)
	}
	return nil
}

// checkLabel applies the ABNF rules
//
//	label    = ld-char [ *61ldh-char ld-char ]
//	ld-char  = %x61-7A / DIGIT
//	ldh-char = ld-char / "-"
//
// and the A-label requirement of §4.1.
func checkLabel(l string) error {
	if len(l) < 1 || len(l) > 63 {
		return fmt.Errorf("%w: label %q length", ErrName, l)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		isLD := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !isLD && c != '-' {
			return fmt.Errorf("%w: label %q contains %q", ErrName, l, c)
		}
		if c == '-' && (i == 0 || i == len(l)-1) {
			return fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrName, l)
		}
	}
	if len(l) >= 4 && l[2] == '-' && l[3] == '-' {
		if !strings.HasPrefix(l, "xn--") {
			return fmt.Errorf("%w: label %q has hyphens in positions 3-4 but is not an A-label", ErrName, l)
		}
		u, err := aLabelProfile.ToUnicode(l)
		if err != nil {
			return fmt.Errorf("%w: label %q is not a valid A-label: %v", ErrName, l, err)
		}
		back, err := aLabelProfile.ToASCII(u)
		if err != nil || back != l {
			return fmt.Errorf("%w: label %q does not round-trip as an A-label", ErrName, l)
		}
		if err := checkULabel(u); err != nil {
			return fmt.Errorf("%w: label %q: %v", ErrName, l, err)
		}
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// CanonicalInput converts a name supplied by a user or a relying party to
// canonical form (§6.1).  ASCII input is lowercased and a trailing dot removed;
// non-ASCII input is converted to A-labels.  The result must satisfy IsCanonical.
func CanonicalInput(name string) (string, error) {
	n := strings.TrimSpace(name)
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return "", fmt.Errorf("%w: empty", ErrName)
	}
	ascii := true
	for i := 0; i < len(n); i++ {
		if n[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		n = strings.ToLower(n)
	} else {
		a, err := inputProfile.ToASCII(n)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrName, err)
		}
		// A trailing ideographic full stop maps to "." only during conversion.
		n = strings.TrimSuffix(strings.ToLower(a), ".")
	}
	if err := checkCanonical(n); err != nil {
		return "", err
	}
	return n, nil
}

// DisplayName returns the form used when showing a name to people: the A-label
// form, followed by the Unicode form in parentheses when they differ.  Showing
// the A-label form makes confusable characters evident (§11.15).
func DisplayName(canonical string) string {
	u, err := idna.Display.ToUnicode(canonical)
	if err != nil || u == canonical {
		return canonical
	}
	return fmt.Sprintf("%s (%s)", canonical, u)
}

// IsBelowOrEqual reports whether name equals base or is below it.
// Both arguments must be canonical.
func IsBelowOrEqual(name, base string) bool {
	return name == base || strings.HasSuffix(name, "."+base)
}
