package dac

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the value of the "v" tag (§4.1).
const Version = "DAC1"

// Label is the underscored node name (§4.2, §13.1).
const Label = "_affiliation"

// ErrMalformed is returned (wrapped) for DAC records that are not well-formed.
var ErrMalformed = errors.New("malformed DAC record")

// Record is a well-formed DAC record: an ordered set of tags (§4.1).
type Record struct {
	tags  map[string]string
	order []string
}

// Get returns the value of a tag and whether it is present.
func (r *Record) Get(name string) (string, bool) {
	v, ok := r.tags[name]
	return v, ok
}

// Tags returns the tag names in the order they appear.
func (r *Record) Tags() []string { return append([]string(nil), r.order...) }

func isWSP(c byte) bool { return c == ' ' || c == '\t' }

func trimWSP(s string) string {
	i, j := 0, len(s)
	for i < j && isWSP(s[i]) {
		i++
	}
	for j > i && isWSP(s[j-1]) {
		j--
	}
	return s[i:j]
}

// IsDAC reports whether the text of a TXT record is a DAC record (§4.1): after
// any leading spaces or tabs it begins with "v", optional whitespace, "=",
// optional whitespace, and "DAC1", followed by whitespace, ";", or the end.
// Other TXT records are ignored by the protocol.
func IsDAC(txt string) bool {
	s := strings.TrimLeft(txt, " \t")
	if !strings.HasPrefix(s, "v") {
		return false
	}
	s = strings.TrimLeft(s[1:], " \t")
	if !strings.HasPrefix(s, "=") {
		return false
	}
	s = strings.TrimLeft(s[1:], " \t")
	if !strings.HasPrefix(s, Version) {
		return false
	}
	s = s[len(Version):]
	return s == "" || isWSP(s[0]) || s[0] == ';'
}

func isTvalChar(c byte) bool { return (c >= 0x21 && c <= 0x3A) || (c >= 0x3C && c <= 0x7E) }

func isAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Parse parses the text of a DAC record and checks that it is well-formed
// (§4.1): it matches the "record" rule, no tag name appears more than once, and
// the value of every tag defined in the document matches its rule.
func Parse(txt string) (*Record, error) {
	items := strings.Split(txt, ";")
	// "[ *WSP ";" ] *WSP" permits one trailing ";" followed only by whitespace.
	if len(items) > 1 && trimWSP(items[len(items)-1]) == "" {
		items = items[:len(items)-1]
	}
	r := &Record{tags: map[string]string{}}
	for i, raw := range items {
		item := trimWSP(raw)
		eq := strings.IndexByte(item, '=')
		if eq < 0 {
			return nil, fmt.Errorf("%w: item %q has no '='", ErrMalformed, item)
		}
		name, value := trimWSP(item[:eq]), trimWSP(item[eq+1:])
		if name == "" || !isAlpha(name[0]) {
			return nil, fmt.Errorf("%w: bad tag name %q", ErrMalformed, name)
		}
		for j := 1; j < len(name); j++ {
			if c := name[j]; !isAlpha(c) && !isDigit(c) && c != '_' {
				return nil, fmt.Errorf("%w: bad tag name %q", ErrMalformed, name)
			}
		}
		if value == "" {
			return nil, fmt.Errorf("%w: empty value for %q", ErrMalformed, name)
		}
		for j := 0; j < len(value); j++ {
			if !isTvalChar(value[j]) {
				return nil, fmt.Errorf("%w: invalid character in value of %q", ErrMalformed, name)
			}
		}
		if _, dup := r.tags[name]; dup {
			return nil, fmt.Errorf("%w: tag %q appears more than once", ErrMalformed, name)
		}
		if i == 0 && (name != "v" || value != Version) {
			return nil, fmt.Errorf("%w: record does not begin with v=%s", ErrMalformed, Version)
		}
		r.tags[name] = value
		r.order = append(r.order, name)
	}
	if err := checkValueRules(r); err != nil {
		return nil, err
	}
	return r, nil
}

// checkValueRules checks the value rules of the tags defined in the document.
// Unknown tags are not checked; verifiers ignore them (§4.1).
func checkValueRules(r *Record) error {
	for _, name := range []string{"p", "d"} {
		if v, ok := r.tags[name]; ok && !IsCanonical(v) {
			return fmt.Errorf("%w: %s=%q is not a canonical domain name", ErrMalformed, name, v)
		}
	}
	if v, ok := r.tags["t"]; ok && !IsToken(v) {
		return fmt.Errorf("%w: t= is not 26-52 lowercase base32 characters", ErrMalformed)
	}
	if v, ok := r.tags["x"]; ok {
		if _, err := ParseExpiry(v); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
	}
	// c, m, r, s and f values are 1*tval-char, already checked above.
	return nil
}

// ParseExpiry parses an "x" value: a full-date in UTC (RFC 3339) matching
// 4DIGIT "-" 2DIGIT "-" 2DIGIT that is a valid calendar date.  It returns the
// first instant after the confirmation's validity: 00:00:00 UTC on the next day.
func ParseExpiry(v string) (time.Time, error) {
	if len(v) != 10 || v[4] != '-' || v[7] != '-' {
		return time.Time{}, fmt.Errorf("x=%q is not YYYY-MM-DD", v)
	}
	for i, c := range []byte(v) {
		if i == 4 || i == 7 {
			continue
		}
		if !isDigit(c) {
			return time.Time{}, fmt.Errorf("x=%q is not YYYY-MM-DD", v)
		}
	}
	d, err := time.Parse("2006-01-02", v)
	if err != nil || d.Format("2006-01-02") != v {
		return time.Time{}, fmt.Errorf("x=%q is not a valid calendar date", v)
	}
	return d.UTC().AddDate(0, 0, 1), nil
}

// String renders a record in the form "v=DAC1; k=v; ...".
func (r *Record) String() string {
	parts := make([]string, 0, len(r.order))
	for _, n := range r.order {
		parts = append(parts, n+"="+r.tags[n])
	}
	return strings.Join(parts, "; ")
}

// NewRecord builds a record from tag/value pairs; "v=DAC1" is added first.
// The result is checked with Parse, so only well-formed records are produced.
func NewRecord(pairs ...string) (*Record, error) {
	if len(pairs)%2 != 0 {
		return nil, errors.New("NewRecord: odd number of arguments")
	}
	parts := []string{"v=" + Version}
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			continue
		}
		parts = append(parts, pairs[i]+"="+pairs[i+1])
	}
	return Parse(strings.Join(parts, "; "))
}
