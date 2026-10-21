package dac

import (
	"fmt"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// IDNA2008 code point validation (RFC 5892).  golang.org/x/net/idna applies
// UTS #46 mapping and validity rules, which accept some code points that
// IDNA2008 disallows (for example emoji).  §4.1 requires A-labels to be valid
// A-labels as defined by RFC 5890, so every U-label is additionally checked
// here: each code point must be PVALID, or CONTEXTO with its rule satisfied
// (CONTEXTJ is checked by the idna package's CheckJoiners option), and the
// label must be in NFC.

var foldCaser = cases.Fold()

// exceptions is RFC 5892 §2.6.
var exceptions = map[rune]string{
	0x00DF: "PVALID", 0x03C2: "PVALID", 0x06FD: "PVALID", 0x06FE: "PVALID", 0x0F0B: "PVALID", 0x3007: "PVALID",
	0x00B7: "CONTEXTO", 0x0375: "CONTEXTO", 0x05F3: "CONTEXTO", 0x05F4: "CONTEXTO", 0x30FB: "CONTEXTO",
	0x0640: "DISALLOWED", 0x07FA: "DISALLOWED", 0x302E: "DISALLOWED", 0x302F: "DISALLOWED",
	0x3031: "DISALLOWED", 0x3032: "DISALLOWED", 0x3033: "DISALLOWED", 0x3034: "DISALLOWED",
	0x3035: "DISALLOWED", 0x303B: "DISALLOWED",
}

func init() {
	for r := rune(0x0660); r <= 0x0669; r++ {
		exceptions[r] = "CONTEXTO"
	}
	for r := rune(0x06F0); r <= 0x06F9; r++ {
		exceptions[r] = "CONTEXTO"
	}
}

func assigned(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
		unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
}

// defaultIgnorable derives Default_Ignorable_Code_Point (Unicode
// DerivedCoreProperties): Other_Default_Ignorable_Code_Point + Cf +
// Variation_Selector - White_Space - FFF9..FFFB - 13430..1343F -
// Prepended_Concatenation_Mark.
func defaultIgnorable(r rune) bool {
	if !(unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r)) {
		return false
	}
	if unicode.Is(unicode.White_Space, r) || (r >= 0xFFF9 && r <= 0xFFFB) || (r >= 0x13430 && r <= 0x1343F) ||
		unicode.Is(unicode.Prepended_Concatenation_Mark, r) {
		return false
	}
	return true
}

func oldHangulJamo(r rune) bool {
	return (r >= 0x1100 && r <= 0x11FF) || (r >= 0xA960 && r <= 0xA97C) || (r >= 0xD7B0 && r <= 0xD7C6) ||
		(r >= 0xD7CB && r <= 0xD7FB)
}

// idnaProperty computes the RFC 5892 §3 derived property of r.
func idnaProperty(r rune) string {
	if p, ok := exceptions[r]; ok { // F
		return p
	}
	if !assigned(r) { // J
		return "UNASSIGNED"
	}
	if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' { // K
		return "PVALID"
	}
	if r == 0x200C || r == 0x200D { // H
		return "CONTEXTJ"
	}
	s := string(r) // B: Unstable
	if norm.NFKC.String(foldCaser.String(norm.NFKC.String(s))) != s {
		return "DISALLOWED"
	}
	if defaultIgnorable(r) || unicode.Is(unicode.White_Space, r) || unicode.Is(unicode.Noncharacter_Code_Point, r) { // C
		return "DISALLOWED"
	}
	if (r >= 0x20D0 && r <= 0x20FF) || (r >= 0x1D100 && r <= 0x1D1FF) || (r >= 0x1D200 && r <= 0x1D24F) { // D
		return "DISALLOWED"
	}
	if oldHangulJamo(r) { // I
		return "DISALLOWED"
	}
	if unicode.In(r, unicode.Ll, unicode.Lu, unicode.Lo, unicode.Nd, unicode.Lm, unicode.Mn, unicode.Mc) { // A
		return "PVALID"
	}
	return "DISALLOWED"
}

// contextO evaluates the CONTEXTO rules of RFC 5892 Appendix A.3-A.9.
func contextO(label []rune, i int) bool {
	r := label[i]
	switch {
	case r == 0x00B7: // MIDDLE DOT: between two 'l'
		return i > 0 && i < len(label)-1 && label[i-1] == 'l' && label[i+1] == 'l'
	case r == 0x0375: // GREEK KERAIA: followed by Greek
		return i < len(label)-1 && unicode.Is(unicode.Greek, label[i+1])
	case r == 0x05F3 || r == 0x05F4: // HEBREW GERESH/GERSHAYIM: preceded by Hebrew
		return i > 0 && unicode.Is(unicode.Hebrew, label[i-1])
	case r == 0x30FB: // KATAKANA MIDDLE DOT: label has Hiragana, Katakana or Han
		for _, c := range label {
			if c != 0x30FB && (unicode.Is(unicode.Hiragana, c) || unicode.Is(unicode.Katakana, c) || unicode.Is(unicode.Han, c)) {
				return true
			}
		}
		return false
	case r >= 0x0660 && r <= 0x0669: // ARABIC-INDIC DIGITS: no extended Arabic-Indic digits
		for _, c := range label {
			if c >= 0x06F0 && c <= 0x06F9 {
				return false
			}
		}
		return true
	case r >= 0x06F0 && r <= 0x06F9: // EXTENDED ARABIC-INDIC DIGITS: no Arabic-Indic digits
		for _, c := range label {
			if c >= 0x0660 && c <= 0x0669 {
				return false
			}
		}
		return true
	}
	return false
}

// checkULabel validates a U-label under IDNA2008 code point rules.
func checkULabel(u string) error {
	if !norm.NFC.IsNormalString(u) {
		return fmt.Errorf("U-label %q is not in NFC", u)
	}
	rs := []rune(u)
	for i, r := range rs {
		switch idnaProperty(r) {
		case "PVALID", "CONTEXTJ": // CONTEXTJ is checked by CheckJoiners
		case "CONTEXTO":
			if !contextO(rs, i) {
				return fmt.Errorf("U+%04X in %q does not satisfy its CONTEXTO rule", r, u)
			}
		default:
			return fmt.Errorf("U+%04X in %q is not permitted by IDNA2008", r, u)
		}
	}
	return nil
}
