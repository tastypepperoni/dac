package dac

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Inventory is a parent operator's record of its affiliations.  It is the
// source from which the marker, confirmations and claims are generated, so
// that a confirmation exists exactly for the domains listed (§5, §10.1).
type Inventory struct {
	// Domain is the parent domain this inventory publishes for.
	Domain string `json:"domain"`
	// Channel is "dns" or "https" (§4.4).
	Channel string `json:"channel"`
	// Contact is the "r" URI; Report is the "f" URI; Mode is "enforce" or "test".
	Contact string `json:"contact,omitempty"`
	Report  string `json:"report,omitempty"`
	Mode    string `json:"mode,omitempty"`
	// TTL in seconds for generated DNS records.
	TTL int `json:"ttl"`
	// MaxAge in seconds for HTTPS confirmations (§10.5: SHOULD set max-age).
	MaxAge int `json:"max_age"`
	// Claim is this domain's own claim when it is also a child; its tags are
	// published in the same record as the marker (§4.4).
	Claim *OwnClaim `json:"claim,omitempty"`
	// Children are the confirmed child domains.
	Children []Child `json:"children"`
	// UsedTokens lists every token ever issued, so that no token is reused
	// (§4.6: MUST use a different token for each child; SHOULD use a new token
	// when re-establishing an affiliation).
	UsedTokens []string `json:"used_tokens"`
}

// OwnClaim is the claim this domain makes about its own parent.
type OwnClaim struct {
	Parent string `json:"parent"`
	Token  string `json:"token"`
}

// Child is one confirmed child domain.
type Child struct {
	Domain  string    `json:"domain"`
	Token   string    `json:"token"`
	Subtree bool      `json:"subtree,omitempty"`
	Expires string    `json:"expires,omitempty"`
	Added   time.Time `json:"added"`
}

// LoadInventory reads an inventory file.
func LoadInventory(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{}
	if err := json.Unmarshal(b, inv); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return inv, inv.Validate()
}

// Save writes the inventory atomically.
func (inv *Inventory) Save(path string) error {
	if err := inv.Validate(); err != nil {
		return err
	}
	sort.Slice(inv.Children, func(i, j int) bool { return inv.Children[i].Domain < inv.Children[j].Domain })
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate checks the inventory against the publisher requirements.
func (inv *Inventory) Validate() error {
	if !IsCanonical(inv.Domain) {
		return fmt.Errorf("domain %q is not canonical", inv.Domain)
	}
	if inv.Channel != "dns" && inv.Channel != "https" {
		return fmt.Errorf("channel must be dns or https")
	}
	if inv.Mode != "" && inv.Mode != "enforce" && inv.Mode != "test" {
		return fmt.Errorf("mode must be enforce or test")
	}
	if inv.Contact != "" && (ValidContact(inv.Contact) == "" || strings.ContainsAny(inv.Contact, "; \t")) {
		return fmt.Errorf("contact must be a mailto: or https: URI without ';' or whitespace (percent-encode them)")
	}
	if inv.Report != "" && ValidReportURI(inv.Report, inv.Domain) == "" {
		return fmt.Errorf("report URI must be https://host[/path] or mailto:address at %s or below it (Section 4.4)", inv.Domain)
	}
	if inv.TTL <= 0 {
		return fmt.Errorf("ttl must be positive")
	}
	if inv.Claim != nil {
		if !IsCanonical(inv.Claim.Parent) || inv.Claim.Parent == inv.Domain {
			return fmt.Errorf("own claim parent %q invalid", inv.Claim.Parent)
		}
		if !IsToken(inv.Claim.Token) {
			return fmt.Errorf("own claim token invalid")
		}
	}
	seen := map[string]bool{}
	tokens := map[string]bool{}
	for _, c := range inv.Children {
		if !IsCanonical(c.Domain) || c.Domain == inv.Domain {
			return fmt.Errorf("child %q invalid", c.Domain)
		}
		if seen[c.Domain] {
			return fmt.Errorf("child %q listed twice", c.Domain)
		}
		seen[c.Domain] = true
		if !IsToken(c.Token) || tokens[c.Token] {
			return fmt.Errorf("child %q: token invalid or shared with another child", c.Domain)
		}
		tokens[c.Token] = true
		if c.Expires != "" {
			if _, err := ParseExpiry(c.Expires); err != nil {
				return fmt.Errorf("child %q: %v", c.Domain, err)
			}
		}
	}
	return nil
}

func (inv *Inventory) tokenUsed(t string) bool {
	for _, u := range inv.UsedTokens {
		if u == t {
			return true
		}
	}
	return false
}

// AddChild confirms a child with a fresh token.  subtree asserts that the
// parent operates or authorizes every name below the child; it MUST NOT be set
// when others can create names below it (§4.3).
func (inv *Inventory) AddChild(domainInput string, subtree bool, expires string, now time.Time) (*Child, error) {
	d, err := CanonicalInput(domainInput)
	if err != nil {
		return nil, err
	}
	if d == inv.Domain {
		return nil, errors.New("a domain cannot be its own child")
	}
	for _, c := range inv.Children {
		if c.Domain == d {
			return nil, fmt.Errorf("%s is already confirmed; remove it first to issue a new token", d)
		}
	}
	if expires != "" {
		end, err := ParseExpiry(expires)
		if err != nil {
			return nil, err
		}
		if !now.Before(end) {
			return nil, fmt.Errorf("expiry %s is in the past", expires)
		}
	}
	var tok string
	for {
		tok, err = NewToken(DefaultTokenBits)
		if err != nil {
			return nil, err
		}
		if !inv.tokenUsed(tok) {
			break
		}
	}
	inv.UsedTokens = append(inv.UsedTokens, tok)
	c := Child{Domain: d, Token: tok, Subtree: subtree, Expires: expires, Added: now.UTC()}
	inv.Children = append(inv.Children, c)
	return &c, nil
}

// RemoveChild ends an affiliation (§5.2).  The token is kept in UsedTokens and
// is never issued again.
func (inv *Inventory) RemoveChild(domainInput string) error {
	d, err := CanonicalInput(domainInput)
	if err != nil {
		return err
	}
	for i, c := range inv.Children {
		if c.Domain == d {
			inv.Children = append(inv.Children[:i], inv.Children[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%s is not in the inventory", d)
}

// SetExpiry changes or clears a child's expiry date (§4.5).
func (inv *Inventory) SetExpiry(domainInput, expires string, now time.Time) error {
	d, err := CanonicalInput(domainInput)
	if err != nil {
		return err
	}
	if expires != "" {
		end, err := ParseExpiry(expires)
		if err != nil {
			return err
		}
		if !now.Before(end) {
			return fmt.Errorf("expiry %s is in the past", expires)
		}
	}
	for i := range inv.Children {
		if inv.Children[i].Domain == d {
			inv.Children[i].Expires = expires
			return nil
		}
	}
	return fmt.Errorf("%s is not in the inventory", d)
}

// MarkerRecord returns the record at "_affiliation.<domain>": the marker tags
// and, if the domain is also a child, its own claim tags (§4.4).
func (inv *Inventory) MarkerRecord() (string, error) {
	pairs := []string{}
	if inv.Claim != nil {
		pairs = append(pairs, "p", inv.Claim.Parent, "t", inv.Claim.Token)
	}
	if inv.Channel == "https" {
		pairs = append(pairs, "c", "https")
	}
	pairs = append(pairs, "r", inv.Contact, "f", inv.Report)
	if inv.Mode == "test" {
		pairs = append(pairs, "m", "test")
	}
	return buildChecked(pairs...)
}

// ConfirmationRecord returns the confirmation for a child (§4.5, §7.1).
func (c Child) ConfirmationRecord() (string, error) {
	s := ""
	if c.Subtree {
		s = "subtree"
	}
	return buildChecked("d", c.Domain, "s", s, "x", c.Expires)
}

// ClaimRecord returns the record the child's operator publishes at
// "_affiliation.<child>" (§4.2).  If the child is itself a parent, its operator
// adds its marker tags to this record.
func (inv *Inventory) ClaimRecord(c Child) (string, error) {
	return buildChecked("p", inv.Domain, "t", c.Token)
}

// buildChecked builds a record, re-parses it, and enforces the single
// character-string limit of 255 octets (§4.1: SHOULD).
func buildChecked(pairs ...string) (string, error) {
	r, err := NewRecord(pairs...)
	if err != nil {
		return "", err
	}
	s := r.String()
	if len(s) > 255 {
		return "", fmt.Errorf("record is %d octets; keep it within 255 (Section 4.1)", len(s))
	}
	return s, nil
}

// ZoneQuote renders a record as one quoted zone-file character-string.
func ZoneQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// ZoneLines returns zone-file lines for the parent's records: the marker and,
// for the DNS channel, one confirmation per child.  Confirmations are listed
// before the marker is needed; publish them before the children's claims (§5.1).
func (inv *Inventory) ZoneLines() ([]string, error) {
	var out []string
	m, err := inv.MarkerRecord()
	if err != nil {
		return nil, err
	}
	out = append(out, fmt.Sprintf("%s.%s. %d IN TXT %s", Label, inv.Domain, inv.TTL, ZoneQuote(m)))
	if inv.Channel == "dns" {
		for _, c := range inv.Children {
			rec, err := c.ConfirmationRecord()
			if err != nil {
				return nil, err
			}
			out = append(out, fmt.Sprintf("%s.%s.%s. %d IN TXT %s", c.Token, Label, inv.Domain, inv.TTL, ZoneQuote(rec)))
		}
	}
	return out, nil
}

// HTTPSResources returns token -> confirmation content for the HTTPS channel.
func (inv *Inventory) HTTPSResources() (map[string]string, error) {
	out := map[string]string{}
	for _, c := range inv.Children {
		rec, err := c.ConfirmationRecord()
		if err != nil {
			return nil, err
		}
		out[c.Token] = rec
	}
	return out, nil
}
