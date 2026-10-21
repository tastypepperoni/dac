package dac

import (
	"context"
	"fmt"
)

// Finding is one result of a publisher-side check.
type Finding struct {
	Level   string // "error" (a MUST is not met), "warning" (a SHOULD), or "ok"
	Message string
}

func (f Finding) String() string { return fmt.Sprintf("%-7s %s", f.Level, f.Message) }

// CheckParent checks what the DNS publishes for an inventory's domain against
// the requirements on parents (§4.4, §4.5, §10.6) and verifies every child.
func CheckParent(ctx context.Context, v *Verifier, inv *Inventory) []Finding {
	var out []Finding
	add := func(level, format string, a ...any) {
		out = append(out, Finding{level, fmt.Sprintf(format, a...)})
	}
	name := Label + "." + inv.Domain
	m := v.Resolver.LookupTXT(ctx, name)
	switch {
	case temporary(m):
		add("error", "%s: lookup failed (%s)", name, m.Rcode)
		return out
	case m.ViaAlias:
		add("error", "%s: the marker MUST be a TXT record owned by this name, not reached through a CNAME or DNAME", name)
	case noRecord(m):
		add("error", "%s: no marker published", name)
	default:
		rec, err := single(m)
		if err != nil {
			add("error", "%s: %v (exactly one well-formed DAC record is required)", name, err)
		} else if want, _ := inv.MarkerRecord(); rec.String() != want {
			add("warning", "%s: published %q, inventory says %q", name, rec.String(), want)
		} else {
			add("ok", "%s: marker matches the inventory", name)
		}
	}
	if m.Rcode == "NOERROR" && !m.Secure {
		add("warning", "%s: not validated as secure; parents SHOULD sign their zones with DNSSEC (Section 10.6)", name)
	}

	// Wildcards at or below "_affiliation" are prohibited (§4.5, §10.6).
	probe, _ := NewToken(DefaultTokenBits)
	w := v.Resolver.LookupTXT(ctx, probe+"."+name)
	if w.Rcode == "NOERROR" && (len(w.TXT) > 0 || w.ViaAlias) {
		add("error", "%s: a random name below it has data; wildcard records MUST NOT be published at or below %s", name, name)
	}
	// Wildcard CNAMEs covering "_affiliation" SHOULD NOT be published (§10.6).
	if wc := v.Resolver.LookupTXT(ctx, probe+"."+inv.Domain); wc.Rcode == "NOERROR" && wc.ViaAlias {
		add("warning", "%s: a wildcard CNAME exists at the apex; wildcard CNAMEs SHOULD NOT cover %s", inv.Domain, name)
	}

	if inv.Channel == "dns" {
		for _, c := range inv.Children {
			cn := c.Token + "." + name
			q := v.Resolver.LookupTXT(ctx, cn)
			want, _ := c.ConfirmationRecord()
			switch {
			case temporary(q):
				add("error", "%s: confirmation lookup failed (%s)", c.Domain, q.Rcode)
			case noRecord(q):
				add("error", "%s: confirmation missing at %s", c.Domain, cn)
			default:
				rec, err := single(q)
				if err != nil {
					add("error", "%s: confirmation: %v (a confirmation name MUST NOT hold more than one DAC record)", c.Domain, err)
				} else if rec.String() != want {
					add("warning", "%s: confirmation is %q, inventory says %q", c.Domain, rec.String(), want)
				}
			}
		}
	}
	for _, c := range inv.Children {
		r := v.Verify(ctx, c.Domain)
		switch {
		case r.Outcome == Confirmed && r.Parent == inv.Domain:
			add("ok", "%s: confirmed", c.Domain)
		case r.Outcome == None:
			add("warning", "%s: the child does not publish its claim yet", c.Domain)
		case r.Parent != "" && r.Parent != inv.Domain:
			add("warning", "%s: the child claims %s instead (moved to another parent? Section 5.3)", c.Domain, r.Parent)
		default:
			add("error", "%s: %s (%s)", c.Domain, r.Outcome, r.Detail)
		}
	}
	return out
}

// CheckChild checks a child's own records (§4.2, §10.6, §11.10).
func CheckChild(ctx context.Context, v *Verifier, child string) []Finding {
	var out []Finding
	add := func(level, format string, a ...any) {
		out = append(out, Finding{level, fmt.Sprintf(format, a...)})
	}
	c, err := CanonicalInput(child)
	if err != nil {
		return []Finding{{"error", err.Error()}}
	}
	name := Label + "." + c
	a := v.Resolver.LookupTXT(ctx, name)
	if a.ViaAlias {
		add("warning", "%s: the claim is a CNAME; it SHOULD point only to names the child or its parent operator control (Section 11.10)", name)
	}
	probe, _ := NewToken(DefaultTokenBits)
	if w := v.Resolver.LookupTXT(ctx, probe+"."+name); w.Rcode == "NOERROR" && (len(w.TXT) > 0 || w.ViaAlias) {
		add("error", "%s: wildcard records MUST NOT be published at or below this name", name)
	}
	// A wildcard below the child covers "_affiliation" only if that name does
	// not exist (RFC 4592).
	if a.Rcode == "NXDOMAIN" || (a.Rcode == "NOERROR" && len(a.TXT) == 0 && !a.ViaAlias) {
		if w := v.Resolver.LookupTXT(ctx, probe+"."+c); w.Rcode == "NOERROR" && (len(w.TXT) > 0 || w.ViaAlias) {
			add("error", "%s: a wildcard below the child covers %s; children MUST NOT publish wildcards covering it (Section 11.10)", c, name)
		}
	}
	r := v.Verify(ctx, c)
	level := "ok"
	if r.Outcome != Confirmed {
		level = "error"
	}
	add(level, "%s: %s (%s)", c, r.Outcome, r.Detail)
	return out
}
