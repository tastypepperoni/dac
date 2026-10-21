package dac

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"strings"
	"time"
)

// Outcome is a verification result (§6.3).
type Outcome string

const (
	Confirmed    Outcome = "confirmed"
	NotConfirmed Outcome = "not-confirmed"
	None         Outcome = "none"
	TempError    Outcome = "temperror"
	PermError    Outcome = "permerror"
)

// Report reasons (§13.3.3).
const (
	ReasonUnconfirmedToken      = "unconfirmed-token"
	ReasonDifferentChild        = "different-child"
	ReasonExpired               = "expired"
	ReasonMalformedConfirmation = "malformed-confirmation"
)

// MaxReuse is the longest a result may be reused (§6.6).
const MaxReuse = 86400 * time.Second

// DefaultHTTPFreshness applies when a response carries no max-age (§7.2).
const DefaultHTTPFreshness = 3600 * time.Second

// Result is the output of the procedure (§6.1).
type Result struct {
	Outcome Outcome `json:"result"`
	Detail  string  `json:"detail"`
	Child   string  `json:"child"`
	Parent  string  `json:"parent,omitempty"`
	Channel string  `json:"channel,omitempty"`
	// Authenticated is "dnssec", "dnssec+webpki", or empty (§6.5).
	Authenticated string `json:"authenticated,omitempty"`
	// Mode is "enforce" or "test" when a marker was obtained (§4.4).
	Mode string `json:"mode,omitempty"`
	// Contact is the marker's abuse contact; it is authenticated only when
	// the marker is (§6.5), which ContactAuthenticated reports.
	Contact              string `json:"contact,omitempty"`
	ContactAuthenticated bool   `json:"contact_authenticated,omitempty"`
	// Subtree is set when the confirmation covers names below the child (§4.3).
	Subtree bool   `json:"subtree,omitempty"`
	Expires string `json:"expires,omitempty"`
	// Reuse is how long the result may be reused (§6.6).
	Reuse        time.Duration `json:"-"`
	ReuseSeconds int64         `json:"reuse_seconds"`
	// ReportTo and ReportReason are set when a failure report may be sent (§9.1).
	ReportTo     string    `json:"report_to,omitempty"`
	ReportReason string    `json:"report_reason,omitempty"`
	Observed     time.Time `json:"observed"`
}

// Verifier carries out the procedure of §6.
type Verifier struct {
	Resolver Resolver
	// Fetcher enables the "https" channel.  With a nil Fetcher, the channel is
	// unsupported and yields "not-confirmed" (§6.2 step 2d).
	Fetcher *Fetcher
	// Limiter, if set, rate-limits queries and requests per parent domain; it
	// SHOULD be set when names to verify come from untrusted sources (§11.11).
	Limiter *ParentLimiter
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

// noRecord implements "no record" (§6.2): NXDOMAIN, or NOERROR with no DAC record.
func noRecord(a DNSAnswer) bool {
	if a.Rcode == "NXDOMAIN" {
		return true
	}
	for _, t := range a.TXT {
		if IsDAC(t) {
			return false
		}
	}
	return true
}

func temporary(a DNSAnswer) bool { return a.Rcode != "NOERROR" && a.Rcode != "NXDOMAIN" }

// single returns the only DAC record of an answer, or an error if there is more
// than one or it is malformed.
func single(a DNSAnswer) (*Record, error) {
	var recs []string
	for _, t := range a.TXT {
		if IsDAC(t) {
			recs = append(recs, t)
		}
	}
	if len(recs) != 1 {
		return nil, fmt.Errorf("%d DAC records", len(recs))
	}
	return Parse(recs[0])
}

func minDur(ds ...time.Duration) time.Duration {
	m := MaxReuse
	for _, d := range ds {
		if d < m {
			m = d
		}
	}
	if m < 0 {
		m = 0
	}
	return m
}

// ValidContact returns r if it is a URI with scheme "mailto" or "https";
// otherwise "" (§4.4: verifiers ignore other "r" tags).
func ValidContact(r string) string {
	u, err := url.Parse(r)
	if err != nil || (u.Scheme != "mailto" && u.Scheme != "https") {
		return ""
	}
	if u.Scheme == "mailto" && u.Opaque == "" {
		return ""
	}
	if u.Scheme == "https" && u.Host == "" {
		return ""
	}
	return r
}

// ValidReportURI returns f if it meets the conditions of §4.4 for the given
// parent; otherwise "".  Accepted forms: "https://" host [path] with no
// userinfo, port, query or fragment, where path is an RFC 3986 path-abempty;
// "mailto:" exactly one address (an RFC 5322 dot-atom local part) with no
// header fields.  The host or address domain is canonical and is the parent
// domain or below it.
func ValidReportURI(f, parent string) string {
	switch {
	case strings.HasPrefix(f, "https://"):
		rest := f[len("https://"):]
		host, path := rest, ""
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			host, path = rest[:i], rest[i:]
		}
		if !IsCanonical(host) || !IsBelowOrEqual(host, parent) {
			return "" // also rejects userinfo ("@") and ports (":")
		}
		if !validPathAbempty(path) {
			return ""
		}
		return f
	case strings.HasPrefix(f, "mailto:"):
		addr := f[len("mailto:"):]
		at := strings.IndexByte(addr, '@')
		if at <= 0 || strings.Count(addr, "@") != 1 {
			return ""
		}
		local, domain := addr[:at], addr[at+1:]
		if !validDotAtom(local) || !IsCanonical(domain) || !IsBelowOrEqual(domain, parent) {
			return "" // also rejects "?" header fields, "," lists and percent-encoding
		}
		return f
	}
	return ""
}

func isHex(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }

// validPathAbempty checks RFC 3986 path-abempty = *( "/" segment ), with
// segment = *pchar and pchar = unreserved / pct-encoded / sub-delims / ":" / "@".
// ";" cannot occur in a tag value and is therefore never present.
func validPathAbempty(p string) bool {
	if p != "" && p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case isAlpha(c) || isDigit(c) || strings.IndexByte("-._~!$&'()*+,=:@/", c) >= 0:
		case c == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

// validDotAtom checks an RFC 5322 dot-atom-text local part, excluding the
// characters that a mailto URI would require to be percent-encoded.
func validDotAtom(l string) bool {
	if l == "" || l[0] == '.' || l[len(l)-1] == '.' || strings.Contains(l, "..") {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(isAlpha(c) || isDigit(c) || c == '.' || strings.IndexByte("!$&'*+-=^_`{|}~", c) >= 0) {
			return false
		}
	}
	return true
}

// Verify evaluates one child domain.
func (v *Verifier) Verify(ctx context.Context, childInput string) Result {
	now := v.now()
	child, err := CanonicalInput(childInput)
	if err != nil {
		return Result{Outcome: PermError, Detail: err.Error(), Child: childInput, Observed: now}
	}
	r := Result{Child: child, Observed: now}
	// secure tracks whether every DNS answer used so far was validated as
	// secure; webpki whether an HTTPS response was obtained (§6.5).
	secure, webpki := false, false
	done := func(o Outcome, detail string, reuse ...time.Duration) Result {
		r.Outcome, r.Detail = o, detail
		r.Authenticated = ""
		if o != TempError && secure {
			r.Authenticated = "dnssec"
			if webpki {
				r.Authenticated = "dnssec+webpki"
			}
		}
		r.Reuse = 0 // results without stated TTLs are not reused
		if len(reuse) > 0 {
			r.Reuse = minDur(reuse...)
		}
		r.ReuseSeconds = int64(r.Reuse / time.Second)
		if o != NotConfirmed && o != PermError {
			r.ReportReason = ""
		}
		if r.ReportReason == "" {
			r.ReportTo = ""
		}
		return r
	}

	// Step 1: the claim.
	claimName := Label + "." + child
	if len(claimName) > 253 {
		return done(None, "claim name would exceed 253 octets")
	}
	a := v.Resolver.LookupTXT(ctx, claimName)
	if temporary(a) {
		return done(TempError, "claim lookup: "+a.Rcode)
	}
	secure = a.Secure
	if noRecord(a) {
		return done(None, "no claim", a.TTL)
	}
	claim, err := single(a)
	if err != nil {
		return done(PermError, "claim: "+err.Error())
	}
	p, hasP := claim.Get("p")
	t, hasT := claim.Get("t")
	if !hasP && !hasT {
		return done(None, "record at the claim name is a marker only", a.TTL)
	}
	if !hasP || !hasT {
		return done(PermError, "claim has only one of p and t")
	}
	if p == child {
		return done(PermError, "claim names the child as its own parent")
	}
	r.Parent = p

	if v.Limiter != nil {
		if err := v.Limiter.Wait(ctx, p); err != nil {
			return done(TempError, "rate limit for parent: "+err.Error())
		}
	}

	// Step 2: the marker.
	markerName := Label + "." + p
	if len(markerName) > 253 {
		return done(NotConfirmed, "marker name would exceed 253 octets", a.TTL)
	}
	m := v.Resolver.LookupTXT(ctx, markerName)
	if temporary(m) {
		return done(TempError, "marker lookup: "+m.Rcode)
	}
	secure = secure && m.Secure
	r.ContactAuthenticated = m.Secure
	if m.ViaAlias { // (a)
		return done(PermError, "marker answer contains a CNAME or DNAME record")
	}
	if noRecord(m) { // (b)
		return done(NotConfirmed, "parent publishes no marker", a.TTL, m.TTL)
	}
	marker, err := single(m) // (c); any p and t tags belong to the parent's own claim
	if err != nil {
		return done(PermError, "marker: "+err.Error())
	}
	channel := "dns"
	if c, ok := marker.Get("c"); ok {
		channel = c
	}
	r.Channel = channel
	r.Mode = "enforce"
	if mv, ok := marker.Get("m"); ok && mv != "enforce" {
		r.Mode = "test" // any value other than "enforce" is treated as "test"
	}
	if rv, ok := marker.Get("r"); ok {
		r.Contact = ValidContact(rv)
	}
	if fv, ok := marker.Get("f"); ok {
		r.ReportTo = ValidReportURI(fv, p)
	}
	if channel != "dns" && (channel != "https" || v.Fetcher == nil) { // (d)
		r.ReportTo = "" // no reports for an unsupported channel
		return done(NotConfirmed, fmt.Sprintf("unsupported channel %q", channel), a.TTL, m.TTL)
	}

	// Step 3: the confirmation.
	var conf *Record
	var reuse time.Duration
	if channel == "dns" {
		confName := t + "." + Label + "." + p
		if len(confName) > 253 {
			r.ReportReason = ReasonUnconfirmedToken
			return done(NotConfirmed, "confirmation name would exceed 253 octets", a.TTL, m.TTL)
		}
		q := v.Resolver.LookupTXT(ctx, confName)
		if temporary(q) {
			return done(TempError, "confirmation lookup: "+q.Rcode)
		}
		secure = secure && q.Secure
		if noRecord(q) {
			r.ReportReason = ReasonUnconfirmedToken
			return done(NotConfirmed, "parent does not confirm the token", a.TTL, m.TTL, q.TTL)
		}
		conf, err = single(q)
		if err != nil {
			r.ReportReason = ReasonMalformedConfirmation
			return done(PermError, "confirmation: "+err.Error())
		}
		reuse = minDur(a.TTL, m.TTL, q.TTL)
	} else {
		var o Outcome
		var detail string
		conf, reuse, o, detail = v.https(ctx, p, t)
		if o == TempError || (o == PermError && detail == noGlobalDetail) {
			secure = secure && o != PermError // no-address results rest on an unauthenticated lookup
		} else {
			webpki = true // a response was obtained over validated TLS
		}
		if conf == nil {
			switch o {
			case NotConfirmed:
				r.ReportReason = ReasonUnconfirmedToken
				return done(o, detail, a.TTL, m.TTL, reuse)
			case PermError:
				r.ReportReason = ReasonMalformedConfirmation
				return done(o, detail)
			default:
				return done(o, detail)
			}
		}
		reuse = minDur(a.TTL, m.TTL, reuse)
	}

	// Step 4: the "d" tag.
	d, ok := conf.Get("d")
	if !ok {
		r.ReportReason = ReasonMalformedConfirmation
		return done(PermError, "confirmation has no d tag")
	}
	if d != child {
		r.ReportReason = ReasonDifferentChild
		return done(NotConfirmed, "confirmation names "+d, reuse)
	}
	if x, ok := conf.Get("x"); ok {
		end, _ := ParseExpiry(x) // validated by Parse
		r.Expires = x
		if !now.Before(end) {
			r.ReportReason = ReasonExpired
			return done(NotConfirmed, "confirmation expired at the end of "+x, reuse)
		}
		reuse = minDur(reuse, end.Sub(now))
	}
	if s, ok := conf.Get("s"); ok && s == "subtree" {
		r.Subtree = true
	}
	return done(Confirmed, "parent confirms child", reuse)
}

const noGlobalDetail = "parent has no globally reachable address"

// https obtains a confirmation over the HTTPS channel (§7).  It returns the
// record, or nil with the outcome to report.
func (v *Verifier) https(ctx context.Context, parent, token string) (*Record, time.Duration, Outcome, string) {
	h := v.Fetcher.Get(ctx, parent, "/.well-known/affiliation/"+token)
	switch {
	case h.Status == StatusNoGlobalAddress:
		return nil, 0, PermError, noGlobalDetail
	case h.Status == StatusTransport || (h.Status >= 500 && h.Status <= 599):
		return nil, 0, TempError, fmt.Sprintf("HTTPS request failed (status %d)", h.Status)
	case h.Status == 404 || h.Status == 410:
		return nil, freshness(h), NotConfirmed, "parent does not confirm the token"
	case h.Status != 200:
		return nil, 0, PermError, fmt.Sprintf("HTTPS status %d", h.Status)
	}
	mt, _, err := mime.ParseMediaType(h.ContentType)
	if (err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter)) || mt != "text/plain" {
		return nil, 0, PermError, "HTTPS response is not text/plain"
	}
	if h.TooLarge {
		return nil, 0, PermError, "HTTPS content longer than 1024 octets"
	}
	body := h.Body
	for _, c := range body {
		if c >= 0x80 {
			return nil, 0, PermError, "HTTPS content is not ASCII"
		}
	}
	text := string(body)
	if strings.HasSuffix(text, "\r\n") {
		text = text[:len(text)-2]
	} else if strings.HasSuffix(text, "\n") {
		text = text[:len(text)-1]
	}
	if strings.ContainsAny(text, "\r\n") || !IsDAC(text) {
		return nil, 0, PermError, "HTTPS content is not exactly one DAC record"
	}
	rec, err := Parse(text)
	if err != nil {
		return nil, 0, PermError, "confirmation: " + err.Error()
	}
	return rec, freshness(h), Confirmed, ""
}

// freshness implements §7.2: zero for no-store or no-cache, otherwise max-age,
// otherwise 3600 seconds.
func freshness(h HTTPResult) time.Duration {
	switch {
	case h.NoStore:
		return 0
	case h.MaxAge != nil:
		return time.Duration(*h.MaxAge) * time.Second
	default:
		return DefaultHTTPFreshness
	}
}

// MaxExtraLevels is the most levels a verifier follows beyond the first parent (§5.4).
const MaxExtraLevels = 2

// VerifyLevels verifies child and then, while each step is confirmed, its
// parent as a child, following at most extra (≤ MaxExtraLevels) levels beyond
// the first parent and stopping if a domain repeats (§5.4).  Each result means
// only what §8 states about its own pair.
func (v *Verifier) VerifyLevels(ctx context.Context, child string, extra int) []Result {
	if extra > MaxExtraLevels {
		extra = MaxExtraLevels
	}
	seen := map[string]bool{}
	var out []Result
	cur := child
	for i := 0; i <= extra; i++ {
		res := v.Verify(ctx, cur)
		out = append(out, res)
		seen[res.Child] = true
		if res.Outcome != Confirmed || res.Parent == "" || seen[res.Parent] {
			break
		}
		cur = res.Parent
	}
	return out
}
