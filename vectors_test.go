package dac

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The test vectors of Appendix D of the draft, numbered as there.

const (
	tok    = "mfrggzdfmztwq2lknnwg23tpobyxe43u"
	tok2   = "onxw2zjanfzsa4tbnzsg63jaon2hezlb"
	child  = "embank.example"
	parent = "bank.example"
)

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// zone is a mock resolver: names map to answers; missing names are NXDOMAIN.
type zone map[string]DNSAnswer

func (z zone) LookupTXT(_ context.Context, q string) DNSAnswer {
	if a, ok := z[q]; ok {
		return a
	}
	return DNSAnswer{Rcode: "NXDOMAIN", TTL: 300 * time.Second}
}

func txt(recs ...string) DNSAnswer {
	return DNSAnswer{Rcode: "NOERROR", TXT: recs, TTL: 3600 * time.Second}
}

func base() zone {
	return zone{
		"_affiliation." + child:         txt("v=DAC1; p=" + parent + "; t=" + tok),
		"_affiliation." + parent:        txt("v=DAC1; r=mailto:abuse@bank.example"),
		tok + "._affiliation." + parent: txt("v=DAC1; d=" + child),
	}
}

func (z zone) with(name string, a *DNSAnswer) zone {
	out := zone{}
	for k, v := range z {
		out[k] = v
	}
	if a == nil {
		delete(out, name)
	} else {
		out[name] = *a
	}
	return out
}

func ptr(a DNSAnswer) *DNSAnswer { return &a }

func verifier(z zone) *Verifier {
	return &Verifier{Resolver: z, Now: func() time.Time { return testNow }}
}

func expect(t *testing.T, n int, r Result, want Outcome) {
	t.Helper()
	if r.Outcome != want {
		t.Fatalf("vector %d: got %s (%s), want %s", n, r.Outcome, r.Detail, want)
	}
}

func TestVectorsDNS(t *testing.T) {
	ctx := context.Background()
	claim := "_affiliation." + child
	marker := "_affiliation." + parent
	conf := tok + "._affiliation." + parent

	// 1
	r := verifier(base()).Verify(ctx, child)
	expect(t, 1, r, Confirmed)
	if r.Parent != parent || r.Channel != "dns" || r.Mode != "enforce" || r.Contact != "mailto:abuse@bank.example" || r.Subtree || r.Reuse != time.Hour {
		t.Fatalf("vector 1 details: %+v", r)
	}
	// 2-4
	expect(t, 2, verifier(base().with(claim, nil)).Verify(ctx, child), None)
	expect(t, 3, verifier(base().with(claim, ptr(txt("v=spf1 -all")))).Verify(ctx, child), None)
	expect(t, 4, verifier(base().with(claim, ptr(txt("v=DAC10; p=bank.example; t="+tok)))).Verify(ctx, child), None)
	// 5
	expect(t, 5, verifier(base().with(marker, nil)).Verify(ctx, child), NotConfirmed)
	// 6
	z := base().with("_affiliation.embank-login.example", ptr(txt("v=DAC1; p="+parent+"; t="+tok)))
	r = verifier(z).Verify(ctx, "embank-login.example")
	expect(t, 6, r, NotConfirmed)
	// 7
	expect(t, 7, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t="+tok2)))).Verify(ctx, child), NotConfirmed)
	// 8
	expect(t, 8, verifier(base().with(conf, nil)).Verify(ctx, child), NotConfirmed)
	// 9
	expect(t, 9, verifier(base().with(marker, ptr(DNSAnswer{Rcode: "NOERROR", TTL: 300 * time.Second}))).Verify(ctx, child), NotConfirmed)
	// 10, 11
	expect(t, 10, verifier(base().with(marker, ptr(DNSAnswer{Rcode: "NOERROR", TXT: []string{"v=DAC1"}, TTL: time.Hour, ViaAlias: true}))).Verify(ctx, child), PermError)
	expect(t, 11, verifier(base().with(marker, ptr(DNSAnswer{Rcode: "NOERROR", TTL: time.Hour, ViaAlias: true}))).Verify(ctx, child), PermError)
	// 12, 13
	a := txt("v=DAC1; p=" + parent + "; t=" + tok)
	a.ViaAlias = true
	expect(t, 12, verifier(base().with(claim, &a)).Verify(ctx, child), Confirmed)
	c := txt("v=DAC1; d=" + child)
	c.ViaAlias, c.TTL = true, 600*time.Second
	r = verifier(base().with(conf, &c)).Verify(ctx, child)
	expect(t, 13, r, Confirmed)
	if r.Reuse != 600*time.Second {
		t.Fatalf("vector 13 reuse %v", r.Reuse)
	}
	// 14-17
	expect(t, 14, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t="+tok, "v=DAC1; p=other.example; t="+tok2)))).Verify(ctx, child), PermError)
	expect(t, 15, verifier(base().with(conf, ptr(txt("v=DAC1; d=old.example", "v=DAC1; d="+child)))).Verify(ctx, child), PermError)
	expect(t, 16, verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; d="+child)))).Verify(ctx, child), PermError)
	expect(t, 17, verifier(base().with(conf, ptr(txt("v=DAC1; x2=y")))).Verify(ctx, child), PermError)
	// 18, 19
	expect(t, 18, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t="+strings.ToUpper(tok))))).Verify(ctx, child), PermError)
	expect(t, 19, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t=mfrggzdf")))).Verify(ctx, child), PermError)
	// 20
	t26 := strings.Repeat("a", 26)
	z = base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t="+t26))).with(t26+"._affiliation."+parent, ptr(txt("v=DAC1; d="+child)))
	expect(t, 20, verifier(z).Verify(ctx, child), Confirmed)
	// 21-24
	expect(t, 21, verifier(base().with(claim, ptr(txt("v=DAC1; p=Bank.Example.; t="+tok)))).Verify(ctx, child), PermError)
	expect(t, 22, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t="+tok+"; z=future")))).Verify(ctx, child), Confirmed)
	expect(t, 23, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent+"; p="+parent+"; t="+tok)))).Verify(ctx, child), PermError)
	expect(t, 24, verifier(base().with(claim, ptr(txt("v=DAC1; p="+child+"; t="+tok)))).Verify(ctx, child), PermError)
	// 25
	z = zone{
		claim:                      txt("v=DAC1; p=bank; t=" + tok),
		"_affiliation.bank":        txt("v=DAC1"),
		tok + "._affiliation.bank": txt("v=DAC1; d=" + child),
	}
	expect(t, 25, verifier(z).Verify(ctx, child), Confirmed)
	// 26
	expect(t, 26, verifier(base().with(claim, ptr(txt("v=DAC1; p=192.0.2.1; t="+tok)))).Verify(ctx, child), PermError)
	// 27, 28
	for n, m := range map[int]string{27: "test", 28: "other"} {
		r = verifier(base().with(marker, ptr(txt("v=DAC1; m="+m)))).Verify(ctx, child)
		expect(t, n, r, Confirmed)
		if r.Mode != "test" {
			t.Fatalf("vector %d: mode %q", n, r.Mode)
		}
	}
	// 29, 30
	r = verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; s=subtree")))).Verify(ctx, child)
	expect(t, 29, r, Confirmed)
	if !r.Subtree {
		t.Fatal("vector 29: subtree not reported")
	}
	r = verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; s=other")))).Verify(ctx, child)
	expect(t, 30, r, Confirmed)
	if r.Subtree {
		t.Fatal("vector 30: subtree reported")
	}
	// 31-35
	expect(t, 31, verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; x=2099-12-31")))).Verify(ctx, child), Confirmed)
	r = verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; x=2020-01-01")))).Verify(ctx, child)
	expect(t, 32, r, NotConfirmed)
	if r.ReportReason != ReasonExpired {
		t.Fatalf("vector 32 reason %q", r.ReportReason)
	}
	expect(t, 33, verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; x=2027-02-30")))).Verify(ctx, child), PermError)
	r = verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; x=2026-10-22")))).Verify(ctx, child)
	expect(t, 34, r, Confirmed)
	if r.Reuse != time.Hour {
		t.Fatalf("vector 34 reuse %v", r.Reuse)
	}
	r = verifier(base().with(conf, ptr(txt("v=DAC1; d="+child+"; s=subtree; x=2099-12-31")))).Verify(ctx, child)
	expect(t, 35, r, Confirmed)
	if !r.Subtree {
		t.Fatal("vector 35: subtree not reported")
	}
	// 36-39
	unknownTok := base().with(claim, ptr(txt("v=DAC1; p="+parent+"; t="+tok2)))
	r = verifier(unknownTok.with(marker, ptr(txt("v=DAC1; f=mailto:dac-reports@bank.example")))).Verify(ctx, child)
	expect(t, 36, r, NotConfirmed)
	if r.ReportTo != "mailto:dac-reports@bank.example" || r.ReportReason != ReasonUnconfirmedToken {
		t.Fatalf("vector 36: %q %q", r.ReportTo, r.ReportReason)
	}
	for n, f := range map[int][]string{
		37: {"mailto:reports@other.example"},
		38: {"mailto:r@bank.example?cc=x@other.example"},
		39: {"https://user@bank.example/r", "https://bank.example:8443/r"},
	} {
		for _, fv := range f {
			r = verifier(unknownTok.with(marker, ptr(txt("v=DAC1; f="+fv)))).Verify(ctx, child)
			expect(t, n, r, NotConfirmed)
			if r.ReportTo != "" {
				t.Fatalf("vector %d: report destination %q accepted", n, fv)
			}
		}
	}
	// 41
	r = verifier(base().with(marker, ptr(txt("v=DAC1; f=mailto:r@bank.example"))).with(conf, ptr(txt("v=DAC1; d="+child+"; d="+child)))).Verify(ctx, child)
	expect(t, 41, r, PermError)
	if r.ReportReason != ReasonMalformedConfirmation || r.ReportTo == "" {
		t.Fatalf("vector 41: %q %q", r.ReportTo, r.ReportReason)
	}
	// 42
	expect(t, 42, verifier(base().with(claim, ptr(txt("v=DAC1; r=mailto:abuse@embank.example")))).Verify(ctx, child), None)
	// 43
	gtok := strings.Repeat("g", 32)
	z = base().with(marker, ptr(txt("v=DAC1; p=group.example; t="+gtok+"; r=mailto:a@bank.example"))).
		with("_affiliation.group.example", ptr(txt("v=DAC1"))).
		with(gtok+"._affiliation.group.example", ptr(txt("v=DAC1; d="+parent)))
	expect(t, 43, verifier(z).Verify(ctx, child), Confirmed)
	expect(t, 43, verifier(z).Verify(ctx, parent), Confirmed)
	chain := verifier(z).VerifyLevels(ctx, child, 2)
	if len(chain) != 3 || chain[1].Parent != "group.example" || chain[2].Outcome != None {
		t.Fatalf("vector 43 levels: %+v", chain)
	}
	// 44
	expect(t, 44, verifier(base().with(claim, ptr(txt("v=DAC1; p="+parent)))).Verify(ctx, child), PermError)
	// 45
	r = verifier(base().with(marker, ptr(txt("v=DAC1; r=ftp://x.example")))).Verify(ctx, child)
	expect(t, 45, r, Confirmed)
	if r.Contact != "" {
		t.Fatal("vector 45: contact kept")
	}
	// 46
	for _, cv := range []string{"future", "HTTPS"} {
		expect(t, 46, verifier(base().with(marker, ptr(txt("v=DAC1; c="+cv)))).Verify(ctx, child), NotConfirmed)
	}
	// 47
	for _, name := range []string{claim, marker, conf} {
		for _, rc := range []string{"SERVFAIL", "TIMEOUT", "REFUSED", "TRUNCATED"} {
			expect(t, 47, verifier(base().with(name, ptr(DNSAnswer{Rcode: rc}))).Verify(ctx, child), TempError)
		}
	}
	// 48
	expect(t, 48, verifier(base().with(conf, ptr(DNSAnswer{Rcode: "NOERROR", TTL: 300 * time.Second}))).Verify(ctx, child), NotConfirmed)
}

func TestAuthenticated(t *testing.T) {
	ctx := context.Background()
	z := zone{}
	for k, v := range base() {
		v.Secure = true
		z[k] = v
	}
	if r := verifier(z).Verify(ctx, child); r.Authenticated != "dnssec" {
		t.Fatalf("all secure: %q", r.Authenticated)
	}
	conf := tok + "._affiliation." + parent
	a := z[conf]
	a.Secure = false
	if r := verifier(z.with(conf, &a)).Verify(ctx, child); r.Authenticated != "" {
		t.Fatalf("one insecure answer: %q", r.Authenticated)
	}
}

// --- HTTPS channel vectors 40 and 49-60 against a real TLS server ---------

type route struct {
	status int
	ctype  string
	body   string
	cc     string
	loc    string
}

func tlsFetcher(t *testing.T, routes map[string]route) (*Fetcher, func()) {
	return tlsFetcherHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("credentials sent")
		}
		rt, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if rt.ctype != "" {
			w.Header().Set("Content-Type", rt.ctype)
		}
		if rt.cc != "" {
			w.Header().Set("Cache-Control", rt.cc)
		}
		if rt.loc != "" {
			w.Header().Set("Location", rt.loc)
		}
		w.WriteHeader(rt.status)
		w.Write([]byte(rt.body))
	}))
}

func tlsFetcherHandler(t *testing.T, h http.Handler) (*Fetcher, func()) {
	srv := httptest.NewTLSServer(h)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	f := &Fetcher{
		allowAddr: func(netip.Addr) bool { return true },
		testTLS:   &tls.Config{RootCAs: pool},
		port:      port,
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
	return f, srv.Close
}

// httptest certificates are issued for "example.com"; the parent in these
// vectors is therefore example.com.
const hParent = "example.com"

func httpsZone(marker string) zone {
	return zone{
		"_affiliation." + child:          txt("v=DAC1; p=" + hParent + "; t=" + tok),
		"_affiliation." + hParent:        txt(marker),
		tok + "._affiliation." + hParent: txt("v=DAC1; d=" + child), // must not be consulted
	}
}

func TestVectorsHTTPS(t *testing.T) {
	ctx := context.Background()
	path := "/.well-known/affiliation/" + tok
	ok := "v=DAC1; d=" + child
	cases := []struct {
		n      int
		rt     *route
		want   Outcome
		reuse  time.Duration
		reason string
	}{
		{49, &route{200, "text/plain", ok, "", ""}, Confirmed, time.Hour, ""},
		{49, &route{200, "text/plain", ok + "\r\n", "max-age=600", ""}, Confirmed, 600 * time.Second, ""},
		{50, &route{200, "text/plain; charset=utf-8", ok + "\n", "", ""}, Confirmed, time.Hour, ""},
		{51, &route{200, "text/plain", ok, "no-store", ""}, Confirmed, 0, ""},
		{52, nil, NotConfirmed, -1, ReasonUnconfirmedToken},
		{53, &route{301, "text/plain", "", "", "https://example.com/elsewhere"}, PermError, -1, ReasonMalformedConfirmation},
		{54, &route{200, "text/html", ok, "", ""}, PermError, -1, ""},
		{55, &route{200, "text/plain", "v=DAC1; d=" + child + "; z=" + strings.Repeat("a", 1100), "", ""}, PermError, -1, ""},
		{56, &route{200, "text/plain", ok + "\n" + ok, "", ""}, PermError, -1, ""},
		{57, &route{200, "text/plain", "v=DAC1; d=" + child + "; d=" + child, "", ""}, PermError, -1, ""},
		{58, &route{503, "text/plain", "", "", ""}, TempError, -1, ""},
		{60, nil, NotConfirmed, -1, ""},
	}
	for _, c := range cases {
		routes := map[string]route{}
		if c.rt != nil {
			routes[path] = *c.rt
		}
		f, done := tlsFetcher(t, routes)
		v := verifier(httpsZone("v=DAC1; c=https; f=https://reports.example.com/dac"))
		v.Fetcher = f
		r := v.Verify(ctx, child)
		done()
		expect(t, c.n, r, c.want)
		if c.reuse >= 0 && r.Reuse != c.reuse {
			t.Fatalf("vector %d: reuse %v, want %v", c.n, r.Reuse, c.reuse)
		}
		if c.reason != "" && r.ReportReason != c.reason {
			t.Fatalf("vector %d: reason %q, want %q", c.n, r.ReportReason, c.reason)
		}
		if c.want == Confirmed && r.Authenticated != "" {
			t.Fatalf("vector %d: unauthenticated marker yet result authenticated", c.n)
		}
	}
	// 40: report on 404 with a valid https destination
	f, done := tlsFetcher(t, map[string]route{})
	v := verifier(httpsZone("v=DAC1; c=https; f=https://reports.example.com/dac"))
	v.Fetcher = f
	r := v.Verify(ctx, child)
	done()
	if r.ReportTo != "https://reports.example.com/dac" || r.ReportReason != ReasonUnconfirmedToken {
		t.Fatalf("vector 40: %q %q", r.ReportTo, r.ReportReason)
	}
	// 58: connection failure
	f, done = tlsFetcher(t, map[string]route{})
	done() // server closed
	v = verifier(httpsZone("v=DAC1; c=https"))
	v.Fetcher = f
	expect(t, 58, v.Verify(ctx, child), TempError)
	// 59: no globally reachable address (real filter)
	f, done = tlsFetcher(t, map[string]route{})
	f.allowAddr = nil
	v = verifier(httpsZone("v=DAC1; c=https"))
	v.Fetcher = f
	expect(t, 59, v.Verify(ctx, child), PermError)
	done()
	// Authenticated only when claim and marker are DNSSEC-secure (Section 6.5).
	f, done = tlsFetcher(t, map[string]route{path: {200, "text/plain", ok, "", ""}})
	z := zone{}
	for k, a := range httpsZone("v=DAC1; c=https") {
		a.Secure = true
		z[k] = a
	}
	v = verifier(z)
	v.Fetcher = f
	if r := v.Verify(ctx, child); r.Outcome != Confirmed || r.Authenticated != "dnssec+webpki" {
		t.Fatalf("signed marker: %s %q", r.Outcome, r.Authenticated)
	}
	// Without a fetcher, the https channel is unsupported: not-confirmed.
	v = verifier(httpsZone("v=DAC1; c=https"))
	expect(t, 46, v.Verify(ctx, child), NotConfirmed)
	done()
}

func TestWrongCertificateIsTemperror(t *testing.T) {
	// A certificate not valid for the parent is a TLS failure (Section 7.2).
	f, done := tlsFetcher(t, map[string]route{})
	defer done()
	f.testTLS = &tls.Config{RootCAs: x509.NewCertPool()}
	v := verifier(httpsZone("v=DAC1; c=https"))
	v.Fetcher = f
	expect(t, 58, v.Verify(context.Background(), child), TempError)
}
