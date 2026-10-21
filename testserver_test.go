package dac

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startTestServer(t *testing.T, zoneText string, ad bool) (*WireResolver, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	os.WriteFile(path, []byte(zoneText), 0o600)
	// pick a free port
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	s := &TestServer{ZonePath: path, AD: ad}
	go s.ListenAndServe(addr)
	time.Sleep(100 * time.Millisecond)
	return &WireResolver{Servers: []string{addr}, TrustAD: true, Timeout: 500 * time.Millisecond}, path
}

func TestTestServer(t *testing.T) {
	long := strings.Repeat("y", 255)
	zoneText := `; test zone
_affiliation.embank.example. 3600 IN TXT "v=DAC1; p=bank.example; t=` + tok + `"
_affiliation.bank.example. 600 IN TXT "v=DAC1; r=mailto:abuse@bank.example"
` + tok + `._affiliation.bank.example. 60 TXT "v=DAC1; " "d=embank.example"
*.wild.example TXT "wildcard"
alias.example CNAME target.example
target.example TXT "v=DAC1"
dn.example DNAME other.example
x.other.example TXT "rewritten"
broken.example SERVFAIL
silent.example TIMEOUT
plain.example INSECURE
plain.example TXT "x"
big.example TXT "` + long + `" "` + long + `" "` + long + `"
`
	r, _ := startTestServer(t, zoneText, true)
	ctx := context.Background()
	check := func(name, rcode string, ntxt int, alias, secure bool) DNSAnswer {
		t.Helper()
		a := r.LookupTXT(ctx, name)
		if a.Rcode != rcode || len(a.TXT) != ntxt || a.ViaAlias != alias || a.Secure != secure {
			t.Fatalf("%s: %+v", name, a)
		}
		return a
	}
	a := check(tok+"._affiliation.bank.example", "NOERROR", 1, false, true)
	if a.TXT[0] != "v=DAC1; d=embank.example" || a.TTL != 60*time.Second {
		t.Fatalf("concatenation/TTL: %+v", a)
	}
	check("_affiliation.example", "NXDOMAIN", 0, false, true)
	check("bank.example", "NOERROR", 0, false, true) // empty non-terminal
	check("anything.wild.example", "NOERROR", 1, false, true)
	check("alias.example", "NOERROR", 1, true, true)
	check("x.dn.example", "NOERROR", 1, true, true)
	check("broken.example", "SERVFAIL", 0, false, false)
	check("silent.example", "TIMEOUT", 0, false, false)
	check("plain.example", "NOERROR", 1, false, false)
	if a := check("big.example", "NOERROR", 1, false, true); len(a.TXT[0]) != 765 {
		t.Fatal("TCP fallback for large answer")
	}
	v := &Verifier{Resolver: r, Now: func() time.Time { return testNow }}
	if res := v.Verify(ctx, "embank.example"); res.Outcome != Confirmed || res.Authenticated != "dnssec" {
		t.Fatalf("verify via testdns: %+v", res)
	}
}

func TestTestServerReload(t *testing.T) {
	r, path := startTestServer(t, `a.example TXT "one"`+"\n", false)
	if a := r.LookupTXT(context.Background(), "a.example"); len(a.TXT) != 1 || a.TXT[0] != "one" {
		t.Fatalf("%+v", a)
	}
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(path, []byte(`a.example TXT "two"`+"\n"), 0o600)
	now := time.Now().Add(time.Second)
	os.Chtimes(path, now, now)
	if a := r.LookupTXT(context.Background(), "a.example"); len(a.TXT) != 1 || a.TXT[0] != "two" {
		t.Fatalf("reload: %+v", a)
	}
}
