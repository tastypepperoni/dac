package dac

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCanonical(t *testing.T) {
	good := []string{"bank.example", "bank", "a-b.example", "xn--lodbwdo.example", "embank.example"}
	bad := []string{"", "Bank.example", "bank.example.", "a..example", "-a.example", "a-.example",
		"a_b.example", "ab--cd.example", "xn--zz.example", "192.0.2.1", "1.2", strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "aaa"}
	for _, g := range good {
		if !IsCanonical(g) {
			t.Errorf("%q should be canonical", g)
		}
	}
	for _, b := range bad {
		if IsCanonical(b) {
			t.Errorf("%q should not be canonical", b)
		}
	}
	if c, err := CanonicalInput(" EMBANK.Example. "); err != nil || c != "embank.example" {
		t.Errorf("CanonicalInput ASCII: %q %v", c, err)
	}
	if c, err := CanonicalInput("ბანკი.example"); err != nil || c != "xn--lodbwdo.example" {
		t.Errorf("CanonicalInput IDN: %q %v", c, err)
	}
	if !strings.Contains(DisplayName("xn--lodbwdo.example"), "xn--lodbwdo.example") {
		t.Error("display must show the A-label form")
	}
}

func TestIsDACAndParse(t *testing.T) {
	for _, s := range []string{"v=DAC1", "v = DAC1 ; p=bank.example", " \tv=DAC1;", "v=DAC1 "} {
		if !IsDAC(s) {
			t.Errorf("IsDAC(%q) false", s)
		}
	}
	for _, s := range []string{"v=DAC10", "v=dac1", "V=DAC1", "x=1; v=DAC1", "vv=DAC1", ""} {
		if IsDAC(s) {
			t.Errorf("IsDAC(%q) true", s)
		}
	}
	r, err := Parse("v=DAC1;p=bank.example; t=" + tok + " ;")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := r.Get("p"); v != "bank.example" {
		t.Fatal("p")
	}
	bad := []string{
		"p=bank.example; v=DAC1",           // v not first
		"v=DAC1; p",                        // no '='
		"v=DAC1; p=a b.example",            // whitespace in value
		"v=DAC1; 1x=y",                     // bad tag name
		"v=DAC1; p=",                       // empty value
		"v=DAC1;;",                         // empty item
		"v=DAC1; d=x.example; d=x.example", // duplicate
		"v=DAC1; t=ABC",                    // t rule
		"v=DAC1; x=2027-13-01",             // x rule
		"v=DAC1; d=héllo.example",          // non-ASCII
		"v=DAC2",
	}
	for _, b := range bad {
		if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q) accepted", b)
		}
	}
	if _, err := Parse("v=DAC1; Z_9=anything; future=ok"); err != nil {
		t.Errorf("unknown tags must be accepted: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	end, err := ParseExpiry("2026-10-22")
	if err != nil || !end.Equal(time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%v %v", end, err)
	}
	for _, b := range []string{"2027-02-30", "2027-1-01", "20270101", "2027-01-01T00:00:00Z"} {
		if _, err := ParseExpiry(b); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
	// Last second of the day is valid; the next instant is not.
	z := base().with(tok+"._affiliation."+parent, ptr(txt("v=DAC1; d="+child+"; x=2026-10-22")))
	v := verifier(z)
	v.Now = func() time.Time { return time.Date(2026, 10, 22, 23, 59, 59, 0, time.UTC) }
	if r := v.Verify(context.Background(), child); r.Outcome != Confirmed || r.Reuse != time.Second {
		t.Fatalf("last second: %s %v", r.Outcome, r.Reuse)
	}
	v.Now = func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
	if r := v.Verify(context.Background(), child); r.Outcome != NotConfirmed {
		t.Fatalf("after expiry: %s", r.Outcome)
	}
}

func TestTokens(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tk, err := NewToken(DefaultTokenBits)
		if err != nil || len(tk) != 32 || !IsToken(tk) || seen[tk] {
			t.Fatalf("token %q %v", tk, err)
		}
		seen[tk] = true
	}
	if tk, _ := NewToken(128); len(tk) != 26 {
		t.Fatal("128-bit token length")
	}
	for _, b := range []int{64, 127, 130} {
		if _, err := NewToken(b); err == nil {
			t.Errorf("NewToken(%d) accepted", b)
		}
	}
}

func TestGloballyReachable(t *testing.T) {
	no := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1",
		"0.1.2.3", "192.0.2.5", "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.0.1",
		"::1", "::", "fe80::1", "fc00::1", "2001:db8::1", "::ffff:10.0.0.1", "64:ff9b:1::1", "2001::1", "2002::1", "ff02::1", "3fff::1",
		"64:ff9b::a00:1"}
	yes := []string{"8.8.8.8", "192.0.0.9", "2606:4700::1", "2001:4:112::1", "64:ff9b::808:808", "2001:20::1", "::ffff:8.8.8.8"}
	for _, s := range no {
		if GloballyReachable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range yes {
		if !GloballyReachable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestReportURI(t *testing.T) {
	ok := []string{"mailto:dac@bank.example", "mailto:r@reports.bank.example", "https://bank.example",
		"https://reports.bank.example/dac", "https://bank.example/a/b"}
	bad := []string{"mailto:r@other.example", "mailto:r@bank.example?cc=x@other.example", "mailto:a@bank.example,b@other.example",
		"mailto:r@BANK.example", "mailto:r@bank%2eexample", "mailto:r@evilbank.example", "https://user@bank.example/",
		"https://bank.example:8443/", "https://bank.example/?q=1", "https://bank.example/#f", "https://bank.example.evil.example/",
		"http://bank.example/", "ftp://bank.example/", "mailto:", "https://"}
	for _, f := range ok {
		if ValidReportURI(f, "bank.example") == "" {
			t.Errorf("%q rejected", f)
		}
	}
	for _, f := range bad {
		if ValidReportURI(f, "bank.example") != "" {
			t.Errorf("%q accepted", f)
		}
	}
}

type recSender struct {
	msgs  [][]byte
	fails int
}

func (s *recSender) Send(_ context.Context, dest, parent string, body []byte) error {
	if s.fails > 0 {
		s.fails--
		return errors.New("down")
	}
	s.msgs = append(s.msgs, body)
	return nil
}

func failing(child string) Result {
	return Result{Outcome: NotConfirmed, Child: child, Parent: "bank.example", Observed: testNow,
		ReportTo: "mailto:r@bank.example", ReportReason: ReasonUnconfirmedToken}
}

func TestReporter(t *testing.T) {
	dir := t.TempDir()
	mail := &recSender{}
	rp := &Reporter{StatePath: filepath.Join(dir, "state.json"), Mail: mail, Reporter: "filter.example"}
	ctx := context.Background()
	for i := 0; i < 1200; i++ {
		rp.Queue(failing("c" + strings.Repeat("x", i%7) + itoa(i) + ".example"))
	}
	// duplicate is not queued twice
	if q, _ := rp.Queue(failing("c0.example")); q {
		t.Fatal("duplicate queued")
	}
	// confirmed and temperror results are never reported
	if q, _ := rp.Queue(Result{Outcome: Confirmed, ReportTo: "mailto:r@bank.example", ReportReason: "x"}); q {
		t.Fatal("confirmed queued")
	}
	res, _ := rp.Flush(ctx, testNow)
	if len(mail.msgs) != 1 || res[0].Sent == 0 || res[0].Sent > MaxReportsPerMessage {
		t.Fatalf("first flush: %d messages, %+v", len(mail.msgs), res)
	}
	var reps []Report
	json.Unmarshal(mail.msgs[0], &reps)
	if len(reps) != res[0].Sent || reps[0].Version != "DAC1" || reps[0].Reporter != "filter.example" || len(mail.msgs[0]) > MaxReportBody {
		t.Fatalf("report content: %d entries, %d octets", len(reps), len(mail.msgs[0]))
	}
	// At most one message per destination in 24 hours.
	rp.Flush(ctx, testNow.Add(23*time.Hour))
	if len(mail.msgs) != 1 {
		t.Fatal("second message within 24 hours")
	}
	rp.Flush(ctx, testNow.Add(24*time.Hour))
	if len(mail.msgs) != 2 {
		t.Fatal("no message after 24 hours")
	}
	// Delivery is retried once, then abandoned and counted.
	rp.Queue(failing("late.example"))
	mail.fails = 2
	res, _ = rp.Flush(ctx, testNow.Add(48*time.Hour))
	if res[0].Err == nil || len(mail.msgs) != 2 {
		t.Fatalf("failed delivery: %+v", res)
	}
	rp.Flush(ctx, testNow.Add(49*time.Hour))
	if len(mail.msgs) != 2 {
		t.Fatal("abandoned report was resent")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestReportEmail(t *testing.T) {
	m := string(BuildReportEmail("dac@filter.example", "r@bank.example", "bank.example", []byte("[\n]"), testNow))
	for _, want := range []string{"Subject: DAC report for bank.example\r\n", "Content-Type: application/json\r\n", "To: <r@bank.example>"} {
		if !strings.Contains(m, want) {
			t.Errorf("email lacks %q", want)
		}
	}
}

func TestInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.json")
	inv := &Inventory{Domain: "bank.example", Channel: "dns", TTL: 3600, MaxAge: 3600,
		Contact: "mailto:abuse@bank.example", Report: "mailto:dac@bank.example"}
	c1, err := inv.AddChild("EMBANK.example", false, "", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.AddChild("embank.example", false, "", testNow); err == nil {
		t.Fatal("same child twice")
	}
	if _, err := inv.AddChild("bank.example", false, "", testNow); err == nil {
		t.Fatal("self as child")
	}
	if _, err := inv.AddChild("old.example", false, "2020-01-01", testNow); err == nil {
		t.Fatal("past expiry accepted")
	}
	c2, _ := inv.AddChild("promo.example", true, "2099-12-31", testNow)
	if c1.Token == c2.Token {
		t.Fatal("token reused")
	}
	// Re-establishing an ended affiliation gets a new token.
	inv.RemoveChild("embank.example")
	c3, _ := inv.AddChild("embank.example", false, "", testNow)
	if c3.Token == c1.Token {
		t.Fatal("token reused after removal")
	}
	inv.Claim = &OwnClaim{Parent: "group.example", Token: strings.Repeat("g", 32)}
	if err := inv.Save(path); err != nil {
		t.Fatal(err)
	}
	inv2, err := LoadInventory(path)
	if err != nil || len(inv2.Children) != 2 {
		t.Fatalf("reload: %v", err)
	}
	m, _ := inv2.MarkerRecord()
	if m != "v=DAC1; p=group.example; t="+strings.Repeat("g", 32)+"; r=mailto:abuse@bank.example; f=mailto:dac@bank.example" {
		t.Fatalf("marker %q", m)
	}
	// Generated records verify end to end.
	lines, _ := inv2.ZoneLines()
	z := zone{}
	for _, l := range lines {
		f := strings.SplitN(l, " ", 5)
		z[strings.TrimSuffix(f[0], ".")] = txt(strings.Trim(f[4], `"`))
	}
	for _, c := range inv2.Children {
		cr, _ := inv2.ClaimRecord(c)
		z[Label+"."+c.Domain] = txt(cr)
	}
	for _, c := range inv2.Children {
		r := verifier(z).Verify(context.Background(), c.Domain)
		if r.Outcome != Confirmed || r.Subtree != c.Subtree {
			t.Fatalf("%s: %+v", c.Domain, r)
		}
	}
	// Report URI must be at the parent domain or below.
	inv2.Report = "mailto:r@other.example"
	if err := inv2.Validate(); err == nil {
		t.Fatal("foreign report URI accepted")
	}
}

func TestConfirmationHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.json")
	inv := &Inventory{Domain: "bank.example", Channel: "https", TTL: 3600, MaxAge: 600}
	c, _ := inv.AddChild("embank.example", false, "", time.Now())
	exp, _ := inv.AddChild("gone.example", false, time.Now().UTC().Format("2006-01-02"), time.Now())
	inv.Save(path)
	// make the second one expired by editing the file
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"expires": "`+exp.Expires+`"`, `"expires": "2020-01-01"`, 1)), 0o600)
	h := &ConfirmationHandler{InventoryPath: path}
	get := func(p, method string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, p, nil))
		return w
	}
	w := get("/.well-known/affiliation/"+c.Token, "GET")
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain" || w.Body.String() != "v=DAC1; d=embank.example\n" || w.Header().Get("Cache-Control") != "max-age=600" {
		t.Fatalf("200 case: %d %q %q", w.Code, w.Body.String(), w.Header())
	}
	if w = get("/.well-known/affiliation/"+exp.Token, "GET"); w.Code != 404 {
		t.Fatalf("expired confirmation served: %d", w.Code)
	}
	if w = get("/.well-known/affiliation/"+tok2, "GET"); w.Code != 404 {
		t.Fatalf("unknown token: %d", w.Code)
	}
	if w = get("/.well-known/affiliation/"+c.Token, "POST"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

func TestCacheBackoff(t *testing.T) {
	c := NewCache()
	r := Result{Outcome: TempError, Child: "x.example"}
	c.Put(r, testNow)
	if _, ok := c.Get("x.example", testNow.Add(59*time.Second)); !ok {
		t.Fatal("retried within a minute")
	}
	if _, ok := c.Get("x.example", testNow.Add(60*time.Second)); ok {
		t.Fatal("still blocked after a minute")
	}
	c.Put(r, testNow.Add(60*time.Second))
	if _, ok := c.Get("x.example", testNow.Add(170*time.Second)); !ok {
		t.Fatal("backoff did not double")
	}
	ok := Result{Outcome: Confirmed, Child: "y.example", Reuse: 10 * time.Second}
	c.Put(ok, testNow)
	if _, hit := c.Get("y.example", testNow.Add(10*time.Second)); hit {
		t.Fatal("reused beyond Reuse")
	}
}

func TestLevelsStopOnRepeat(t *testing.T) {
	// a -> b -> a loop
	ta, tb := strings.Repeat("a", 32), strings.Repeat("b", 32)
	z := zone{
		"_affiliation.a.example":       txt("v=DAC1; p=b.example; t=" + tb),
		"_affiliation.b.example":       txt("v=DAC1; p=a.example; t=" + ta),
		tb + "._affiliation.b.example": txt("v=DAC1; d=a.example"),
		ta + "._affiliation.a.example": txt("v=DAC1; d=b.example"),
	}
	chain := verifier(z).VerifyLevels(context.Background(), "a.example", 2)
	if len(chain) != 2 {
		t.Fatalf("loop not stopped: %d results", len(chain))
	}
	if n := len(verifier(base()).VerifyLevels(context.Background(), child, 5)); n > 3 {
		t.Fatal("more than two extra levels")
	}
}

func TestChunkedTooLarge(t *testing.T) {
	// A server that streams more than 1024 octets without Content-Length: the
	// verifier stops reading at the limit and reports permerror.
	f, done := tlsFetcherHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fl := w.(http.Flusher)
		w.Write([]byte("v=DAC1; d=" + child + "; z="))
		for i := 0; i < 50; i++ {
			w.Write([]byte(strings.Repeat("a", 100)))
			fl.Flush()
		}
	}))
	defer done()
	h := f.Get(context.Background(), hParent, "/x")
	if !h.TooLarge || len(h.Body) > MaxConfirmationBody {
		t.Fatalf("chunked: TooLarge=%v len=%d", h.TooLarge, len(h.Body))
	}
	v := verifier(httpsZone("v=DAC1; c=https"))
	v.Fetcher = f
	expect(t, 55, v.Verify(context.Background(), child), PermError)
}

// ---- audit regressions ----------------------------------------------------

func TestIDNA2008(t *testing.T) {
	for _, bad := range []string{"xn--ls8h.example", "xn--xy-0ea.example"} { // emoji; middle dot not between l and l
		if IsCanonical(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := CanonicalInput("\U0001F4A9.example"); err == nil {
		t.Error("emoji input accepted")
	}
	for _, ok := range []string{"xn--bcher-kva.example", "xn--lodbwdo.example"} {
		if !IsCanonical(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	if c, err := CanonicalInput("l\u00b7l.example"); err != nil || !IsCanonical(c) {
		t.Errorf("Catalan l\u00b7l: %q %v", c, err)
	}
	if c, err := CanonicalInput("embank.example\u3002"); err != nil || c != "embank.example" {
		t.Errorf("ideographic full stop: %q %v", c, err)
	}
}

func TestNegativeTTLThroughCNAME(t *testing.T) {
	addr, stop := startDNS(t, func(q string) respSpec {
		return respSpec{
			answers:   []rrSpec{{q, typeCNAME, 5, wireName("target.example")}},
			authority: []rrSpec{{"example", typeSOA, 3600, soaRdata(3600)}},
		}
	})
	defer stop()
	a := (&WireResolver{Servers: []string{addr}}).LookupTXT(context.Background(), "x.example")
	if a.TTL != 5*time.Second || !a.ViaAlias {
		t.Fatalf("%+v", a)
	}
}

func TestClassAndExtendedRcode(t *testing.T) {
	q, _, _ := buildQuery("x.example")
	resp := buildResponse(q, respSpec{answers: []rrSpec{{"x.example", typeTXT, 60, txtRdata("v=DAC1")}}}, 0, false)
	// change the answer class to CH (3)
	off := len(resp) - (2 + 2 + 4 + 2 + len(txtRdata("v=DAC1")))
	binary.BigEndian.PutUint16(resp[off+2:], 3)
	a, _ := (&WireResolver{}).interpret(resp, "x.example")
	if len(a.TXT) != 0 {
		t.Fatal("CH-class TXT used")
	}
	// extended RCODE: OPT with ext-rcode 0x80 and header NXDOMAIN
	q2, _, _ := buildQuery("y.example")
	r2 := buildResponse(q2, respSpec{rcode: 3}, 0, false)
	binary.BigEndian.PutUint16(r2[10:], 1)
	r2 = append(r2, 0)
	r2 = binary.BigEndian.AppendUint16(r2, typeOPT)
	r2 = binary.BigEndian.AppendUint16(r2, 1232)
	r2 = binary.BigEndian.AppendUint32(r2, 0x80000000)
	r2 = binary.BigEndian.AppendUint16(r2, 0)
	if a, _ := (&WireResolver{}).interpret(r2, "y.example"); a.Rcode == "NXDOMAIN" || a.Rcode == "NOERROR" {
		t.Fatalf("extended rcode lost: %s", a.Rcode)
	}
}

func TestHTTPDetails(t *testing.T) {
	path := "/.well-known/affiliation/" + tok
	body := "v=DAC1; d=" + child + "; z=" + strings.Repeat("a", 1024-len("v=DAC1; d="+child+"; z="))
	if len(body) != 1024 {
		t.Fatal("setup")
	}
	f, done := tlsFetcher(t, map[string]route{path: {200, "text/plain;charset", body, `no-cache="Set-Cookie", max-age=10`, ""}})
	defer done()
	h := f.Get(context.Background(), hParent, path)
	if h.TooLarge || len(h.Body) != 1024 || !h.NoStore {
		t.Fatalf("exact 1024 with Content-Length / qualified no-cache: %+v", h)
	}
	v := verifier(httpsZone("v=DAC1; c=https"))
	v.Fetcher = f
	if r := v.Verify(context.Background(), child); r.Outcome != Confirmed || r.Reuse != 0 {
		t.Fatalf("text/plain;charset: %s %v", r.Outcome, r.Reuse)
	}
	ds := cacheDirectives([]string{`private="a,b", max-age=600`, "max-age=60"})
	if len(ds) != 3 || ds[0].name != "private" {
		t.Fatalf("directives %+v", ds)
	}
}

func TestReportURIPaths(t *testing.T) {
	for _, ok := range []string{"https://bank.example/a%20b", "https://bank.example/r:1@x", "mailto:first.last@bank.example"} {
		if ValidReportURI(ok, "bank.example") == "" {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"https://bank.example/a\"b", "https://bank.example/<x>", "https://bank.example/%zz", "mailto:a.@bank.example", "mailto:.a@bank.example", "mailto:a..b@bank.example"} {
		if ValidReportURI(bad, "bank.example") != "" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAuthenticatedForEveryOutcome(t *testing.T) {
	z := zone{}
	for k, v := range base().with(tok+"._affiliation."+parent, nil) {
		v.Secure = true
		z[k] = v
	}
	conf := tok + "._affiliation." + parent
	z[conf] = DNSAnswer{Rcode: "NXDOMAIN", Secure: true, TTL: time.Minute}
	r := verifier(z).Verify(context.Background(), child)
	if r.Outcome != NotConfirmed || r.Authenticated != "dnssec" || !r.ContactAuthenticated {
		t.Fatalf("secure not-confirmed: %s %q %v", r.Outcome, r.Authenticated, r.ContactAuthenticated)
	}
	none := zone{"_affiliation." + child: {Rcode: "NXDOMAIN", Secure: true}}
	if r := verifier(none).Verify(context.Background(), child); r.Outcome != None || r.Authenticated != "dnssec" {
		t.Fatalf("secure none: %+v", r)
	}
	if r := verifier(zone{"_affiliation." + child: {Rcode: "SERVFAIL"}}).Verify(context.Background(), child); r.Authenticated != "" {
		t.Fatal("temperror reported as authenticated")
	}
}

func TestReporterLock(t *testing.T) {
	dir := t.TempDir()
	rp := &Reporter{StatePath: filepath.Join(dir, "s.json")}
	unlock, err := rp.lock()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u, err := rp.lock()
		if err == nil {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second holder acquired the lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("lock not released")
	}
}

func TestExact1024Chunked(t *testing.T) {
	body := "v=DAC1; d=" + child + "; z=" + strings.Repeat("a", 1024-len("v=DAC1; d="+child+"; z="))
	f, done := tlsFetcherHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(body[:500]))
		w.(http.Flusher).Flush()
		w.Write([]byte(body[500:]))
		w.(http.Flusher).Flush()
	}))
	defer done()
	h := f.Get(context.Background(), hParent, "/x")
	if h.TooLarge || len(h.Body) != 1024 {
		t.Fatalf("exactly 1024 chunked: TooLarge=%v len=%d", h.TooLarge, len(h.Body))
	}
}
