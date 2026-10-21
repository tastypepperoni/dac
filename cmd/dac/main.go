// Command dac verifies and publishes Domain Affiliation Confirmation (DAC)
// records, as specified in draft-manelidis-dnsop-domain-affiliation-00.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"time"

	dac "github.com/tastypepperoni/dac"
)

const usage = `dac - Domain Affiliation Confirmation (draft-manelidis-dnsop-domain-affiliation-00)

Verifier:
  dac verify [flags] <domain>...          verify domains (Section 6)
  dac report flush [flags]                send queued failure reports (Section 9)

Publisher (parent operator):
  dac publish init   -i FILE -domain D [-channel dns|https] [-contact URI] [-report URI] [-mode enforce|test]
  dac publish set    -i FILE [-channel ...] [-contact ...] [-report ...] [-mode ...] [-ttl N] [-max-age N]
  dac publish add    -i FILE [-subtree] [-expires YYYY-MM-DD] <child>
  dac publish remove -i FILE <child>
  dac publish expire -i FILE <child> <YYYY-MM-DD|none>
  dac publish own-claim -i FILE (-parent P -token T | -clear)
  dac publish list   -i FILE
  dac publish zone   -i FILE                 zone-file lines for the parent's zone
  dac publish claim  -i FILE <child>         the record the child publishes
  dac publish https-dir -i FILE <dir>        write HTTPS-channel files for a static server
  dac serve -i FILE [-listen :443] [-tls-cert F -tls-key F | -behind-tls-proxy]

Checks:
  dac check parent -i FILE                   check the parent's published records
  dac check child <domain>                   check a child's published records

Testing:
  dac testdns -zone FILE [-listen 127.0.0.1:5300] [-ad]
                                             local DNS server answering from a zone file;
                                             then: dac verify -resolver 127.0.0.1:5300 <domain>

Other:
  dac token [-bits 160]                      generate a token (Section 4.6)

Run "dac <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "verify":
		code, err = cmdVerify(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "publish":
		err = cmdPublish(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "check":
		code, err = cmdCheck(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "testdns":
		err = cmdTestDNS(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dac:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// ---------------------------------------------------------------- resolvers

type resolverFlags struct {
	servers string
	trustAD string
	noHTTPS bool
	rate    time.Duration
}

func (rf *resolverFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&rf.servers, "resolver", "", "comma-separated resolver addresses (default: /etc/resolv.conf)")
	fs.StringVar(&rf.trustAD, "trust-ad", "auto", "trust the AD bit: auto (only for loopback resolvers), yes, no (Section 6.5)")
	fs.BoolVar(&rf.noHTTPS, "no-https", false, `do not support the "https" channel (such results are "not-confirmed")`)
	fs.DurationVar(&rf.rate, "per-parent-interval", time.Second, "minimum interval between verifications reaching one parent (Section 11.11); 0 disables")
}

func (rf *resolverFlags) verifier() (*dac.Verifier, error) {
	var trust *bool
	switch rf.trustAD {
	case "auto":
	case "yes":
		t := true
		trust = &t
	case "no":
		f := false
		trust = &f
	default:
		return nil, fmt.Errorf("-trust-ad must be auto, yes or no")
	}
	var res *dac.WireResolver
	if rf.servers == "" {
		r, err := dac.NewSystemResolver(trust)
		if err != nil {
			return nil, err
		}
		res = r
	} else {
		res = &dac.WireResolver{}
		allLoopback := true
		for _, s := range strings.Split(rf.servers, ",") {
			s = strings.TrimSpace(s)
			ap, err := netip.ParseAddrPort(s)
			if err != nil {
				a, err2 := netip.ParseAddr(s)
				if err2 != nil {
					return nil, fmt.Errorf("resolver %q: %v", s, err)
				}
				ap = netip.AddrPortFrom(a, 53)
			}
			if !ap.Addr().IsLoopback() {
				allLoopback = false
			}
			res.Servers = append(res.Servers, ap.String())
		}
		res.TrustAD = allLoopback
		if trust != nil {
			res.TrustAD = *trust
		}
	}
	v := &dac.Verifier{Resolver: res}
	if !rf.noHTTPS {
		v.Fetcher = &dac.Fetcher{}
	}
	if rf.rate > 0 {
		v.Limiter = &dac.ParentLimiter{Interval: rf.rate}
	}
	return v, nil
}

// ---------------------------------------------------------------- verify

type reportFlags struct {
	state    string
	reporter string
	flush    bool
	smtp     string
	from     string
}

func (f *reportFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.state, "report-state", "", "queue failure reports in this state file (Section 9)")
	fs.StringVar(&f.reporter, "reporter", "", `value of the "reporter" member: a domain identifying your organization`)
	fs.BoolVar(&f.flush, "report-flush", false, "send queued reports whose 24-hour interval has passed")
	fs.StringVar(&f.smtp, "smtp", "", "submission server host:port for mailto: reports (SMTP_USER/SMTP_PASSWORD from the environment)")
	fs.StringVar(&f.from, "smtp-from", "", "From address for report email; SHOULD be at a domain that authenticates its mail")
}

func (f *reportFlags) reporterFor() (*dac.Reporter, error) {
	reporter := ""
	if f.reporter != "" {
		c, err := dac.CanonicalInput(f.reporter)
		if err != nil {
			return nil, fmt.Errorf("-reporter: %v", err)
		}
		reporter = c
	}
	r := &dac.Reporter{StatePath: f.state, Reporter: reporter,
		HTTPS: dac.HTTPSSender{Fetcher: &dac.Fetcher{}}}
	if f.smtp != "" {
		var auth smtp.Auth
		if u := os.Getenv("SMTP_USER"); u != "" {
			host, _, _ := net.SplitHostPort(f.smtp)
			auth = smtp.PlainAuth("", u, os.Getenv("SMTP_PASSWORD"), host)
		}
		r.Mail = dac.SMTPSender{Server: f.smtp, From: f.from, Auth: auth}
	}
	return r, nil
}

func cmdVerify(args []string) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var rf resolverFlags
	var rep reportFlags
	rf.register(fs)
	rep.register(fs)
	levels := fs.Int("levels", 0, "also verify the parent as a child, up to 2 further levels (Section 5.4)")
	asJSON := fs.Bool("json", false, "print results as JSON")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: dac verify [flags] <domain>..."); fs.PrintDefaults() }
	fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return 2, nil
	}
	if *levels < 0 || *levels > dac.MaxExtraLevels {
		return 2, fmt.Errorf("-levels must be between 0 and %d", dac.MaxExtraLevels)
	}
	v, err := rf.verifier()
	if err != nil {
		return 2, err
	}
	var reporter *dac.Reporter
	if rep.state != "" {
		if reporter, err = rep.reporterFor(); err != nil {
			return 2, err
		}
	}
	ctx := context.Background()
	code := 0
	var all [][]dac.Result
	for _, d := range fs.Args() {
		chain := v.VerifyLevels(ctx, d, *levels)
		all = append(all, chain)
		if chain[0].Outcome != dac.Confirmed {
			code = 1
		}
		if reporter != nil {
			for _, r := range chain {
				if _, err := reporter.Queue(r); err != nil {
					fmt.Fprintln(os.Stderr, "dac: queueing report:", err)
				}
			}
		}
		if !*asJSON {
			for i, r := range chain {
				printResult(r, i)
			}
		}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(all); err != nil {
			return 2, err
		}
	}
	if reporter != nil && rep.flush {
		if err := flush(reporter); err != nil {
			return 2, err
		}
	}
	return code, nil
}

func printResult(r dac.Result, level int) {
	indent := strings.Repeat("  ", level)
	fmt.Printf("%s%s: %s\n", indent, dac.DisplayName(r.Child), r.Outcome)
	kv := func(k, v string) {
		if v != "" {
			fmt.Printf("%s  %-14s %s\n", indent, k+":", v)
		}
	}
	if r.Parent != "" {
		kv("parent", dac.DisplayName(r.Parent))
	}
	kv("detail", r.Detail)
	kv("channel", r.Channel)
	auth := r.Authenticated
	if auth == "" && r.Outcome != dac.TempError {
		auth = "no"
	}
	kv("authenticated", auth)
	kv("mode", r.Mode)
	if r.Outcome == dac.Confirmed {
		if r.Subtree {
			kv("scope", "child and every name below it")
		} else {
			kv("scope", "child only")
		}
	}
	kv("expires", r.Expires)
	if r.Contact != "" {
		note := ""
		if !r.ContactAuthenticated {
			note = " (unauthenticated)"
		}
		kv("abuse contact", r.Contact+note)
	}
	if r.Reuse > 0 {
		kv("reusable for", r.Reuse.String())
	}
	if r.ReportTo != "" && r.ReportReason != "" {
		kv("report", r.ReportReason+" -> "+r.ReportTo)
	}
}

// ---------------------------------------------------------------- report

func cmdReport(args []string) error {
	if len(args) == 0 || args[0] != "flush" {
		return errors.New("usage: dac report flush -report-state FILE [-smtp host:port -smtp-from ADDR]")
	}
	fs := flag.NewFlagSet("report flush", flag.ExitOnError)
	var rep reportFlags
	rep.register(fs)
	fs.Parse(args[1:])
	if rep.state == "" {
		return errors.New("-report-state is required")
	}
	r, err := rep.reporterFor()
	if err != nil {
		return err
	}
	return flush(r)
}

func flush(r *dac.Reporter) error {
	res, err := r.Flush(context.Background(), time.Now().UTC())
	for _, fr := range res {
		switch {
		case fr.Err != nil:
			fmt.Fprintf(os.Stderr, "report to %s: %v\n", fr.Destination, fr.Err)
		case fr.Sent > 0:
			fmt.Printf("report to %s: sent %d entries for %s\n", fr.Destination, fr.Sent, fr.Parent)
		default:
			fmt.Printf("report to %s: waiting until %s (one message per 24 hours)\n", fr.Destination, fr.NextAllowed.Format(time.RFC3339))
		}
	}
	return err
}

// ---------------------------------------------------------------- publish

func cmdPublish(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dac publish <init|set|add|remove|expire|own-claim|list|zone|claim|https-dir> ...")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("publish "+sub, flag.ExitOnError)
	path := fs.String("i", "", "inventory file (required)")
	domain := fs.String("domain", "", "parent domain (init)")
	channel := fs.String("channel", "", "confirmation channel: dns or https")
	contact := fs.String("contact", "", `abuse contact URI for the "r" tag (mailto: or https:)`)
	report := fs.String("report", "", `failure-report URI for the "f" tag, at the parent domain or below`)
	mode := fs.String("mode", "", "enforce or test")
	ttl := fs.Int("ttl", 0, "TTL of generated DNS records in seconds (default 3600)")
	maxAge := fs.Int("max-age", 0, "Cache-Control max-age for HTTPS confirmations (default 3600)")
	subtree := fs.Bool("subtree", false, "confirm every name below the child too (Section 4.3)")
	expires := fs.String("expires", "", "last day of validity, YYYY-MM-DD in UTC (Section 4.5)")
	parent := fs.String("parent", "", "own-claim: this domain's parent")
	token := fs.String("token", "", "own-claim: the token issued by that parent")
	clear := fs.Bool("clear", false, "own-claim: remove the own claim")
	fs.Parse(args)
	if *path == "" {
		return errors.New("-i FILE is required")
	}
	allowed := map[string]string{
		"init":      "i domain channel contact report mode ttl max-age",
		"set":       "i channel contact report mode ttl max-age",
		"add":       "i subtree expires",
		"own-claim": "i parent token clear",
	}
	ok := " " + allowed[sub] + " "
	if allowed[sub] == "" {
		ok = " i "
	}
	var bad []string
	fs.Visit(func(f *flag.Flag) {
		if !strings.Contains(ok, " "+f.Name+" ") {
			bad = append(bad, "-"+f.Name)
		}
	})
	if len(bad) > 0 {
		return fmt.Errorf("publish %s does not take %s", sub, strings.Join(bad, ", "))
	}
	now := time.Now().UTC()

	if sub == "init" {
		if _, err := os.Stat(*path); err == nil {
			return fmt.Errorf("%s already exists", *path)
		}
		d, err := dac.CanonicalInput(*domain)
		if err != nil {
			return fmt.Errorf("-domain: %v", err)
		}
		inv := &dac.Inventory{Domain: d, Channel: "dns", Mode: "enforce", TTL: 3600, MaxAge: 3600}
		applySettings(inv, *channel, *contact, *report, *mode, *ttl, *maxAge)
		if err := inv.Save(*path); err != nil {
			return err
		}
		fmt.Printf("created %s for %s; publish the marker with: dac publish zone -i %s\n", *path, d, *path)
		return nil
	}

	inv, err := dac.LoadInventory(*path)
	if err != nil {
		return err
	}
	save := func() error { return inv.Save(*path) }

	switch sub {
	case "set":
		applySettings(inv, *channel, *contact, *report, *mode, *ttl, *maxAge)
		if err := save(); err != nil {
			return err
		}
		fmt.Println("updated; republish the marker (dac publish zone).")
		if *channel != "" {
			fmt.Println("When changing channel: publish confirmations in the new channel before changing the marker,")
			fmt.Println("and remove the old ones after the marker's TTL has passed (Section 10.4).")
		}
	case "add":
		if fs.NArg() != 1 {
			return errors.New("usage: dac publish add -i FILE [-subtree] [-expires YYYY-MM-DD] <child>")
		}
		c, err := inv.AddChild(fs.Arg(0), *subtree, *expires, now)
		if err != nil {
			return err
		}
		if err := save(); err != nil {
			return err
		}
		conf, _ := c.ConfirmationRecord()
		claim, _ := inv.ClaimRecord(*c)
		fmt.Printf("confirmed %s with a new token.\n\n", c.Domain)
		fmt.Println("1. Publish the confirmation first (Section 5.1):")
		if inv.Channel == "dns" {
			fmt.Printf("   %s.%s.%s. %d IN TXT %s\n\n", c.Token, dac.Label, inv.Domain, inv.TTL, dac.ZoneQuote(conf))
		} else {
			fmt.Printf("   https://%s/.well-known/affiliation/%s -> %s\n\n", inv.Domain, c.Token, conf)
		}
		fmt.Println("2. Then the child publishes its claim:")
		fmt.Printf("   %s.%s. %d IN TXT %s\n", dac.Label, c.Domain, inv.TTL, dac.ZoneQuote(claim))
		if c.Subtree {
			fmt.Println("\nSubtree: you state that you operate or authorize EVERY name below", c.Domain+".")
			fmt.Println("This MUST NOT be used if others can create names below it (Section 4.3), and the")
			fmt.Println("child's zone must have no dangling records or wildcards pointing elsewhere (Section 11.12).")
		}
	case "remove":
		if fs.NArg() != 1 {
			return errors.New("usage: dac publish remove -i FILE <child>")
		}
		if err := inv.RemoveChild(fs.Arg(0)); err != nil {
			return err
		}
		if err := save(); err != nil {
			return err
		}
		fmt.Println("removed from the inventory. Now delete its confirmation from the zone (or republish the")
		fmt.Println("zone / HTTPS files). This MUST be done when the domain is transferred, sold or expires (Section 5.2).")
	case "expire":
		if fs.NArg() != 2 {
			return errors.New("usage: dac publish expire -i FILE <child> <YYYY-MM-DD|none>")
		}
		x := fs.Arg(1)
		if x == "none" {
			x = ""
		}
		if err := inv.SetExpiry(fs.Arg(0), x, now); err != nil {
			return err
		}
		if err := save(); err != nil {
			return err
		}
		fmt.Println("updated; republish the confirmation.")
	case "own-claim":
		if *clear {
			inv.Claim = nil
		} else {
			p, err := dac.CanonicalInput(*parent)
			if err != nil {
				return fmt.Errorf("-parent: %v", err)
			}
			if !dac.IsToken(*token) {
				return errors.New("-token must be the token issued by the parent (26-52 lowercase base32 characters)")
			}
			inv.Claim = &dac.OwnClaim{Parent: p, Token: *token}
		}
		if err := save(); err != nil {
			return err
		}
		fmt.Println("updated; the claim and marker tags share one record (Section 4.4). Republish it:")
		m, _ := inv.MarkerRecord()
		fmt.Printf("   %s.%s. %d IN TXT %s\n", dac.Label, inv.Domain, inv.TTL, dac.ZoneQuote(m))
	case "list":
		fmt.Printf("%s  channel=%s mode=%s ttl=%d\n", inv.Domain, inv.Channel, modeOf(inv), inv.TTL)
		for _, c := range inv.Children {
			extra := ""
			if c.Subtree {
				extra += " subtree"
			}
			if c.Expires != "" {
				extra += " expires=" + c.Expires
			}
			fmt.Printf("  %s%s\n", dac.DisplayName(c.Domain), extra)
		}
	case "zone":
		lines, err := inv.ZoneLines()
		if err != nil {
			return err
		}
		fmt.Printf("; DAC records for %s (%d children, channel %s)\n", inv.Domain, len(inv.Children), inv.Channel)
		for _, l := range lines {
			fmt.Println(l)
		}
	case "claim":
		if fs.NArg() != 1 {
			return errors.New("usage: dac publish claim -i FILE <child>")
		}
		d, err := dac.CanonicalInput(fs.Arg(0))
		if err != nil {
			return err
		}
		for _, c := range inv.Children {
			if c.Domain == d {
				rec, err := inv.ClaimRecord(c)
				if err != nil {
					return err
				}
				fmt.Printf("%s.%s. %d IN TXT %s\n", dac.Label, c.Domain, inv.TTL, dac.ZoneQuote(rec))
				return nil
			}
		}
		return fmt.Errorf("%s is not in the inventory", d)
	case "https-dir":
		if fs.NArg() != 1 {
			return errors.New("usage: dac publish https-dir -i FILE <dir>")
		}
		return writeHTTPSDir(inv, fs.Arg(0))
	default:
		return fmt.Errorf("unknown publish command %q", sub)
	}
	return nil
}

func modeOf(inv *dac.Inventory) string {
	if inv.Mode == "" {
		return "enforce"
	}
	return inv.Mode
}

func applySettings(inv *dac.Inventory, channel, contact, report, mode string, ttl, maxAge int) {
	if channel != "" {
		inv.Channel = channel
	}
	if contact != "" {
		if contact == "none" {
			contact = ""
		}
		inv.Contact = contact
	}
	if report != "" {
		if report == "none" {
			report = ""
		}
		inv.Report = report
	}
	if mode != "" {
		inv.Mode = mode
	}
	if ttl > 0 {
		inv.TTL = ttl
	}
	if maxAge > 0 {
		inv.MaxAge = maxAge
	}
}

func writeHTTPSDir(inv *dac.Inventory, dir string) error {
	res, err := inv.HTTPSResources()
	if err != nil {
		return err
	}
	base := filepath.Join(dir, ".well-known", "affiliation")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		if _, keep := res[e.Name()]; !keep && dac.IsToken(e.Name()) {
			os.Remove(filepath.Join(base, e.Name())) // ended affiliations (Section 5.2)
		}
	}
	for tok, rec := range res {
		if err := os.WriteFile(filepath.Join(base, tok), []byte(rec+"\n"), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d files under %s\n", len(res), base)
	fmt.Println("Serve them at https://" + inv.Domain + "/.well-known/affiliation/<token> with:")
	fmt.Println("  Content-Type: text/plain, status 200, no redirects, and Cache-Control: max-age=N (Section 10.5).")
	fmt.Println("Unknown tokens must get 404. The apex must serve HTTPS on port 443 directly (Section 10.4).")
	return nil
}

// ---------------------------------------------------------------- serve

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("i", "", "inventory file (required)")
	listen := fs.String("listen", ":443", "listen address")
	cert := fs.String("tls-cert", "", "TLS certificate file (PEM)")
	key := fs.String("tls-key", "", "TLS key file (PEM)")
	behind := fs.Bool("behind-tls-proxy", false, "serve plain HTTP for a TLS-terminating proxy that serves the parent domain on port 443")
	fs.Parse(args)
	if *path == "" {
		return errors.New("-i FILE is required")
	}
	if _, err := dac.LoadInventory(*path); err != nil {
		return err
	}
	h := &dac.ConfirmationHandler{InventoryPath: *path}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	switch {
	case *cert != "" && *key != "":
		fmt.Printf("serving HTTPS-channel confirmations on %s\n", *listen)
		return srv.ListenAndServeTLS(*cert, *key)
	case *behind:
		fmt.Printf("serving plain HTTP on %s for a TLS-terminating proxy\n", *listen)
		return srv.ListenAndServe()
	default:
		return errors.New("the HTTPS channel requires TLS: give -tls-cert and -tls-key, or -behind-tls-proxy")
	}
}

// ---------------------------------------------------------------- check

func cmdCheck(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("usage: dac check parent -i FILE | dac check child <domain>")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("check "+sub, flag.ExitOnError)
	var rf resolverFlags
	rf.register(fs)
	path := fs.String("i", "", "inventory file (check parent)")
	fs.Parse(args)
	v, err := rf.verifier()
	if err != nil {
		return 2, err
	}
	v.Limiter = nil
	ctx := context.Background()
	var findings []dac.Finding
	switch sub {
	case "parent":
		if *path == "" {
			return 2, errors.New("-i FILE is required")
		}
		inv, err := dac.LoadInventory(*path)
		if err != nil {
			return 2, err
		}
		findings = dac.CheckParent(ctx, v, inv)
	case "child":
		if fs.NArg() != 1 {
			return 2, errors.New("usage: dac check child <domain>")
		}
		findings = dac.CheckChild(ctx, v, fs.Arg(0))
	default:
		return 2, fmt.Errorf("unknown check %q", sub)
	}
	code := 0
	for _, f := range findings {
		fmt.Println(f)
		if f.Level == "error" {
			code = 1
		}
	}
	return code, nil
}

// ---------------------------------------------------------------- token

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	bits := fs.Int("bits", dac.DefaultTokenBits, "token size in bits (at least 128; 160 recommended)")
	fs.Parse(args)
	t, err := dac.NewToken(*bits)
	if err != nil {
		return err
	}
	fmt.Println(t)
	return nil
}

// ---------------------------------------------------------------- testdns

func cmdTestDNS(args []string) error {
	fs := flag.NewFlagSet("testdns", flag.ExitOnError)
	zone := fs.String("zone", "", "zone file (required); edited files are reloaded automatically")
	listen := fs.String("listen", "127.0.0.1:5300", "address to listen on (UDP and TCP)")
	ad := fs.Bool("ad", false, "set the AD bit, as a validating resolver does for secure answers")
	neg := fs.Uint("neg-ttl", 300, "TTL of negative answers")
	quiet := fs.Bool("quiet", false, "do not log queries")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dac testdns -zone FILE [-listen 127.0.0.1:5300] [-ad]

Zone file lines (names are absolute; a trailing dot is optional):
  name [ttl] [IN] TXT "string" ["string"...]
  name [ttl] [IN] CNAME target
  name [ttl] [IN] DNAME target
  name SERVFAIL | REFUSED | TIMEOUT    inject a failure for this name
  name INSECURE                        never set AD for this name (with -ad)
  ; comment
Owner names may start with "*." (wildcards).  Output of "dac publish zone" and
"dac publish claim" can be pasted in directly.

`)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *zone == "" {
		fs.Usage()
		return errors.New("-zone is required")
	}
	ap, err := netip.ParseAddrPort(*listen)
	if err != nil {
		return fmt.Errorf("-listen: %v", err)
	}
	if !ap.Addr().IsLoopback() {
		fmt.Fprintln(os.Stderr, "warning: testdns is a test tool; listening on a non-loopback address exposes it to the network")
	}
	s := &dac.TestServer{ZonePath: *zone, AD: *ad, NegativeTTL: uint32(*neg)}
	if !*quiet {
		s.Log = os.Stdout
	}
	names, err := s.Names()
	if err != nil {
		return err
	}
	fmt.Printf("dac testdns: %d names from %s on %s (UDP and TCP)%s\n", len(names), *zone, *listen,
		map[bool]string{true: ", AD set", false: ""}[*ad])
	fmt.Printf("try: dac verify -resolver %s <domain>\n", *listen)
	return s.ListenAndServe(*listen)
}
