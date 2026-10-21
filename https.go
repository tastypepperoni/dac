package dac

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// MaxConfirmationBody is the most content a verifier reads (§7.2).
const MaxConfirmationBody = 1024

// MaxReportBody is the most content of a report POST (§9.3).
const MaxReportBody = 65536

// HTTPResult is the outcome of one restricted HTTPS request.
type HTTPResult struct {
	// Status is the HTTP status code, StatusTransport for a connection, TLS or
	// timeout failure, or StatusNoGlobalAddress when the host has no globally
	// reachable address (§7.2).
	Status      int
	ContentType string
	Body        []byte
	// TooLarge is set when the content exceeds the limit; the excess is not read.
	TooLarge bool
	// MaxAge is the Cache-Control max-age, if any; NoStore is set for no-store
	// or no-cache.
	MaxAge  *int
	NoStore bool
}

const (
	StatusTransport       = 0
	StatusNoGlobalAddress = -1
)

// Fetcher performs HTTPS requests under the restrictions of §7.2:
// "https" on port 443 to the given host, certificate validation for that name,
// no redirects, connections only to globally reachable addresses that were
// checked before connecting, no cookies or credentials, bounded size and time.
type Fetcher struct {
	// Timeout bounds the whole request (§7.2: SHOULD limit to 10 seconds).
	Timeout time.Duration
	// LookupNetIP resolves the host; nil means net.DefaultResolver.
	LookupNetIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
	// UserAgent identifies the verifier.
	UserAgent string

	// For tests only: replace GloballyReachable, the TLS roots and the port.
	allowAddr func(netip.Addr) bool
	testTLS   *tls.Config
	port      string
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return 10 * time.Second
}

var errNoGlobal = errors.New("no globally reachable address")

func (f *Fetcher) client(host string) *http.Client {
	allow := GloballyReachable
	if f.allowAddr != nil {
		allow = f.allowAddr
	}
	lookup := f.LookupNetIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	port := "443"
	if f.port != "" {
		port = f.port
	}
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		addrs, err := lookup(ctx, "ip", host)
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				return nil, errNoGlobal
			}
			return nil, err
		}
		var lastErr error = errNoGlobal
		var d net.Dialer
		for _, a := range addrs {
			a = a.Unmap() // dial the IPv4 address that was checked
			if !allow(a) {
				continue
			}
			// Connect to exactly the address that was checked.
			c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, mustPort(port)).String())
			if err == nil {
				return c, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	tlsConf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if f.testTLS != nil {
		tlsConf.RootCAs = f.testTLS.RootCAs
	}
	tr := &http.Transport{
		Proxy:                  nil, // a proxy would make the connection go to an unchecked address
		DialContext:            dial,
		TLSClientConfig:        tlsConf,
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    f.timeout(),
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   f.timeout(),
		Jar:       nil, // no cookies
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
	}
}

type directive struct{ name, value string }

// cacheDirectives splits Cache-Control field values into directives
// (RFC 9111 §5.2), respecting quoted strings.
func cacheDirectives(values []string) []directive {
	var out []directive
	for _, v := range values {
		var cur strings.Builder
		inQuote, escaped := false, false
		flush := func() {
			item := strings.TrimSpace(cur.String())
			cur.Reset()
			if item == "" {
				return
			}
			name, value, _ := strings.Cut(item, "=")
			out = append(out, directive{strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)})
		}
		for i := 0; i < len(v); i++ {
			c := v[i]
			switch {
			case escaped:
				escaped = false
			case inQuote && c == '\\':
				escaped = true
			case c == '"':
				inQuote = !inQuote
			case c == ',' && !inQuote:
				flush()
				continue
			}
			cur.WriteByte(c)
		}
		flush()
	}
	return out
}

func mustPort(p string) uint16 {
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return 443
	}
	return uint16(n)
}

// Get fetches https://host/path and reads at most MaxConfirmationBody octets.
func (f *Fetcher) Get(ctx context.Context, host, path string) HTTPResult {
	return f.do(ctx, http.MethodGet, host, path, nil, "", MaxConfirmationBody)
}

// Post sends body to https://host/path with the given media type (§9.3).
func (f *Fetcher) Post(ctx context.Context, host, path string, body []byte, mediaType string) HTTPResult {
	if len(body) > MaxReportBody {
		return HTTPResult{Status: StatusTransport, TooLarge: true}
	}
	return f.do(ctx, http.MethodPost, host, path, body, mediaType, 4096)
}

func (f *Fetcher) do(ctx context.Context, method, host, path string, body []byte, mediaType string, limit int) HTTPResult {
	u := "https://" + host
	if f.port != "" {
		u += ":" + f.port
	}
	u += path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return HTTPResult{Status: StatusTransport}
	}
	req.Header.Set("Accept", "text/plain")
	ua := f.UserAgent
	if ua == "" {
		ua = "dac-go/1"
	}
	req.Header.Set("User-Agent", ua)
	if mediaType != "" {
		req.Header.Set("Content-Type", mediaType)
	}
	resp, err := f.client(host).Do(req)
	if err != nil {
		if errors.Is(err, errNoGlobal) {
			return HTTPResult{Status: StatusNoGlobalAddress}
		}
		return HTTPResult{Status: StatusTransport}
	}
	defer resp.Body.Close()
	res := HTTPResult{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type")}
	for _, d := range cacheDirectives(resp.Header.Values("Cache-Control")) {
		switch d.name {
		case "no-store", "no-cache": // with or without an argument
			res.NoStore = true
		case "max-age":
			n, err := strconv.ParseInt(strings.Trim(d.value, `"`), 10, 64)
			if err != nil || n < 0 {
				continue
			}
			if n > int64(MaxReuse/time.Second) {
				n = int64(MaxReuse / time.Second)
			}
			if res.MaxAge == nil || int(n) < *res.MaxAge { // the smallest of duplicates
				v := int(n)
				res.MaxAge = &v
			}
		}
	}
	if resp.ContentLength > int64(limit) {
		res.TooLarge = true // not read
		return res
	}
	if resp.ContentLength >= 0 {
		// Known length within the limit: read exactly that many octets.
		buf := make([]byte, resp.ContentLength)
		if _, err := io.ReadFull(resp.Body, buf); err != nil {
			return HTTPResult{Status: StatusTransport}
		}
		res.Body = buf
		return res
	}
	// Unknown length: read at most `limit` octets of content.  Once `limit`
	// octets are held, one more read into a one-octet buffer distinguishes
	// "exactly `limit`" (end of content, which consumes only framing) from
	// "more than `limit`"; in the latter case the content is too large and
	// nothing further is used.
	buf := make([]byte, limit)
	n := 0
	for n < limit {
		m, err := resp.Body.Read(buf[n:])
		n += m
		if err == io.EOF {
			res.Body = buf[:n]
			return res
		}
		if err != nil {
			return HTTPResult{Status: StatusTransport}
		}
	}
	var probe [1]byte
	for {
		m, err := resp.Body.Read(probe[:])
		if m > 0 {
			res.TooLarge = true
			return res
		}
		if err == io.EOF {
			res.Body = buf[:n]
			return res
		}
		if err != nil {
			return HTTPResult{Status: StatusTransport}
		}
	}
}
