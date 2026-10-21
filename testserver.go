package dac

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TestServer is a small DNS server for testing DAC deployments locally.  It
// answers queries for any name from a zone file, as a recursive resolver
// would, so that `dac verify -resolver 127.0.0.1:PORT` can be pointed at it.
//
// Zone file lines (owner names are absolute; a trailing dot is optional):
//
//	name [ttl] [IN] TXT "string" ["string"...]
//	name [ttl] [IN] CNAME target
//	name [ttl] [IN] DNAME target
//	name SERVFAIL | REFUSED | TIMEOUT     ; inject a failure for this name
//	name INSECURE                         ; never set AD for this name (with -ad)
//	; comment
//
// Owner names may start with "*." for RFC 4592 wildcards.  Names that exist only
// because names below them exist (empty non-terminals) answer NOERROR with no
// data.  Negative answers carry an SOA record.  The file is reloaded when it
// changes.  It is a test tool: it is not a full DNS server.
type TestServer struct {
	ZonePath string
	// AD sets the AD bit, as a validating resolver does for secure answers.
	AD bool
	// NegativeTTL is the SOA TTL and MINIMUM in negative answers.
	NegativeTTL uint32
	// Log, if set, receives one line per query.
	Log io.Writer

	mu      sync.Mutex
	modTime time.Time
	z       *testZone
}

type testRR struct {
	typ   uint16
	ttl   uint32
	txt   []string // TXT strings
	cname string   // CNAME or DNAME target
}

type testZone struct {
	rrs      map[string][]testRR
	nodes    map[string]bool // owners and all their ancestors
	failure  map[string]string
	insecure map[string]bool
}

func (s *TestServer) zone() (*testZone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.ZonePath)
	if err != nil {
		return nil, err
	}
	if s.z != nil && st.ModTime().Equal(s.modTime) {
		return s.z, nil
	}
	z, err := parseTestZone(s.ZonePath)
	if err != nil {
		return nil, err
	}
	s.z, s.modTime = z, st.ModTime()
	return z, nil
}

func normName(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }

func parseTestZone(path string) (*testZone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z := &testZone{rrs: map[string][]testRR{}, nodes: map[string]bool{}, failure: map[string]string{}, insecure: map[string]bool{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		toks, err := zoneTokens(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, line, err)
		}
		if len(toks) == 0 {
			continue
		}
		owner := normName(toks[0].s)
		rest := toks[1:]
		ttl := uint32(3600)
		if len(rest) > 0 && !rest[0].quoted {
			if n, err := strconv.ParseUint(rest[0].s, 10, 31); err == nil {
				ttl, rest = uint32(n), rest[1:]
			}
		}
		if len(rest) > 0 && strings.EqualFold(rest[0].s, "IN") && !rest[0].quoted {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return nil, fmt.Errorf("%s:%d: missing type", path, line)
		}
		typ := strings.ToUpper(rest[0].s)
		args := rest[1:]
		switch typ {
		case "TXT":
			if len(args) == 0 {
				return nil, fmt.Errorf("%s:%d: TXT needs at least one string", path, line)
			}
			var ss []string
			for _, a := range args {
				if len(a.s) > 255 {
					return nil, fmt.Errorf("%s:%d: TXT string longer than 255 octets; split it", path, line)
				}
				ss = append(ss, a.s)
			}
			z.rrs[owner] = append(z.rrs[owner], testRR{typ: typeTXT, ttl: ttl, txt: ss})
		case "CNAME", "DNAME":
			if len(args) != 1 {
				return nil, fmt.Errorf("%s:%d: %s needs one target", path, line, typ)
			}
			t := uint16(typeCNAME)
			if typ == "DNAME" {
				t = typeDNAME
			}
			z.rrs[owner] = append(z.rrs[owner], testRR{typ: t, ttl: ttl, cname: normName(args[0].s)})
		case "SERVFAIL", "REFUSED", "TIMEOUT":
			z.failure[owner] = typ
		case "INSECURE":
			z.insecure[owner] = true
		default:
			return nil, fmt.Errorf("%s:%d: unsupported type %s", path, line, typ)
		}
		for n := owner; n != ""; {
			z.nodes[n] = true
			i := strings.IndexByte(n, '.')
			if i < 0 {
				break
			}
			n = n[i+1:]
		}
	}
	return z, sc.Err()
}

type zoneToken struct {
	s      string
	quoted bool
}

// zoneTokens splits a zone-file line, honouring quoted strings with \" \\ and
// \DDD escapes, and stopping at an unquoted ';'.
func zoneTokens(line string) ([]zoneToken, error) {
	var out []zoneToken
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == ';':
			return out, nil
		case c == '"':
			var b strings.Builder
			i++
			for {
				if i >= len(line) {
					return nil, errors.New("unterminated quoted string")
				}
				c = line[i]
				if c == '"' {
					i++
					break
				}
				if c == '\\' && i+1 < len(line) {
					if i+3 < len(line) && isDigit(line[i+1]) && isDigit(line[i+2]) && isDigit(line[i+3]) {
						n, _ := strconv.Atoi(line[i+1 : i+4])
						if n > 255 {
							return nil, errors.New("bad \\DDD escape")
						}
						b.WriteByte(byte(n))
						i += 4
						continue
					}
					b.WriteByte(line[i+1])
					i += 2
					continue
				}
				b.WriteByte(c)
				i++
			}
			out = append(out, zoneToken{b.String(), true})
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' && line[j] != ';' {
				j++
			}
			out = append(out, zoneToken{line[i:j], false})
			i = j
		}
	}
	return out, nil
}

// ListenAndServe serves UDP and TCP on addr until an error occurs.
func (s *TestServer) ListenAndServe(addr string) error {
	_, errc, _, err := s.Start(addr)
	if err != nil {
		return err
	}
	return <-errc
}

// Start binds UDP and TCP on addr (port 0 picks a free port), starts serving,
// and returns the bound address.  The server is ready when Start returns.
// stop closes both listeners.
func (s *TestServer) Start(addr string) (bound string, errc <-chan error, stop func(), err error) {
	if _, err := s.zone(); err != nil {
		return "", nil, nil, err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", nil, nil, err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return "", nil, nil, err
	}
	ch := make(chan error, 2)
	go func() { ch <- s.serveUDP(pc) }()
	go func() { ch <- s.serveTCP(ln) }()
	return pc.LocalAddr().String(), ch, func() { pc.Close(); ln.Close() }, nil
}

func (s *TestServer) serveUDP(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := s.handle(q, true); resp != nil {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

func (s *TestServer) serveTCP(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			for {
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := s.handle(q, false)
				if resp == nil {
					return
				}
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
			}
		}(c)
	}
}

func (s *TestServer) logf(format string, a ...any) {
	if s.Log != nil {
		fmt.Fprintf(s.Log, format+"\n", a...)
	}
}

// handle builds the response to one query; nil means no response.
func (s *TestServer) handle(q []byte, udp bool) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	qname, qend, err := readName(q, 12)
	if err != nil || qend+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[qend:])
	question := q[12 : qend+4]
	udpLimit := 512
	// EDNS(0) in the additional section raises the UDP limit.
	if arc := binary.BigEndian.Uint16(q[10:]); arc > 0 && qend+4+11 <= len(q) {
		o := qend + 4
		if q[o] == 0 && binary.BigEndian.Uint16(q[o+1:]) == typeOPT {
			if sz := int(binary.BigEndian.Uint16(q[o+3:])); sz > udpLimit {
				udpLimit = sz
			}
		}
	}
	name := strings.ToLower(qname)
	z, err := s.zone()
	if err != nil {
		s.logf("zone error: %v", err)
		return header(q, question, 2, false, false)
	}

	ad := s.AD
	answers, authority, rcode, fail := z.resolve(name, qtype, s.negTTL())
	if z.insecure[name] {
		ad = false
	}
	switch fail {
	case "TIMEOUT":
		s.logf("%-50s TXT? -> (no response)", name)
		return nil
	case "SERVFAIL":
		rcode = 2
	case "REFUSED":
		rcode = 5
	}
	if rcode != 0 && rcode != 3 {
		ad = false
		answers, authority = nil, nil
	}
	m := header(q, question, rcode, ad, false)
	binary.BigEndian.PutUint16(m[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(m[8:], uint16(len(authority)))
	for _, r := range answers {
		m = append(m, r...)
	}
	for _, r := range authority {
		m = append(m, r...)
	}
	s.logf("%-50s -> %s, %d answer(s)%s", name, rcodeName(rcode), len(answers), map[bool]string{true: ", AD", false: ""}[ad])
	if udp && len(m) > udpLimit {
		return header(q, question, rcode, ad, true)
	}
	return m
}

func (s *TestServer) negTTL() uint32 {
	if s.NegativeTTL == 0 {
		return 300
	}
	return s.NegativeTTL
}

func header(q, question []byte, rcode int, ad, tc bool) []byte {
	m := make([]byte, 12, 512)
	copy(m, q[:2])
	m[2] = 0x80 | (q[2] & 0x01) // QR, copy RD
	if tc {
		m[2] |= 0x02
	}
	m[3] = 0x80 | byte(rcode) // RA
	if ad {
		m[3] |= 0x20
	}
	binary.BigEndian.PutUint16(m[4:], 1)
	return append(m, question...)
}

func wireRR(owner string, typ uint16, ttl uint32, rdata []byte) []byte {
	b, _ := encodeName(owner)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, classIN)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// resolve answers qname/qtype from the zone, following CNAMEs and DNAMEs and
// applying wildcards.  It returns answer and authority RRs in wire form.
func (z *testZone) resolve(qname string, qtype uint16, negTTL uint32) (ans, auth [][]byte, rcode int, fail string) {
	cur := qname
	for hops := 0; hops < 8; hops++ {
		if f, ok := z.failure[cur]; ok {
			return nil, nil, 0, f
		}
		// DNAME at an ancestor rewrites the name (RFC 6672).
		if owner, rr, ok := z.dnameAbove(cur); ok {
			ans = append(ans, wireRR(owner, typeDNAME, rr.ttl, mustName(rr.cname)))
			target := strings.TrimSuffix(cur, owner) + rr.cname
			ans = append(ans, wireRR(cur, typeCNAME, rr.ttl, mustName(target)))
			cur = target
			continue
		}
		rrs, exists := z.rrs[cur], z.nodes[cur]
		owner := cur
		if !exists {
			if w, ok := z.wildcardFor(cur); ok {
				rrs, exists = z.rrs[w], true
			}
		}
		if !exists {
			return ans, [][]byte{soaRR(negTTL)}, 3, ""
		}
		var next string
		for _, r := range rrs {
			if r.typ == typeCNAME && qtype != typeCNAME {
				ans = append(ans, wireRR(owner, typeCNAME, r.ttl, mustName(r.cname)))
				next = r.cname
				break
			}
		}
		if next != "" {
			cur = next
			continue
		}
		found := false
		for _, r := range rrs {
			if r.typ == qtype && r.typ == typeTXT {
				var rd []byte
				for _, t := range r.txt {
					rd = append(rd, byte(len(t)))
					rd = append(rd, t...)
				}
				ans = append(ans, wireRR(owner, typeTXT, r.ttl, rd))
				found = true
			}
		}
		if !found {
			auth = [][]byte{soaRR(negTTL)}
		}
		return ans, auth, 0, ""
	}
	return ans, nil, 2, ""
}

func (z *testZone) dnameAbove(name string) (string, testRR, bool) {
	for n := name; ; {
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return "", testRR{}, false
		}
		n = n[i+1:]
		for _, r := range z.rrs[n] {
			if r.typ == typeDNAME {
				return n, r, true
			}
		}
	}
}

// wildcardFor implements RFC 4592: the closest existing ancestor of name, with
// "*." prepended, is the source of synthesis if it exists.
func (z *testZone) wildcardFor(name string) (string, bool) {
	for n := name; ; {
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return "", false
		}
		n = n[i+1:]
		if z.nodes[n] {
			w := "*." + n
			_, ok := z.rrs[w]
			return w, ok
		}
	}
}

func mustName(n string) []byte {
	b, err := encodeName(n)
	if err != nil {
		return []byte{0}
	}
	return b
}

func soaRR(ttl uint32) []byte {
	rd := append(mustName("ns.test.invalid"), mustName("hostmaster.test.invalid")...)
	for _, v := range []uint32{1, 3600, 600, 86400, ttl} {
		rd = binary.BigEndian.AppendUint32(rd, v)
	}
	return wireRR("invalid", typeSOA, ttl, rd)
}

// Names returns the owner names in the zone, for display.
func (s *TestServer) Names() ([]string, error) {
	z, err := s.zone()
	if err != nil {
		return nil, err
	}
	var out []string
	for n := range z.rrs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
