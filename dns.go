package dac

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// DNSAnswer is the outcome of one TXT query, with the information the
// procedure needs from the answer section (§6.2).
type DNSAnswer struct {
	// Rcode is "NOERROR", "NXDOMAIN", another response code name, "TIMEOUT"
	// or "TRUNCATED" (a truncated response that could not be retried over TCP).
	Rcode string
	// TXT holds each TXT record's character-strings concatenated (§4.1).
	TXT []string
	// TTL is the smallest TTL of the records used; for a negative answer, the
	// negative-caching TTL of RFC 2308 (zero if no SOA record was returned).
	TTL time.Duration
	// Secure is true if the answer was validated as secure by a validating
	// resolver reached over a trusted path (§6.5).
	Secure bool
	// ViaAlias is true if the answer section contains a CNAME or DNAME record.
	ViaAlias bool
}

// Resolver performs TXT queries.  Implementations MUST expose the answer
// section so that CNAME and DNAME records can be detected (§6.2).
type Resolver interface {
	LookupTXT(ctx context.Context, qname string) DNSAnswer
}

// WireResolver is a stub resolver speaking the DNS wire protocol over UDP with
// fallback to TCP (§6.4: verifiers MUST support DNS over TCP).
type WireResolver struct {
	// Servers are "address:port" strings of recursive resolvers.
	Servers []string
	// TrustAD makes the resolver report Secure when a response carries the AD
	// bit.  Set it only when the path to the resolvers is trusted (§6.5); see
	// NewSystemResolver for the default.
	TrustAD bool
	// Timeout bounds one attempt against one server.  Default 3 seconds.
	Timeout time.Duration
}

// NewSystemResolver uses the system's configured DNS servers: those in
// /etc/resolv.conf on Unix-like systems, and those of the active network
// adapters on Windows.  The AD bit is trusted only when every server is a
// loopback address, which is the usual arrangement for a local validating
// resolver; trustAD overrides this when the operator knows the path to the
// resolvers is otherwise protected (§6.5).
func NewSystemResolver(trustAD *bool) (*WireResolver, error) {
	addrs, err := systemDNSServers()
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no DNS servers configured; use -resolver")
	}
	var servers []string
	allLoopback := true
	for _, a := range addrs {
		servers = append(servers, netip.AddrPortFrom(a, 53).String())
		if !a.IsLoopback() {
			allLoopback = false
		}
	}
	trust := allLoopback
	if trustAD != nil {
		trust = *trustAD
	}
	return &WireResolver{Servers: servers, TrustAD: trust}, nil
}

const (
	typeCNAME = 5
	typeSOA   = 6
	typeTXT   = 16
	typeDNAME = 39
	typeOPT   = 41
	classIN   = 1
	udpSize   = 1232
)

var rcodeNames = map[int]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
	6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS",
}

func rcodeName(c int) string {
	if n, ok := rcodeNames[c]; ok {
		return n
	}
	return fmt.Sprintf("RCODE%d", c)
}

// LookupTXT queries each server in turn until one gives NOERROR or NXDOMAIN.
func (r *WireResolver) LookupTXT(ctx context.Context, qname string) DNSAnswer {
	last := DNSAnswer{Rcode: "TIMEOUT"}
	query, id, err := buildQuery(qname)
	if err != nil {
		return DNSAnswer{Rcode: "FORMERR"}
	}
	for _, srv := range r.Servers {
		for attempt := 0; attempt < 2; attempt++ {
			if ctx.Err() != nil {
				return DNSAnswer{Rcode: "TIMEOUT"}
			}
			ans, final := r.exchange(ctx, srv, qname, query, id)
			last = ans
			if final {
				return ans
			}
			if ans.Rcode != "TIMEOUT" {
				break // a definite but unusable answer: try the next server
			}
		}
		// fresh ID for the next server
		query, id, _ = buildQuery(qname)
	}
	return last
}

func (r *WireResolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 3 * time.Second
}

// exchange performs one UDP exchange, retrying over TCP on truncation.  final
// is true for NOERROR and NXDOMAIN.
func (r *WireResolver) exchange(ctx context.Context, srv, qname string, query []byte, id uint16) (DNSAnswer, bool) {
	dctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "udp", srv)
	if err != nil {
		return DNSAnswer{Rcode: "TIMEOUT"}, false
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		return DNSAnswer{Rcode: "TIMEOUT"}, false
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return DNSAnswer{Rcode: "TIMEOUT"}, false
		}
		msg := buf[:n]
		// Responses that do not match the query are ignored (RFC 5452).
		if !matches(msg, id, qname) {
			continue
		}
		if len(msg) >= 4 && msg[2]&0x02 != 0 { // TC
			return r.exchangeTCP(ctx, srv, qname)
		}
		return r.interpret(msg, qname)
	}
}

func (r *WireResolver) exchangeTCP(ctx context.Context, srv, qname string) (DNSAnswer, bool) {
	query, id, err := buildQuery(qname)
	if err != nil {
		return DNSAnswer{Rcode: "TRUNCATED"}, false
	}
	dctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "tcp", srv)
	if err != nil {
		return DNSAnswer{Rcode: "TRUNCATED"}, false
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return DNSAnswer{Rcode: "TRUNCATED"}, false
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return DNSAnswer{Rcode: "TRUNCATED"}, false
	}
	msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return DNSAnswer{Rcode: "TRUNCATED"}, false
	}
	if !matches(msg, id, qname) || msg[2]&0x02 != 0 {
		return DNSAnswer{Rcode: "TRUNCATED"}, false
	}
	return r.interpret(msg, qname)
}

// buildQuery encodes a TXT query with RD and AD set and an EDNS(0) OPT record
// with the DO bit, so that a validating resolver reports validation status.
func buildQuery(qname string) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	m := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(m[0:], id)
	m[2] = 0x01                           // RD
	m[3] = 0x20                           // AD (RFC 6840 §5.7)
	binary.BigEndian.PutUint16(m[4:], 1)  // QDCOUNT
	binary.BigEndian.PutUint16(m[10:], 1) // ARCOUNT
	wire, err := encodeName(qname)
	if err != nil {
		return nil, 0, err
	}
	m = append(m, wire...)
	m = binary.BigEndian.AppendUint16(m, typeTXT)
	m = binary.BigEndian.AppendUint16(m, classIN)
	// OPT: root name, type 41, UDP size, extended RCODE/version 0, DO bit.
	m = append(m, 0)
	m = binary.BigEndian.AppendUint16(m, typeOPT)
	m = binary.BigEndian.AppendUint16(m, udpSize)
	m = binary.BigEndian.AppendUint32(m, 0x00008000)
	m = binary.BigEndian.AppendUint16(m, 0)
	return m, id, nil
}

func encodeName(name string) ([]byte, error) {
	if len(name) > 253 {
		return nil, errors.New("name too long")
	}
	var out []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(l) == 0 || len(l) > 63 {
			return nil, fmt.Errorf("bad label %q", l)
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0), nil
}

// matches checks the response ID, the QR bit, the opcode and the question.
func matches(msg []byte, id uint16, qname string) bool {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg) != id || msg[2]&0x80 == 0 || (msg[2]>>3)&0x0f != 0 {
		return false
	}
	if binary.BigEndian.Uint16(msg[4:]) != 1 {
		return false
	}
	name, off, err := readName(msg, 12)
	if err != nil || off+4 > len(msg) {
		return false
	}
	return strings.EqualFold(name, strings.TrimSuffix(qname, ".")) &&
		binary.BigEndian.Uint16(msg[off:]) == typeTXT &&
		binary.BigEndian.Uint16(msg[off+2:]) == classIN
}

type rr struct {
	owner string
	typ   uint16
	class uint16
	ttl   uint32
	rdata []byte
	rdOff int // offset of rdata in the message, for names inside rdata
}

func (r *WireResolver) interpret(msg []byte, qname string) (DNSAnswer, bool) {
	rcode := int(msg[3] & 0x0f)
	ad := msg[3]&0x20 != 0
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	ar := int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, o, err := readName(msg, off)
		if err != nil || o+4 > len(msg) {
			return DNSAnswer{Rcode: "FORMERR"}, false
		}
		off = o + 4
	}
	answers, off, err := readRRs(msg, off, an)
	if err != nil {
		return DNSAnswer{Rcode: "FORMERR"}, false
	}
	authority, off, err := readRRs(msg, off, ns)
	if err != nil {
		return DNSAnswer{Rcode: "FORMERR"}, false
	}
	additional, _, err := readRRs(msg, off, ar)
	if err != nil {
		return DNSAnswer{Rcode: "FORMERR"}, false
	}
	opts := 0
	for _, a := range additional {
		if a.typ == typeOPT {
			opts++
			rcode |= int(a.ttl>>24) << 4 // extended RCODE
		}
	}
	if opts > 1 { // RFC 6891 §6.1.1
		return DNSAnswer{Rcode: "FORMERR"}, false
	}
	name := rcodeName(rcode)
	if rcode != 0 && rcode != 3 {
		return DNSAnswer{Rcode: name}, false
	}
	res := DNSAnswer{Rcode: name, Secure: r.TrustAD && ad}
	for _, a := range answers {
		if (a.typ == typeCNAME || a.typ == typeDNAME) && a.class == classIN {
			res.ViaAlias = true
		}
	}
	// Follow the CNAME chain in the answer section to the final owner name.
	cur := strings.ToLower(strings.TrimSuffix(qname, "."))
	minTTL := uint32(1<<31 - 1)
	for hops := 0; hops < 16; hops++ {
		next := ""
		for _, a := range answers {
			if a.typ == typeCNAME && a.class == classIN && a.owner == cur {
				t, _, err := readName(msg, a.rdOff)
				if err != nil {
					return DNSAnswer{Rcode: "FORMERR"}, false
				}
				next = strings.ToLower(t)
				if a.ttl < minTTL {
					minTTL = a.ttl
				}
				break
			}
		}
		if next == "" {
			break
		}
		cur = next
	}
	for _, a := range answers {
		if a.typ == typeTXT && a.class == classIN && a.owner == cur {
			s, err := txtString(a.rdata)
			if err != nil {
				return DNSAnswer{Rcode: "FORMERR"}, false
			}
			res.TXT = append(res.TXT, s)
			if a.ttl < minTTL {
				minTTL = a.ttl
			}
		}
	}
	if len(res.TXT) > 0 {
		res.TTL = time.Duration(minTTL) * time.Second
		return res, true
	}
	// Negative answer: TTL per RFC 2308 §5, min(SOA TTL, SOA MINIMUM), and no
	// longer than any CNAME followed to reach it.  Without an SOA, zero.
	res.TTL = 0
	for _, a := range authority {
		if a.typ == typeSOA && len(a.rdata) >= 20 {
			minimum := binary.BigEndian.Uint32(a.rdata[len(a.rdata)-4:])
			t := a.ttl
			if minimum < t {
				t = minimum
			}
			if minTTL < t {
				t = minTTL
			}
			res.TTL = time.Duration(t) * time.Second
			break
		}
	}
	return res, true
}

func readRRs(msg []byte, off, count int) ([]rr, int, error) {
	var out []rr
	for i := 0; i < count; i++ {
		name, o, err := readName(msg, off)
		if err != nil || o+10 > len(msg) {
			return nil, 0, errors.New("short RR")
		}
		typ := binary.BigEndian.Uint16(msg[o:])
		class := binary.BigEndian.Uint16(msg[o+2:])
		ttl := binary.BigEndian.Uint32(msg[o+4:])
		rdlen := int(binary.BigEndian.Uint16(msg[o+8:]))
		start := o + 10
		if start+rdlen > len(msg) {
			return nil, 0, errors.New("short rdata")
		}
		if ttl > 1<<31-1 && typ != typeOPT { // RFC 2181 §8; OPT's TTL field holds flags
			ttl = 0
		}
		out = append(out, rr{owner: strings.ToLower(name), typ: typ, class: class, ttl: ttl, rdata: msg[start : start+rdlen], rdOff: start})
		off = start + rdlen
	}
	return out, off, nil
}

// readName decodes a possibly compressed name.  Label bytes other than
// letters, digits, '-' and '_' are escaped so that comparisons are exact.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	jumps := 0
	wire := 1 // the root label
	for {
		if off >= len(msg) {
			return "", 0, errors.New("name overflows message")
		}
		c := int(msg[off])
		switch {
		case c == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case c&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("bad pointer")
			}
			if end < 0 {
				end = off + 2
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
			if jumps++; jumps > 64 || ptr >= len(msg) {
				return "", 0, errors.New("compression loop")
			}
			off = ptr
		case c&0xC0 != 0:
			return "", 0, errors.New("unsupported label type")
		default:
			if off+1+c > len(msg) {
				return "", 0, errors.New("label overflows message")
			}
			if wire += 1 + c; wire > 255 {
				return "", 0, errors.New("name longer than 255 octets")
			}
			var b strings.Builder
			for _, ch := range msg[off+1 : off+1+c] {
				if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
					b.WriteByte(ch)
				} else {
					fmt.Fprintf(&b, "\\%03d", ch)
				}
			}
			labels = append(labels, b.String())
			off += 1 + c
		}
	}
}

// txtString concatenates the character-strings of TXT rdata (§4.1).
func txtString(rd []byte) (string, error) {
	var b strings.Builder
	for i := 0; i < len(rd); {
		l := int(rd[i])
		if i+1+l > len(rd) {
			return "", errors.New("bad TXT rdata")
		}
		b.Write(rd[i+1 : i+1+l])
		i += 1 + l
	}
	return b.String(), nil
}
