package dac

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A minimal authoritative-style DNS responder on loopback, used to test the
// wire client: answer-section parsing, CNAME and DNAME detection, string
// concatenation, negative TTLs, the AD bit, truncation and TCP fallback, and
// that mismatched responses are ignored.

type rrSpec struct {
	owner string
	typ   uint16
	ttl   uint32
	rdata []byte
}

type respSpec struct {
	rcode     int
	ad        bool
	tc        bool // set TC on UDP responses
	answers   []rrSpec
	authority []rrSpec
	badID     bool // first send a response with the wrong ID
}

func wireName(n string) []byte {
	b, _ := encodeName(n)
	return b
}

func txtRdata(parts ...string) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return b
}

func soaRdata(minimum uint32) []byte {
	b := append(wireName("ns.example"), wireName("host.example")...)
	for _, v := range []uint32{1, 3600, 600, 86400, minimum} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

func buildResponse(query []byte, s respSpec, id uint16, udp bool) []byte {
	// Copy the question from the query.
	_, qend, _ := readName(query, 12)
	question := query[12 : qend+4]
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m, id)
	m[2] = 0x80 | 0x01 // QR, RD
	if s.tc && udp {
		m[2] |= 0x02
	}
	m[3] = 0x80 | byte(s.rcode&0x0f) // RA
	if s.ad {
		m[3] |= 0x20
	}
	binary.BigEndian.PutUint16(m[4:], 1)
	if s.tc && udp {
		return append(m, question...)
	}
	binary.BigEndian.PutUint16(m[6:], uint16(len(s.answers)))
	binary.BigEndian.PutUint16(m[8:], uint16(len(s.authority)))
	m = append(m, question...)
	for _, set := range [][]rrSpec{s.answers, s.authority} {
		for _, r := range set {
			m = append(m, wireName(r.owner)...)
			m = binary.BigEndian.AppendUint16(m, r.typ)
			m = binary.BigEndian.AppendUint16(m, classIN)
			m = binary.BigEndian.AppendUint32(m, r.ttl)
			m = binary.BigEndian.AppendUint16(m, uint16(len(r.rdata)))
			m = append(m, r.rdata...)
		}
	}
	return m
}

func startDNS(t *testing.T, handle func(qname string) respSpec) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name, _, _ := readName(q, 12)
			s := handle(name)
			id := binary.BigEndian.Uint16(q)
			if s.badID {
				pc.WriteTo(buildResponse(q, s, id^0xffff, true), from)
			}
			pc.WriteTo(buildResponse(q, s, id, true), from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				name, _, _ := readName(q, 12)
				resp := buildResponse(q, handle(name), binary.BigEndian.Uint16(q), false)
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				c.Write(append(out, resp...))
			}(c)
		}
	}()
	return addr, func() { pc.Close(); ln.Close() }
}

func TestWireResolver(t *testing.T) {
	long := strings.Repeat("x", 300)
	addr, stop := startDNS(t, func(q string) respSpec {
		switch q {
		case "split.example":
			return respSpec{answers: []rrSpec{{q, typeTXT, 120, txtRdata("v=DAC1; ", "d=embank.example")}}}
		case "alias.example":
			return respSpec{answers: []rrSpec{
				{q, typeCNAME, 50, wireName("target.example")},
				{"target.example", typeTXT, 900, txtRdata("v=DAC1")},
			}}
		case "dname.example":
			return respSpec{answers: []rrSpec{{"example", typeDNAME, 60, wireName("other.example")}}}
		case "missing.example":
			return respSpec{rcode: 3, authority: []rrSpec{{"example", typeSOA, 900, soaRdata(120)}}}
		case "nodata.example":
			return respSpec{authority: []rrSpec{{"example", typeSOA, 60, soaRdata(3600)}}}
		case "secure.example":
			return respSpec{ad: true, answers: []rrSpec{{q, typeTXT, 300, txtRdata("v=DAC1")}}}
		case "big.example":
			return respSpec{tc: true, answers: []rrSpec{{q, typeTXT, 300, txtRdata(long[:255], long[255:])}}}
		case "spoof.example":
			return respSpec{badID: true, answers: []rrSpec{{q, typeTXT, 300, txtRdata("v=DAC1; real")}}}
		case "servfail.example":
			return respSpec{rcode: 2}
		}
		return respSpec{rcode: 5}
	})
	defer stop()
	ctx := context.Background()
	r := &WireResolver{Servers: []string{addr}, Timeout: 2 * time.Second}

	a := r.LookupTXT(ctx, "split.example")
	if a.Rcode != "NOERROR" || len(a.TXT) != 1 || a.TXT[0] != "v=DAC1; d=embank.example" || a.TTL != 120*time.Second {
		t.Fatalf("split: %+v", a)
	}
	a = r.LookupTXT(ctx, "alias.example")
	if !a.ViaAlias || len(a.TXT) != 1 || a.TTL != 50*time.Second {
		t.Fatalf("alias: %+v", a)
	}
	a = r.LookupTXT(ctx, "dname.example")
	if !a.ViaAlias || len(a.TXT) != 0 {
		t.Fatalf("dname: %+v", a)
	}
	a = r.LookupTXT(ctx, "missing.example")
	if a.Rcode != "NXDOMAIN" || a.TTL != 120*time.Second {
		t.Fatalf("nxdomain negative TTL: %+v", a)
	}
	a = r.LookupTXT(ctx, "nodata.example")
	if a.Rcode != "NOERROR" || len(a.TXT) != 0 || a.TTL != 60*time.Second {
		t.Fatalf("nodata negative TTL: %+v", a)
	}
	if a = r.LookupTXT(ctx, "secure.example"); a.Secure {
		t.Fatal("AD trusted without TrustAD")
	}
	rt := &WireResolver{Servers: []string{addr}, TrustAD: true, Timeout: 2 * time.Second}
	if a = rt.LookupTXT(ctx, "secure.example"); !a.Secure {
		t.Fatal("AD not reported with TrustAD")
	}
	a = r.LookupTXT(ctx, "big.example")
	if a.Rcode != "NOERROR" || len(a.TXT) != 1 || a.TXT[0] != long {
		t.Fatalf("TCP fallback: %+v", a)
	}
	a = r.LookupTXT(ctx, "spoof.example")
	if a.Rcode != "NOERROR" || len(a.TXT) != 1 {
		t.Fatalf("spoof handling: %+v", a)
	}
	if a = r.LookupTXT(ctx, "servfail.example"); a.Rcode != "SERVFAIL" {
		t.Fatalf("servfail: %+v", a)
	}
	if a = r.LookupTXT(ctx, "refused.example"); a.Rcode != "REFUSED" {
		t.Fatalf("refused: %+v", a)
	}
}

func TestWireResolverTimeout(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	defer pc.Close()
	r := &WireResolver{Servers: []string{pc.LocalAddr().String()}, Timeout: 200 * time.Millisecond}
	if a := r.LookupTXT(context.Background(), "x.example"); a.Rcode != "TIMEOUT" {
		t.Fatalf("timeout: %+v", a)
	}
}

func TestEndToEndOverWire(t *testing.T) {
	z := base()
	addr, stop := startDNS(t, func(q string) respSpec {
		a, ok := z[q]
		if !ok {
			return respSpec{rcode: 3, authority: []rrSpec{{"example", typeSOA, 300, soaRdata(300)}}}
		}
		var ans []rrSpec
		for _, s := range a.TXT {
			ans = append(ans, rrSpec{q, typeTXT, 3600, txtRdata(s)})
		}
		return respSpec{answers: ans}
	})
	defer stop()
	v := &Verifier{Resolver: &WireResolver{Servers: []string{addr}}, Now: func() time.Time { return testNow }}
	if r := v.Verify(context.Background(), "EMBANK.example."); r.Outcome != Confirmed {
		t.Fatalf("end to end: %+v", r)
	}
}
