package dac

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Report is one entry of a failure report (§9.2).
type Report struct {
	Version  string `json:"version"`
	Observed string `json:"observed"`
	Child    string `json:"child"`
	Parent   string `json:"parent"`
	Result   string `json:"result"`
	Reason   string `json:"reason"`
	Reporter string `json:"reporter,omitempty"`
}

// MaxReportsPerMessage limits the entries in one message (§9.1: SHOULD limit,
// for example to 1000).
const MaxReportsPerMessage = 1000

// ReportInterval is the minimum time between messages to one destination
// (§9.1: MUST send at most one message per report destination in 24 hours).
const ReportInterval = 24 * time.Hour

// ReportFor returns the report for a result, or false if none may be sent:
// the result must carry a report destination and reason (§9.1).
func ReportFor(res Result, reporter string) (Report, bool) {
	if res.ReportTo == "" || res.ReportReason == "" ||
		(res.Outcome != NotConfirmed && res.Outcome != PermError) {
		return Report{}, false
	}
	return Report{
		Version:  Version,
		Observed: res.Observed.UTC().Format(time.RFC3339),
		Child:    res.Child,
		Parent:   res.Parent,
		Result:   string(res.Outcome),
		Reason:   res.ReportReason,
		Reporter: reporter,
	}, true
}

// Sender delivers one message to one destination.
type Sender interface {
	Send(ctx context.Context, destination, parent string, body []byte) error
}

// Reporter queues reports and sends them under the limits of §9.1 and §9.3.
// Its state is kept in a JSON file so that the 24-hour limit holds across runs.
type Reporter struct {
	StatePath string
	Reporter  string // optional "reporter" member (§9.2)
	HTTPS     Sender // for "https" destinations
	Mail      Sender // for "mailto" destinations

	mu sync.Mutex
}

type destState struct {
	LastSent time.Time `json:"last_sent"`
	Pending  []Report  `json:"pending"`
}

type reporterState struct {
	Destinations map[string]*destState `json:"destinations"`
}

// lock takes an exclusive lock on the state file, so that the 24-hour limit
// holds across processes (§9.1).  See lock_unix.go and lock_other.go.
func (r *Reporter) lock() (func(), error) { return lockFile(r.StatePath + ".lock") }

func (r *Reporter) load() (*reporterState, error) {
	st := &reporterState{Destinations: map[string]*destState{}}
	b, err := os.ReadFile(r.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("report state %s: %w", r.StatePath, err)
	}
	if st.Destinations == nil {
		st.Destinations = map[string]*destState{}
	}
	return st, nil
}

func (r *Reporter) save(st *reporterState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.StatePath)
}

// Queue adds the report for res, if any.  Duplicate entries for the same child,
// parent and reason are not queued twice.
func (r *Reporter) Queue(res Result) (bool, error) {
	rep, ok := ReportFor(res, r.Reporter)
	if !ok {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, err := r.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	st, err := r.load()
	if err != nil {
		return false, err
	}
	d := st.Destinations[res.ReportTo]
	if d == nil {
		d = &destState{}
		st.Destinations[res.ReportTo] = d
	}
	for _, p := range d.Pending {
		if p.Child == rep.Child && p.Parent == rep.Parent && p.Reason == rep.Reason {
			return false, r.save(st)
		}
	}
	if len(d.Pending) >= 10*MaxReportsPerMessage {
		return false, r.save(st) // bound the queue; excess reports are dropped
	}
	d.Pending = append(d.Pending, rep)
	return true, r.save(st)
}

// FlushResult describes what Flush did for one destination.
type FlushResult struct {
	Destination string
	Parent      string
	Sent        int
	Err         error
	NextAllowed time.Time
}

// Flush sends at most one message to each destination whose 24-hour interval
// has passed.  A message carries reports for one parent (its subject names that
// parent, §9.3), at most MaxReportsPerMessage of them, within MaxReportBody
// octets.  A failed delivery is retried once and then abandoned (§9.3).
func (r *Reporter) Flush(ctx context.Context, now time.Time) ([]FlushResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, err := r.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	var out []FlushResult
	dests := make([]string, 0, len(st.Destinations))
	for k := range st.Destinations {
		dests = append(dests, k)
	}
	sort.Strings(dests)
	for _, dest := range dests {
		d := st.Destinations[dest]
		if len(d.Pending) == 0 {
			continue
		}
		next := d.LastSent.Add(ReportInterval)
		if !d.LastSent.IsZero() && now.Before(next) {
			out = append(out, FlushResult{Destination: dest, NextAllowed: next})
			continue
		}
		parent := d.Pending[0].Parent
		var batch, rest []Report
		for _, p := range d.Pending {
			if p.Parent == parent && len(batch) < MaxReportsPerMessage {
				batch = append(batch, p)
			} else {
				rest = append(rest, p)
			}
		}
		body, err := json.MarshalIndent(batch, "", "  ")
		for err == nil && len(body) > MaxReportBody && len(batch) > 1 {
			half := len(batch) / 2
			moved := append([]Report(nil), batch[half:]...)
			rest = append(moved, rest...)
			batch = batch[:half]
			body, err = json.MarshalIndent(batch, "", "  ")
		}
		if err != nil {
			return out, err
		}
		sender := r.HTTPS
		if strings.HasPrefix(dest, "mailto:") {
			sender = r.Mail
		}
		fr := FlushResult{Destination: dest, Parent: parent}
		if sender == nil {
			fr.Err = errors.New("no sender configured for this destination")
			out = append(out, fr)
			continue
		}
		// Re-check the destination against the parent before sending (§9.1).
		if ValidReportURI(dest, parent) == "" {
			fr.Err = errors.New("destination does not meet the conditions of Section 4.4")
			d.Pending = rest
			out = append(out, fr)
			continue
		}
		sendErr := sender.Send(ctx, dest, parent, body)
		if sendErr != nil {
			sendErr = sender.Send(ctx, dest, parent, body) // one retry, no more
		}
		// The message counts against the 24-hour limit whether or not it was
		// delivered, and its reports are not sent again.
		d.LastSent = now
		d.Pending = rest
		fr.Sent, fr.Err, fr.NextAllowed = len(batch), sendErr, now.Add(ReportInterval)
		if sendErr != nil {
			fr.Sent = 0
		}
		out = append(out, fr)
	}
	return out, r.save(st)
}

// HTTPSSender posts reports with the restrictions of §7.2, except that the
// content may be up to 65536 octets (§9.3).
type HTTPSSender struct{ Fetcher *Fetcher }

// Send implements Sender.
func (s HTTPSSender) Send(ctx context.Context, dest, _ string, body []byte) error {
	rest := strings.TrimPrefix(dest, "https://")
	host, path := rest, "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	h := s.Fetcher.Post(ctx, host, path, body, "application/json")
	if h.Status < 200 || h.Status > 299 {
		return fmt.Errorf("report POST to %s: status %d", dest, h.Status)
	}
	return nil
}

// SMTPSender sends reports by email through a submission server (§9.3).
// From SHOULD be an address at a domain that authenticates its mail.
type SMTPSender struct {
	Server string // host:port of the submission server
	From   string
	Auth   smtp.Auth
}

// Send implements Sender.
func (s SMTPSender) Send(_ context.Context, dest, parent string, body []byte) error {
	to := strings.TrimPrefix(dest, "mailto:")
	if s.Server == "" || s.From == "" {
		return errors.New("SMTP server and From address are required")
	}
	msg := BuildReportEmail(s.From, to, parent, body, time.Now())
	return smtp.SendMail(s.Server, s.Auth, s.From, []string{to}, msg)
}

// BuildReportEmail builds the message of §9.3: subject "DAC report for"
// followed by the parent domain, and the report as the body with media type
// "application/json".
func BuildReportEmail(from, to, parent string, body []byte, now time.Time) []byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	domain := from
	if i := strings.LastIndexByte(from, '@'); i >= 0 {
		domain = from[i+1:]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: <%s>\r\n", from)
	fmt.Fprintf(&b, "To: <%s>\r\n", to)
	fmt.Fprintf(&b, "Subject: DAC report for %s\r\n", parent)
	fmt.Fprintf(&b, "Date: %s\r\n", now.UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id[:]), domain)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: application/json\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(string(body), "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}
