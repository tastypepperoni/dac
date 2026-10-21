# dac: Domain Affiliation Confirmation

[![test](https://github.com/tastypepperoni/dac/actions/workflows/test.yml/badge.svg)](https://github.com/tastypepperoni/dac/actions/workflows/test.yml)

Domain Affiliation Confirmation (DAC) lets the operator of an established domain
confirm, in the DNS, that another domain is operated by it or under its
authority, so that takedown services and reputation systems can tell a
legitimate new domain from an impersonation.

- **Specification:** [draft-manelidis-dnsop-domain-affiliation](draft/draft-manelidis-dnsop-domain-affiliation-00.txt)
  ([HTML](draft/draft-manelidis-dnsop-domain-affiliation-00.html), [XML source](draft/draft-manelidis-dnsop-domain-affiliation-00.xml))
- **Reference implementation:** this repository: a verifier, a publisher, an
  HTTPS confirmation server, publisher-side checks, failure reporting and a test
  DNS server. Section numbers in the code and in messages refer to the draft.

```
_affiliation.embank.example.   TXT "v=DAC1; p=bank.example; t=<token>"   ; the child's claim
_affiliation.bank.example.     TXT "v=DAC1"                              ; the parent's marker
<token>._affiliation.bank.example. TXT "v=DAC1; d=embank.example"        ; the parent's confirmation
```

## Install

Requires Go 1.24 or later.

```
go install github.com/tastypepperoni/dac/cmd/dac@latest
```

or from a clone:

```
go build -o dac ./cmd/dac      # dac.exe on Windows
go test ./...
```

The only dependencies are `golang.org/x/net` (IDNA) and `golang.org/x/text`.
The DNS client is built in, because the procedure needs the answer section of
responses (to detect CNAME and DNAME records), which the standard library's
resolver does not expose.

## Platforms

Linux, macOS, FreeBSD and Windows (amd64 and arm64). On Windows build with
`go build -o dac.exe ./cmd/dac` and run `dac.exe` in the same way.

- DNS servers come from `/etc/resolv.conf` on Unix-like systems and from the
  active network adapters on Windows; `-resolver` overrides either.
- The report state file is locked with `flock` on Unix-like systems. On Windows
  a `reports.json.lock` file is used instead; if a process crashes while holding
  it, delete that file by hand.

## Testing locally

`dac testdns -zone FILE` runs a small DNS server that answers from a zone file
you edit, so every case can be tried without owning a domain. See
[testing/TESTING.md](testing/TESTING.md) and the ready-made
`testing/scenarios.zone`.

## Verifying

```
dac verify embank.example
dac verify -levels 2 -json embank.example other.example
```

Results are `confirmed`, `not-confirmed`, `none`, `temperror` or `permerror`
(Section 6.3). For each result the tool shows the parent, the channel, whether
the result is authenticated, the parent's mode and abuse contact, the scope
(child only, or every name below it), any expiry date, and how long the result
may be reused. Exit status is 0 when every domain is confirmed, 1 otherwise.

**DNSSEC.** A result is reported as authenticated only when the answers carried
the AD bit from a resolver reached over a trusted path (Section 6.5). By default
the AD bit is trusted only if every resolver is a loopback address, the usual
setup with a local validating resolver such as Unbound. Use `-trust-ad yes` only
when the path to a remote validating resolver is otherwise protected.

**HTTPS channel.** Confirmations over HTTPS are fetched on port 443 with
certificate validation, without redirects, cookies, credentials or proxies,
only from globally reachable addresses that are checked before connecting, and
with at most 1024 octets read (Section 7.2). `-no-https` turns the channel off;
such parents then yield `not-confirmed`.

**Rate limiting.** If names come from untrusted sources, keep the default
per-parent interval (`-per-parent-interval 1s`) so the verifier cannot be used to
flood a parent (Section 11.11).

## Failure reports

```
dac verify -report-state reports.json -reporter filter.example \
           -report-flush -smtp smtp.example:587 -smtp-from dac@filter.example \
           copycat.example
dac report flush -report-state reports.json -smtp smtp.example:587 -smtp-from dac@filter.example
```

Reports are queued only for results the draft allows (Section 9.1) and only to
destinations that pass the rules of Section 4.4. Each destination gets at most one
message per 24 hours (the state file enforces this across runs), with at most
1000 reports, within 65536 octets. A failed delivery is retried once, then
dropped. SMTP credentials come from `SMTP_USER` and `SMTP_PASSWORD`. Send from a
domain that authenticates its mail (SPF, DKIM, DMARC).

## Publishing (parent operator)

The inventory file is the source of truth: confirmations exist exactly for the
domains it lists, and every token ever issued is remembered so none is reused.

```
dac publish init -i bank.json -domain bank.example \
     -contact mailto:abuse@bank.example -report mailto:dac-reports@bank.example
dac publish add -i bank.json embank.example
dac publish add -i bank.json -subtree -expires 2027-12-31 promo.example
dac publish zone -i bank.json          # records for the bank.example zone
dac publish claim -i bank.json embank.example   # record for the child's zone
dac publish remove -i bank.json embank.example  # then republish the zone
```

`add` prints the confirmation and the claim in the order to publish them:
confirmation first (Section 5.1). When a domain is sold or transferred, `remove`
it and republish: this is a MUST (Section 5.2). To move a child to another
parent, follow Section 5.3.

If the parent is itself a child of another domain, record its own claim; the
claim tags and marker tags are published in one record (Section 4.4):

```
dac publish own-claim -i bank.json -parent group.example -token <token from group.example>
```

`-subtree` states that the parent operates or authorizes every name below the
child. Do not use it if anyone else can create names under the child (customer
subdomains, delegations, or dangling records) (Sections 4.3 and 11.12).

### HTTPS channel

```
dac publish set -i bank.json -channel https
dac serve -i bank.json -tls-cert cert.pem -tls-key key.pem       # on port 443
dac publish https-dir -i bank.json ./site                        # or static files
```

The server answers `/.well-known/affiliation/<token>` with `text/plain`,
`Cache-Control: max-age`, and 404 for unknown or expired tokens. The parent apex
must serve HTTPS on port 443 without redirecting (Section 10.4).

## Checking

```
dac check parent -i bank.json   # marker, wildcards, every confirmation, every child
dac check child embank.example  # claim, wildcards and CNAMEs, verification
```

`error` lines are MUST violations; `warning` lines are SHOULD items.

## Tokens

```
dac token            # 160 bits, base32, lowercase (Section 4.6)
dac token -bits 128  # the minimum
```

## Library

```go
import "github.com/tastypepperoni/dac"

v := &dac.Verifier{Resolver: res, Fetcher: &dac.Fetcher{}, Limiter: &dac.ParentLimiter{Interval: time.Second}}
r := v.Verify(ctx, "embank.example")
if r.Outcome == dac.Confirmed { ... }
```

Use `VerifyCached` with a `Cache` to reuse results within the limits of
Section 6.6 and to space out retries after `temperror`.

## License

BSD 3-Clause; see [LICENSE](LICENSE). The draft text is subject to the IETF
Trust's Legal Provisions (BCP 78).
