# Testing DAC locally

`dac testdns` is a small DNS server that answers from a text file you edit. Point
`dac verify` at it and you can try any situation, including broken ones, without
owning a domain. Fake names such as `embank.example` work because only `dac`
asks this server.

## 1. Start it

Build once (from the repository root):

```
go build -o dac ./cmd/dac      # dac.exe on Windows
```

In one terminal:

```
./dac testdns -zone testing/scenarios.zone
```

It listens on `127.0.0.1:5300` and logs every query. Edit the zone file while it
runs; changes are picked up on the next query.

In a second terminal:

```
./dac verify -resolver 127.0.0.1:5300 embank.example
```

## 2. The ready-made scenarios

`scenarios.zone` contains one child domain per behaviour:

| Command: `./dac verify -resolver 127.0.0.1:5300 …` | Result | What it shows |
|---|---|---|
| `embank.example` | confirmed | the normal case |
| `-levels 2 embank.example` | confirmed, then bank.example confirmed by group.example | a parent that is also a child |
| `copycat.example` | not-confirmed | a copied claim fails: the confirmation names embank.example |
| `fake.example` | not-confirmed | an invented token |
| `sold.example` | not-confirmed | the parent deleted the confirmation |
| `promo.example` | confirmed, scope: every name below it | `s=subtree` with an expiry date |
| `campaign.example` | not-confirmed | an expired confirmation |
| `twoclaims.example` | permerror | two claims at one name |
| `orphan.example` | not-confirmed | the parent publishes no marker |
| `flaky.example` | temperror | the parent's DNS fails (SERVFAIL) |
| `hijack.example` | permerror | the wildcard attack, caught: the marker is reached through a CNAME |
| `hijack2.example` | not-confirmed | the wildcard attack, blocked by the parent's marker |
| `testmode.example` | confirmed, mode test | a parent in test mode |
| `aliased.example` | permerror | a parent whose marker is a CNAME |

Add `-json` for machine-readable output.

## 3. Zone file format

```
name [ttl] [IN] TXT "string" ["string"...]   ; several strings are joined
name [ttl] [IN] CNAME target
name [ttl] [IN] DNAME target
*.name ...                                    ; wildcard owner
name SERVFAIL | REFUSED | TIMEOUT             ; make queries for this name fail
name INSECURE                                 ; no AD bit for this name (with -ad)
; comment
```

Names that exist only because names below them exist (empty non-terminals)
answer "no data", as real servers do. Missing names answer NXDOMAIN.

## 4. Things to try

Break something in the zone file, save, and verify again:

- Delete the `d=` from embank's confirmation → `permerror`.
- Change `d=embank.example` to `d=other.example` → `not-confirmed`.
- Write the token in capitals in the claim → `permerror`.
- Add a second confirmation record at the same token → `permerror`.
- Add `x=2026-10-22` (today, in UTC) to a confirmation → `confirmed` until midnight UTC.
- Add `_affiliation.bank.example TIMEOUT` → `temperror` after the timeout.
- Change the marker to `"v=DAC1; c=future"` → `not-confirmed` (unsupported channel).
- Add unknown tags like `z=whatever` anywhere → ignored, still `confirmed`.

## 5. Test the publishing workflow end to end

Keep the parent's records and the children's claims in separate files, as they
would live in separate zones, and join them for testdns:

```
./dac publish init -i bank.json -domain bank.example -contact mailto:abuse@bank.example
./dac publish add -i bank.json embank.example
./dac publish add -i bank.json -subtree promo.example

./dac publish zone -i bank.json                  > parent.zone
./dac publish claim -i bank.json embank.example  > children.zone
./dac publish claim -i bank.json promo.example  >> children.zone
cat parent.zone children.zone > my.zone

./dac testdns -zone my.zone -listen 127.0.0.1:5301
./dac verify -resolver 127.0.0.1:5301 embank.example promo.example
./dac check parent -resolver 127.0.0.1:5301 -i bank.json
```

Now end embank's affiliation the way a parent would, by deleting only its
confirmation:

```
./dac publish remove -i bank.json embank.example
./dac publish zone -i bank.json > parent.zone
cat parent.zone children.zone > my.zone
./dac verify -resolver 127.0.0.1:5301 embank.example     # not-confirmed
```

embank's claim is still published, but the parent no longer confirms it.

## 6. DNSSEC ("authenticated")

`-ad` makes testdns set the AD bit, as a validating resolver does for signed
zones. Because testdns runs on a loopback address, `dac verify` trusts that bit
by default:

```
./dac testdns -zone testing/scenarios.zone -ad
./dac verify -resolver 127.0.0.1:5300 embank.example     # authenticated: dnssec
```

Mark one name `INSECURE` in the zone file to see the result drop to
"authenticated: no". This tests how `dac` handles validation results; it does
not test real signing. For that you need a signed zone (Knot DNS, BIND or
PowerDNS) and a validating resolver such as Unbound.

## 7. Failure reports

```
./dac verify -resolver 127.0.0.1:5300 -report-state reports.json -reporter test.example copycat.example
cat reports.json
```

The report for `copycat.example` is queued for `mailto:dac-reports@bank.example`.
To see the email without sending real mail, run a local SMTP debug server
(`python3 -m aiosmtpd -n -l 127.0.0.1:1025`) and flush to it:

```
./dac report flush -report-state reports.json -smtp 127.0.0.1:1025 -smtp-from dac@test.example
```

Run the flush again: it refuses, because a destination gets at most one message
per 24 hours.

## 8. What cannot be tested locally

**The HTTPS channel.** By design (Section 7.2) the verifier refuses to connect to
loopback and private addresses, so a parent served from your own machine always
yields `permerror` ("no globally reachable address"). Test it with a real domain
whose apex serves HTTPS on port 443:

```
./dac publish set -i bank.json -channel https
./dac serve -i bank.json -tls-cert cert.pem -tls-key key.pem
```

The Go test suite covers the HTTPS channel against a local TLS server with that
restriction relaxed only inside the tests.

**Real-world caching and propagation.** Use two real domains (a test parent and a
test child) at any DNS provider, publish the records from `dac publish`, and
verify with `./dac verify` using your normal resolver.
