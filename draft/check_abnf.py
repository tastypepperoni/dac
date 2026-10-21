"""Check the draft's examples against the draft's own ABNF.

The grammar is taken from the <sourcecode type="abnf"> block of the XML source,
so the grammar checked is exactly the grammar published.  Every quoted DAC
record in the rendered text must match the "record" rule, and a set of known
good and bad values must be accepted and rejected as expected.

    pip install abnf
    python3 check_abnf.py draft-manelidis-dnsop-domain-affiliation-00.txt
"""
import re
import sys
from pathlib import Path

from abnf.parser import ParseError, Rule as _Rule


class R(_Rule):
    pass


def main() -> int:
    txt_path = Path(sys.argv[1] if len(sys.argv) > 1 else "draft-manelidis-dnsop-domain-affiliation-00.txt")
    xml_path = txt_path.with_suffix(".xml")
    xml = xml_path.read_text(encoding="utf-8")
    grammar = re.search(r'<sourcecode type="abnf"[^>]*><!\[CDATA\[\n(.*?)\]\]>', xml, re.S).group(1)
    R.load_grammar(grammar)

    def ok(rule: str, s: str) -> bool:
        try:
            R(rule).parse_all(s)
            return True
        except ParseError:
            return False

    tok = "mfrggzdfmztwq2lknnwg23tpobyxe43u"
    good = [("record", f"v=DAC1; p=bank.example; t={tok}"),
            ("record", "v=DAC1; c=https; r=mailto:abuse@bank.example"),
            ("record", "v=DAC1"), ("record", "v=DAC1;"), ("record", "v = DAC1 ; d=embank.example"),
            ("record", "v=DAC1; m=test"), ("record", "v=DAC1; d=xn--lodbwdo.example"),
            ("record", "v=DAC1; d=embank.example; s=subtree; x=2027-12-31"),
            ("p-value", "bank.example"), ("p-value", "bank"), ("d-value", "xn--lodbwdo.example"),
            ("t-value", tok), ("t-value", "a" * 26), ("x-value", "2027-03-31")]
    bad = [("record", "v=dac1"), ("record", "V=DAC1"), ("record", "p=x; v=DAC1"),
           ("record", "v=DAC1; p"), ("record", "v=DAC1; p=a b"), ("t-value", tok.upper()),
           ("t-value", "a" * 25), ("t-value", "a1" * 13), ("domain", "-a.example"),
           ("domain", "a-.example"), ("domain", "Bank.example"), ("domain", "bank.example."),
           ("x-value", "2027-1-01")]
    fails = [f"should match {r}: {s!r}" for r, s in good if not ok(r, s)]
    fails += [f"should not match {r}: {s!r}" for r, s in bad if ok(r, s)]

    text = txt_path.read_text(encoding="utf-8")
    n = 0
    for m in re.finditer(r'"(v=DAC1[^"]*)"', text):
        rec = m.group(1)
        if "|" in rec:            # box drawing in figures
            continue
        if "t=T" in rec:          # test-vector shorthand
            continue
        n += 1
        if not ok("record", " ".join(rec.split())):
            fails.append(f"example does not match the ABNF: {rec!r}")
    for f in fails:
        print("FAIL", f)
    print(f"checked {n} records from {txt_path.name}; {len(fails)} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
