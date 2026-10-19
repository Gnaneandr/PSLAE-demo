"""Packet inspector for M1 and M2, generated from the REAL message objects (nothing hard-coded except the paper's published widths)."""
import json
from .stage_demos import Ctx, PAPER, M1_SRC, M1_PROT, M2_SRC, M2_PROT

PURPOSE = {"T6LN": "sensor timestamp (freshness)", "D": "alias mask AID6LN xor TID6LC (lookup key)", "CT": "encrypted A||B", "Tag6LN": "authentication tag of M1", "RN1": "sensor fresh random",
           "T6C": "controller timestamp (freshness)", "A1": "B1 xor RN1 (lets the sensor verify the controller)", "M": "SHA-1(SK) key confirmation", "CT1": "encrypted Sc1||RN2", "Tag6LC": "authentication tag of M2", "RN2": "controller fresh random"}


def build(config, seed=2024):
    c = Ctx(config, seed, out=lambda *_: None)
    c.ensure_m2()
    return c


def accounting(c):
    """Return the per-message accounting: measured field bits, literal paper widths, reconstructed total, difference."""
    res = {}
    for name, msg, paper in (("M1", c.m1, PAPER["M1_fields"]), ("M2", c.m2, PAPER["M2_fields"])):
        if msg is None: continue
        rows = [dict(field=f, purpose=PURPOSE[f], bits=len(v) * 8, bytes=len(v), paper_bits=paper.get(f), differs=len(v) * 8 != paper.get(f),
                     source=(M1_SRC if name == "M1" else M2_SRC)[f], protection=(M1_PROT if name == "M1" else M2_PROT)[f]) for f, v in msg.items()]
        measured = sum(r["bits"] for r in rows); literal = sum(paper.values())
        res[name] = dict(rows=rows, measured_bits=measured, measured_bytes=measured // 8, literal_paper_field_bits=literal,
                         paper_reported_bits=PAPER[f"{name}_bits"], diff_vs_paper_reported=measured - PAPER[f"{name}_bits"], diff_vs_literal_fields=measured - literal,
                         serialized_length_bytes=sum(len(v) for v in msg.values()),
                         framing_headers_padding="none: messages are Python dicts of byte strings; no framing/header/padding is added by the code (the demo's wire length is the plain concatenation)")
    if "M1" not in res or "M2" not in res: return res
    res["total"] = dict(measured_bits=res["M1"]["measured_bits"] + res["M2"]["measured_bits"], paper_reported_bits=PAPER["total_bits"],
                        literal_paper_field_bits=res["M1"]["literal_paper_field_bits"] + res["M2"]["literal_paper_field_bits"])
    # internal validation
    for n in [k for k in ("M1", "M2") if k in res]:
        assert res[n]["measured_bits"] == res[n]["serialized_length_bytes"] * 8
    return res


def show(c, which="both", out=print):
    acc = accounting(c)
    out("=" * 78); out(f"PACKET INSPECTOR - {c.cfg.label}"); out("=" * 78)
    for n in ("M1", "M2"):
        if which not in ("both", n) or n not in acc: continue
        a = acc[n]
        out(f"\n{n}   direction: " + ("6LN -> 6LC" if n == "M1" else "6LC -> 6LN") + "   (fields in wire order)")
        out(f"| {'Field':<7}| {'Purpose':<48}| {'Bits':>4} | {'Bytes':>5} | {'Paper':>5} | {'Source':<22}| Protection")
        for r in a["rows"]:
            out(f"| {r['field']:<7}| {r['purpose']:<48}| {r['bits']:>4} | {r['bytes']:>5} | {str(r['paper_bits']):>5} | {r['source']:<22}| {r['protection']}")
        out(f"| TOTAL  | {'':<48}| {a['measured_bits']:>4} | {a['measured_bytes']:>5} | {a['literal_paper_field_bits']:>5} |")
        out(f"  Paper-reported total        : {a['paper_reported_bits']} bits")
        out(f"  Literal paper field widths  : {a['literal_paper_field_bits']} bits (sum of the widths the paper states for each field; M uses 160 bits = SHA-1)")
        out(f"  Measured from real message  : {a['measured_bits']} bits  ({a['serialized_length_bytes']} bytes concatenated)")
        out(f"  Difference vs paper-reported: {a['diff_vs_paper_reported']:+d} bits;  vs literal fields: {a['diff_vs_literal_fields']:+d} bits")
        out(f"  Framing / headers / padding : {a['framing_headers_padding']}")
        if n == "M2":
            t = len(c.m2["T6C"]) * 8
            if t != 32:
                out(f"  EXPLANATION: the {t}-bit T6C is a RECONSTRUCTION (paper: '32 bits timestamp'). With T6C = 32 bits the total is {a['measured_bits'] - (t - 32)} bits (= literal), not 608.")
                out("  The 608/1024 targets are therefore reached only through that field-width change; both figures are reported.")
            else:
                out("  EXPLANATION: with the paper's stated widths M2 totals 576 bits; the paper reports 608 (a 32-bit gap the field list does not explain).")
    if which == "both" and "total" in acc:
        t = acc["total"]
        out(f"\nTOTAL M1+M2: measured {t['measured_bits']} bits | literal field widths {t['literal_paper_field_bits']} | paper-reported {t['paper_reported_bits']} (paper text also says ~1010: inconsistent)")
    return acc


def save(config, outdir):
    c = build(config); acc = accounting(c)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"packets_{config}.json").write_text(json.dumps(acc, indent=1))
    return acc
