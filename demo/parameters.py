"""Machine-readable + human-readable parameter register. Sizes come from a REAL run; 'stored' and 'transmitted' are derived from the real objects."""
import json
from .stage_demos import Ctx, ake3_stage

# key, symbol/name, purpose, origin, secret?, first generated (function), used in, paper section, status, declared_bits (None = no fixed width), encoding
P = [
 ("id6ln", "ID6LN sensor real identity", "anchors the alias identity", "input (given at registration)", True, "demo input -> register_sensor()", "AID6LN, Sm", "Sec.5.1 RP-1/RP-2", "literal", 64),
 ("id6lc", "ID6LC controller real identity", "feeds T = Mk xor H(ID6LC) -> Sc1", "random", True, "registration.make_controller()", "ake.step_ake2 (T)", "Sec.5.1 RP-1; AKE2", "literal (width assumed)", 64),
 ("tid6lc", "TID6LC controller temporary identity", "masks AID6LN inside D", "random", True, "registration.make_controller()", "D, alias recovery", "Sec.5.1 RP-1; AKE1/AKE2", "literal (generation rule not stated)", 64),
 ("r6lc", "R6LC random value", "feeds Mk(reg)", "random", True, "registration.register_sensor()", "Mk(reg)", "Sec.5.1 RP-1/RP-2", "literal", 64),
 ("k6lc", "K6LC key (controller side)", "blinds AID6LN", "random", True, "registration.register_sensor()", "AID6LN (never again)", "Sec.5.1 RP-1/RP-2", "literal; unused after registration in the code", 64),
 ("k6ln", "K6LN key (sensor side)", "blinds AID6LN; feeds AD, B1, Mk", "random", True, "registration.register_sensor()", "AID6LN, AD, B1, Mk(reconstructed)", "Sec.5.1 RP-1/RP-2; AKE", "literal", 64),
 ("aid6ln", "AID6LN alias identity", "pseudonymous identity; database key; SK input", "derived (ID xor K6LN xor K6LC)", True, "registration.register_sensor()", "A, B, D, SK, DB lookup", "Sec.5.1 RP-2", "literal (rotation after sessions is a reconstruction)", 64),
 ("ms", "Ms master secret", "root of Mk(reg)", "random", True, "registration.register_sensor()", "Mk(reg)", "Sec.5.1 RP-2", "reconstructed width: paper says '265 bits'", 256),
 ("mk_reg", "Mk(reg) = Ms xor H(R6LC)", "registration-time master key", "derived", True, "registration.register_sensor()", "Sm", "Sec.5.1 RP-2", "reconstructed (H_bits extension)", 256),
 ("sm", "Sm = Mk(reg) xor H(ID6LN)", "seed of Sc", "derived", True, "registration.register_sensor()", "Sc", "Sec.5.1 RP-2", "reconstructed (H_bits extension)", 256),
 ("sc", "Sc secret authentication parameter", "proves the sensor knows a shared secret", "derived (fold of Sm)", True, "registration.register_sensor()", "A, Sc' check, X", "Sec.5.1 RP-2", "literal; later replaced by Sc1 (reconstruction)", 64),
 ("mk", "Mk master key used by AKE", "feeds X, Fr, T", "derived", True, "entities.SixLN.mk / SensorRecord.mk", "X, Fr, T", "Sec.5.1 RP-2/RP-4", "reconstructed in the audited configuration: H_bits(Sc||K6LN)", 256),
 ("x", "X = Mk xor tile(Sc)", "source of Nc, Kc", "derived", True, "registration.compute_Si()", "Si", "Sec.5.1 RP-4", "reconstructed (tile)", 256),
 ("nc", "Nc nonce / counter block", "AES-CTR initial counter", "derived (X first half)", True, "registration.compute_Si()", "ACE", "Sec.5.1 RP-4; Sec.4.4", "literal split", 128),
 ("kc", "Kc key", "AES-128 key and HMAC key", "derived (X second half)", True, "registration.compute_Si()", "ACE", "Sec.5.1 RP-4; Sec.4.4", "literal split", 128),
 ("si", "Si = Nc||Kc initial state", "ACE state", "derived", True, "ace.init_state()", "encrypt/decrypt", "Sec.5.1 RP-4", "literal (paper says '265 bits')", 256),
 ("fr", "Fr = Mk xor H(K6LN)", "source of AD", "derived", True, "registration.compute_AD()", "AD", "Sec.5.1 RP-5", "reconstructed (H_bits)", 256),
 ("ad", "AD associated data", "authenticated, not encrypted, not transmitted", "derived (Fr1 xor Fr2)", True, "registration.compute_AD()", "ACE tag", "Sec.5.1 RP-5", "literal", 128),
 ("rn1", "RN1 sensor random number", "freshness; hidden in B; SK input", "random", False, "ake.step_ake1()", "A, B, A1, SK", "Sec.5.2 AKE1", "literal", 64),
 ("t6ln", "T6LN sensor timestamp", "freshness window", "clock", False, "ake.step_ake1()", "AKE2 freshness only", "Sec.5.2 AKE1", "literal (32 bits)", 32),
 ("a", "A = AID6LN xor RN1 xor Sc", "carries Sc to the controller", "derived", True, "ake.step_ake1()", "PT of M1; Sc' check", "Sec.5.2 AKE1", "literal", 64),
 ("b", "B = AID6LN xor RN1", "carries RN1", "derived", True, "ake.step_ake1()", "PT of M1; RN1 recovery", "Sec.5.2 AKE1", "literal", 64),
 ("pt", "PT = A||B", "plaintext block of M1", "derived", True, "ake.step_ake1()", "ACE encrypt", "Sec.5.2 AKE1", "literal", 128),
 ("d", "D = AID6LN xor TID6LC", "alias lookup key on the wire", "derived", False, "ake.step_ake1()", "AKE2 lookup", "Sec.5.2 AKE1 (Fig.5 prints AID6LC)", "literal (text version)", 64),
 ("ct", "CT ciphertext of M1", "hides A||B", "derived (AES-CTR)", False, "ace.encrypt()", "AKE2", "Sec.5.2 AKE1", "ACE interface reconstruction", 128),
 ("tag6ln", "Tag6LN authentication tag", "integrity/authenticity of AD||CT", "derived (HMAC-SHA256/128)", False, "ace.encrypt()", "AKE2", "Sec.5.2 AKE1", "ACE interface reconstruction", 128),
 ("aid_from_d", "AID6LN recovered = TID6LC xor D", "database lookup", "derived", True, "ake.step_ake2()", "lookup, SK", "Sec.5.2 AKE2", "literal", 64),
 ("mk_prime", "Mk' at the controller", "feeds Si', AD', T", "derived", True, "SensorRecord.mk", "AKE2", "Sec.5.2 AKE2", "reconstructed in audited config", 256),
 ("t6c", "T6C controller timestamp", "freshness window", "clock", False, "ake.step_ake2()", "AKE3 freshness only", "Sec.5.2 AKE2", "RECONSTRUCTED to 64 bits in the audited config (paper: 32)", None),
 ("rn2", "RN2 controller random number", "freshness; B1; SK input", "random", False, "ake.step_ake2()", "B1, SK", "Sec.5.2 AKE2", "literal (R2 identified with RN2)", 64),
 ("t_val", "T = Mk' xor H(ID6LC)", "source of Sc1", "derived", True, "ake.step_ake2()", "Sc1", "Sec.5.2 AKE2", "reconstructed (H_bits)", 256),
 ("sc1", "Sc1 new Sc", "SK input; replaces Sc", "derived (fold of T)", True, "ake.step_ake2()", "SK, CT1, next session", "Sec.5.2 AKE2", "literal; replacing Sc is a reconstruction", 64),
 ("b1", "B1 = RN2 xor K6LN", "SK input; A1", "derived", True, "ake.step_ake2()", "A1, SK", "Sec.5.2 AKE2", "literal", 64),
 ("a1", "A1 = B1 xor RN1", "lets the sensor verify the controller", "derived", False, "ake.step_ake2()", "AKE3 check", "Sec.5.2 AKE2", "literal", 64),
 ("sk_6lc", "SK session key (controller)", "session key; NEVER transmitted", "derived (SHA-1)", True, "ake.step_ake2()", "later communication", "Sec.5.2 AKE2", "literal; width 160 bits (paper silent)", 160),
 ("m", "M = SHA-1(SK)", "key confirmation", "derived", False, "ake.step_ake2()", "AKE3 check", "Sec.5.2 AKE2", "literal (second, separate hash)", 160),
 ("pt1", "PT1 = Sc1||RN2", "plaintext block of M2", "derived", True, "ake.step_ake2()", "ACE encrypt", "Sec.5.2 AKE2", "literal ('R2' typo resolved to RN2)", 128),
 ("ct1", "CT1 ciphertext of M2", "hides Sc1||RN2", "derived", False, "ace.encrypt()", "AKE3", "Sec.5.2 AKE2", "ACE interface reconstruction", 128),
 ("tag6lc", "Tag6LC authentication tag", "integrity of AD||CT1", "derived", False, "ace.encrypt()", "AKE3", "Sec.5.2 AKE2", "ACE interface reconstruction", 128),
 ("b1_prime", "B1' = RN2 xor K6LN (sensor)", "independent recomputation", "derived", True, "ake.step_ake3()", "A1', SK'", "Sec.5.2 AKE3", "literal (B1 vs B1' typo resolved)", 64),
 ("sk_6ln", "SK' session key (sensor)", "must equal SK", "derived (SHA-1)", True, "ake.step_ake3()", "later communication", "Sec.5.2 AKE3", "literal; Sc1 taken from CT1 (reconstruction)", 160),
]
WIRE = {"t6ln", "d", "ct", "tag6ln", "rn1", "t6c", "a1", "m", "ct1", "tag6lc", "rn2"}


def build(config, seed=2024):
    c = Ctx(config, seed, out=lambda *_: None)
    c.ensure_m2(); ake3_stage(c, header=False)
    sens, rec = vars(c.sensor), vars(next(iter(c.controller.db.values())))
    rows = []
    for key, name, purpose, origin, secret, first, used, paper, status, declared in P:
        v = c.vals.get(key)
        if v is None: continue
        bits = len(v) * 8
        st = [w for w, d in (("6LN", sens), ("6LC record", rec), ("6LC controller object", vars(c.controller))) if key in d or key.replace("_", "") in d]
        rows.append(dict(key=key, symbol_name=name, purpose=purpose, bits=bits, bytes=len(v), declared_bits=declared, width_matches_declaration=(declared is None or declared == bits),
                         data_type="bytes (big-endian where numeric)", encoding="raw bytes; hex in reports", origin=origin, secret=secret, first_generated=first, used_in=used,
                         transmitted=("yes (wire field)" if key in WIRE else ("hidden inside CT/CT1" if key in {"a", "b", "pt", "pt1", "sc1"} else "no")),
                         stored=("; ".join(st) if st else "no (derived on demand / transient)"), source_file="src/ " + first, paper_section=paper, literal_or_reconstructed=status))
    return c, rows


def save_and_markdown(config, outdir, mdpath=None):
    c, rows = build(config)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"parameter_register_{config}.json").write_text(json.dumps(rows, indent=1))
    md = [f"# Parameter register ({config} configuration)\n", "Generated by `python demo.py parameters --save`. Sizes measured from a real run; 'stored' is derived from the real objects' attributes.\n",
          "| Key | Name | Bits | Bytes | Secret | Origin | Transmitted | Stored | First generated | Paper | Status |", "|---|---|---:|---:|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['key']} | {r['symbol_name']} | {r['bits']} | {r['bytes']} | {'secret' if r['secret'] else 'public'} | {r['origin']} | {r['transmitted']} | {r['stored']} | {r['first_generated']} | {r['paper_section']} | {r['literal_or_reconstructed']} |")
    return c, rows, "\n".join(md) + "\n"


def show(config, out=print):
    c, rows = build(config)
    out("=" * 78); out(f"PARAMETER REGISTER - {c.cfg.label}"); out("=" * 78)
    out(f"{'Key':<11}{'Bits':>5}{'B':>4} {'Kind':<7}{'Transmitted':<24}{'Stored':<26}Status")
    for r in rows:
        out(f"{r['key']:<11}{r['bits']:>5}{r['bytes']:>4} {'secret' if r['secret'] else 'public':<7}{r['transmitted'][:23]:<24}{r['stored'][:25]:<26}{r['literal_or_reconstructed'][:50]}")
    bad = [r["key"] for r in rows if not r["width_matches_declaration"]]
    out(f"\n{len(rows)} parameters; width differs from declaration for: {bad or 'none'}  (full JSON/Markdown via --save)")
    return rows
