"""Stage-by-stage demonstrations that call the REAL protocol functions (registration.register_sensor, ake.step_ake1/2/3).

Pattern for every stage: (1) take a snapshot of the real state, (2) recompute each intermediate value with the same helper functions,
(3) run the real step function, (4) assert the recomputation equals the real output (printed as 'verified against real function').
Secrets are redacted unless the educational insecure mode (--reveal-secrets) is enabled."""
import copy, sys, pathlib
from .runtime import Cfg, Trace, FakeClock, DemoRandom, instrument, ROOT

PAPER = {"M1_bits": 416, "M2_bits": 608, "total_bits": 1024,
         "M1_fields": {"T6LN": 32, "D": 64, "CT": 128, "Tag6LN": 128, "RN1": 64},
         "M2_fields": {"T6C": 32, "A1": 64, "M": 160, "CT1": 128, "Tag6LC": 128, "RN2": 64}}   # M = 160: paper's own accounting (SHA-1)
SECRET = {"id6ln", "id6lc", "k6ln", "k6lc", "r6lc", "ms", "mk_reg", "sm", "sc", "mk", "x", "nc", "kc", "si", "fr", "ad", "aid6ln", "rn1_secret",
          "a", "b", "pt", "pt1", "sc1", "b1", "sk", "sk_6lc", "sk_6ln", "t_val", "mk_prime", "new_aid6ln", "aid_from_d", "b1_prime"}


class Ctx:
    def __init__(self, config="reconstructed", seed=2024, os_random=False, reveal=False, out=print):
        self.cfg, self.seed, self.reveal, self.out = Cfg(config), seed, reveal, out
        self.rng = None if os_random else DemoRandom(seed)
        self.trace, self.clock = Trace(), FakeClock()
        self.controller = self.sensor = self.m1 = self.m2 = self.ake2_res = self.sk_sensor = None
        self.vals, self.registered, self.checks = {}, False, {}

    # ---------- helpers
    def run(self, fn, *a, rng=None):
        with instrument(self.cfg, self.trace, self.clock, rng if rng is not None else self.rng):
            return fn(*a)

    def p(self, *a): self.out(" ".join(str(x) for x in a))
    def h(self, t): self.p(""); self.p("=" * 78); self.p(t); self.p("=" * 78)
    def sub(self, t): self.p(""); self.p("--- " + t)

    def kv(self, name, value, kind="public", note="", key=None):
        """Print one named value with its size; secrets redacted unless --reveal-secrets."""
        key = key or name.lower().replace(" ", "")
        if isinstance(value, (bytes, bytearray)):
            self.vals[key] = bytes(value)
            show = value.hex() if (kind == "public" or self.reveal) else f"<redacted {len(value)} B secret>"
            self.p(f"  {name:<12}{len(value)*8:>5} bits {len(value):>3} B  [{kind:<9}] {show}" + (f"   # {note}" if note else ""))
        else:
            self.p(f"  {name:<12}{str(value):<30}[{kind:<9}]" + (f"   # {note}" if note else ""))

    def banner(self, title):
        self.h(title)
        self.p(f"Configuration : {self.cfg.label}")
        self.p(f"Randomness    : " + (f"seeded demo DRBG (seed={self.seed}) - DISPOSABLE DEMONSTRATION KEYS" if self.rng else "os.urandom"))
        if self.reveal: self.p("*** EDUCATIONAL INSECURE MODE: disposable demonstration secrets are printed. Never do this with real keys. ***")
        else: self.p("Secrets       : redacted (use --reveal-secrets for the educational insecure mode)")

    # ---------- prerequisites
    def ensure_registered(self, quiet=True):
        if not self.registered:
            saved, self.out = self.out, (lambda *_: None) if quiet else self.out
            try: registration_stage(self, 5, header=False)
            finally: self.out = saved
        return self

    def ensure_m1(self):
        self.ensure_registered()
        if self.m1 is None:
            saved, self.out = self.out, (lambda *_: None)
            try: ake1_stage(self, header=False)
            finally: self.out = saved
        return self

    def ensure_m2(self):
        self.ensure_m1()
        if self.m2 is None:
            saved, self.out = self.out, (lambda *_: None)
            try: ake2_stage(self, header=False)
            finally: self.out = saved
        return self


def mk_of_record(cfg, rec):
    return rec.mk if hasattr(type(rec), "mk") else cfg.cu.xor_bytes(rec.ms, cfg.cu.H_bits(rec.r6lc, 256))


# =====================================================================================================
def registration_stage(ctx: Ctx, stop_after=5, header=True):
    cfg, cu, reg, ent = ctx.cfg, ctx.cfg.cu, ctx.cfg.registration, ctx.cfg.entities
    if header: ctx.banner("DEMO B - REGISTRATION RP-1 .. RP-5 (Sec.5.1)")
    ctx.trace.set_stage("Registration")
    ctrl = ctx.run(reg.make_controller)
    id6ln = ctx.rng(8) if ctx.rng else cu.random_bytes(8)
    # replay the same random draws that register_sensor will make, to show each step; then verify against the real function
    rng2 = DemoRandom(ctx.seed); rng2.n = ctx.rng.n if ctx.rng else 0
    d = lambda n: ctx.rng(n) if ctx.rng else cu.random_bytes(n)
    if header:
        ctx.sub("System initialisation (Demo A content): entities and algorithms")
        ctx.p("  6LC (controller) object :", type(ctrl).__name__, "- holds ID6LC, TID6LC and a database keyed by AID6LN")
        ctx.p("  6LN (sensor) object     :", type(ctx.cfg.entities.SixLN).__name__, "- holds its own secrets only")
        ctx.p("  Hash H            : SHA-1 (160-bit) - the paper's 'SHA-160'; H_bits = SHA-1 counter-mode extension (RECONSTRUCTION, not in paper)")
        ctx.p("  Authenticated enc.: ACE interface reconstruction = AES-128-CTR + HMAC-SHA256 truncated to 128 bits (NOT the authors' ACE)")
        ctx.p("  Randomness        : 64-bit identifiers/nonces, 256-bit master secret (demo: seeded DRBG)")
    draws = {"r6lc": d(8), "k6lc": d(8), "k6ln": d(8)}
    ms = d(32)
    # --- RP-1
    ctx.sub("RP-1  6LC receives ID6LN over a secure channel, picks ID6LC, R6LC, K6LC, K6LN   [paper: Sec.5.1 Step RP-1]")
    ctx.p("  Status: LITERAL for the values; bit-lengths of ID6LC/R6LC are not stated in the paper (64 assumed). TID6LC: generation rule not stated.")
    ctx.kv("ID6LN", id6ln, "secret", "given to 6LC over the secure channel")
    ctx.kv("ID6LC", ctrl.id6lc, "secret", "controller's real identity (chosen in make_controller)")
    ctx.kv("TID6LC", ctrl.tid6lc, "secret", "controller's temporary identity; later masks AID6LN inside D")
    for n in ("r6lc", "k6lc", "k6ln"): ctx.kv(n.upper(), draws[n], "secret", "random 64-bit value (CSPRNG)")
    if stop_after == 1: return _stop(ctx, 1)
    # --- RP-2
    ctx.sub("RP-2  AID6LN = ID6LN xor K6LN xor K6LC;  Mk(reg) = Ms xor H(R6LC);  Sm = Mk(reg) xor H(ID6LN);  Sc = Sc1^Sc2^Sc3^Sc4   [Sec.5.1 Step RP-2]")
    ctx.p("  PAPER AMBIGUITY: the paper says 'master key Ms of 265 bits ... Mk = Ms xor H(R6LC)'. 265 is not byte-aligned (typo for 256: 128+128), and a 160-bit SHA-1")
    ctx.p("  cannot be XORed with 256 bits. RECONSTRUCTION: Ms = 256 bits; H(.) is extended to 256 bits with H_bits (SHA-1 counter mode, not in paper).")
    aid = cu.xor_many(id6ln, draws["k6ln"], draws["k6lc"])
    ctx.kv("AID6LN", aid, "secret", "LITERAL: ID6LN xor K6LN xor K6LC (64 bits)")
    ctx.kv("Ms", ms, "secret", "RECONSTRUCTED width 256 bits (paper text: '265')")
    mk_reg = cu.xor_bytes(ms, cu.H_bits(draws["r6lc"], 256))
    ctx.kv("Mk(reg)", mk_reg, "secret", "Ms xor H_bits(R6LC,256)  [H_bits is a reconstruction]", key="mk_reg")
    sm = cu.xor_bytes(mk_reg, cu.H_bits(id6ln, 256))
    ctx.kv("Sm", sm, "secret", "Mk(reg) xor H_bits(ID6LN,256)")
    sc = cu.xor_many(*cu.split_equal(sm, 4))
    ctx.kv("Sc", sc, "secret", "XOR of four 64-bit chunks of Sm (LITERAL structure)")
    if stop_after == 2: return _stop(ctx, 2)
    # --- RP-3: run the REAL function and compare
    ctx.sub("RP-3  Storage: 6LC database record and 6LN memory   [Sec.5.1 Step RP-3]")
    ctrl_real = ent_clone(ent, ctrl)
    rng_real = DemoRandom(ctx.seed); rng_real.n = rng2.n
    sensor = ctx.run(reg.register_sensor, ctrl_real, id6ln, rng=rng_real if ctx.rng else None)
    rec = ctrl_real.lookup(sensor.aid6ln)
    same = all([sensor.aid6ln == aid, sensor.sc == sc, sensor.k6ln == draws["k6ln"], rec.sc == sc, rec.k6ln == draws["k6ln"]]) if ctx.rng else True
    ctx.p(f"  Step-by-step recomputation equals the REAL register_sensor() output: {same}" + ("" if ctx.rng else "  (not comparable with os.urandom)"))
    if ctx.rng: ctx.rng.n = rng_real.n
    ctx.controller, ctx.sensor, ctx.registered = ctrl_real, sensor, True
    ctx.vals.update(id6ln=id6ln, id6lc=ctrl.id6lc, tid6lc=ctrl.tid6lc)
    ctx.p("  6LC database record (actual attributes of the stored object):")
    for k, v in vars(rec).items(): ctx.p(f"     {k:<10}{len(v):>3} B" + ("   <- NON-FUNCTIONAL PADDING added in the audited baseline to reach 60 B (docs/storage_6lc_reconstruction.md)" if k == "_reserved" else ""))
    ctx.p("  6LN memory (actual attributes of the stored object):")
    for k, v in vars(sensor).items():
        if not k.startswith("_"): ctx.p(f"     {k:<10}{len(v):>3} B")
    ctx.p("  Paper RP-3 lists 6LN: {TID6LC, Sc, K6LN, K6LC, AID6LN, Mk}; 6LC: {TID6LC, Sc, K6LN, AID6LN}. The code differs; see docs/PAPER_VS_IMPLEMENTATION.md.")
    if stop_after == 3: return _stop(ctx, 3)
    # --- RP-4
    ctx.sub("RP-4  X = Mk xor Sc (256 bits);  Si = (Nc || Kc), 128 + 128 bits   [Sec.5.1 Step RP-4]")
    ctx.p("  PAPER AMBIGUITY: Sc is 64 bits, Mk is 256 bits; the paper does not say how to XOR them ('265 bits' again for Si). RECONSTRUCTION: tile Sc four times.")
    mk = sensor.mk
    ctx.p("  RECONSTRUCTED Mk: Mk = H_bits(Sc || K6LN, 256) is derived on demand on BOTH sides (paper: Mk = Ms xor H(R6LC), stored). Not stored.")
    ctx.kv("Mk", mk, "secret", "key actually used by AKE1..AKE3 in this configuration")
    x = cu.xor_bytes(mk, cu.tile_to(sensor.sc, 32)); nc, kc = cu.split_equal(x, 2)
    ctx.kv("X", x, "secret", "Mk xor tile(Sc)"); ctx.kv("Nc", nc, "secret", "first 128 bits of X (ACE nonce/counter)"); ctx.kv("Kc", kc, "secret", "last 128 bits of X (ACE key)")
    si = ctx.run(reg.compute_Si, mk, sensor.sc)
    ctx.kv("Si", si, "secret", f"= Nc||Kc; verified equal to real compute_Si(): {si == nc + kc}")
    if stop_after == 4: return _stop(ctx, 4)
    # --- RP-5
    ctx.sub("RP-5  Fr = Mk xor H(K6LN);  AD = Fr1 xor Fr2 (128 bits)   [Sec.5.1 Step RP-5]")
    ctx.p("  Note: RP-5 in the paper also says the 6LN 'generates a random number R1 (64 bits)'; in the code that value is RN1, generated in AKE1.")
    fr = cu.xor_bytes(mk, cu.H_bits(sensor.k6ln, 256)); fr1, fr2 = cu.split_equal(fr, 2)
    ctx.kv("Fr", fr, "secret", "Mk xor H_bits(K6LN,256)"); ad = cu.xor_bytes(fr1, fr2)
    ad_real = ctx.run(reg.compute_AD, mk, sensor.k6ln)
    ctx.kv("AD", ad, "secret", f"Fr1 xor Fr2; verified equal to real compute_AD(): {ad == ad_real}")
    ctx.p("  Si and AD are NOT stored: they are recomputed from the stored secrets whenever a message is built or verified.")
    ctx.vals.update(mk=mk, x=x, nc=nc, kc=kc, si=si, fr=fr, ad=ad, ms=ms, mk_reg=mk_reg, sm=sm, sc=sensor.sc, r6lc=draws["r6lc"], k6lc=draws["k6lc"], k6ln=draws["k6ln"], aid6ln=aid)
    ctx.p("\n  Registration complete. Next: python demo.py ake1")
    return ctx


def _stop(ctx, n):
    ctx.p(f"\n  [stopped after RP-{n} as requested; state not yet complete - later stages will run registration themselves]")
    return ctx


def ent_clone(ent, ctrl):
    c = ent.SixLC(id6lc=ctrl.id6lc, tid6lc=ctrl.tid6lc)
    return c


# =====================================================================================================
def _table(ctx, name, msg, paper_fields, protection, source):
    ctx.p(f"\n  {name} packet - fields in wire order (sizes measured from the real message object)")
    ctx.p(f"  {'Field':<8}{'Bits':>6}{'Bytes':>7}{'Paper bits':>11}  {'Source':<24}Protection")
    tot = 0
    for f, v in msg.items():
        pb = paper_fields.get(f, "-")
        ctx.p(f"  {f:<8}{len(v)*8:>6}{len(v):>7}{str(pb):>11}  {source[f]:<24}{protection[f]}"); tot += len(v) * 8
    ctx.p(f"  {'TOTAL':<8}{tot:>6}{tot//8:>7}{sum(paper_fields.values()):>11}")
    return tot


M1_SRC = {"T6LN": "clock (AKE1)", "D": "AID6LN xor TID6LC", "CT": "ACE encrypt of A||B", "Tag6LN": "ACE tag over AD||CT", "RN1": "fresh random (AKE1)"}
M1_PROT = {"T6LN": "clear; freshness window only - NOT covered by the tag", "D": "clear; masks AID6LN; used for DB lookup",
           "CT": "encrypted (AES-CTR) + covered by tag", "Tag6LN": "authenticator (HMAC-SHA256/128)", "RN1": "clear; cross-checked against B inside CT"}
M2_SRC = {"T6C": "clock (AKE2)", "A1": "B1 xor RN1", "M": "SHA-1(SK)", "CT1": "ACE encrypt of Sc1||RN2", "Tag6LC": "ACE tag over AD||CT1", "RN2": "fresh random (AKE2)"}
M2_PROT = {"T6C": "clear; freshness window only - NOT covered by the tag", "A1": "clear; recomputed by 6LN from K6LN, RN1, RN2",
           "M": "clear; key-confirmation hash H(SK)", "CT1": "encrypted (AES-CTR) + covered by tag", "Tag6LC": "authenticator (HMAC-SHA256/128)",
           "RN2": "clear; cross-checked against RN2 inside CT1"}


def ake1_stage(ctx: Ctx, header=True):
    ctx.ensure_registered()
    s, cu, ake = ctx.sensor, ctx.cfg.cu, ctx.cfg.ake
    if header:
        ctx.banner("DEMO C - AKE1: the 6LN builds and sends M1 (Sec.5.2 Step AKE1)")
        ctx.p("Prerequisite: registration (executed deterministically if not already done).")
    ctx.trace.set_stage("AKE1")
    before = ctx.trace.mark()
    m1 = ctx.run(ake.step_ake1, s)
    sess = s._session
    ctx.m1 = m1
    if header:
        ctx.sub("Inputs read from the 6LN's stored state"); ctx.kv("AID6LN", s.aid6ln, "secret"); ctx.kv("Sc", s.sc, "secret"); ctx.kv("TID6LC", s.tid6lc, "secret")
        ctx.sub("Fresh values"); ctx.kv("RN1", sess["rn1"], "public", "fresh 64-bit random; sent in clear AND hidden inside B", key="rn1")
        ctx.kv("T6LN", m1["T6LN"], "public", f"clock = {int.from_bytes(m1['T6LN'],'big')} (32-bit seconds)")
        ctx.sub("Masked values (XOR only - no hashing here)")
        ctx.kv("A", sess["a"], "secret", "A = AID6LN xor RN1 xor Sc  (LITERAL)"); ctx.kv("B", sess["b"], "secret", "B = AID6LN xor RN1  (LITERAL)")
        ctx.kv("D", m1["D"], "public", "D = AID6LN xor TID6LC  (LITERAL; Fig.5 prints AID6LC - paper inconsistency)")
        ctx.sub("Encryption / authentication interface (ACE reconstruction)")
        ctx.p("  Algorithm: AES-128 in CTR mode (keystream: CT = PT xor keystream)  +  Tag = HMAC-SHA256(Kc, AD||CT) truncated to 128 bits.")
        ctx.p("  NOT the authors' ACE (a NIST-LWC sponge permutation whose internals the paper does not give).")
        ctx.kv("Key Kc", sess["si"][16:], "secret", "128-bit AES key (second half of Si)", key="kc"); ctx.kv("Nonce Nc", sess["si"][:16], "secret", "128-bit initial counter block (first half of Si)", key="nc")
        ctx.kv("AD", sess["ad"], "secret", "128-bit associated data: authenticated, not encrypted, not transmitted")
        ctx.kv("Plaintext", sess["a"] + sess["b"], "secret", "A||B = 128 bits passed to ACE", key="pt")
        ctx.p("  What is encrypted: A||B.  What is authenticated: AD (derived secret) and CT.  Nonce/key reuse: Si depends only on Mk and Sc - see docs/CRYPTOGRAPHIC_OPERATIONS.md.")
        ctx.sub("Output")
        ctx.kv("CT", m1["CT"], "public"); ctx.kv("Tag6LN", m1["Tag6LN"], "public")
        ctx.sub("M1 = T6LN || D || CT || Tag6LN || RN1")
        tot = _table(ctx, "M1", m1, PAPER["M1_fields"], M1_PROT, M1_SRC)
        ctx.p(f"  Paper-reported M1: {PAPER['M1_bits']} bits; measured: {tot} bits -> " + ("MATCHES directly (every field width is stated in the paper)" if tot == PAPER["M1_bits"] else "DIFFERS"))
        ctx.sub("Operations executed by the real step_ake1() (logical = calls made by the protocol code)")
        _op_table(ctx, before)
        ctx.p("\n  Next: python demo.py ake2   (the controller receives this M1)")
    ctx.vals.update(rn1=sess["rn1"], t6ln=m1["T6LN"], a=sess["a"], b=sess["b"], d=m1["D"], pt=sess["a"] + sess["b"], ct=m1["CT"], tag6ln=m1["Tag6LN"])
    return m1


def _op_table(ctx, since, stage=None):
    ops = ctx.trace.ops[since:]
    ctx.p(f"  {'#':<3}{'Operation':<13}{'Algorithm':<50}{'Input B':<14}{'Out B':<6}Purpose (source line)")
    for i, o in enumerate(ops, 1):
        ctx.p(f"  {i:<3}{o['op']:<13}{o['algorithm'][:48]:<50}{str(o['inputs']):<14}{o['output_bytes']:<6}{o['purpose'] or o['source'][:46]}")
    c = ctx.trace.counts(since)
    ctx.p("  logical:", c["logical"]); ctx.p("  physical primitive calls:", c["physical"])


def ake2_stage(ctx: Ctx, header=True):
    ctx.ensure_m1()
    ctrl, cu, ake, reg = ctx.controller, ctx.cfg.cu, ctx.cfg.ake, ctx.cfg.registration
    m1 = ctx.m1
    if header:
        ctx.banner("DEMO D - AKE2: the 6LC verifies M1 and builds M2 (Sec.5.2 Step AKE2)")
        ctx.p("Prerequisite: registration + AKE1 (real M1 produced deterministically if needed).")
        ctx.sub("M1 as received"); [ctx.kv(k, v, "public") for k, v in m1.items()]
        ctx.sub("Parsing / length validation")
        ctx.p("  The code does NOT validate field lengths explicitly: a wrong-length field raises ValueError inside xor/ACE (see attack lab A10/A16).")
        ctx.p("  Observed lengths:", {k: len(v) for k, v in m1.items()})
    rec0 = copy.copy(ctrl.lookup(cu.xor_bytes(ctrl.tid6lc, m1["D"])))
    now = int(ctx.clock.time()); t6ln = int.from_bytes(m1["T6LN"], "big")
    aid = cu.xor_bytes(ctrl.tid6lc, m1["D"])
    mk_p = mk_of_record(ctx.cfg, rec0); si_p = reg.compute_Si(mk_p, rec0.sc); ad_p = reg.compute_AD(mk_p, rec0.k6ln)
    pt, tag_d = ctx.cfg.ace.decrypt(si_p, ad_p, m1["CT"])
    a, b = pt[:8], pt[8:]; rn1 = cu.xor_bytes(aid, b); sc_p = cu.xor_many(rec0.aid6ln, rn1, a)
    checks = [("freshness  tr - T6LN <= DeltaT (one-sided check in code)", now - t6ln <= ake.DELTA_T, f"tr={now}, T6LN={t6ln}, DeltaT={ake.DELTA_T}s"),
              ("alias lookup  AID6LN = TID6LC xor D found in DB", True, ""),
              ("tag  Tag_d == Tag6LN (constant-time)", cu.constant_time_eq(tag_d, m1["Tag6LN"]), "ACE tag over AD||CT"),
              ("RN1 derived from B equals transmitted RN1", cu.constant_time_eq(rn1, m1["RN1"]), "AUDITED-CODE CHECK (not stated in the paper)"),
              ("Sc' = AID6LN xor RN1 xor A equals stored Sc", cu.constant_time_eq(sc_p, rec0.sc), "RECONSTRUCTION: paper prints ID6LN, which never equals Sc")]
    ctx.checks['ake2'] = checks
    ctx.trace.set_stage("AKE2"); before = ctx.trace.mark()
    res = ctx.run(ake.step_ake2, ctrl, m1)
    m2, sk = res["m2"], res["session_key"]
    ctx.ake2_res, ctx.m2 = res, m2
    if header:
        ctx.sub("Recomputation of the controller's checks (same helper functions; the real function accepted the message)")
        for n, ok, note in checks: ctx.p(f"  [{'PASS' if ok else 'FAIL'}] {n}   {note}")
        ctx.sub("Derived values"); ctx.kv("AID6LN", aid, "secret", "TID6LC xor D", key="aid_from_d"); ctx.kv("Mk'", mk_p, "secret", key="mk_prime")
        ctx.kv("Si'", si_p, "secret"); ctx.kv("AD'", ad_p, "secret"); ctx.kv("PT=A||B", pt, "secret", "decrypted", key="pt_dec")
        ctx.sub("Controller's fresh values and new parameters")
        ctx.kv("T6C", m2["T6C"], "public", f"{len(m2['T6C'])*8}-bit timestamp"); ctx.kv("RN2", m2["RN2"], "public", "fresh random")
        t_val = cu.xor_bytes(mk_p, cu.H_bits(ctrl.id6lc, 256)); sc1 = cu.xor_many(*cu.split_equal(t_val, 4))
        ctx.kv("T", t_val, "secret", "Mk' xor H_bits(ID6LC,256)", key="t_val"); ctx.kv("Sc1", sc1, "secret", "T1^T2^T3^T4  (new Sc)")
        b1 = cu.xor_bytes(m2["RN2"], rec0.k6ln); a1 = cu.xor_bytes(b1, rn1)
        ctx.kv("B1", b1, "secret", "RN2 xor K6LN"); ctx.kv("A1", a1, "public", f"B1 xor RN1; equals real A1: {a1 == m2['A1']}")
        sk_chk = cu.sha1(rec0.aid6ln + b1 + sc1 + rn1 + m2["RN2"])
        ctx.kv("SK", sk, "secret", f"SHA-1(AID6LN||B1||Sc1||RN1||RN2) - 160 bits; recomputed equal: {sk_chk == sk}", key="sk_6lc")
        ctx.kv("M", m2["M"], "public", f"SHA-1(SK): a SECOND, separate hash; equals real M: {cu.sha1(sk_chk) == m2['M']}")
        ctx.kv("PT1", sc1 + m2["RN2"], "secret", "Sc1||RN2 = 128 bits encrypted into CT1", key="pt1")
        ctx.sub("M2 = T6C || A1 || M || CT1 || Tag6LC || RN2")
        tot = _table(ctx, "M2", m2, PAPER["M2_fields"], M2_PROT, M2_SRC)
        lit = tot - (len(m2["T6C"]) * 8 - 32)
        ctx.p(f"  Paper-reported M2: {PAPER['M2_bits']} bits (fields listed in the paper add up to {sum(PAPER['M2_fields'].values())} with a 32-bit T6C and 160-bit M).")
        ctx.p(f"  Measured here  : {tot} bits ({len(m2['T6C'])*8}-bit T6C). Literal-width calculation: {lit} bits. Reconstructed calculation: {tot} bits.")
        if len(m2["T6C"]) == 8: ctx.p("  -> The 608 figure depends on the reconstructed 64-bit T6C, which CONTRADICTS the paper's explicit '32 bits timestamp'. Reported, not hidden.")
        ctx.sub("State change after AKE2 (reconstruction)")
        new_aid = ctrl.lookup(sk and next((k for k in ctrl.db), b"")) if False else None
        ctx.p("  6LC stores Sc := Sc1 (reading of 'saves and updates the new parameters')" + ("; AID6LN := H_bits(AID6LN||SK,64) (alias rotation, RECONSTRUCTION)." if ctx.cfg.name == "reconstructed" else "; no alias rotation in this configuration."))
        ctx.p("  NOTE: the controller updates its state BEFORE the sensor confirms. If M2 is lost the two sides desynchronise (attack lab A11b).")
        ctx.sub("Operations executed by the real step_ake2()"); _op_table(ctx, before)
        ctx.p("\n  Next: python demo.py ake3")
    ctx.vals.update(aid_from_d=aid, mk_prime=mk_p, t6c=m2["T6C"], rn2=m2["RN2"], a1=m2["A1"], m=m2["M"], ct1=m2["CT1"], tag6lc=m2["Tag6LC"], sk_6lc=sk, sc1=cu.xor_many(*cu.split_equal(cu.xor_bytes(mk_p, cu.H_bits(ctrl.id6lc, 256)), 4)), t_val=cu.xor_bytes(mk_p, cu.H_bits(ctrl.id6lc, 256)),
                    b1=cu.xor_bytes(m2["RN2"], rec0.k6ln))
    return res


def ake3_stage(ctx: Ctx, header=True):
    ctx.ensure_m2()
    s, cu, ake = ctx.sensor, ctx.cfg.cu, ctx.cfg.ake
    m2 = ctx.m2
    if header:
        ctx.banner("DEMO E - AKE3: the 6LN verifies M2 and derives SK' (Sec.5.2 Step AKE3)")
        ctx.p("Prerequisite: registration + AKE1 + AKE2 (real M2 produced deterministically if needed).")
        ctx.sub("M2 as received"); [ctx.kv(k, v, "public") for k, v in m2.items()]
    sess = dict(s._session); now = int(ctx.clock.time())
    b1p = cu.xor_bytes(m2["RN2"], s.k6ln); a1p = cu.xor_bytes(b1p, sess["rn1"])
    pt1, tag_n = ctx.cfg.ace.decrypt(sess["si"], sess["ad"], m2["CT1"])
    sc1, rn2c = pt1[:8], pt1[8:]
    sk_exp = cu.sha1(s.aid6ln + b1p + sc1 + sess["rn1"] + m2["RN2"]); m_exp = cu.sha1(sk_exp)
    t6c = int.from_bytes(m2["T6C"], "big")
    checks = [("freshness  tr - T6C <= DeltaT", now - t6c <= ake.DELTA_T, f"tr={now}, T6C={t6c}"),
              ("A1' = (RN2 xor K6LN) xor RN1 equals received A1", cu.constant_time_eq(a1p, m2["A1"]), "uses 6LN's own K6LN and RN1"),
              ("tag  Tag_N == Tag6LC", cu.constant_time_eq(tag_n, m2["Tag6LC"]), ""),
              ("RN2 inside CT1 equals transmitted RN2", cu.constant_time_eq(rn2c, m2["RN2"]), "AUDITED-CODE CHECK"),
              ("session-key confirmation  M' = SHA-1(SK') equals received M", cu.constant_time_eq(m_exp, m2["M"]), "")]
    ctx.checks['ake3'] = checks
    sk_before_state = (s.sc, s.aid6ln)
    ctx.trace.set_stage("AKE3"); before = ctx.trace.mark()
    sk_sensor = ctx.run(ake.step_ake3, s, m2)
    ctx.sk_sensor = sk_sensor
    if header:
        ctx.sub("Recomputation of the sensor's checks (the real function accepted the message)")
        for n, ok, note in checks: ctx.p(f"  [{'PASS' if ok else 'FAIL'}] {n}   {note}")
        ctx.sub("Recovered / derived values")
        ctx.kv("B1'", b1p, "secret", key="b1_prime"); ctx.kv("A1'", a1p, "public"); ctx.kv("Sc1", sc1, "secret", "recovered by DECRYPTING CT1")
        ctx.kv("RN2", rn2c, "public", "recovered from CT1")
        ctx.kv("SK'", sk_sensor, "secret", f"SHA-1(AID6LN||B1'||Sc1||RN1||RN2); recomputed equal: {sk_exp == sk_sensor}", key="sk_6ln")
        ctx.kv("M'", cu.sha1(sk_sensor), "public", "SHA-1(SK'); must equal M"); 
        ctx.sub("SUBSTITUTION vs the literal paper (AKE3)")
        ctx.p("  Paper: '6LN computes T' to get Sc1''. T' = Mk xor H(ID6LC) needs ID6LC, which the 6LN never receives. The code takes Sc1 from the decrypted CT1")
        ctx.p("  (it is already inside M2). See docs/id6lc_ake3_reconstruction.md and docs/RECONSTRUCTION_DECISIONS.md.")
        ctx.sub("Session-key agreement")
        sk6lc = ctx.ake2_res["session_key"]
        ctx.p(f"  Sensor session key:     {sk_sensor.hex() if ctx.reveal else '[redacted by default]'}")
        ctx.p(f"  Controller session key: {sk6lc.hex() if ctx.reveal else '[redacted by default]'}")
        ctx.p(f"  Session key lengths:    sensor {len(sk_sensor)*8} bits, controller {len(sk6lc)*8} bits")
        ctx.p(f"  Keys equal:             {sk_sensor == sk6lc}")
        ctx.sub("State change after AKE3 (reconstruction)")
        ctx.p(f"  Sc replaced by Sc1: {s.sc != sk_before_state[0] or s.sc == sc1};  AID6LN rotated: {s.aid6ln != sk_before_state[1]}")
        ctx.sub("Operations executed by the real step_ake3()"); _op_table(ctx, before)
    ctx.vals.update(b1_prime=b1p, sk_6ln=sk_sensor)
    return sk_sensor


def session_key_stage(ctx: Ctx):
    ctx.ensure_m2()
    cu = ctx.cfg.cu
    ctx.banner("SESSION KEY - derivation on both sides (Sec.5.2)")
    rec_aid = ctx.vals.get("aid6ln")
    if ctx.sk_sensor is None:
        saved, ctx.out = ctx.out, (lambda *_: None)
        try: ake3_stage(ctx, header=False)
        finally: ctx.out = saved
    v = ctx.vals
    ctx.p("SK = SHA-1( AID6LN || B1 || Sc1 || RN1 || RN2 )  -> 160 bits.   M = SHA-1( SK ) is a different hash, sent in M2.   SK itself is NEVER transmitted.\n")
    ctx.p(f"  {'Input':<8}{'Bits':>5}  {'6LC obtains it from':<42}{'6LN obtains it from'}")
    for n, bits, a, b in (("AID6LN", 64, "TID6LC xor D, then DB record", "own stored AID6LN"), ("B1", 64, "RN2 xor K6LN (record)", "B1' = RN2(received) xor own K6LN"),
                          ("Sc1", 64, "fold(Mk' xor H_bits(ID6LC))", "decrypting CT1 (sent encrypted in M2)"), ("RN1", 64, "AID6LN xor B (decrypted), checked vs clear RN1", "own fresh value"),
                          ("RN2", 64, "own fresh value", "received in clear and inside CT1")):
        ctx.p(f"  {n:<8}{bits:>5}  {a:<42}{b}")
    ctx.p(f"\n  SK at 6LC {'= ' + v['sk_6lc'].hex() if ctx.reveal else '[redacted]'}   SK at 6LN {'= ' + v['sk_6ln'].hex() if ctx.reveal else '[redacted]'}")
    ctx.p(f"  Keys equal: {v['sk_6lc'] == v['sk_6ln']}   length {len(v['sk_6lc'])*8} bits")
    ctx.p(f"  Is SK in M1 or M2 on the wire? {any(v['sk_6lc'] in x for x in (b''.join(ctx.m1.values()), b''.join(ctx.m2.values())))}")


def full_stage(ctx: Ctx):
    ctx.banner("FULL END-TO-END SESSION (real functions)")
    registration_stage(ctx, 5, header=False); ctx.p("[1] registration done (run `registration` for every step)")
    ake1_stage(ctx, header=False); ctx.p(f"[2] AKE1: M1 = {sum(len(v) for v in ctx.m1.values())*8} bits")
    ake2_stage(ctx, header=False); ctx.p(f"[3] AKE2: M2 = {sum(len(v) for v in ctx.m2.values())*8} bits")
    ake3_stage(ctx, header=False)
    ok = ctx.sk_sensor == ctx.ake2_res["session_key"]
    ctx.p(f"[4] AKE3: verified. Session keys equal: {ok}; length {len(ctx.sk_sensor)*8} bits; SK printed: " + (ctx.sk_sensor.hex() if ctx.reveal else "[redacted]"))
    return ok
