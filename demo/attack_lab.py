"""Attacker demonstration laboratory. Every scenario drives the REAL protocol functions (ake.step_ake1/2/3, registration.register_sensor)
of the selected configuration. Nothing is mocked and nothing is forced: the observed ACCEPT/REJECT is whatever the code did.

Classification vocabulary: Protected in the tested configuration | Vulnerable in the tested configuration | Partially protected |
Not applicable | Not tested or inconclusive.  A REJECT here means only that THIS input was rejected; it does not prove resistance to every attack."""
import copy, json, time as _t, pathlib, traceback
from .runtime import Cfg, Trace, FakeClock, DemoRandom, instrument, ROOT

PROTECTED, VULN, PARTIAL, NA, INCONCL = ("Protected in the tested configuration", "Vulnerable in the tested configuration",
                                         "Partially protected", "Not applicable", "Not tested or inconclusive")
CHECKS = [("not fresh", "freshness window"), ("AID6LN not found", "alias lookup in the 6LC database"), ("Tag6LN mismatch", "tag verification of M1"),
          ("RN1 mismatch", "RN1 consistency (clear RN1 vs RN1 hidden in B)"), ("Sc mismatch", "Sc' legitimacy check"), ("A1 verification", "A1 recomputation at the 6LN"),
          ("Tag6LC mismatch", "tag verification of M2"), ("RN2 mismatch", "RN2 consistency (clear RN2 vs RN2 inside CT1)"),
          ("session-key confirmation", "session-key confirmation M' == M"), ("no prior Step AKE1", "no pending AKE1 session at the 6LN")]


class Env:
    def __init__(self, config, seed=11, n=1):
        self.cfg, self.trace, self.clock, self.rng = Cfg(config), Trace(), FakeClock(), DemoRandom(seed)
        self.ctrl = self.call(self.cfg.registration.make_controller)
        self.sensors = [self.call(self.cfg.registration.register_sensor, self.ctrl, self.rng(8)) for _ in range(n)]
        self.AuthErr = self.cfg.ake.AuthenticationError

    def call(self, fn, *a):
        with instrument(self.cfg, self.trace, self.clock, self.rng):
            return fn(*a)

    def try_(self, fn, *a):
        """Run a protocol step; return a normalised outcome without ever faking success."""
        try:
            v = self.call(fn, *a)
            return dict(status="ACCEPT", reason="accepted", check="-", graceful=True, value=v)
        except self.AuthErr as e:
            msg = str(e); chk = next((c for k, c in CHECKS if k in msg), msg)
            return dict(status="REJECT", reason=msg, check=chk, graceful=True, value=None)
        except Exception as e:   # not an AuthenticationError: rejected by an unhandled exception (no graceful validation)
            return dict(status="REJECT", reason=f"{type(e).__name__}: {e}", check=f"unhandled {type(e).__name__} (no explicit validation)", graceful=False, value=None)

    def ake1(self, i=0): return self.call(self.cfg.ake.step_ake1, self.sensors[i])
    def ake2(self, m1): return self.try_(self.cfg.ake.step_ake2, self.ctrl, m1)
    def ake3(self, m2, i=0): return self.try_(self.cfg.ake.step_ake3, self.sensors[i], m2)

    def session(self, i=0):
        m1 = self.ake1(i); r = self.ake2(m1); assert r["status"] == "ACCEPT", r
        m2 = r["value"]["m2"]; o3 = self.ake3(m2, i); assert o3["status"] == "ACCEPT", o3
        return m1, m2, r["value"]["session_key"], o3["value"]


def flip(b, bit=0): x = bytearray(b); x[len(x) - 1 if bit < 0 else 0] ^= 1; return bytes(x)
def hx(b): return b.hex()
def with_(m, **kw): d = dict(m); d.update(kw); return d


def R(id, title, plain, attacker, original, action, steps, outcome, check, expected, observed, interp, cls, test, extra=None):
    return dict(id=id, title=title, plain_english=plain, attacker=attacker, original_message=original, action=action, steps=steps, outcome=outcome,
                responsible_check=check, expected=expected, observed=observed, interpretation=interp, classification=cls, automated_test=test, extra=extra or {})


def short(m): return {k: hx(v) for k, v in m.items()}


# --------------------------------------------------------------------------------------------------
def a01_replay(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); m2 = r1["value"]["m2"]; e.ake3(m2)
    r2 = e.ake2(m1)
    unused = len(e.ctrl.seen_nonces) + len(e.ctrl.seen_timestamps)
    out.append(R("A01a", "Exact replay of M1 after a completed session", "The attacker recorded M1 of a successful login and sends the identical bytes again.",
                 "Passive capture + retransmission on the open channel.", short(m1), "Resend M1 unchanged to the 6LC (clock unchanged, inside DeltaT).",
                 [f"1st delivery: {r1['status']}", f"2nd delivery: {r2['status']} ({r2['check']})", f"6LC replay-cache sets contain {unused} entries (present in the class, never filled by step_ake2)"],
                 r2["status"], r2["check"], "REJECT", r2["reason"],
                 "Rejection comes from the STATE TRANSITION after the first session (the stored Sc"
                 + (" and alias are" if cfg == "reconstructed" else " is") + " replaced), not from a replay cache or the timestamp (still fresh). This is a property of the reconstructed state update, not a literal paper mechanism.",
                 PROTECTED if r2["status"] == "REJECT" else VULN, f"test_attack_lab[A01a-{cfg}]"))
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); r2 = e.ake2(m1)
    out.append(R("A01b", "Replay of M1 before the sensor has processed M2", "The same M1 reaches the controller twice in a row (duplicate delivery).",
                 "Network duplication or attacker retransmission.", short(m1), "Deliver M1 twice back to back.",
                 [f"1st: {r1['status']}", f"2nd: {r2['status']} ({r2['check']})"], r2["status"], r2["check"], "REJECT", r2["reason"],
                 "The controller updates state immediately after the first AKE2, so the duplicate fails.", PROTECTED if r2["status"] == "REJECT" else VULN, f"test_attack_lab[A01b-{cfg}]"))
    return out


def a01c_replay_later_session(cfg):
    e = Env(cfg); e.session(); e.clock.advance(1); m1, m2, sk, _ = e.session(); e.clock.advance(1); r_next = e.session(); e.clock.advance(1)
    r = e.ake2(m1)
    return [R("A01c", "Replay of M1 from the SECOND completed session", "Replay an M1 recorded in a later session (after the stored state has already been rotated once).", "Passive capture + retransmission, inside DeltaT.", short(m1),
              "Run 3 sessions; resend session 2's M1 (timestamp still fresh).", [f"replay: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"],
              ("Accepted: the stored state stopped changing, so old M1 messages stay valid until the timestamp expires." if r["status"] == "ACCEPT"
               else "Rejected: the reconstructed alias rotation changes the stored state every session, so a recorded M1 is only valid once."),
              VULN if r["status"] == "ACCEPT" else PROTECTED, f"test_attack_lab[A01c-{cfg}]")]


def a02_stale(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); e.clock.advance(60); r = e.ake2(m1)
    out.append(R("A02a", "Stale M1 (60 s old)", "A message older than the allowed window is delivered.", "Delays or stores traffic.", short(m1),
                 "Deliver M1 after 60 s (DeltaT = 5 s).", [f"T6LN = {int.from_bytes(m1['T6LN'],'big')}, now = {int(e.clock.time())}, DeltaT = {e.cfg.ake.DELTA_T}", f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "Freshness window works for honest, unmodified timestamps.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A02a-{cfg}]"))
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); e.clock.advance(60); r = e.ake3(r1["value"]["m2"])
    out.append(R("A02b", "Stale M2 (60 s old)", "The controller's reply arrives too late.", "Delays the reply.", short(r1["value"]["m2"]),
                 "Deliver M2 to the sensor after 60 s.", [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"], "Same freshness check at the sensor.",
                 PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A02b-{cfg}]"))
    e = Env(cfg); e.clock.advance(3600); m1 = e.ake1(); e.clock.advance(-3600); r = e.ake2(m1)
    out.append(R("A02c", "Future-dated timestamp (+3600 s)", "A message stamped one hour in the future.", "Controls a clock or edits the unauthenticated timestamp.", short(m1),
                 "Deliver an M1 whose T6LN is 3600 s ahead of the controller's clock.", [f"response: {r['status']}"], r["status"], r["check"], "REJECT (a symmetric window would reject)", r["reason"],
                 "The code tests `tr - T6LN > DeltaT` only, so negative differences always pass. Minor, but a real deviation from the paper's |Tr - T| form.",
                 VULN if r["status"] == "ACCEPT" else PROTECTED, f"test_attack_lab[A02c-{cfg}]"))
    return out


def a03_timestamp_tamper(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); e.clock.advance(60)                       # attacker holds M1 in flight; it is now stale
    stale = e.ake2(copy.deepcopy(m1)) if False else None
    forged = with_(m1, T6LN=int(e.clock.time()).to_bytes(len(m1["T6LN"]), "big"))
    r = e.ake2(forged)
    desync = None
    if r["status"] == "ACCEPT":   # attacker withholds M2; the sensor tries again
        m1b = e.ake1(); desync = e.ake2(m1b)
    out.append(R("A03a", "Timestamp refresh on an intercepted, undelivered M1 (delay attack)", "The attacker blocks M1, waits until it is stale, rewrites only the timestamp to 'now' and delivers it.",
                 "Active man-in-the-middle on the channel; no secrets needed.", short(m1), "Replace T6LN by the current time (all other fields untouched), deliver to the 6LC, withhold M2.",
                 [f"forged M1: {r['status']}", "attacker withholds M2 (sensor never sees it)", f"sensor's next honest M1: {desync['status'] + ' (' + desync['check'] + ')' if desync else 'n/a'}"],
                 r["status"], r["check"], "REJECT", r["reason"],
                 "T6LN is not covered by the tag, so the old M1 passes. The controller then updates its state while the sensor does not: the two sides are desynchronised and later honest sessions fail (DoS). The attacker cannot learn SK.",
                 VULN if r["status"] == "ACCEPT" else PROTECTED, f"test_attack_lab[A03a-{cfg}]", {"desync_followup": desync and desync["status"]}))
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); e.ake3(r1["value"]["m2"]); e.clock.advance(60)
    forged = with_(m1, T6LN=int(e.clock.time()).to_bytes(len(m1["T6LN"]), "big")); r = e.ake2(forged)
    out.append(R("A03b", "Timestamp refresh on an already-completed M1", "Same rewrite, but the session had already finished.", "Passive capture, then rewrites the timestamp.", short(m1),
                 "Rewrite T6LN to now and resend.", [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"],
                 "Protection again comes from the state update (stored Sc/alias changed), not from timestamp integrity.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A03b-{cfg}]"))
    return out


def a04_a05_ct_tag(cfg):
    out = []
    for aid, what, field, bit in (("A04a", "ciphertext", "CT", 0), ("A04b", "ciphertext (last bit)", "CT", -1), ("A05a", "authentication tag", "Tag6LN", 0), ("A05b", "authentication tag (last bit)", "Tag6LN", -1)):
        e = Env(cfg); m1 = e.ake1(); f = with_(m1, **{field: flip(m1[field], bit)}); r = e.ake2(f)
        out.append(R(aid, f"M1 {what} modified", f"One bit of M1's {field} is flipped in transit.", "Active MITM, no secrets.", short(m1), f"Flip one bit of {field}.",
                     [f"response: {r['status']} ({r['check']})", "no plaintext is used after the failed tag comparison (state unchanged)"], r["status"], r["check"], "REJECT", r["reason"],
                     "Tag = HMAC-SHA256(Kc, AD||CT)[:128 bit] compared in constant time. The inverse-free cipher still computes a plaintext, but it is discarded before any use.",
                     PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[{aid}-{cfg}]"))
    for aid, field in (("A04c", "CT1"), ("A05c", "Tag6LC")):
        e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); m2 = r1["value"]["m2"]; f = with_(m2, **{field: flip(m2[field])}); r = e.ake3(f)
        out.append(R(aid, f"M2 {field} modified", f"One bit of M2's {field} is flipped.", "Active MITM, no secrets.", short(m2), f"Flip one bit of {field}.", [f"response: {r['status']} ({r['check']})"],
                     r["status"], r["check"], "REJECT", r["reason"], "Same tag check at the sensor.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[{aid}-{cfg}]"))
    return out


def _mutate(cfg_obj, field, v, clock):
    if field in ("T6LN", "T6C"): return (int.from_bytes(v, "big") + 1).to_bytes(len(v), "big")      # timestamp +1 s (still inside the window)
    return flip(v)


def a06_fields(cfg):
    out, matrix = [], {}
    for msg_name, fields in (("M1", ["T6LN", "D", "CT", "Tag6LN", "RN1"]), ("M2", ["T6C", "A1", "M", "CT1", "Tag6LC", "RN2"])):
        for f in fields:
            e = Env(cfg); m1 = e.ake1()
            if msg_name == "M1":
                mod = with_(m1, **{f: _mutate(e.cfg, f, m1[f], e.clock)}); r = e.ake2(mod)
            else:
                r1 = e.ake2(m1); m2 = r1["value"]["m2"]; mod = with_(m2, **{f: _mutate(e.cfg, f, m2[f], e.clock)}); r = e.ake3(mod)
            matrix[f"{msg_name}.{f}"] = (r["status"], r["check"], r["graceful"])
            cls = PROTECTED if r["status"] == "REJECT" else VULN
            note = {"T6LN": "Timestamp changed by +1 s (still fresh): ACCEPTED - the field is not cryptographically bound; it affects neither SK nor any check except freshness.",
                    "T6C": "Same for T6C: accepted; no effect on SK."}.get(f, "Detected by the check shown.")
            out.append(R(f"A06-{msg_name}.{f}", f"{msg_name} field {f} modified", f"Only {f} of {msg_name} is altered (all other fields intact).", "Active MITM, no secrets.", {}, f"Alter {f}.",
                         [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"], note, cls, f"test_attack_lab[A06-{msg_name}.{f}-{cfg}]"))
    return out, matrix


def build_m1(e, i=0, rn1_clear=None, a=None, b=None, sc_override=None):
    """WHITE-BOX: build an M1 with REAL keys but chosen inconsistencies. Emulates a compromised/buggy sender; tests receiver logic only."""
    cfg, s = e.cfg, e.sensors[i]
    rn1 = e.rng(8); aa = a if a is not None else cfg.cu.xor_many(s.aid6ln, rn1, sc_override or s.sc); bb = b if b is not None else cfg.cu.xor_bytes(s.aid6ln, rn1)
    si, ad = cfg.registration.compute_Si(s.mk, s.sc), cfg.registration.compute_AD(s.mk, s.k6ln)
    ct, tag = cfg.ace.encrypt(si, ad, aa + bb)
    ts = int(e.clock.time()).to_bytes(4, "big")
    return {"T6LN": ts, "D": cfg.cu.xor_bytes(s.aid6ln, s.tid6lc), "CT": ct, "Tag6LN": tag, "RN1": rn1_clear if rn1_clear is not None else rn1}


def a06b_whitebox(cfg):
    out = []
    e = Env(cfg); r = e.ake2(build_m1(e, sc_override=e.rng(8)))
    out.append(R("A06b-1", "[white-box] valid tag but wrong Sc inside A", "A sender holding the keys builds A with a wrong Sc.", "Insider/compromised-sensor emulation (uses real keys).", {}, "Build M1 with A = AID^RN1^Sc_wrong and a valid tag.",
                 [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"], "Tests the receiver's Sc' check (reconstructed equation). Not an outsider attack.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A06b-1-{cfg}]"))
    e = Env(cfg); r = e.ake2(build_m1(e, rn1_clear=e.rng(8)))
    out.append(R("A06b-2", "[white-box] clear RN1 differs from RN1 hidden in B", "A sender sends one RN1 in clear and another inside B.", "Insider emulation.", {}, "Build M1 with mismatching RN1.",
                 [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"], "The audited code checks consistency between the two RN1 copies (this check is not in the paper).", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A06b-2-{cfg}]"))
    return out


def a07_unknown(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); r = e.ake2(with_(m1, D=e.rng(8)))
    out.append(R("A07a", "Unknown alias (random D)", "The attacker invents an identity.", "Outsider, no secrets.", short(m1), "Replace D by random bytes.", [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"],
                 "Lookup of AID6LN = TID6LC xor D fails; rejection happens before any decryption (cheap).", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A07a-{cfg}]"))
    e1, e2 = Env(cfg, seed=11), Env(cfg, seed=99)
    m_other = e2.ake1(); r = e1.ake2(m_other)
    out.append(R("A07b", "Sensor registered with a different controller", "A genuine sensor of another network contacts this controller.", "Foreign device.", short(m_other), "Deliver foreign M1.", [f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "Alias unknown here.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A07b-{cfg}]"))
    return out


def a08_wrong_key(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); cfgm = e.cfg
    wrong_si = e.rng(32); ad = e.rng(16)
    pt, tag_p = cfgm.ace.decrypt(wrong_si, ad, m1["CT"])
    true_pt = e.sensors[0]._session["a"] + e.sensors[0]._session["b"]
    ct2, tag2 = cfgm.ace.encrypt(wrong_si, ad, e.rng(16))
    r = e.ake2(with_(m1, CT=ct2, Tag6LN=tag2))
    out.append(R("A08", "Wrong key", "The attacker uses a key it guessed.", "Outsider without Si/AD.", short(m1), "(1) primitive level: decrypt CT with a wrong Si; (2) protocol level: send M1 whose CT/Tag were made with the attacker's own key.",
                 [f"(1) wrong-key decrypt returns a plaintext equal to the true one? {pt == true_pt}; recomputed tag equals transmitted tag? {cfgm.ace.tags_match(tag_p, m1['Tag6LN'])}", f"(2) controller response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "A wrong key yields garbage plaintext and a different tag; the tag check rejects. (Step 1 is a primitive-level illustration, step 2 uses only public wire material.)",
                 PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A08-{cfg}]"))
    return out


def a09_substitution(cfg):
    out = []
    e = Env(cfg, n=2); mx = e.ake1(0); my = e.ake1(1)
    r = e.ake2(with_(mx, D=my["D"]))
    out.append(R("A09a", "Identity substitution: D of sensor Y on sensor X's ciphertext", "The attacker splices fields of two captured messages.", "Active MITM with captured messages from two sensors.", {"X": short(mx), "Y": short(my)},
                 "Use D from Y with CT/Tag/RN1/T from X.", [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"], "The controller decrypts with Y's keys; the tag fails.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A09a-{cfg}]"))
    e = Env(cfg, n=2); m1x = e.ake1(0); m1y = e.ake1(1); rx = e.ake2(m1x); ry = e.ake2(m1y)
    r = e.ake3(rx["value"]["m2"], 1)
    out.append(R("A09b", "Cross-delivery of M2 (X's reply delivered to Y)", "The controller's reply for one sensor is handed to another.", "Active MITM.", short(rx["value"]["m2"]), "Deliver X's M2 to Y's pending session.",
                 [f"response: {r['status']} ({r['check']})"], r["status"], r["check"], "REJECT", r["reason"], "A1' uses Y's own K6LN and RN1, so it mismatches.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A09b-{cfg}]"))
    return out


def a10_impersonation(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); rnd = {"T6LN": m1["T6LN"], "D": e.rng(8), "CT": e.rng(16), "Tag6LN": e.rng(16), "RN1": e.rng(8)}; r = e.ake2(rnd)
    out.append(R("A10a", "Impersonation with random fields", "An outsider with no registration tries to log in.", "Outsider, no secrets, correct lengths only.", {}, "Send a random 5-field M1.", [f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "Unknown alias.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A10a-{cfg}]"))
    r = e.ake2(with_(m1, CT=e.rng(16), Tag6LN=e.rng(16)))
    out.append(R("A10b", "Impersonation with a captured alias (D) and random CT/Tag", "The attacker reuses an observed D but cannot encrypt.", "Eavesdropper who saw D.", short(m1), "Keep D, T6LN, RN1; random CT and Tag.", [f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "Alias found, tag fails.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A10b-{cfg}]"))
    r = e.ake2(with_(m1, RN1=e.rng(8)))
    out.append(R("A10c", "New session built from captured CT/Tag with a fresh RN1", "The attacker tries to restart a session from recorded ciphertext.", "Eavesdropper.", short(m1), "Keep D, CT, Tag; replace the clear RN1.", [f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "Tag still verifies (RN1 is not covered by it) but the RN1 consistency check inside the code rejects.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A10c-{cfg}]"))
    return out


def a11_drop(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); before = (e.ctrl.lookup(next(iter(e.ctrl.db))).sc)
    m1b = e.ake1(); r1 = e.ake2(m1b); o3 = e.ake3(r1["value"]["m2"])
    out.append(R("A11a", "M1 dropped", "The first message never reaches the controller.", "Network attacker drops M1.", short(m1), "Drop M1; the sensor starts a new session.",
                 ["controller state unchanged (nothing received)", "the sensor's pending state is overwritten by the next AKE1 (the code has NO timeout)", f"next session: AKE2 {r1['status']}, AKE3 {o3['status']}"],
                 o3["status"], "-", "later session works", "later session works" if o3["status"] == "ACCEPT" else "later session fails", "Dropping M1 is harmless; no stuck state.", PROTECTED if o3["status"] == "ACCEPT" else VULN, f"test_attack_lab[A11a-{cfg}]"))
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1)                       # M2 dropped
    tries = []
    for _ in range(3):
        mm = e.ake1(); r = e.ake2(mm); tries.append(f"{r['status']} ({r['check']})")
    stuck = all(t.startswith("REJECT") for t in tries)
    out.append(R("A11b", "M2 dropped (desynchronisation)", "The controller's reply is lost; the controller has already updated its state.", "Network attacker drops M2 (or the radio fails).", short(m1), "Drop M2, then let the sensor retry 3 times.",
                 ["controller already replaced its stored Sc" + (" and alias" if cfg == "reconstructed" else ""), "sensor still holds the old state"] + [f"retry {i+1}: {t}" for i, t in enumerate(tries)],
                 "REJECT" if stuck else "ACCEPT", "alias lookup / tag check" if stuck else "-", "later session works", "later sessions fail permanently" if stuck else "recovered",
                 "There is no recovery path: the controller keeps no previous state and the sensor cannot resynchronise. A single lost M2 permanently locks the device out until re-registration.",
                 VULN if stuck else PROTECTED, f"test_attack_lab[A11b-{cfg}]"))
    return out


def a12_reorder(cfg):
    out = []
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); m2 = r1["value"]["m2"]; ok = e.ake3(m2); dup = e.ake3(m2)
    out.append(R("A12a", "Duplicate M2", "The reply is delivered twice.", "Duplication.", short(m2), "Deliver M2 twice to the sensor.", [f"1st: {ok['status']}", f"2nd: {dup['status']} ({dup['check']})"], dup["status"], dup["check"], "REJECT", dup["reason"],
                 "The sensor clears its pending session after success.", PROTECTED if dup["status"] == "REJECT" else VULN, f"test_attack_lab[A12a-{cfg}]"))
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); old_m2 = r1["value"]["m2"]; e.ake3(old_m2)
    m1n = e.ake1(); r = e.ake3(old_m2)
    out.append(R("A12b", "Old M2 delivered into a newer session", "An M2 from session 1 is replayed while session 2 is pending.", "Replay of recorded M2.", short(old_m2), "Start session 2 (AKE1), then deliver the old M2.", [f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "A1' depends on the pending RN1; the old M2 cannot match.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A12b-{cfg}]"))
    e = Env(cfg); m1 = e.ake1(); r1 = e.ake2(m1); sens2 = e.sensors[0]; sens2._session = {}; r = e.ake3(r1["value"]["m2"])
    out.append(R("A12c", "M2 arrives with no pending AKE1 (out of order)", "A reply arrives before/without a request.", "Reordering/injection.", short(r1["value"]["m2"]), "Deliver M2 to a sensor that has no pending session.", [f"response: {r['status']} ({r['check']})"],
                 r["status"], r["check"], "REJECT", r["reason"], "Explicit no-session check.", PROTECTED if r["status"] == "REJECT" else VULN, f"test_attack_lab[A12c-{cfg}]"))
    return out


def a14_isolation(cfg):
    e = Env(cfg); log = []
    for _ in range(5):
        m1, m2, sk_lc, sk_ln = e.session(); log.append(dict(m1=m1, m2=m2, sk=sk_lc, eq=(sk_lc == sk_ln)))
        e.clock.advance(1)
    keys = [x["sk"] for x in log]; rn1s = [x["m1"]["RN1"] for x in log]; rn2s = [x["m2"]["RN2"] for x in log]; Ds = [x["m1"]["D"] for x in log]
    replays = [e.ake2(x["m1"])["status"] for x in log[:-1]]
    steps = [f"within-session key equality (5 sessions): {[x['eq'] for x in log]}", f"all 5 session keys distinct: {len(set(keys)) == 5}", f"RN1 distinct: {len(set(rn1s)) == 5}, RN2 distinct: {len(set(rn2s)) == 5}",
             f"D (clear alias mask) distinct across sessions: {len(set(Ds)) == 5}", f"old M1 of sessions 1-4 replayed now: {replays}"]
    ok = all(x["eq"] for x in log) and len(set(keys)) == 5 and all(s == "REJECT" for s in replays)
    return [R("A14", "Session-key agreement and cross-session isolation", "Run five sessions in a row and compare keys and fresh values.", "None (property test).", {}, "5 sequential sessions; replay every earlier M1.", steps, "ACCEPT" if ok else "REJECT", "-", "keys equal inside sessions, different across sessions, old M1 rejected",
              "as expected" if ok else "unexpected", "Fresh RN1/RN2 give a fresh SK; old messages do not start new sessions (via state transition).", PROTECTED if ok else VULN, f"test_attack_lab[A14-{cfg}]", {"D_changes": len(set(Ds)) == 5})]


def a15_alias(cfg):
    e = Env(cfg); s = e.sensors[0]; Ds, changed, aids = [], [], []
    for _ in range(3):
        aid0 = s.aid6ln; m1, m2, sk, _ = e.session(); Ds.append(m1["D"]); changed.append(s.aid6ln != aid0); e.clock.advance(1)
    linkable = len(set(Ds)) < len(Ds)
    eq = "AID6LN' = H_bits(AID6LN || SK, 64)  [RECONSTRUCTION; the paper gives no update equation]" if cfg == "reconstructed" else "none (this configuration never updates AID6LN)"
    return [R("A15", "Alias rotation and traceability", "Does the identifier that appears on the wire (D) change from session to session?", "Passive eavesdropper trying to link sessions.", {"D values": [hx(d) for d in Ds]},
              "Observe D in three consecutive sessions.", [f"AID6LN changed after each session: {changed}", f"update equation: {eq}", f"D sequence: {[hx(d) for d in Ds]}", f"sessions linkable by identical D: {linkable}"],
              "REJECT" if not linkable else "ACCEPT", "-", "D differs every session (paper: Prop.3 claims an alias that changes)", "D differs" if not linkable else "D identical -> sessions linkable",
              ("This demonstrates the RECONSTRUCTED implementation, not a literal paper equation." if cfg == "reconstructed" else "This is the paper's literal behaviour (no update equation): sessions are linkable by D."),
              PROTECTED if not linkable else VULN, f"test_attack_lab[A15-{cfg}]", {"linkable": linkable})]


def a16_dos(cfg, N=200):
    e = Env(cfg); m1 = e.ake1(); out_rows = []
    def measure(name, mk):
        mark = e.trace.mark(); t0 = _t.perf_counter(); res = []
        for _ in range(N): res.append(e.ake2(mk()))
        dt = (_t.perf_counter() - t0) / N * 1e6; c = e.trace.counts(mark)["logical"]
        out_rows.append((name, res[0]["status"], res[0]["check"], {k: round(v / N, 2) for k, v in c.items()}, round(dt, 1)))
    measure("wrong-length fields (truncated CT)", lambda: with_(m1, CT=m1["CT"][:5]))
    measure("random alias (unknown D)", lambda: with_(m1, D=e.rng(8)))
    measure("valid alias + forged tag (D captured in flight)", lambda: with_(m1, Tag6LN=e.rng(16)))
    graceful = all(r[1] == "REJECT" for r in out_rows)
    steps = [f"{n}: {s} via '{c}'; logical ops/msg {ops}; ~{us} us/msg (local, {N} msgs)" for n, s, c, ops, us in out_rows]
    return [R("A16", "Denial-of-service considerations (local processing cost only)", "How much work does the controller do before rejecting garbage? No network flooding is performed.", "Message flooder (simulated locally, 200 calls per case).", {},
              "Feed malformed / forged M1 to step_ake2 in a local loop and count operations.", steps, "REJECT" if graceful else "ACCEPT", "various", "cheap rejection of garbage", "rejected; costs shown",
              "Unknown aliases are rejected after one XOR and a dictionary lookup; a known alias with a forged tag forces key derivation and an AEAD decryption per message; malformed lengths are rejected by unhandled ValueError (works, but not graceful). The code has no rate limiting.",
              PARTIAL, f"test_attack_lab[A16-{cfg}]", {"rows": out_rows})]


def a17_keystream(cfg):
    e = Env(cfg); s = e.sensors[0]; aid_true = s.aid6ln; tid = e.ctrl.tid6lc
    m1, m2, sk, _ = e.session()
    x = bytes(a ^ b for a, b in zip(m1["CT"], m2["CT1"]))                       # (A||B) xor (Sc1||RN2) because both use the same keystream
    aid_rec = bytes(p ^ q ^ r for p, q, r in zip(x[8:16], m1["RN1"], m2["RN2"]))
    tid_rec = bytes(p ^ q for p, q in zip(m1["D"], aid_rec))
    ok = aid_rec == aid_true and tid_rec == tid
    return [R("A17", "Passive keystream-reuse analysis of one session (M1 xor M2)", "An eavesdropper XORs the two ciphertexts of one session.", "Passive eavesdropper; sees only M1 and M2.", {"M1.CT": hx(m1["CT"]), "M2.CT1": hx(m2["CT1"])},
              "CT xor CT1 = (A||B) xor (Sc1||RN2); second half = B xor RN2 = AID6LN xor RN1 xor RN2; RN1, RN2 are public, so AID6LN falls out; TID6LC = D xor AID6LN.",
              [f"recovered AID6LN equals the true AID6LN: {aid_rec == aid_true}", f"recovered TID6LC equals the true TID6LC: {tid_rec == tid}"], "ACCEPT" if ok else "REJECT", "-", "AID6LN stays hidden", "AID6LN and TID6LC recovered" if ok else "not recovered",
              "M1 and M2 are encrypted with the SAME Si (the paper itself says Si' is used for CT1; the audited code uses Si'' = Si'), i.e. same AES-CTR key and counter block, hence the same keystream. Reported as a weakness of the specified construction, not of the stand-in cipher: any nonce-based AEAD fails under key+nonce reuse.",
              VULN if ok else PROTECTED, f"test_attack_lab[A17-{cfg}]", {"recovered": ok})]


def a18_sk_secrecy(cfg):
    e = Env(cfg); s = e.sensors[0]; aid_true = s.aid6ln
    m1, m2, sk, _ = e.session()
    x = bytes(a ^ b for a, b in zip(m1["CT"], m2["CT1"])); aid_rec = bytes(p ^ q ^ r for p, q, r in zip(x[8:16], m1["RN1"], m2["RN2"]))
    guesses = [e.cfg.cu.sha1(aid_rec + e.rng(8) + e.rng(8) + m1["RN1"] + m2["RN2"]) for _ in range(100)]
    ok = sk not in guesses
    return [R("A18", "Passive attempt to compute SK from the transcript (with AID6LN recovered via A17)", "Can the eavesdropper form the session key?", "Passive eavesdropper that also exploited A17.", {}, "Compute SHA-1(AID||B1||Sc1||RN1||RN2) with the known AID, RN1, RN2 and 100 guesses for the unknown B1, Sc1.",
              [f"session key among 100 guesses: {not ok}"], "REJECT" if ok else "ACCEPT", "-", "SK not derivable", "not derived in this attempt", "SK still needs B1 (RN2 xor K6LN) and Sc1, both secret; the tested guesses failed. This is NOT a proof of secrecy.",
              PARTIAL if ok else VULN, f"test_attack_lab[A18-{cfg}]")]


SCENARIO_FUNCS = [a01_replay, a01c_replay_later_session, a02_stale, a03_timestamp_tamper, a04_a05_ct_tag, None, a06b_whitebox, a07_unknown, a08_wrong_key, a09_substitution, a10_impersonation, a11_drop, a12_reorder, a14_isolation, a15_alias, a16_dos, a17_keystream, a18_sk_secrecy]


def run_all(config, only=None):
    res = []
    for fn in SCENARIO_FUNCS:
        if fn is None:
            r, matrix = a06_fields(config); res += r; continue
        res += fn(config)
    # A13 summary derived from A06 rows
    a06 = {r["id"].split("-", 1)[1]: r for r in res if r["id"].startswith("A06-")}
    rows = {f: a06.get(f) for f in ("M1.D", "M1.RN1", "M2.RN2", "M1.T6LN", "M2.T6C", "M2.A1", "M2.M")}
    res.append(R("A13", "Altered identity, nonce and session values (summary of A06)", "Each identity/nonce/session field altered separately.", "Active MITM.", {}, "see A06 rows",
                 [f"{f}: {r['outcome']} via {r['responsible_check']}" for f, r in rows.items() if r], "REJECT" if all(r["outcome"] == "REJECT" for r in rows.values() if r) else "MIXED", "see steps", "REJECT",
                 "see steps", "Identity (D), nonces (RN1, RN2) and A1/M are detected; the two timestamps are accepted when changed within the window.", PARTIAL, f"test_attack_lab[A13-{config}]"))
    if only: res = [r for r in res if r["id"].startswith(only)]
    return res


def render(r, p):
    p(""); p("-" * 78); p(f"{r['id']}  {r['title']}"); p("-" * 78)
    p(f"  In plain English : {r['plain_english']}"); p(f"  Attacker         : {r['attacker']}")
    if r["original_message"]: p(f"  Original message : {json.dumps(r['original_message'])[:200]}")
    p(f"  Action           : {r['action']}")
    for s in r["steps"]: p(f"    - {s}")
    p(f"  Outcome          : {r['outcome']}   responsible check: {r['responsible_check']}")
    p(f"  Expected / Observed: {r['expected']}  /  {str(r['observed'])[:140]}")
    p(f"  Interpretation   : {r['interpretation']}")
    p(f"  Classification   : {r['classification']}"); p(f"  Automated test   : {r['automated_test']}")


def save(config, res, outdir=ROOT / "results" / "attack_lab"):
    outdir.mkdir(parents=True, exist_ok=True)
    clean = json.loads(json.dumps(res, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
    (outdir / f"attack_results_{config}.json").write_text(json.dumps(clean, indent=1))
    md = [f"# Attack laboratory results - {config} configuration\n", "| ID | Scenario | Outcome | Check | Classification |", "|---|---|---|---|---|"]
    for r in res: md.append(f"| {r['id']} | {r['title']} | {r['outcome']} | {r['responsible_check']} | {r['classification']} |")
    (outdir / f"ATTACK_RESULTS_{config}.md").write_text("\n".join(md) + "\n")
