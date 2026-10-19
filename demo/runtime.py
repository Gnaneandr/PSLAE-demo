"""Runtime support: configuration loading, deterministic randomness, controllable clock, and operation tracing.

* One implementation: the audited reconstruction in package `src` (64-bit T6C, Mk = H_bits(Sc||K6LN), AID6LN rotation).
* Determinism: `random_bytes` is replaced by a seeded counter-mode generator (DEMO ONLY, disposable keys) unless --random is given.
* Clock: `ake.time` is replaced by a controllable clock so freshness attacks are reproducible.
* Tracing: wrappers around the real primitives record operation name, algorithm, input/output SIZES, calling function and source line.
  Secret values are never recorded.
"""
import hashlib, importlib, linecache, re, sys, pathlib, math, contextlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CONFIGS = {"reconstructed": "src"}
BASE_TIME = 1_700_000_000


class DemoRandom:
    """Seeded SHA-256 counter-mode byte generator. Disposable DEMONSTRATION randomness - never use for real keys."""
    def __init__(self, seed):
        self.seed, self.n = int(seed), 0

    def __call__(self, nbytes):
        out = b""
        while len(out) < nbytes:
            out += hashlib.sha256(b"pslae-demo|%d|%d" % (self.seed, self.n)).digest(); self.n += 1
        return out[:nbytes]


class FakeClock:
    def __init__(self, t=BASE_TIME): self.t = t
    def time(self): return float(self.t)
    def advance(self, s): self.t += s


class Cfg:
    """Loaded configuration: the modules of one implementation package."""
    def __init__(self, name):
        self.name, self.pkg = name, CONFIGS[name]
        m = lambda n: importlib.import_module(f"{self.pkg}.{n}")
        self.registration, self.ake, self.entities, self.ace, self.cu = m("registration"), m("ake"), m("entities"), m("ace"), m("crypto_utils")

    @property
    def label(self):
        return "RECONSTRUCTED implementation (audited src/)"


_PURPOSE = {
    "r6lc": "R6LC: random value that feeds Mk(reg)", "k6lc": "K6LC: controller-side key of the sensor", "k6ln": "K6LN: sensor-side key",
    "aid6ln": "AID6LN = ID6LN xor K6LN xor K6LC (alias identity)", "ms": "Ms: 256-bit master secret", "mk_reg": "Mk(reg) = Ms xor H(R6LC)",
    "sm": "Sm = Mk(reg) xor H(ID6LN)", "sc1, sc2, sc3, sc4": "split Sm into four 64-bit chunks", "sc": "Sc = Sc1^Sc2^Sc3^Sc4 (secret authentication parameter)",
    "x": "X = Mk xor tile(Sc)  (RP-4)", "nc, kc": "split X into Nc (128) and Kc (128)", "si": "Si = Nc||Kc (ACE initial state)",
    "fr": "Fr = Mk xor H(K6LN)  (RP-5)", "fr1, fr2": "split Fr into Fr1, Fr2 (128 bits each)", "ad": "AD = Fr1 xor Fr2 (associated data)",
    "rn1": "RN1: sensor's fresh random number", "t6ln": "T6LN: sensor timestamp", "a": "A = AID6LN xor RN1 xor Sc", "b": "B = AID6LN xor RN1",
    "pt": "plaintext block A||B for ACE", "ct, tag6ln": "(CT||Tag6LN) = E_Si{AD, A||B}", "d": "D = AID6LN xor TID6LC", "aid6ln_from_d": "AID6LN = TID6LC xor D",
    "mk_prime": "Mk' derived by the controller", "si_prime": "Si' at the controller", "ad_prime": "AD' at the controller", "pt, tag_d": "decrypt CT, recompute tag Tag_d",
    "rn1_from_b": "RN1 = AID6LN xor B", "sc_prime": "Sc' = AID6LN xor RN1 xor A (reconstruction of the paper's check)", "t6c": "T6C: controller timestamp",
    "rn2": "RN2: controller's fresh random number", "t_val": "T = Mk' xor H(ID6LC)", "t1, t2, t3, t4": "split T into four 64-bit chunks", "sc1": "Sc1 = T1^T2^T3^T4 (new Sc)",
    "b1": "B1 = RN2 xor K6LN", "a1": "A1 = B1 xor RN1", "sk": "SK = H(AID6LN||B1||Sc1||RN1||RN2)", "m": "M = H(SK) (key-confirmation value)",
    "pt1": "PT1 = Sc1||RN2", "ct1, tag6lc": "(CT1||Tag6LC) = E_Si{AD, Sc1||RN2}", "new_aid6ln": "AID6LN' = H_bits(AID6LN||SK, 64) (rotation; reconstruction)",
    "b1_prime": "B1' = RN2 xor K6LN (sensor's own recomputation)", "a1_prime": "A1' = B1' xor RN1", "pt1, tag_n": "decrypt CT1, recompute tag Tag_N",
    "sk_prime": "SK' = H(AID6LN||B1'||Sc1||RN1||RN2)", "m_prime": "M' = H(SK')", "tag": "tag"}


class Trace:
    """Records operations. `logical` counts one entry per primitive call made by the protocol code; `physical` expands them
    (H_bits -> ceil(bits/160) SHA-1 compressions-calls, xor_many -> n-1 XORs, ace.encrypt/decrypt -> 1 AES-CTR + 1 HMAC)."""
    def __init__(self):
        self.ops, self.stage, self._depth = [], "-", 0

    def set_stage(self, s): self.stage = s
    def reset(self): self.ops.clear()
    def mark(self): return len(self.ops)

    def record(self, op, alg, ins, out, caller, line, physical):
        self.ops.append(dict(stage=self.stage, op=op, algorithm=alg, inputs=ins, output_bytes=out, caller=caller, source=line,
                             purpose=_purpose_for(line, caller, op), physical=physical))

    def counts(self, since=0, stage=None):
        c = {"logical": {}, "physical": {}}
        for o in self.ops[since:]:
            if stage and o["stage"] != stage: continue
            c["logical"][o["op"]] = c["logical"].get(o["op"], 0) + 1
            for k, v in o["physical"].items(): c["physical"][k] = c["physical"].get(k, 0) + v
        return c


_CALLER_VAR = {("step_ake2", "aid6ln"): "AID6LN = TID6LC xor D (alias recovery)", ("step_ake2", "rn1"): "RN1 = AID6LN xor B (recovered from decrypted B)",
               ("step_ake2", "a, b"): "split PT into A and B"}
_CALLER_OP = {("mk", "hash"): "Mk = H_bits(Sc||K6LN,256) derived on demand (reconstruction)", ("tags_match", "compare"): "compare received tag with recomputed tag",
              ("step_ake2", "compare"): "equality check (RN1 / Sc' consistency)", ("step_ake3", "compare"): "equality check (A1' / RN2 / M')",
              ("ake2", "x"): ""}


def _purpose_for(line, caller="", op=""):
    m = re.match(r"\s*([\w, ]+?)\s*=", line or "")
    key = m.group(1).strip() if m else ""
    return _CALLER_VAR.get((caller, key)) or _CALLER_OP.get((caller, op)) or _PURPOSE.get(key, "")


def _assign_line(frame):
    """Source line (statement start) for the call in `frame`."""
    fn, ln = frame.f_code.co_filename, frame.f_lineno
    for k in range(0, 8):
        s = linecache.getline(fn, ln - k)
        if re.match(r"\s*[\w, ]+?\s*=", s) and "==" not in s.split("=")[0]:
            return s.strip()
        if k == 0 and "return" in s: return s.strip()
    return linecache.getline(fn, ln).strip()


@contextlib.contextmanager
def instrument(cfg: Cfg, trace: Trace, clock: FakeClock, rng):
    """Patch the REAL modules of `cfg` for the duration of the block."""
    cu, ace, ake, reg, ent = cfg.cu, cfg.ace, cfg.ake, cfg.registration, cfg.entities
    saved = []

    def setattr_all(name, new):
        for mod in (cu, ace, ake, reg, ent):
            if hasattr(mod, name) and mod is not None:
                saved.append((mod, name, getattr(mod, name))); setattr(mod, name, new)

    def wrap(name, op, alg, physical_fn, out_len=lambda r: len(r) if isinstance(r, (bytes, bytearray)) else 0, ins_fn=None):
        orig = getattr(cu, name) if hasattr(cu, name) else None
        def w(*a, **k):
            trace._depth += 1
            try:
                r = orig(*a, **k)
            finally:
                trace._depth -= 1
            if trace._depth == 0:
                fr = sys._getframe(1)
                ins = [len(x) for x in a if isinstance(x, (bytes, bytearray))] if ins_fn is None else ins_fn(a)
                trace.record(op, alg, ins, out_len(r), fr.f_code.co_name, _assign_line(fr), physical_fn(a, k, r))
            return r
        w.__wrapped__ = orig
        setattr_all(name, w)

    wrap("sha1", "hash", "SHA-1 (160-bit)", lambda a, k, r: {"sha1": 1})
    wrap("H_bits", "hash", "H_bits = SHA-1 counter-mode KDF (reconstruction)", lambda a, k, r: {"sha1": math.ceil(len(r) * 8 / 160)}, ins_fn=lambda a: [len(a[0])])
    wrap("xor_bytes", "xor", "bytewise XOR", lambda a, k, r: {"xor": 1})
    wrap("xor_many", "xor", "bytewise XOR (n operands)", lambda a, k, r: {"xor": len(a) - 1})
    wrap("random_bytes", "random", "seeded DRBG (demo)" if rng else "os.urandom", lambda a, k, r: {"random": 1}, ins_fn=lambda a: [])
    wrap("hmac_sha256", "mac", "HMAC-SHA256", lambda a, k, r: {"hmac": 1})
    wrap("constant_time_eq", "compare", "constant-time compare", lambda a, k, r: {"compare": 1}, out_len=lambda r: 0)
    # AEAD wrappers (ace.encrypt / ace.decrypt are called as `ace.encrypt(...)`; patch attributes on the ace module itself)
    for fname, op in (("encrypt", "aead-encrypt"), ("decrypt", "aead-decrypt")):
        orig = getattr(ace, fname)
        def mk(orig=orig, op=op):
            def w(*a, **k):
                trace._depth += 1
                try:
                    r = orig(*a, **k)
                finally:
                    trace._depth -= 1
                if trace._depth == 0:
                    fr = sys._getframe(1)
                    ins = [len(x) for x in a if isinstance(x, (bytes, bytearray))]
                    trace.record(op, "AES-128-CTR + HMAC-SHA256 truncated to 128 bit (ACE interface reconstruction)", ins, sum(len(x) for x in r),
                                 fr.f_code.co_name, _assign_line(fr), {"aes_ctr": 1, "hmac": 1})
                return r
            return w
        saved.append((ace, fname, orig)); setattr(ace, fname, mk())
    if rng is not None:
        setattr_all("random_bytes", _traced_rng(trace, rng))
    saved.append((ake, "time", ake.time)); ake.time = clock
    try:
        yield
    finally:
        for mod, name, orig in reversed(saved): setattr(mod, name, orig)


def _traced_rng(trace, rng):
    def f(n):
        r = rng(n)
        if trace._depth == 0:
            fr = sys._getframe(1)
            trace.record("random", "seeded DRBG (demo)", [], len(r), fr.f_code.co_name, _assign_line(fr), {"random": 1})
        return r
    return f
