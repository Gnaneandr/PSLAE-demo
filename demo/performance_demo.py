"""Performance and storage demonstrations (hash, crypto, communication, storage, time). Paper value, measured value and difference side by side."""
import json, sys, time, pickle
from .stage_demos import Ctx, ake3_stage
from . import crypto_trace, packet_inspector

PAPER = {"hash_ops": 8, "ace_ops": 2, "M1_bits": 416, "M2_bits": 608, "total_bits": 1024, "sixLN_bytes": 32, "sixLC_bytes": 60, "time_ms": 0.411}


def field_usage(config, seed=2024):
    """Which stored attributes are actually READ during one full AKE (measured by instrumenting attribute access)."""
    c = Ctx(config, seed, out=lambda *_: None); c.ensure_registered()
    ent = c.cfg.entities; reads = {"SixLN": set(), "SensorRecord": set(), "SixLC": set()}
    classes = {"SixLN": ent.SixLN, "SensorRecord": ent.SensorRecord, "SixLC": ent.SixLC}
    orig = {n: k.__getattribute__ for n, k in classes.items()}
    def mk(n, o):
        def g(self, name):
            v = o(self, name)
            if not name.startswith("__") and name not in ("db", "lookup", "add_sensor_record") and not callable(v): reads[n].add(name)
            return v
        return g
    for n, k in classes.items(): k.__getattribute__ = mk(n, orig[n])
    try:
        from .stage_demos import ake1_stage, ake2_stage
        reads_clear = lambda: [v.clear() for v in reads.values()]
        reads_clear(); ake1_stage(c, header=False); ake2_stage(c, header=False); ake3_stage(c, header=False)
    finally:
        for n, k in classes.items(): k.__getattribute__ = orig[n]
    return c, reads


def storage(config, out=print, seed=2024):
    c = Ctx(config, seed, out=lambda *_: None); c.ensure_registered()
    sensor, rec = c.sensor, next(iter(c.controller.db.values()))
    s_attrs = {k: len(v) for k, v in vars(sensor).items() if not k.startswith("_")}
    r_attrs = {k: len(v) for k, v in vars(rec).items()}
    c2, reads = field_usage(config, seed)
    s_used = {k: v for k, v in s_attrs.items() if k in reads["SixLN"]}; r_used = {k: v for k, v in r_attrs.items() if k in reads["SensorRecord"]}
    pyobj = lambda o: len(pickle.dumps(o)); sz = lambda o: sys.getsizeof(o) + sum(sys.getsizeof(v) for v in vars(o).values())
    out("=" * 78); out(f"STORAGE - {c.cfg.label}"); out("=" * 78)
    out("\n1) Logical protocol state = the byte strings the objects hold after registration")
    out(f"   6LN stores {sum(s_attrs.values())} B: {s_attrs}")
    out(f"   6LC record per sensor stores {sum(r_attrs.values())} B: {r_attrs}   (+ controller id6lc/tid6lc {len(c.controller.id6lc)+len(c.controller.tid6lc)} B)")
    out("\n2) Cryptographic key/field storage actually READ during one full AKE (measured, attribute-access instrumentation)")
    out(f"   6LN reads {sum(s_used.values())} B: {sorted(s_used)}   never read: {sorted(set(s_attrs)-set(s_used))}")
    out(f"   6LC record reads {sum(r_used.values())} B: {sorted(r_used)}   never read: {sorted(set(r_attrs)-set(r_used))}")
    if "_reserved" in r_attrs: out("   '_reserved' (4 B) is non-functional padding in the audited baseline: it exists only to make the record total 60 B.")
    out("\n3) Python runtime object memory (NOT a protocol quantity; interpreter overhead)")
    out(f"   6LN object ~{sz(sensor)} B (sys.getsizeof of object + attribute byte strings); pickled {pyobj(sensor)} B.   6LC record ~{sz(rec)} B; pickled {pyobj(rec)} B")
    out("\nPaper (Table 6): 6LN 32 B, 6LC 60 B.")
    out(f"   6LN: stored {sum(s_attrs.values())} B, used {sum(s_used.values())} B -> " + ("stored attributes = 32 B" if sum(s_attrs.values()) == 32 else f"differs from 32 B (stored attributes include {sorted(set(s_attrs)-{'tid6lc','sc','k6ln','aid6ln'})} beyond the four fields the paper counts)"))
    out(f"   6LC: stored {sum(r_attrs.values())} B, used {sum(r_used.values())} B -> " + ("stored attributes = 60 B but 4 B are non-functional padding" if sum(r_attrs.values()) == 60 else "differs from 60 B"))
    return dict(sensor_stored=s_attrs, record_stored=r_attrs, sensor_used=s_used, record_used=r_used)


def comm(config, out=print):
    c = packet_inspector.build(config); a = packet_inspector.show(c, "both", out)
    return a


def hash_ops(config, out=print):
    return crypto_trace.show(config, out)


def crypto_ops(config, out=print):
    c, stages = crypto_trace.run_trace(config)
    out("=" * 78); out(f"ENCRYPTION / DECRYPTION OPERATIONS - {c.cfg.label}"); out("=" * 78)
    ops = [o for o in c.trace.ops if o["op"].startswith("aead") and o["stage"] != "Registration"]
    for o in ops: out(f"  [{o['stage']}] {o['op']:<13} inputs(B)={o['inputs']} output={o['output_bytes']} B  {o['purpose']}")
    out(f"  executed: {sum(1 for o in ops if o['op']=='aead-encrypt')} encryptions + {sum(1 for o in ops if o['op']=='aead-decrypt')} decryptions; paper convention: 2 (one per message). Each = 1 AES-128-CTR pass + 1 HMAC-SHA256.")
    return ops


def timing(config, out=print, n=500):
    c = Ctx(config, 2024, out=lambda *_: None); c.ensure_registered()
    from .attack_lab import Env
    e = Env(config); t_ln = t_lc = 0.0
    for _ in range(n):
        a = time.perf_counter(); m1 = e.cfg.ake.step_ake1(e.sensors[0]); b = time.perf_counter(); r = e.cfg.ake.step_ake2(e.ctrl, m1); d = time.perf_counter()
        e.cfg.ake.step_ake3(e.sensors[0], r["m2"]); f = time.perf_counter(); t_ln += (b - a) + (f - d); t_lc += d - b
        # NOTE: runs un-instrumented with the real clock; AKE1->AKE3 inside one second
    out("=" * 78); out(f"END-TO-END TIMING - {c.cfg.label}"); out("=" * 78)
    out(f"  {n} full sessions, un-instrumented, this PC / Python {sys.version.split()[0]}: sensor {t_ln/n*1000:.3f} ms, controller {t_lc/n*1000:.3f} ms per session, total {(t_ln+t_lc)/n*1000:.3f} ms")
    out(f"  Paper's 0.411 ms is a MODELLED value (10 x 0.0411 ms taken from another work); these wall-clock numbers are not comparable and say nothing about constrained devices.")
    return dict(sensor_ms=t_ln / n * 1000, controller_ms=t_lc / n * 1000)


def summary(out=print, save=None):
    """Paper vs measured values for the implementation (no value is forced to match)."""
    out("=" * 78); out("PERFORMANCE SUMMARY - paper vs measured (reconstructed implementation)"); out("=" * 78)
    out(f"{'Metric':<34}{'Paper':>8}{'Measured':>10}  Note")
    cc, st = crypto_trace.run_trace("reconstructed"); a = packet_inspector.accounting(cc)
    stg = lambda k: sum(st[s]["logical"].get(k, 0) for s in ("AKE1", "AKE2", "AKE3"))
    sens = {k: len(v) for k, v in vars(cc.sensor).items() if not k.startswith("_")}; rec = {k: len(v) for k, v in vars(next(iter(cc.controller.db.values()))).items()}
    m = dict(hash=stg("hash"), ace_exec=stg("aead-encrypt") + stg("aead-decrypt"), M1=a["M1"]["measured_bits"], M2=a["M2"]["measured_bits"], total=a["total"]["measured_bits"], s6ln=sum(sens.values()), s6lc=sum(rec.values()))
    lines = [("Hash ops, logical, AKE phase", PAPER["hash_ops"], m["hash"], "audited overhead.py hard-codes 8; measured = %d" % m["hash"]),
             ("AEAD ops executed", PAPER["ace_ops"], m["ace_exec"], "paper convention: once per message = 2"),
             ("M1 bits", 416, m["M1"], "match"), ("M2 bits", 608, m["M2"], "matches only via the reconstructed 64-bit T6C (paper: 32 bits -> 576)"),
             ("Total bits", 1024, m["total"], "paper text also says ~1010"), ("6LN stored bytes", 32, m["s6ln"], "attributes held by the object (incl. id6ln); 32 B are actually read"),
             ("6LC record stored bytes", 60, m["s6lc"], "includes 4 B non-functional padding")]
    rows = []
    for n, pv, mv, note in lines:
        out(f"{n:<34}{pv:>8}{mv:>10}  {note}"); rows.append(dict(metric=n, paper=pv, measured=mv, note=note))
    if save:
        save.mkdir(parents=True, exist_ok=True); (save / "performance_summary.json").write_text(json.dumps(rows, indent=1))
        import csv; w = csv.DictWriter(open(save / "performance_summary.csv", "w", newline=""), fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    return rows
