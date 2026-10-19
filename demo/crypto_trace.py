"""Cryptographic-operation trace for a full session: logical vs physical counts, per stage, with the paper's counting convention."""
import json
from .stage_demos import Ctx


def run_trace(config, seed=2024):
    c = Ctx(config, seed, out=lambda *_: None)
    c.ensure_m2(); c.out = lambda *_: None
    from .stage_demos import ake3_stage
    ake3_stage(c, header=False)
    stages = {}
    for st in ("Registration", "AKE1", "AKE2", "AKE3"):
        stages[st] = c.trace.counts(stage=st)
    return c, stages


def show(config, out=print, seed=2024, detail=False):
    c, stages = run_trace(config, seed)
    out("=" * 78); out(f"CRYPTOGRAPHIC OPERATION TRACE - {c.cfg.label}"); out("=" * 78)
    out("Secret values are never recorded; only operation, algorithm, sizes, calling function and the source line.\n")
    out(f"{'Stage':<14}{'hash(logical)':>14}{'SHA-1 calls':>12}{'XOR':>6}{'AEAD enc':>9}{'AEAD dec':>9}{'random':>7}{'compare':>8}")
    tot = {}
    for st, cnt in stages.items():
        L, P = cnt["logical"], cnt["physical"]
        out(f"{st:<14}{L.get('hash',0):>14}{P.get('sha1',0):>12}{P.get('xor',0):>6}{L.get('aead-encrypt',0):>9}{L.get('aead-decrypt',0):>9}{L.get('random',0):>7}{L.get('compare',0):>8}")
        if st != "Registration":
            for k, v in L.items(): tot[("L", k)] = tot.get(("L", k), 0) + v
            for k, v in P.items(): tot[("P", k)] = tot.get(("P", k), 0) + v
    h_log, h_phys = tot.get(("L", "hash"), 0), tot.get(("P", "sha1"), 0)
    ace_exec = tot.get(("L", "aead-encrypt"), 0) + tot.get(("L", "aead-decrypt"), 0)
    out("\nAKE phase only (AKE1+AKE2+AKE3), versus the paper (Sec.7.2 / Table 4: 8 T_SHA + 2 T_ACE):")
    out(f"  hash operations, logical (calls made by the protocol code)   : {h_log}    paper: 8   {'MATCH' if h_log == 8 else 'DIFFERENT'}")
    out(f"  SHA-1 invocations, physical (H_bits expands to ceil(bits/160)) : {h_phys}")
    out(f"  ACE-interface operations actually executed (enc + dec)        : {ace_exec}    (each = 1 AES-CTR pass + 1 HMAC)")
    out(f"  ACE under the paper's convention (once per message)           : 2         (a counting convention, not a reduction of work)")
    out("  Note: the audited baseline's performance/overhead.py HARD-CODES 'SHA-1 = 8'; this trace MEASURES the count.")
    if detail:
        out("\nFull operation list:")
        for i, o in enumerate(c.trace.ops, 1):
            out(f"{i:>3} [{o['stage']:<12}] {o['op']:<13} in={o['inputs']} out={o['output_bytes']}B  {o['algorithm'][:40]:<40} {o['purpose'] or o['source'][:50]}")
    return dict(stages=stages, ake_logical_hash=h_log, ake_physical_sha1=h_phys, ake_aead_executed=ace_exec, ops=c.trace.ops)
