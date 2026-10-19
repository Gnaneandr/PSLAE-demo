"""Command-line interface: python demo.py <command> [options]. Every command is independent; prerequisites are created deterministically and announced."""
import argparse, subprocess, sys, pathlib, json
from .runtime import ROOT
from . import stage_demos as S, packet_inspector, crypto_trace, parameters, performance_demo, verification, attack_lab

COMMANDS = [("list", "list the available demonstrations"), ("overview", "Demo A: system initialisation, roles, algorithms, value classes"),
            ("registration", "Demo B: RP-1..RP-5 step by step (--stop-after N)"), ("ake1", "Demo C: sensor builds M1"), ("ake2", "Demo D: controller verifies M1, builds M2"),
            ("ake3", "Demo E: sensor verifies M2, derives SK'"), ("session-key", "session-key derivation table, both sides"), ("full", "complete end-to-end session"),
            ("parameters", "parameter register (--save writes JSON + Markdown)"), ("packet-breakdown", "packet inspector for M1/M2 (--message M1|M2|both)"),
            ("operations", "cryptographic operation trace: logical vs physical vs paper convention (--detail)"), ("security", "attacker laboratory (--scenario A01.., --list)"),
            ("scyther", "run Scyther on the reconstructed model"), ("svo", "show the SVO derivation (--summary)"),
            ("performance", "hash/crypto/comm/storage/time (--part all|hash|crypto|comm|storage|time|summary)"), ("traceability", "paper-to-code traceability and paper-vs-implementation"),
            ("tests", "run the pytest suite"), ("menu", "interactive menu for a live review"), ("help", "show help")]


def common(sp):
    sp.add_argument("--seed", type=int, default=2024, help="seed of the DEMO deterministic generator (disposable keys)")
    sp.add_argument("--random", action="store_true", help="use os.urandom instead of the seeded demo generator")
    sp.add_argument("--reveal-secrets", action="store_true", help="EDUCATIONAL INSECURE MODE: print disposable demonstration secrets")


def ctx_of(a, out=print):
    return S.Ctx(a.config, a.seed, a.random, a.reveal_secrets, out=out)


def overview(ctx):
    ctx.banner("DEMO A - SYSTEM INITIALISATION AND OVERVIEW")
    registration_ctx = S.registration_stage(ctx, 5, header=False) or ctx
    ctx.p("\nRoles"); ctx.p("  6LN (6LoWPAN sensor node)  : battery-limited device; stores its own secrets; starts AKE with M1.")
    ctx.p("  6LC (6LoWPAN controller)   : verifies sensors, keeps one database record per sensor, answers with M2.")
    ctx.p("\nCryptographic algorithms actually used and their roles")
    for r in (("SHA-1 (160-bit)", "H(): session key SK and confirmation M. One-way hash, no key."), ("H_bits (SHA-1 counter mode)", "RECONSTRUCTION: stretches H() to 64/128/256 bits where the paper's algebra needs it."),
              ("XOR", "masks values (A, B, D, A1, B1, AID6LN, Sc, Mk...). Not encryption by itself."), ("AES-128-CTR", "keystream encryption of A||B and Sc1||RN2 (ACE interface reconstruction)."),
              ("HMAC-SHA256 truncated to 128 bit", "authentication tag over AD||CT (ACE interface reconstruction)."), ("random 64-bit values", "RN1, RN2 and identifiers (demo: seeded generator; real: os.urandom).")):
        ctx.p(f"  {r[0]:<34}{r[1]}")
    _, rows = parameters.build(ctx.cfg.name, ctx.seed)
    ctx.p("\nValue classes from a real run (details: `python demo.py parameters`)")
    sec = [r["key"] for r in rows if r["secret"]]; pub = [r["key"] for r in rows if not r["secret"]]
    ctx.p(f"  public ({len(pub)}): {pub}"); ctx.p(f"  secret ({len(sec)}): {sec}")
    ctx.p(f"  transmitted: {[r['key'] for r in rows if r['transmitted'].startswith('yes')]}")
    ctx.p(f"  stored     : {[r['key'] for r in rows if r['stored'] != 'no (derived on demand / transient)']}")
    ctx.p("  derived on demand / transient: everything else (Si, AD, X, Fr, T, B1, SK, M ...)")


def listing(out=print):
    out("Available demonstrations (python demo.py <command> --help for options):")
    for n, d in COMMANDS: out(f"  {n:<17}{d}")
    out("\nCommon options: --seed N   --random   --reveal-secrets (educational insecure mode)")
    out("Stage commands create their prerequisites deterministically (registration -> AKE1 -> AKE2 -> AKE3) and say so. Use `menu` for a guided live session.")


def run_security(a, out=print):
    cfgs = ["reconstructed"]
    for cfg in cfgs:
        out("=" * 78); out(f"ATTACKER LABORATORY - {cfg} configuration (real protocol code; nothing mocked)"); out("=" * 78)
        out("A REJECT shows only that the tested input was rejected. It does not prove resistance to every attack. ACCEPT rows are reported as found.")
        res = attack_lab.run_all(cfg, only=a.scenario)
        if a.list:
            for r in res: out(f"  {r['id']:<12}{r['title']}")
            continue
        for r in res: attack_lab.render(r, out)
        out("\nSUMMARY"); out(f"  {'ID':<14}{'Outcome':<8}{'Classification':<42}Check")
        for r in res: out(f"  {r['id']:<14}{r['outcome']:<8}{r['classification'][:40]:<42}{r['responsible_check'][:45]}")
        from collections import Counter
        out("  " + str(dict(Counter(r["classification"] for r in res))))
        if a.save: attack_lab.save(cfg, res)


def traceability(out=print):
    p = ROOT / "docs" / "paper_to_code_traceability.md"
    out(p.read_text() if p.exists() else "docs/paper_to_code_traceability.md missing")
    out("\nSee also docs/PAPER_VS_IMPLEMENTATION.md and docs/RECONSTRUCTION_DECISIONS.md")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="demo.py", description="PSLAE research demonstration (calls the real protocol implementation).", epilog="Run `python demo.py list` for all demonstrations.")
    sub = ap.add_subparsers(dest="cmd")
    for n, d in COMMANDS:
        sp = sub.add_parser(n, help=d, description=d)
        if n in ("registration", "overview", "ake1", "ake2", "ake3", "session-key", "full", "parameters", "packet-breakdown", "operations", "performance", "menu"): common(sp)
        if n == "registration": sp.add_argument("--stop-after", type=int, choices=[1, 2, 3, 4, 5], default=5, help="stop after RP-n")
        if n == "parameters": sp.add_argument("--save", action="store_true"); sp.add_argument("--json", action="store_true")
        if n == "packet-breakdown": sp.add_argument("--message", choices=["M1", "M2", "both"], default="both"); sp.add_argument("--save", action="store_true")
        if n == "operations": sp.add_argument("--detail", action="store_true")
        if n == "security":
            sp.add_argument("--scenario", default=None, help="ID prefix, e.g. A01 or A06-M1.D")
            sp.add_argument("--list", action="store_true"); sp.add_argument("--save", action="store_true")
        if n == "scyther": sp.add_argument("--exe", default=None)
        if n == "svo": sp.add_argument("--summary", action="store_true")
        if n == "performance":
            sp.add_argument("--part", choices=["all", "hash", "crypto", "comm", "storage", "time", "summary"], default="all"); sp.add_argument("--save", action="store_true")
        if n == "menu": sp.add_argument("--script", default=None, help="comma-separated menu choices for non-interactive use, e.g. 1,7,9,11,0")
    a = ap.parse_args(argv)
    a.config = "reconstructed"          # the only implementation in this package
    if not a.cmd or a.cmd == "help": ap.print_help(); print(); listing(); return 0
    c = a.cmd
    if c == "list": listing()
    elif c == "overview": overview(ctx_of(a))
    elif c == "registration": S.registration_stage(ctx_of(a), a.stop_after)
    elif c == "ake1": S.ake1_stage(ctx_of(a))
    elif c == "ake2": S.ake2_stage(ctx_of(a))
    elif c == "ake3": S.ake3_stage(ctx_of(a))
    elif c == "session-key": S.session_key_stage(ctx_of(a))
    elif c == "full": return 0 if S.full_stage(ctx_of(a)) else 1
    elif c == "parameters":
        if a.save:
            for cfg in ("reconstructed",):
                _, rows, md = parameters.save_and_markdown(cfg, ROOT / "results" / "packet_analysis", None); (ROOT / "docs" / f"PARAMETER_REGISTER_{cfg}.md").write_text(md)
            print("saved results/packet_analysis/parameter_register_*.json and docs/PARAMETER_REGISTER_*.md")
        rows = parameters.show(a.config)
        if a.json: print(json.dumps(rows, indent=1))
    elif c == "packet-breakdown":
        ctx = packet_inspector.build(a.config, a.seed); packet_inspector.show(ctx, a.message)
        if a.save: packet_inspector.save(a.config, ROOT / "results" / "packet_analysis"); print("saved results/packet_analysis")
    elif c == "operations": crypto_trace.show(a.config, detail=a.detail, seed=a.seed)
    elif c == "security": run_security(a)
    elif c == "scyther": verification.scyther_cmd("reconstructed", a.exe)
    elif c == "svo": verification.svo_cmd(a.summary)
    elif c == "performance":
        P = performance_demo
        parts = {"hash": P.hash_ops, "crypto": P.crypto_ops, "comm": P.comm, "storage": P.storage, "time": P.timing}
        if a.part in ("summary", "all"): P.summary(save=ROOT / "results" / "packet_analysis" if a.save else None)
        for k, f in parts.items():
            if a.part in ("all", k): f(a.config)
    elif c == "traceability": traceability()
    elif c == "tests": return subprocess.call([sys.executable, "-m", "pytest", "-q", "tests"], cwd=ROOT)
    elif c == "menu":
        from .interactive_menu import run_menu
        run_menu(a)
    return 0
