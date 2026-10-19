"""Scyther runner and SVO viewer (formal-analysis demonstrations with honest labels)."""
import os, re, shutil, subprocess, pathlib
from .runtime import ROOT

MODELS = {"reconstructed": (ROOT / "scyther" / "pslae.spdl", "RECONSTRUCTED model: timestamps bound into the authenticated ciphertext (a deliberate change from the paper, which sends them as bare fields)")}
ANSI = re.compile(r"\x1b\[[0-9;]*m")
CMD_FLAGS = ["-r", "100", "-m", "0", "-A"]      # the audited project's own flags (results/baseline/scyther_saved/command_used.txt)


def find_exe(exe=None):
    for c in (exe, os.environ.get("SCYTHER_EXE"), str(ROOT / "scyther" / "bin" / "scyther-linux"), shutil.which("scyther-w32"), shutil.which("scyther-linux"), shutil.which("scyther")):
        if c and (pathlib.Path(c).exists() or shutil.which(c)): return c
    return None


def describe_model(path):
    t = path.read_text()
    roles = re.findall(r"role\s+(\w+)", t); events = re.findall(r"\b(send|recv)_(\w+)\(([^)]*)\)", t); claims = re.findall(r"claim\w*\(\s*\w+\s*,\s*(\w+)", t)
    return roles, events, claims


def run_model(which, exe, out=print, save=True):
    path, label = MODELS[which]
    out("-" * 78); out(f"Model: {path.relative_to(ROOT)}   [{label}]")
    roles, events, claims = describe_model(path)
    out(f"  roles: {sorted(set(roles))}"); out(f"  events: {len(events)} send/recv statements (message tuples are in the model file)"); out(f"  claims declared: {claims}")
    cmd = [exe] + CMD_FLAGS + [str(path)]
    out("  command: " + " ".join(os.path.relpath(x, ROOT) if x.startswith(str(ROOT)) else x for x in cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=600)
    raw = ANSI.sub("", p.stdout + p.stderr)
    rows = []
    for line in raw.splitlines():
        c = line.split("\t")
        if c and c[0] == "claim" and len(c) >= 6: rows.append((c[1].split(",")[-1], c[2], c[4], c[5]))
    out(f"  {'Role':<7}{'Claim':<14}{'Result':<7}Scyther comment")
    for r in rows: out(f"  {r[0]:<7}{r[1]:<14}{r[2]:<7}{r[3]}")
    fails = [r for r in rows if r[2] != "Ok"]
    out(f"  -> {len(rows)-len(fails)} Ok, {len(fails)} Fail" + ("" if not fails else "   (a Fail means Scyther FOUND an attack in this model; traces: add -d to the command for dot graphs)"))
    if save:
        d = ROOT / "results" / "verification"; d.mkdir(parents=True, exist_ok=True); (d / f"scyther_{which}_output.txt").write_text(raw)
    return rows


def scyther_cmd(which="both", exe=None, out=print):
    out("=" * 78); out("SCYTHER FORMAL VERIFICATION"); out("=" * 78)
    exe = find_exe(exe)
    if not exe:
        out("Scyther binary not found. Pass --exe PATH (Windows: scyther-w32.exe from https://github.com/cascremers/scyther) or set SCYTHER_EXE."); return None
    v = subprocess.run([exe, "--version"], capture_output=True, text=True); out("Binary:", exe, "|", ANSI.sub("", (v.stdout + v.stderr)).strip().splitlines()[0] if (v.stdout + v.stderr).strip() else "")
    res = {}
    res["reconstructed"] = run_model("reconstructed", exe, out)
    saved = ROOT / "results" / "baseline" / "scyther_saved" / "pslae_final_output.txt"
    if saved.exists(): out(f"\nOriginal saved output preserved (not overwritten): {saved.relative_to(ROOT)}")
    out("""
HOW TO READ THIS (no formal-methods background needed)
  * Scyther tries to build an attack on a symbolic model of the protocol within a bound (100 runs here). 'Ok' = no attack found / proof within that model; 'Fail' = an attack exists.
  * Secret  : the session key stays unknown to the attacker.   Alive/Weakagree : the partner really ran the protocol.
    Niagree/Nisynch : both sides agree on all exchanged data / message order (the strongest claims).
  * IMPORTANT: this model puts the timestamps INSIDE the authenticated part of M1 and M2. The paper sends them as bare fields, and the paper does not publish its own model. So these Ok results
    are results for the reconstructed model; they do not show that the protocol exactly as written in the paper passes.
  * LIMITATIONS: Scyther cannot compute XOR; the model abstracts XOR as an opaque function (xorf). Timestamps are modelled as variables. State updates (Sc/alias rotation) are not modelled.
    Symbolic 'Ok' is not a proof about the real implementation or about concrete AES/HMAC/SHA-1.""")
    return res


# ------------------------------------------------------------------------------------------------ SVO
SVO = ROOT / "docs" / "svo" / "complete_svo_derivation.md"
BANNER = """SVO LOGIC ANALYSIS (manual derivation - NOT machine-verified)
  [PUBLISHED]     = taken from the paper's Fig.6 as read by the audited project.   [RECONSTRUCTED] = added by the audited project; NOT in the paper.
  G1 : published goal (6LC believes the 6LN said M1's ciphertext).   G2 : the mirror goal for M2 - the paper does not derive it; it is a reconstruction.
  Reviewer caution: our independent reading of the paper's premises (see docs/SVO_EXPLANATION.md) finds that G1's published steps do not follow strictly from the listed premises
  (IS5 treats a ciphertext as a shared key; freshness for the 6LC is not among the premises; Necessitation is applied to assumptions). Verify against Fig.6 of the PDF."""


def svo_cmd(summary=False, out=print):
    out("=" * 78); out(BANNER); out("=" * 78)
    txt = SVO.read_text()
    if summary:
        for l in txt.splitlines():
            if l.startswith("|") or l.startswith("#") or "PUBLISHED" in l or "RECONSTRUCTED" in l: out(l[:200])
    else:
        out(txt)
    out("\nStatus: G1 = published (not machine-verified, caution above). G2 = reconstructed; load-bearing premise IS5' is justified only for the reconstructed Mk derivation (Mk from Sc, K6LN), not for the paper's literal protocol.")
