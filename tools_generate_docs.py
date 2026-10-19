"""Generates the live-output documents from real runs (so documentation cannot disagree with the code)."""
import io, contextlib, sys, pathlib, json, subprocess
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from demo.cli import main
from demo import attack_lab, packet_inspector, parameters, performance_demo, verification

def cap(*argv):
    b = io.StringIO()
    with contextlib.redirect_stdout(b): main(list(argv))
    return b.getvalue()

def block(t): return "```text\n" + t.rstrip() + "\n```\n"
D = ROOT / "docs"
def write(n, t): (D / n).write_text(t)

INTRO = {
 "REGISTRATION_WALKTHROUGH.md": ("Registration RP-1 to RP-5", "python demo.py registration  [--stop-after N] [--reveal-secrets]",
   "Registration happens once, before the sensor is deployed, over a secure channel. The controller (6LC) creates the sensor's secrets and both sides store what they need. Nothing here is sent over the air.\n\n"
   "**What to point out:** (1) RP-2 contains the paper's '265 bit' inconsistency and the reconstructed H_bits extension. (2) RP-3 shows the *actual* attributes stored: the audited 6LC record contains a 4-byte non-functional `_reserved` padding and the 6LN also stores `id6ln`. (3) RP-4/RP-5 show Si and AD, which are never stored. (4) The step-by-step recomputation is checked against the real `register_sensor()` output.\n\n"
   "| Step | Paper equation | Status in the audited code |\n|---|---|---|\n| RP-1 | 6LC picks ID6LC, R6LC, K6LC, K6LN, TID6LC | literal values; widths of ID6LC/R6LC assumed 64 bit; TID6LC generation rule not given |\n| RP-2 | AID = ID xor K6LN xor K6LC; Mk = Ms xor H(R6LC); Sm = Mk xor H(ID6LN); Sc = Sc1^Sc2^Sc3^Sc4 | AID, Sc literal; Ms 256 bit (paper '265'); H extended with H_bits (reconstruction) |\n| RP-3 | storage sets | differs from the paper's list (see output); reconstructed config derives Mk instead of storing it |\n| RP-4 | X = Mk xor Sc; Si = Nc||Kc | Sc tiled to 256 bit (reconstruction) |\n| RP-5 | Fr = Mk xor H(K6LN); AD = Fr1 xor Fr2 | H_bits extension (reconstruction) |\n", ["registration"]),
 "AKE1_WALKTHROUGH.md": ("AKE1 - the sensor builds M1", "python demo.py ake1  [--reveal-secrets]",
   "The sensor picks a fresh random number RN1 and a timestamp, masks its alias with XOR (A, B, D), encrypts A||B with the ACE-interface stand-in (AES-128-CTR + HMAC tag) and sends M1.\n\n"
   "**Key facts:** M1 is 416 bits and matches the paper because every field width is stated. T6LN, D and RN1 travel in clear; only CT is encrypted; the tag covers AD||CT but NOT the timestamp. XOR, hash and encryption are different operations: XOR masks, SHA-1 fingerprints, AES-CTR hides.\n", ["ake1"]),
 "AKE2_WALKTHROUGH.md": ("AKE2 - the controller verifies M1 and builds M2", "python demo.py ake2  [--reveal-secrets]",
   "The controller checks freshness, finds the alias, derives the same key material, decrypts, verifies the tag, checks RN1 and Sc', then builds the session key SK and M2.\n\n"
   "**Rejection conditions (in code order):** stale timestamp; alias not found; tag mismatch; RN1 mismatch; Sc mismatch. Wrong field lengths are rejected by an unhandled `ValueError` (no explicit validation). **Measured, reconstructed config:** M2 = 608 bits only because T6C is 64 bits there (paper: 32; literal field widths give 576).\n", ["ake2"]),
 "AKE3_WALKTHROUGH.md": ("AKE3 - the sensor verifies M2", "python demo.py ake3  [--reveal-secrets]",
   "The sensor checks freshness, recomputes A1', verifies the tag, takes Sc1 and RN2 out of the decrypted CT1, derives SK' and checks M' = M.\n\n"
   "**Substitution vs the paper:** the paper says the sensor computes T' = Mk xor H(ID6LC) to get Sc1', but the sensor never receives ID6LC; the code takes Sc1 from the decrypted CT1 instead. The controller updates its state before the sensor confirms (see attack A11b).\n", ["ake3", "session-key"]),
}
for fn, (title, cmd, text, cmds) in INTRO.items():
    out = f"# {title}\n\nRun: `{cmd}`\n\n{text}\n"
    for c in cmds:
        for cfg in ("reconstructed",):
            out += f"\n## Live output: `{c}` (seed 2024, secrets redacted)\n\n" + block(cap(c))
    write(fn, out)

# parameters & packets
pr = "# PARAMETER_REGISTER\n\nGenerated from real runs by `tools_generate_docs.py`; machine-readable copies: `results/packet_analysis/parameter_register_*.json`. Sizes are measured; 'stored' is derived from the real objects.\n\n"
for cfg in ("reconstructed",):
    _, rows, md = parameters.save_and_markdown(cfg, ROOT / "results" / "packet_analysis"); pr += md.replace("# Parameter register", "## Parameter register") + "\n"
write("PARAMETER_REGISTER.md", pr)
pk = "# PACKET_FORMATS\n\nGenerated from the real message objects. 'Paper' = width the paper states for the field. No framing, header or padding is added by the code.\n\n"
for cfg in ("reconstructed",):
    packet_inspector.save(cfg, ROOT / "results" / "packet_analysis"); pk += f"## {cfg}\n\n" + block(cap("packet-breakdown"))
write("PACKET_FORMATS.md", pk)

# attacks
att = "# ATTACK_DEMONSTRATIONS\n\nGenerated by running `python demo.py security --save` (real protocol code). Frozen outcomes live in `tests/expected_attack_outcomes.json`. **A REJECT shows only that the tested input was rejected.**\n\n"
for cfg in ("reconstructed",):
    res = attack_lab.run_all(cfg); attack_lab.save(cfg, res)
    att += f"## Results ({cfg} implementation)\n\n| ID | Scenario | Outcome | Check | Classification |\n|---|---|---|---|---|\n" + "\n".join(f"| {r['id']} | {r['title']} | {r['outcome']} | {r['responsible_check']} | {r['classification']} |" for r in res) + "\n\n"
    for r in res:
        att += f"### {cfg} {r['id']} - {r['title']}\n- **Plain English:** {r['plain_english']}\n- **Attacker:** {r['attacker']}\n- **Action:** {r['action']}\n" + "".join(f"  - {s}\n" for s in r["steps"]) + f"- **Outcome:** {r['outcome']} ({r['responsible_check']})\n- **Expected / observed:** {r['expected']} / {str(r['observed'])[:160]}\n- **Interpretation:** {r['interpretation']}\n- **Classification:** {r['classification']}\n- **Test:** `{r['automated_test']}`\n\n"
write("ATTACK_DEMONSTRATIONS.md", att)

# performance
pf = "# PERFORMANCE_AND_STORAGE\n\nGenerated by `python demo.py performance --part all --save`. Paper values, measured values and reconstruction status side by side; nothing is forced to match.\n\n"
pf += "## Summary\n\n" + block(cap("performance", "--part", "summary", "--save"))
for cfg in ("reconstructed",):
    for part in ("hash", "comm", "storage", "crypto", "time"):
        pf += f"## {part} ({cfg})\n\n" + block(cap("performance", "--part", part))
write("PERFORMANCE_AND_STORAGE.md", pf)

# scyther
exe = verification.find_exe()
sc = "# SCYTHER_EXPLANATION\n\n"
sc += (ROOT / "docs" / "_scyther_intro.md").read_text() + "\n"
if exe:
    sc += "## Fresh run (generated)\n\n" + block(cap("scyther"))
else:
    sc += "Scyther binary unavailable when this document was generated.\n"
sc += "\n## Original saved output of the audited project (preserved, not overwritten)\n\n" + block((ROOT / "results" / "baseline" / "scyther_saved" / "pslae_final_output.txt").read_text()[:3000].replace("\x1b[32m", "").replace("\x1b[0m", ""))
write("SCYTHER_EXPLANATION.md", sc)
print("docs generated")
