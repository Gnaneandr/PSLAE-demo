# PSLAE research demonstration (upgrade of `PSLAE_complete_final_audited.zip`)

Implements/demonstrates *Ashrif et al., "Provably secured and lightweight authenticated encryption protocol in machine-to-machine communication in Industry 4.0", Computer Communications 218 (2024) 263-275.*
Every demonstration calls the **real** protocol code in `src/` (the audited reconstruction); nothing is mocked and no result is forced.
`src/` is byte-identical to the audited zip: checksums are in `SRC_SHA256.txt` and `tests/test_demo_integrity.py` proves it. The original saved outputs are preserved in `results/baseline/`.

**What "reconstructed" means:** the paper's code is unpublished and parts of its text are unclear or inconsistent, so the audited project made documented choices (64-bit T6C, Mk derived from Sc and K6LN, AID6LN rotation, a SHA-1 counter-mode extension, an AES-CTR + HMAC stand-in for ACE, ...). Every one is listed in `docs/RECONSTRUCTION_DECISIONS.md` and `docs/PAPER_VS_IMPLEMENTATION.md`.

## Quick start
```text
# Windows (PowerShell)                              # Linux/macOS
py -3 -m venv .venv                                 python3 -m venv .venv
.\.venv\Scripts\Activate.ps1                        source .venv/bin/activate
pip install -r requirements-ui.txt                  pip install -r requirements-ui.txt
python demo.py list                                 python3 demo.py list
streamlit run app.py   (dashboard)                  streamlit run app.py
```
## Demonstrations (each runs independently; prerequisites are created deterministically and announced)
| Command | Shows |
|---|---|
| `python demo.py overview` | Demo A: roles, algorithms, public/secret/transmitted/stored values |
| `python demo.py registration [--stop-after 1..5]` | Demo B: RP-1…RP-5 with inputs, sizes, equations, status |
| `python demo.py ake1` / `ake2` / `ake3` | Demos C, D, E with every field, size, check and operation |
| `python demo.py session-key` / `full` | SK derivation on both sides / complete session |
| `python demo.py packet-breakdown [--message M1\|M2]` | field table, sizes, paper comparison |
| `python demo.py parameters [--save]` | parameter register (JSON + Markdown) |
| `python demo.py operations [--detail]` | operation trace: logical vs physical vs paper convention |
| `python demo.py security [--scenario A01] [--list]` | attack lab: 46 scenarios (19 families) on the real code |
| `python demo.py scyther [--exe PATH]` | Scyther on the reconstructed model |
| `python demo.py svo [--summary]` | SVO derivation with PUBLISHED/RECONSTRUCTED labels |
| `python demo.py performance [--part hash\|crypto\|comm\|storage\|time\|summary]` | measured vs paper |
| `python demo.py menu [--script 1,7,9,11,0]` | interactive menu (23 items) |
| `python demo.py tests` | pytest |
Common options: `--seed N`, `--random` (os.urandom), `--reveal-secrets` (**educational insecure mode**: prints disposable demo secrets; default output redacts secrets).

## Dashboard for the panel (Streamlit)
`streamlit run app.py` (or `run_dashboard.bat` / `./run_dashboard.sh`): a 10-page browser dashboard over the same real code (colour-coded attacks, packet-size charts, Scyther tab). Guide: `docs/DASHBOARD_DEMO_GUIDE.md`; opening slide: `docs/sequence_diagram.svg`.

## What the evidence says (from the runs recorded in `results/`)
* Both parties derive equal session keys in every stage test.
* M1 = 416 bits (matches the paper). M2 = 608 bits **only because T6C is 64 bits** (paper: 32; the paper's literal field widths give 576).
* Measured logical hash operations in the AKE phase: **12** (the audited `performance/overhead.py` hard-codes the paper's 8).
* Attack lab (real code, 46 scenarios): 37 protected, 3 partially protected, **6 vulnerable** - A02c future-dated timestamp accepted; A03a held M1 with refreshed timestamp accepted (then desynchronisation); A06 T6LN/T6C not authenticated; A11b one lost M2 permanently desynchronises; A17 M1 and M2 share key and nonce, so one session leaks AID6LN/TID6LC.
* Scyther: 10 Ok in the reconstructed model, in which timestamps are authenticated (the paper sends them bare; its own model is unpublished). XOR is abstracted.
* ACE is an **interface reconstruction** (AES-128-CTR + HMAC-SHA256/128), not the authors' ACE.

## Where to read next
`docs/LIVE_DEMO_GUIDE.md`, `docs/DASHBOARD_DEMO_GUIDE.md`, `docs/PANEL_SPEAKING_SCRIPT.md`, `docs/PAPER_VS_IMPLEMENTATION.md`, `docs/RECONSTRUCTION_DECISIONS.md`, `docs/KNOWN_LIMITATIONS.md`, `docs/SETUP_GUIDE.md`, `docs/DEMO_TROUBLESHOOTING.md`.
The audited project's own documents (`docs/module_*.md`, `paper_ambiguities.md`, ...) are kept unchanged.

## Layout
`demo.py` entry · `app.py` dashboard · `demo/` (runtime/tracing, stage demos, packet inspector, parameters, attack lab, performance, Scyther/SVO, CLI, menu) · `src/` audited code · `tests/` (audited tests + demo tests) · `scyther/` (model + `bin/`) · `results/{baseline,fresh_test_run,attack_lab,packet_analysis,verification}` · `docs/`.
