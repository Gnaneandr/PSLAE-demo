# DASHBOARD_DEMO_GUIDE - how to give the demo (Streamlit dashboard)

## 0. What it is
`app.py` is a browser dashboard over the same demo layer as `demo.py`. **Every button calls the real protocol code**; nothing is simulated. Colour code: green = this input was rejected / property held in this test, red = a weakness found (shown on purpose), orange = partial. Sidebar: educational secrets toggle, presenter notes, step selector.

## 1. Setup (do this the day before)
```text
# Windows (PowerShell)                                  # Linux / macOS
py -3 -m venv .venv                                     python3 -m venv .venv
.\.venv\Scripts\Activate.ps1                            source .venv/bin/activate
pip install -r requirements-ui.txt                      pip install -r requirements-ui.txt
streamlit run app.py        (or run_dashboard.bat)      streamlit run app.py   (or ./run_dashboard.sh)
```
A browser tab opens at http://localhost:8501. If it does not, open that address yourself. Close other heavy programs; no internet is needed.
**Verified here:** the server starts and serves the page (HTTP 200), and an automated test (`tests/test_dashboard.py`, Streamlit AppTest) clicks every page and button in both configurations without errors. **Not verified:** how it looks on your screen/projector and Windows execution - open it once on the presentation laptop and check font size (browser zoom Ctrl +) and the dark/light theme.

## 2. Equipment checklist
Laptop charged and plugged in · project folder + activated venv · browser zoom 110-125 % · terminal window ready as fallback · `docs/sequence_diagram.svg` inserted as slide 1 · optional: Scyther GUI (see 6) · a printed copy of `docs/PANEL_SPEAKING_SCRIPT.md`.

## 3. Running order (about 25 minutes)
Say first (20 s): *"Everything I click runs the real implementation. Where the paper was unclear we say so, and some of its claims do not hold - the attacker lab shows which."*

| Min | Page | Click | Expected on screen | Say |
|---|---|---|---|---|
| 0-2 | slide: sequence diagram, then **1 · The story** | - | sensor ⇄ controller diagram with M1 416 bits and M2 608 (reconstructed; 576 with the paper's 32-bit timestamp) | goal: agree a key without sending it; three ideas: registration, two messages, key computed on both sides |
| 2-5 | **2 · Registration** | slider to 5, **Run registration**; open RP-2, RP-3 | tables of values with bits and public/secret; RP-3 shows what each side stores (incl. 4-byte `_reserved` in the reconstructed config) | one-time safe setup; flag '265-bit' typo and the SHA-1 extension as reconstructions |
| 5-8 | **3 · AKE1** | **Run AKE1** | values table, the encryption box, M1 table: **416 bits = paper** | XOR masks, SHA-1 fingerprints, AES hides, HMAC seals; the timestamp is in clear and not covered by the tag |
| 8-11 | **4 · AKE2** | **Run AKE2** | five green checks; M2 table; yellow note about 64-bit T6C in the reconstructed config | what the controller verifies; session key is computed, only M = SHA-1(SK) is sent |
| 11-13 | **5 · AKE3** | **Run AKE3** | green checks; **Keys equal: YES**, length 160 bits, 'never sent' | both sides computed the same key; one substitution vs the paper (Sc1 read from the decrypted block) |
| 13-14 | **6 · Packet sizes** | tabs M1 / M2 | bar chart of fields, measured vs paper vs sum of paper widths | M1 matches; M2 depends on a flagged choice |
| 14-21 | **7 · Attacker lab** | see section 4 | green and red cards | the core of the demo |
| 21-23 | **8 · Formal checks** | **Run Scyther** | 10 Ok in our model (timestamps authenticated there) | automatic attack search; model caveats; SVO is manual |
| 23-24 | **9 · Numbers vs paper** | - | red cells where values differ from the paper | nothing was forced to match |
| 24-25 | **10 · Paper vs our implementation** | - | 20-row table | what is literal, reconstructed, discrepancy; what we can and cannot claim |

## 4. Attacker lab - what to launch and what you will see
(Verdicts below are the frozen results in `tests/expected_attack_outcomes.json`.)
| Choose | Result | Say |
|---|---|---|
| Replay | all green (A01a-c) | replay is rejected because the stored state changed after the first session - not because of a replay cache |
| Flip a ciphertext bit / Forge or change the tag | green, check = tag verification | one flipped bit is detected |
| Change any single field | green except **T6LN and T6C red** | the timestamps are not protected by the tag |
| Old or altered timestamps | A02a/b, A03b green; **A02c (future timestamp) and A03a red** | A03a: hold a message, refresh its timestamp, deliver - accepted, and the pair desynchronises |
| Unknown or fake identity / Mix messages | green | outsiders and spliced messages fail |
| Drop messages | A11a green, **A11b red** | one lost reply locks the sensor out: no recovery path |
| Duplicate / reorder messages | green | duplicates and out-of-order replies are refused |
| Many sessions and key isolation | green | keys equal inside a session, different across sessions; old M1 messages rejected |
| Does the alias change? | green | D changes every session (a reconstruction, not a paper equation) |
| Eavesdropper analysis | **A17 red**, A18 orange | the two ciphertexts of one session leak the alias (key and nonce shared); the session key itself was not recovered in our tests - not a proof |
| Flooding with garbage | orange | cost per rejected message shown; no rate limiting |
Keep repeating: **a green card means this tested input was rejected, not that the protocol is proven secure.**

## 5. If something goes wrong
| Problem | Do |
|---|---|
| Browser tab does not open | go to http://localhost:8501 |
| Page looks stale | press R in the browser, or use the sidebar to change step |
| Port busy | `streamlit run app.py --server.port 8600` |
| Dashboard fails entirely | use the terminal fallback: `python demo.py full`, `python demo.py security --scenario A01`, `python demo.py scyther`, `python demo.py menu` |
| Scyther button shows 'binary not found' | Linux binary is bundled; on Windows download Scyther and set `SCYTHER_EXE` (docs/SETUP_GUIDE.md); otherwise show `results/verification/scyther_*_output.txt` |
| A red card appears 'unexpectedly' | it is real behaviour; explain it (docs/KNOWN_LIMITATIONS.md) - never edit the code live |

## 6. Optional: Scyther GUI for the formal-methods minute
The Scyther GUI (from https://github.com/cascremers/scyther) can open `scyther/pslae.spdl` and show the protocol's message flow. **I did not test the GUI here** (it needs a graphical environment and wxPython); the dashboard's Scyther tab runs the command-line binary instead. If you use the GUI, rehearse it once, and keep the dashboard tab as the fallback.

## 7. Questions to expect, with safe answers
* *Is this the authors' implementation?* No; their code is unpublished. We reconstructed from the text.
* *Is ACE implemented?* No; AES-128-CTR + HMAC is an interface stand-in.
* *Why are some results red?* Because the code really behaves that way; we report it.
* *Does 'Ok' in Scyther mean secure?* No: it is a statement about an abstract model; XOR is abstracted and the reconstructed model authenticates timestamps.
* *Why does M2 show 608?* The reconstructed timestamp is 64 bits; the paper says 32, which gives 576.
More: `docs/VIVA_QUESTIONS_AND_ANSWERS.md`.
