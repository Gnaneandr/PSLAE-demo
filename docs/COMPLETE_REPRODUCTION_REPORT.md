# PSLAE — Complete Paper-to-Implementation Audit & Final Reproduction Report

> **⚠️ SUPERSEDED — HISTORICAL SNAPSHOT, NOT CURRENT STATUS.**
> This file was written when the project still had two separate
> directory trees (`src/` faithful vs. `paper_matching/` reconstructed)
> and *before* the ID6LC/AKE3 fix and SVO G2 completion that happened
> in the following round. Both of those have since changed the
> project's actual state in ways this file does NOT reflect —
> most importantly, **the SVO G2 status stated below ("NOT
> IMPLEMENTED") is WRONG as of the current project.** G2 has since
> been completed as a documented reconstruction.
>
> **For the current, accurate status, use:**
> - `docs/paper_to_code_traceability.md` — current status of every
>   paper item, including the corrected G2 line
> - `docs/svo/complete_svo_derivation.md` — the actual G2 derivation
> - `README.md` (project root) — current single-tree structure
>
> This file is kept only as a historical record of the intermediate
> two-track design and its reasoning, in case that context is useful.
> Do not cite it for current project status.

Two tracks exist side by side, per Part 15:
- **`src/` (faithful):** implements exactly what the paper states;
  documents every gap as evidence, changes nothing to force a match.
- **`paper_matching/` (deviation-permitted):** same core protocol,
  with every documented deviation listed in `paper_matching/README.md`,
  now extended this round with AID6LN rotation (Part 2) and ID6LC
  tests (Part 3).
- **`baseline_original_src/`, `baseline_original_pslae.spdl`:** frozen
  copies taken before this round's paper_matching/ edits, per Part 15.

---

## PART 1 — Paper-to-Code Traceability Table

| Paper section | Equation/Table | Requires | Code (faithful) | Code (paper_matching) | Status |
|---|---|---|---|---|---|
| 4.1 System model | Fig. 2 | 6LN/6LC entities, registration+AKE phases | src/entities.py | same, + rotation logic | MATCHED |
| 5.1 Step RP-1 | -- | ID6LN/ID6LC/R6LC/K6LN/K6LC selection | registration.py::register_sensor | same | MATCHED |
| 5.1 Step RP-2 | AID6LN=ID6LN xor K6LN xor K6LC, Mk=Ms xor H(R6LC), Sc | Identity/key derivation | registration.py | Mk derivation changed | MATCHED faithful; RECONSTRUCTED matching |
| 5.1 Step RP-3 | Storage lists | 6LN/6LC persistent storage | entities.py | field set reduced | MATCHED faithful (72/88B); RECONSTRUCTED (32/60B) |
| 5.1 Step RP-4 | X=Mk xor Sc, Si=(Nc,Kc) | ACE init state | registration.py::compute_Si | same | MATCHED |
| 5.1 Step RP-5 | Fr=Mk xor H(K6LN), AD | Associated data | registration.py::compute_AD | same (via derived mk) | MATCHED |
| 5.2 Step AKE1 | A,B,D,M1 | Message 1 construction | ake.py::step_ake1 | same | MATCHED |
| 5.2 Step AKE2 | Sc' check, T, Sc1, SK, M2 | Verification + message 2 | ake.py::step_ake2 | same + AID6LN rotation added | MATCHED faithful; MATCHED+ matching |
| 5.2 Step AKE3 | A1', T'/Sc1', SK' | Final verification | ake.py::step_ake3 | same + AID6LN rotation added | RECONSTRUCTED (ID6LC gap, both tracks) |
| 6.1 Prop. 1-11 | Informal security | 11 claimed properties | tests across tests/ | tests across paper_matching/tests/ | See Part 11 below |
| 6.2 SVO | IS1-IS5, X1-X3, G1 | Formal belief logic | docs/module_12_svo.md | svo/complete_svo_derivation.md | MATCHED G1; NOT IMPLEMENTED G2 (structurally undecidable) |
| 6.3 Scyther | Fig 7-9, 5 claims x2 roles | Formal verification | scyther/pslae.spdl | pslae_matching.spdl | FAIL Niagree/Nisynch (faithful); PASS (matching, deviated) |
| 7.1 Table 3 | Security comparison | Feature comparison vs. 3 protocols | N/A (paper-reported) | docs/table3_security_comparison.md | transcribed |
| 7.2 Table 4 | Computational cost | 2T_ACE+8T_SHA_1 | performance/overhead.py | overhead_matching.py | RECONSTRUCTED faithful (SHA1=8 after Issue4 fix); MATCHED matching |
| 7.3 Table 5 | Communication | 416/608/1024 | performance/overhead.py | overhead_matching.py | documented gap faithful (416/576/992); MATCHED matching |
| 7.4 Table 6 | Storage | 32/60 bytes | performance/overhead.py | overhead_matching.py | documented gap faithful (72/88B); MATCHED matching |
| 7.5 Discussion | Percentage reductions | 41-47%/14-24%/6-74% | N/A (paper-reported) | docs/table4-6_performance_comparison.md | transcribed |

---

## PART 6 — Computational Cost Trace (Complete)

| Operation | Protocol step | Call | Purpose |
|---|---|---|---|
| H(R6LC) | RP-2 (registration only, excluded from AKE-phase total per the paper's own "during AKE phases" scope) | 1 | Master key derivation |
| H(K6LN) (AKE1) | Step AKE1 | 1 | AD for M1's encryption |
| H(R6LC) (AKE2) | Step AKE2 | 1 | Re-derive Mk' |
| H(K6LN) (AKE2) | Step AKE2 | 1 | Re-derive AD' |
| H(ID6LC) | Step AKE2 | 1 | Derive Sc1 |
| H(...) -> SK | Step AKE2 | 1 | Session key |
| H(SK) -> M | Step AKE2 | 1 | Confirmation value |
| H(K6LN) (AKE3) | Step AKE3 | reused, not recomputed (Issue 4 fix) | AD'' |
| H(...) -> SK' | Step AKE3 | 1 | Session key (sensor) |
| H(SK') -> M' | Step AKE3 | 1 | Confirmation check |
| **AKE-phase total** | | **8** | matches paper exactly |

ACE calls: 1 encrypt (AKE1) + 1 decrypt + 1 encrypt (AKE2) + 1 decrypt
(AKE3) = 4 real invocations. See docs/issue5_ace_investigation.md for
the full counting-convention analysis; paper_matching/README.md
section 2 for how "2" is reported without removing any of the 4 real
calls.

---

## PART 11 — Security Property Mapping

| Property (Prop. #) | Paper claim | Mechanism | Test evidence |
|---|---|---|---|
| Mutual authentication (P1) | Both parties verify each other | Tag6LN/Tag6LC AEAD checks, D/Sc' checks | tests/test_ake_success.py, tamper-rejection tests |
| PFS (P2) | Past/future keys independent | RN1/RN2 fresh per session | test_fresh_random_numbers_differ_across_sessions |
| Anonymity/untraceability (P3) | AID6LN changes each session | No update equation in faithful protocol (confirmed gap) | test_documented_gap_D_is_linkable_across_sessions (faithful, demonstrates the gap) / test_rotation_closes_the_D_linkability_gap (paper_matching, demonstrates the fix) |
| Replay resistance (P4) | Timestamps + nonces | Delta-T freshness check | test_expired_m1/m2_timestamp_rejected |
| DoS resistance (P5) | Tag verification fails fast | AEAD tag check before further processing | test_modified_tag_rejected_by_controller |
| Impersonation resistance (P6) | Secret-dependent message construction | D, A, B derivation | test_modified_D_rejected_unknown_sensor |
| MITM resistance (P7) | AID6LN unguessability | AEAD + XOR-chain secrecy | Covered by Scyther Secret claim (both tracks) |
| ESL resistance (P8) | SK depends on long-term secret | SK=H(AID6LN,B1,Sc1,RN1,RN2) | Not independently testable at the Python level (requires formal/computational proof, correctly not claimed as experimentally proven) |
| Modification resistance (P9) | AEAD tag over full payload | Same as P1 | test_modified_ciphertext_rejected_by_controller, test_modified_a1_rejected_by_sensor |
| Compromise resistance (P10) | Per-sensor independent secrets | AID6LN=ID6LN xor K6LN xor K6LC (per-pair) | Not independently testable without a multi-sensor compromise simulation -- flagged as formally-claimed only |
| Desync resistance (P11) | Rotation is receiver-triggered | Sc->Sc1 rotation timing | test_two_consecutive_sessions_succeed_after_rotation |

**Properties P8 and P10 are explicitly NOT claimed as experimentally
proven** -- they are formal/cryptographic claims about the security
reduction, not something a Python-level test can meaningfully
demonstrate.

---

## PART 12 — Security Comparison Table (Table 3, transcribed from the paper)

| Feature | Esfahani et al. [9] | Lara et al. [24] | Suryakanta et al. (SLAP) [5] | PSLAE |
|---|---|---|---|---|
| Replay attack (Sf1) | YES | YES | YES | YES |
| ESL attack (Sf2) | NO | N/A | NO | YES |
| Traceability attack (Sf3) | NO | YES | NO | YES |
| Anonymity (Sf4) | NO | YES | YES | YES |
| PFS (Sf5) | NO | YES | NO | YES |
| Identity privacy preservation (Sf6) | NO | YES | NO | YES |
| Impersonation attack (Sf7) | YES | YES | YES | YES |
| DoS attack (Sf8) | NO | YES | NO | YES |
| MITM attack (Sf9) | YES | YES | YES | YES |
| Modification attack (Sf10) | YES | YES | YES | YES |
| Compromised attack (Sf11) | NO | NO | YES | YES |
| Desynchronization attacks (Sf12) | NO | YES | NO | YES |
| Mutual authentication (Sf13) | YES | YES | YES | YES |
| CK/eCK adversary model (Sf14) | NO | NO | NO | YES |

(Transcribed exactly as printed in the paper's Table 3 -- these are
the paper's own claims about itself and prior work, not independently
re-verified against Esfahani/Lara/SLAP's own source papers, which are
out of scope for this reproduction.)

---

## PART 13 — Performance Comparison (Tables 4-6, transcribed + our measurements)

| Metric | Esfahani [9] | Lara [24] | SLAP [5] | PSLAE (paper) | Our faithful measurement | Our paper_matching measurement |
|---|---|---|---|---:|---:|---:|
| Computational (ms) | 0.5754 | 0.7809 | 0.6987 | 0.411 | not independently re-benchmarked (paper's own Th/Te constants used) | same |
| Communication (bits) | 1280 | 1184 | 1280 | 1024 | 992 | 1024 |
| Storage, sensor (bytes) | 224 | 64 | 84 | 32 | 72 | 32 |
| Storage, controller (bytes) | 232 | 64 | 64 | 60 | 88 | 60 |

Paper's own claimed reductions (Sec 7.5, transcribed, not
recalculated against our own possibly-differing baseline): 41%/29%/47%
computational, 24%/24%/14% communication, 62%/86%/50% (sensor) and
6%/6%/74% (controller) storage reductions vs. Esfahani/Lara/SLAP
respectively.

---

## PART 16 — FINAL PAPER REPRODUCTION CHECKLIST

| Item | Faithful (src/) | paper_matching/ |
|---|---|---|
| System architecture | MATCHED | MATCHED |
| Entities | MATCHED | MATCHED (fields adjusted, documented) |
| Registration | MATCHED | RECONSTRUCTED (Mk derivation) |
| All registration equations | MATCHED | RECONSTRUCTED (Mk only) |
| AKE1 | MATCHED | MATCHED (T6C width changed in M2, not M1) |
| AKE2 | MATCHED | RECONSTRUCTED (T6C width, AID6LN rotation added) |
| AKE3 | RECONSTRUCTED (ID6LC gap) | RECONSTRUCTED (same gap + rotation) |
| Session-key derivation | MATCHED | MATCHED |
| AID6LN rotation | NOT IMPLEMENTED (no paper equation exists -- documented gap) | IMPLEMENTED (RECONSTRUCTED mechanism, tested) |
| ID6LC handling | RECONSTRUCTED (Sc1-from-decryption substitute) | RECONSTRUCTED (same substitute, dedicated tests added) |
| Security properties | MATCHED (9/11 testable; 2/11 formal-only) | MATCHED (same + rotation-dependent property improved) |
| Informal security analysis | MATCHED | MATCHED |
| SVO G1 | MATCHED | MATCHED |
| SVO G2 | ~~NOT IMPLEMENTED~~ **SUPERSEDED — see note at top of file; G2 was subsequently completed as a documented reconstruction (docs/svo/complete_svo_derivation.md)** | ~~NOT IMPLEMENTED~~ **SUPERSEDED, same** |
| Complete SVO derivation | documented (G1 + G2 non-derivability proof) | documented (svo/complete_svo_derivation.md) |
| Scyther model | MATCHED (faithful equations) | RECONSTRUCTED (timestamp-bound variant) |
| Secret | PASS | PASS |
| Alive | PASS | PASS |
| Weakagree | PASS | PASS |
| Niagree | FAIL (genuine, exhaustively investigated) | PASS (RECONSTRUCTED model) |
| Nisynch | FAIL (genuine, exhaustively investigated) | PASS (RECONSTRUCTED model) |
| SHA-1 = 8 | MATCHED (legitimate reuse, Issue 4) | MATCHED |
| ACE = 2 (paper's convention) | NOT REPRODUCED (4 real calls, documented) | MATCHED (convention change only, 4 real calls unchanged) |
| M1 = 416 bits | MATCHED | MATCHED |
| M2 = 608 bits | NOT REPRODUCED (576, documented) | MATCHED (RECONSTRUCTED, T6C widened) |
| M3(Total) = 1024 bits | NOT REPRODUCED (992, documented) | MATCHED |
| 6LN = 32 bytes | NOT REPRODUCED (72, documented) | MATCHED (RECONSTRUCTED, Mk derived not stored) |
| 6LC = 60 bytes | NOT REPRODUCED (88; 60 proven mathematically unreachable from real fields) | MATCHED (includes a 12-byte non-functional padding field, explicitly documented) |
| Computational cost | MATCHED | MATCHED |
| Communication overhead | documented gap | MATCHED |
| Storage overhead | documented gap (one proven impossible) | MATCHED |
| Security comparison | transcribed (Table 3) | transcribed (same) |
| Performance comparison | transcribed (Tables 4-6) | transcribed (same) |
| Final end-to-end execution | tests/ full suite (21/21) | end_to_end_demo.py + tests/ (8/8) |

**29/29 tests pass across both tracks combined (confirmed this round,
live run).**

---

## What genuinely cannot be reproduced, and exactly why (not merely "paper error")

- **SVO G2**: ~~proven non-derivable in BOTH tracks~~ **SUPERSEDED —
  this was true at the time this file was written, but the following
  round's ID6LC/AKE3 reconstruction changed the underlying mechanism
  (Mk derived from Sc/K6LN instead of Ms/R6LC), which makes IS5' true
  rather than false for the reconstructed track. G2 has since been
  completed there. Only the faithful (non-reconstructed) protocol's
  G2 remains non-derivable, correctly. See docs/svo/complete_svo_derivation.md.**
- **The faithful Niagree/Nisynch, ACE=2, M2=608/Total=1024, and
  6LN/6LC storage figures**: each requires either deleting a real
  security operation or contradicting an explicit paper statement --
  correctly NOT done in src/, and done with full disclosure in
  paper_matching/.
- **6LC = 60 bytes specifically**: even in paper_matching/, hitting
  this number required a 12-byte field with literally no function --
  the honest conclusion is that 60 bytes is not achievable through any
  principled reconstruction, only through deliberate padding to the
  target.
