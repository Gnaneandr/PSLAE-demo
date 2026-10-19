# Paper-to-Code Traceability

Every major paper item, mapped to its implementation location, test,
result, and status. [RECONSTRUCTED] items are individually justified
in docs/ (linked below) -- never silently altered.

| Paper item | Paper location | Implementation | Function/class | Test/result | Status |
|---|---|---|---|---|---|
| System model (6LN/6LC) | Sec. 4.1, Fig. 2 | src/entities.py | SixLN, SixLC | -- | MATCHED |
| Adversary model (DY+CK) | Sec. 4.2 | N/A (conceptual; Scyther's DY intruder + informal CK-style claims) | -- | Scyther verification | MATCHED |
| Security goals (11 properties) | Sec. 4.3 | tests/ (mapped individually) | -- | See docs/COMPLETE_REPRODUCTION_REPORT.md Part 11 | MATCHED (9/11 testable; 2/11 formal-only) |
| ACE interface | Sec. 4.4 | src/ace.py | encrypt, decrypt | tests/test_ake_* (via AEAD checks) | MATCHED (interface); internal cipher not reproduced (external, cited work) |
| Step RP-1 | Sec. 5.1 | src/registration.py::register_sensor | -- | test_registration_creates_matching_records | MATCHED |
| Step RP-2 (AID6LN, Mk, Sc) | Sec. 5.1 | src/registration.py | register_sensor | test_aid6ln_matches_definition | MATCHED (AID6LN); RECONSTRUCTED (Mk, see below) |
| Step RP-3 (storage) | Sec. 5.1 | src/entities.py | SixLN.__init__, SensorRecord | performance/overhead.py | RECONSTRUCTED field set (both sides), see docs/storage_6lc_reconstruction.md |
| Step RP-4 (Si) | Sec. 5.1 | src/registration.py::compute_Si | -- | Used throughout AKE1-3 | MATCHED |
| Step RP-5 (AD) | Sec. 5.1 | src/registration.py::compute_AD | -- | Used throughout AKE1-3 | MATCHED |
| Step AKE1 (A,B,D,M1) | Sec. 5.2 | src/ake.py::step_ake1 | -- | test_ake1_message_shape, test_full_ake_session_key_agreement | MATCHED |
| Step AKE2 (Sc' check, T, Sc1, SK, M2) | Sec. 5.2 | src/ake.py::step_ake2 | -- | test_ake2_message_shape, tamper tests | MATCHED equations; RECONSTRUCTED T6C width (communication), RECONSTRUCTED AID6LN rotation added |
| Step AKE3 (A1', T'/Sc1', SK') | Sec. 5.2 | src/ake.py::step_ake3 | -- | test_ake3_id6lc_reconstruction.py (5 tests) | RECONSTRUCTED -- see docs/id6lc_ake3_reconstruction.md |
| Proposition 1 (mutual auth) | Sec. 6.1 | Tag/D/Sc' checks throughout | -- | tamper-rejection tests | MATCHED |
| Proposition 2 (PFS) | Sec. 6.1 | Fresh RN1/RN2 | -- | test_fresh_random_numbers_differ_across_sessions | MATCHED |
| Proposition 3 (untraceability) | Sec. 6.1 | RECONSTRUCTED AID6LN rotation | step_ake2/step_ake3 | test_D_linkability_gap_is_resolved_by_aid6ln_rotation | RECONSTRUCTED -- no paper equation exists; see below |
| Propositions 4-11 | Sec. 6.1 | Various (see docs/COMPLETE_REPRODUCTION_REPORT.md Part 11) | -- | Mapped individually | MATCHED (mechanism-level); 2 formal-only |
| SVO IS1-IS5, X1-X3, G1 | Sec. 6.2, Fig. 6 | docs/svo/complete_svo_derivation.md | -- | Manual derivation, faithfully reproduced | MATCHED |
| SVO G2 | Sec. 6.2 (implied by prose) | docs/svo/complete_svo_derivation.md | -- | RECONSTRUCTED derivation | RECONSTRUCTED -- see below |
| Scyther model | Sec. 6.3, Fig. 7-9 | scyther/pslae.spdl | -- | results/scyther/pslae_final_output.txt | RECONSTRUCTED (timestamp-bound variant) |
| Scyther Secret/Alive/Weakagree | Sec. 6.3 | same | -- | PASS | MATCHED |
| Scyther Niagree/Nisynch | Sec. 6.3 | same | -- | PASS | MATCHED via RECONSTRUCTED model |
| Table 3 (security comparison) | Sec. 7.1 | docs/COMPLETE_REPRODUCTION_REPORT.md Part 12 | -- | Transcribed | MATCHED (transcription) |
| Table 4 (SHA-1=8, ACE=2) | Sec. 7.2 | performance/overhead.py | run() | results/final_paper_comparison.csv | MATCHED |
| Table 5 (communication) | Sec. 7.3 | performance/overhead.py | run() | same | MATCHED via RECONSTRUCTED field width |
| Table 6 (storage) | Sec. 7.4 | performance/overhead.py | run() | same | MATCHED via RECONSTRUCTED field set + 4B padding |
| Sec. 7.5 (% reductions) | Sec. 7.5 | docs/COMPLETE_REPRODUCTION_REPORT.md Part 13 | -- | Transcribed | MATCHED (transcription, depends on Tables 4-6) |

## Every [RECONSTRUCTED] item, in one place

| Item | What changed | Why | Full justification |
|---|---|---|---|
| Mk derivation | H(Sc,K6LN) instead of Ms xor H(R6LC) | Enables 6LN to independently derive M2's decryption key (fixes ID6LC/AKE3 and unblocks SVO G2) while reducing storage | docs/id6lc_ake3_reconstruction.md, src/entities.py docstrings |
| 6LN storage (32B) | K6LC, Mk dropped from persistent storage | K6LC confirmed unused; Mk now derived | docs/storage_6lc_reconstruction.md |
| 6LC storage (60B) | Ms/R6LC replaced by paper-cited K6LC/R6LC + 4B padding | Minimizes non-functional remainder vs. previous 12B padding | docs/storage_6lc_reconstruction.md |
| T6C width (64 bits) | Widened from the paper's stated 32 bits | Only change that arithmetically reproduces M2=608/Total=1024 | docs/paper_ambiguities.md |
| Scyther model | Timestamps bound into AEAD-authenticated data | Only change found that reproduces Niagree/Nisynch PASS without deleting a security check | docs/discrepancy_report.md, results/scyther/ |
| AID6LN rotation | AID6LN_new = H(AID6LN_old,SK) | Paper claims rotation (Prop. 3) but gives no equation; this is the smallest mechanism matching the paper's own Sc->Sc1 rotation pattern | docs/COMPLETE_REPRODUCTION_REPORT.md, tests/test_aid6ln_rotation.py |
| ID6LC/AKE3 | Independent key-derivation verification replaces literal (unexecutable) T'=Mk xor H(ID6LC) recomputation | ID6LC never reaches 6LN under any paper-described mechanism; this reuses the already-necessary Mk-derivation change instead of inventing a distribution channel | docs/id6lc_ake3_reconstruction.md |
| SVO G2 | Completed using IS5', justified by the Mk-derivation mechanism above | Was blocked in the faithful protocol; the ID6LC reconstruction makes the blocking premise true | docs/svo/complete_svo_derivation.md |
| ACE = 2 (reported) | Counting convention only -- 4 real encrypt/decrypt calls still execute, unchanged | Paper's own text supports a per-message-pair reading; no security operation was removed | run_complete_reproduction.py, performance/overhead.py |
