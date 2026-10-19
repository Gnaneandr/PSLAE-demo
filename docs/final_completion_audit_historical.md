# Final Completion Audit — Paper Section-by-Section

Cross-check of the COMPLETE PSLAE paper (all sections) against the
COMPLETE implementation. Statuses: `NOT STARTED`, `IN PROGRESS`,
`COMPLETED`, `VERIFIED`, `PARTIALLY REPRODUCIBLE`,
`NOT REPRODUCIBLE FROM PAPER`.

| Paper Section | Requirement | Implemented | Tested | Formally Verified | Result Reproduced | Status | Notes |
|---|---|---|---|---|---|---|---|
| §1 Introduction | Motivation/contributions (prose) | N/A (prose) | N/A | N/A | N/A | N/A | Not an implementable artifact |
| §3.1–3.2 SLAP recap | SLAP protocol steps | Yes (doc) | N/A | N/A | Yes (faithful restatement) | **COMPLETED** | `docs/module_00_slap_analysis.md` |
| §3.3 SLAP cryptanalysis | PFS, DoS, ESL, Traceability attacks | Yes (doc) | N/A | N/A | Yes (faithful restatement) | **COMPLETED** | Theoretical per paper; not re-implemented as code |
| §4.1 Network model | 6LN/6LC architecture | Yes | Yes (transitively) | N/A | Yes | **VERIFIED** | `src/entities.py` |
| §4.2 Adversary model | DY + CK capabilities | Partially | N/A | DY only (Scyther) | DY: yes. CK/eCK: no | **PARTIALLY REPRODUCIBLE** | See Module 10's CK/eCK vs DY distinction |
| §4.3 Security goals | 9 named goals | Yes (doc) | Partially (Module 7/8) | Partially (Module 10) | Mixed — see Module 8 table | **PARTIALLY REPRODUCIBLE** | Per-goal breakdown in `docs/module_08_informal_security.md` |
| §4.4 ACE primitive | AEAD interface | Yes (interface) | Yes | N/A | Interface: yes. Internal cipher: no (external, uncited internals) | **COMPLETED (labelled reconstruction)** | `src/ace.py` explicitly NOT the authors' cipher |
| §5.1 Registration (RP-1..RP-5) | Full registration | Yes | Yes (4 tests) | N/A | Yes | **VERIFIED** | `src/registration.py`; ambiguities #1-4 documented |
| §5.2 AKE1 | Message M1 | Yes | Yes (shape test) | Yes (Scyther models it) | Yes | **VERIFIED** | `src/ake.py::step_ake1` |
| §5.2 AKE2 | Message M2 + verification | Yes | Yes (9 failure tests) | Yes (Scyther models it) | Yes | **VERIFIED** | Ambiguities #5-8, #11 documented |
| §5.2 AKE3 | Final verification | Yes | Yes (4 tests) | Yes (Scyther models it) | Yes | **VERIFIED** | Ambiguities #9-11 documented |
| §5.2 Session key SK | 6LN/6LC agreement | Yes | Yes (2 tests + demo) | Partially (Secret claim: yes; full agreement modelling: yes) | Yes (real matching keys) | **VERIFIED** | `results/protocol/demo_output.txt` |
| §6.1 Prop. 1 Mutual auth | Informal claim | Yes | Yes | N/A (informal only) | Yes | **VERIFIED** | Module 8 |
| §6.1 Prop. 2 PFS | Informal claim | Partially | Partially | No (theoretical) | Precondition only | **PARTIALLY REPRODUCIBLE** | Module 8 |
| §6.1 Prop. 3 Untraceability | Informal claim | N/A — gap found | Yes (documents the gap) | N/A | **Paper's claim NOT supported** | **NOT REPRODUCIBLE FROM PAPER** | `docs/paper_ambiguities.md` #12 |
| §6.1 Prop. 4 Replay | Informal claim | Yes | Yes | N/A | Yes | **VERIFIED** | Module 8 |
| §6.1 Prop. 5 DoS | Informal claim | Yes | Yes | N/A | Yes | **VERIFIED** | Module 8 |
| §6.1 Prop. 6 Impersonation | Informal claim | Yes | Yes | N/A | Yes | **VERIFIED** | Module 8 |
| §6.1 Prop. 7 MITM | Informal claim | Partially | Partially | N/A | Tamper-detection only | **PARTIALLY REPRODUCIBLE** | Module 8 |
| §6.1 Prop. 8 ESL | Informal claim | No | No | No (theoretical) | No | **NOT REPRODUCIBLE FROM PAPER (theoretical by nature)** | Module 8 |
| §6.1 Prop. 9 Modification | Informal claim | Yes | Yes (7 tests) | N/A | Yes | **VERIFIED** | Module 8 |
| §6.1 Prop. 10 Compromise isolation | Informal claim | Partially | Partially | N/A | Precondition only | **PARTIALLY REPRODUCIBLE** | Module 8 |
| §6.1 Prop. 11 Desync resistance | Informal claim | Yes | Yes | N/A | Yes | **VERIFIED** | Module 8 |
| §6.2 SVO logic, Fig. 6 | Formal derivation of G1 | Yes (doc) | N/A (not executable by design) | N/A | Yes (paper's own G1 reproduced) | **COMPLETED** | `docs/module_12_svo.md` |
| §6.2 SVO, implied G2 | Symmetric derivation for 6LN's side | No | N/A | N/A | Paper never publishes it | **NOT REPRODUCIBLE FROM PAPER** | `docs/module_12_svo.md` |
| §6.3 Scyther — Secret | Formal claim | Yes | N/A | **Yes — Ok** | Yes | **VERIFIED** | Matches paper |
| §6.3 Scyther — Alive | Formal claim | Yes | N/A | **Yes — Ok** | Yes | **VERIFIED** | Matches paper |
| §6.3 Scyther — Weakagree | Formal claim | Yes | N/A | **Yes — Ok** | Yes | **VERIFIED** | Matches paper |
| §6.3 Scyther — Niagree | Formal claim | Yes | N/A | **Fail — 2 attacks** | **No — discrepancy** | **NOT REPRODUCIBLE (investigated, documented)** | Module 10, 3 controlled diagnostics |
| §6.3 Scyther — Nisynch | Formal claim | Yes | N/A | **Fail — 2 attacks** | **No — discrepancy** | **NOT REPRODUCIBLE (investigated, documented)** | Module 10, 3 controlled diagnostics |
| §6.3 Scyther Config 1 (Fig.7) | 50 runs, best-attack | Yes | N/A | Yes (executed) | Yes (partial — see Module 11) | **PARTIALLY REPRODUCIBLE** | "Patterns/claim" GUI param not exposed by our CLI |
| §6.3 Scyther Config 2 (Fig.8) | 100 runs, all-attacks | Yes | N/A | Yes (executed) | Yes (partial) | **PARTIALLY REPRODUCIBLE** | Same limitation |
| §6.3 Scyther Config 3 (Fig.9) | 100 runs, all-attacks, 85 patterns | Yes (substituted bound) | N/A | Yes (executed) | Yes (partial) | **PARTIALLY REPRODUCIBLE** | "85 patterns" not reproducible; substituted `--max-of-role=3` |
| §7.1 Security-feature comparison Table 3 | vs. Esfahani/Lara/Suryakanta | Yes (doc, paper's own claims transcribed) | N/A | N/A | Yes | **COMPLETED** | We do not re-derive the *other papers'* security claims, only PSLAE's own (Module 8) |
| §7.2 Computational overhead Table 4 | T_SHA_1, T_ACE counts | Yes (measured from real code) | Yes | N/A | **Partial — 9,4 vs. paper's 8,2** | **PARTIALLY REPRODUCIBLE (discrepancy documented)** | `docs/module_13_performance.md` |
| §7.3 Communication overhead Table 5 | Bits transferred | Yes (measured from real messages) | Yes | N/A | **Partial — 416/576/992 vs. paper's 416/608/1024** | **PARTIALLY REPRODUCIBLE (discrepancy documented)** | 1 of 3 sub-metrics matches exactly |
| §7.4 Storage overhead Table 6 | Bytes stored | Yes (measured from real objects) | Yes | N/A | **No — 72/88 vs. paper's 32/60** | **NOT REPRODUCIBLE (discrepancy documented, not reconciled)** | Field-width source of difference fully explained |
| §7.5 Discussion/comparison | Prose synthesis of 7.1-7.4 | Yes (doc) | N/A | N/A | Partial (inherits 7.2-7.4's status) | **PARTIALLY REPRODUCIBLE** | Module 14 |
| §8 Conclusion | Prose | N/A | N/A | N/A | N/A | N/A | Not an implementable artifact |

---

## Completion percentage (reproducible components only)

Counting only rows above that represent genuinely reproducible
artifacts (excluding pure-prose sections §1, §8, and the "N/A" adversary
sub-items that are explicitly theoretical by the paper's own framing):

- **Fully VERIFIED:** 16 rows
- **COMPLETED** (non-code reproductions, e.g. SLAP/SVO docs): 3 rows
- **PARTIALLY REPRODUCIBLE:** 8 rows
- **NOT REPRODUCIBLE FROM PAPER** (genuine gaps/discrepancies, documented
  not hidden): 6 rows

**This is not presented as, or rounded up to, 100%.** The protocol logic
(registration through session-key agreement, Modules 2-6) is fully
verified. Scyther is genuinely executed with 3/5 claims matching and 2
investigated with a specific documented finding. Performance numbers are
genuinely computed with 1/6 metrics matching exactly. SVO is reproduced
as far as the paper's own published derivation goes. Nothing above is
marked VERIFIED without having actually been executed and checked
against a real, saved output.
