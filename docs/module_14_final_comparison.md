# Module 14 — Final Paper Reproduction / Comparison

**1. Purpose:** A single, final module that pulls together every
reproducible result from Modules 1-12 into one paper-claim-vs-reproduced
comparison, so the whole reproduction can be reviewed in one place.

**2. What the paper says:** Claims scattered across Sections 6 and 7
(security properties, Scyther claims, and Tables 4-6).

**3. What we implemented:** `performance/final_comparison.py` — imports
real results from `performance/overhead.py` (Module 12) and reports
protocol-correctness and Scyther results (Modules 7, 9) alongside them,
printing one consolidated table split into three parts: [A] Protocol
correctness, [B] Scyther formal verification, [C] Performance
evaluation. Nothing in its output is hand-typed; every "Reproduced"
value is computed live by function calls into `src/`/`performance/`
except the Scyther rows, which report the real results already captured
in `results/scyther/` (re-running Scyther on every invocation of this
script would be slow and isn't necessary since Module 9 already produced
deterministic, saved results).

**4. Files involved:** `performance/final_comparison.py`.

**5-7. Input/Processing/Output:** none / live execution / printed +
saved comparison table.

**8. How to run it:**
```bash
python -m performance.final_comparison
```

**9. Expected result:** see
`results/performance/final_comparison_output.txt` for the real captured
run. Summary:

- **Protocol correctness:** fully reproduced and verified (21/21 tests,
  matching session keys) except the `AID6LN`-rotation/untraceability
  claim, which is a documented gap (ambiguity #12), not reproduced,
  because the paper's own protocol steps don't implement it.
- **Scyther:** `Secret`/`Alive`/`Weakagree` reproduced matching the
  paper (Ok on all). `Niagree`/`Nisynch`: **discrepancy** — paper claims
  Ok, our reconstruction finds Fail, investigated and documented in
  Module 9, most likely attributable to the XOR-abstraction modelling
  technique rather than a newly-discovered protocol break, but this is
  not asserted with certainty.
- **Performance:** 1 of 6 measured metrics matches exactly
  (communication 6LN→6LC = 416 bits); the other 5 diverge from the
  paper's published numbers, each with a specific, documented technical
  explanation in Module 12 (none silently forced to match).

**10. How to verify it is correct:** re-run the command; cross-check
each row against the individual module docs (1-12) and their own saved
evidence files.

**11. Paper ambiguity:** aggregates all of `docs/paper_ambiguities.md`.

**12. Status:** **COMPLETED**. This module's own output is fully
reproducible and auditable; whether each *individual* paper claim is
"VERIFIED" or "NOT REPRODUCIBLE FROM PAPER" is tracked precisely in
`docs/completion_checklist.md`, not glossed over here.
