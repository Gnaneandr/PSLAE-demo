# Module 11 — Scyther Configurations

**1. Purpose:** Reproduce the paper's three distinct Scyther
verification configurations (Figs. 7, 8, 9), not just one run.

**2. What the paper says (Section 6.3):**

| | Config 1 (Fig. 7) | Config 2 (Fig. 8) | Config 3 (Fig. 9) |
|---|---|---|---|
| Max runs | 50 | 100 | 100 |
| Matching type | typed matching | typed matching | (not restated) |
| Patterns/claim | 100 | 100 | 85 |
| Search pruning | find best attack | find all attacks | find all attacks |
| Graph output (pt) | 32 | 32 | 32 |

**3. What we implemented:** Three real, executed runs against the actual
compiled `scyther-linux` binary (Module 10), using the closest available
CLI-exposed equivalents:

| | Our Config 1 | Our Config 2 | Our Config 3 |
|---|---|---|---|
| Command | `-r 50 -m 0` | `-r 100 -m 0 -A` | `-r 100 -m 0 -A --max-of-role=3` |
| Max runs | 50 | 100 | 100 |
| Matching type | `-m 0` = typed matching (no type-flaws) | same | same |
| Search pruning | default = find-best-attack | `-A` = find-all-attacks | `-A` = find-all-attacks |
| Patterns/claim | **not exposed by this CLI backend** | **not exposed** | **not exposed** |
| Graph output | N/A (no GUI in this environment) | N/A | N/A |

**Honest limitation:** the rebuilt, modern Scyther CLI backend
(`scyther-linux`, built in Module 10) does not expose a "patterns per
claim" flag — this appears to be a GUI-only bounded-search display
parameter belonging to the legacy Python2/wxPython GUI described in the
paper's own stated environment (Section 6.3: "Scyther 1.1.3, Graphviz
2.46, Python 2.7, and wxPython 2.8"), not the C backend we actually
built and ran. Rather than inventing a flag that doesn't exist in our
build, Configurations 2 and 3 are run with the same CLI flags
(differentiated only by `--max-of-role`, a real, meaningful bound
difference we substituted to make the third run genuinely distinct
rather than a no-op repeat of Config 2).

**4. Files involved:**
`results/scyther/config1_output.txt`,
`results/scyther/config2_output.txt`,
`results/scyther/config3_output.txt` (all real, captured `stdout` from
actual tool invocations, not hand-written).

**5-7. Input/Processing/Output:** SPDL model in; per-configuration
claim-status table out.

**8. How to run it:**
```bash
cd scyther
scyther-linux -r 50  -m 0                       pslae.spdl   # Config 1
scyther-linux -r 100 -m 0 -A                      pslae.spdl   # Config 2
scyther-linux -r 100 -m 0 -A --max-of-role=3      pslae.spdl   # Config 3
```

**9. Expected result:** all three configurations produce the same
Ok/Fail pattern reported in Module 10 (Secret/Alive/Weakagree Ok;
Niagree/Nisynch Fail) — the claim-status pattern is stable across all
three bound settings we tested, which is itself informative (it means
the Niagree/Nisynch counterexample is not an artifact of a specific
narrow bound). This stability across configurations was itself one of
the pieces of evidence used in Module 10's systematic investigation
(ruling out "just need different bounds" as the explanation).

**Scyther version note:** the paper's stated environment is Scyther
1.1.3; we use a modern rebuild from the current `cascremers/scyther`
GitHub source (no way to obtain and build the historical 1.1.3 release
in this environment — see main `README.md`). This is a genuine,
acknowledged variable in comparing our results to the paper's; Module 10
discusses exactly how much of the Niagree/Nisynch finding can and cannot
be attributed to this version difference.

**10. How to verify it is correct:** re-run the three commands; compare
against the saved logs.

**11. Paper ambiguity:** the "patterns per claim" GUI parameter cannot
be reproduced with the CLI backend available in this environment — see
`docs/paper_ambiguities.md` #16.

**12. Status:** **COMPLETED** (three genuinely distinct, executed
configurations) / **NOT FULLY REPRODUCIBLE** for the "patterns per
claim" GUI parameter specifically (documented, not silently dropped).
