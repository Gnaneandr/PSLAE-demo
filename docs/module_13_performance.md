# Module 13 — Performance Evaluation

**1. Purpose:** Reproduce the paper's Tables 4 (computational), 5
(communication), 6 (storage) overhead figures as far as this
implementation genuinely allows, comparing our own measured numbers
against the paper's published numbers — without inventing any numbers.

**2. What the paper says:** Section 7.2 (Table 4): PSLAE = `2·T_ACE +
8·T_SHA_1` ≈ 0.411 ms, vs. 14/19/17 `T_SHA_1` for the three related
schemes. Section 7.3 (Table 5): PSLAE = 416 + 608 = 1024 bits total.
Section 7.4 (Table 6): PSLAE = 32 bytes (sensor) / 60 bytes (controller).

**3. What we implemented:** `performance/overhead.py` — computes all
three metrics **by direct inspection of this repository's own
implementation** (counting real function calls in `src/ake.py`, and
measuring the real byte-lengths of M1/M2 and stored fields from an
actual, live run), not by copying the paper's numbers.

**Real, executed results (see `results/performance/overhead_report.txt`
and `results/performance/final_comparison_output.txt`):**

| Metric | Paper claim | Our reproduced result | Match? |
|---|---|---|---|
| Computational (`T_SHA_1`, `T_ACE`) | 8, 2 | 9, 4 | **No** |
| Communication 6LN→6LC (bits) | 416 | 416 | **Yes** |
| Communication 6LC→6LN (bits) | 608 | 576 | **No** |
| Communication total (bits) | 1024 | 992 | **No** |
| Storage 6LN (bytes) | 32 | 72 | **No** |
| Storage 6LC (literal Step RP-3 fields only, bytes) | 60 | 32 | **No** |

**Why the mismatches — explained, not hidden:**

- **Computational (9 vs 8 `T_SHA_1`; 4 vs 2 `T_ACE`):** our
  reconstruction recomputes `AD` independently at every one of the three
  AKE steps (as the paper's own Step RP-5 formula requires each time
  `Si`/`AD` are needed — see Module 1), which the paper's own claimed
  count of "eight `T_SHA_1`" does not appear to fully itemize (the paper
  gives the final number without showing its own per-step breakdown, so
  we cannot verify how the authors arrived at exactly 8 vs. our
  traceable, step-by-step 9). `T_ACE` differs because we count
  encrypt/decrypt as separate ACE invocations (1 encrypt in AKE1, 1
  decrypt + 1 encrypt in AKE2, 1 decrypt in AKE3 = 4 total), while the
  paper's "2" suggests it may be counting only 1 ACE operation per
  *message* rather than per encrypt/decrypt call — this is a genuine,
  documented interpretation difference, not an error we could silently
  resolve without inventing which convention the authors used.
- **Communication 6LC→6LN (576 vs 608 bits):** our field-by-field
  breakdown (`T6C`=32, `A1`=64, `M`=160, `CT1`=128, `Tag6LC`=128,
  `RN2`=64 → 576 total) uses the paper's own declared field widths
  exactly. 608 − 576 = 32 bits, exactly one `T6C`-timestamp's worth —
  suggesting the paper's Table 5 may double-count a field, but we do not
  assert this with certainty; we simply report our field-by-field sum
  transparently (see `overhead_report.txt`) so the discrepancy is fully
  auditable.
- **Storage (72 vs 32 bytes for 6LN; 32 vs 60 for 6LC-literal-fields):**
  our 6LN storage sums Step RP-3's literal 6-field list
  `{TID6LC(8)+Sc(8)+K6LN(8)+K6LC(8)+AID6LN(8)+Mk(32)} = 72 bytes` — the
  paper's claimed 32 bytes cannot include all six fields at the widths
  the paper itself declares elsewhere (`Mk` alone is 256 bits = 32 bytes
  under our Module-1 reconstruction of the paper's own "265-bit" figure
  — see ambiguity #1). This strongly suggests the paper's Table 6
  entries reflect either a different (undisclosed) field-width
  convention or an unpublished optimization, not something reproducible
  from the text alone.

**We did not adjust any implementation choice to force a match with
Table 4/5/6.** All numbers above come from the same `src/registration.py`
/ `src/ake.py` code exercised by Modules 2-6 and Module 7's passing
tests — changing them to match the paper's tables would mean changing
the protocol logic itself, which the task instructions explicitly
prohibit.

**4. Files involved:** `performance/overhead.py`,
`performance/final_comparison.py`.

**5. Input:** None (each run generates its own fresh registration/AKE
session).

**6. Processing:** live protocol execution + static counting of
operations in the source.

**7. Output:** printed report + `results/performance/*.txt`.

**8. How to run it:**
```bash
python -m performance.overhead
python -m performance.final_comparison
```

**9. Expected result:** the table above, reproduced exactly (values are
deterministic given the field-width constants; only the random
key/nonce *values* differ run to run, not their lengths/counts).

**10. How to verify it is correct:** re-run the commands; every number
is computed from a real function call, auditable in
`performance/overhead.py`'s source.

**11. Paper ambiguity:** see the "why the mismatches" analysis above,
and `docs/paper_ambiguities.md` #14.

**12. Status:** **COMPLETED and VERIFIED** (numbers genuinely computed
and cross-checked) / **DISCREPANCIES DOCUMENTED, NOT RECONCILED**
(paper's own numbers are not fully reproducible from its text alone).
