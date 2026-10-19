# Module 10 — Scyther Formal Verification (ACTUALLY EXECUTED)

**1. Purpose:** Actually run `scyther/pslae.spdl` through a real, locally
built Scyther binary and record genuine output. Investigate the
Niagree/Nisynch failures systematically rather than accepting or hiding
them.

**2. What the paper says:** Section 6.3 reports all 5 claim types
(`Secret`, `Alive`, `Weakagree`, `Nisynch`, `Niagree`) as "Ok / Verified
/ No attacks" across three parameter configurations. The paper does not
publish its own `.spdl` source.

**3. Real result** (`scyther/bin/scyther-linux -r 100 -m 0 -A pslae.spdl`):

| Claim | SixLN | SixLC | Paper |
|---|---|---|---|
| Secret (SK) | Ok | Ok | Ok |
| Alive | Ok | Ok | Ok |
| Weakagree | Ok | Ok | Ok |
| Niagree | **Fail — exactly 2 attacks** | **Fail — exactly 2 attacks** | Ok |
| Nisynch | **Fail — exactly 2 attacks** | **Fail — exactly 2 attacks** | Ok |

Raw logs: `results/scyther/config1_output.txt`,
`config2_output.txt`, `config3_output.txt`.

---

## 4. Systematic investigation (per the required checklist)

**(1) Is the SPDL model faithful to the paper?** Yes, field-for-field
against `src/ake.py`'s implementation, which itself is checked against
the paper's formulas (see `docs/module_09_spdl.md`).

**(2) Is any message missing?** No — PSLAE is a 2-message protocol
(`M1`, `M2`); both are modelled.

**(3) Is any send/receive event represented incorrectly?** Checked
field-by-field against `src/ake.py`; no discrepancy found.

**(4) Are the claims attached to the correct role?** Yes — `claim_i*` on
`SixLN`, `claim_r*` on `SixLC`, matching Section 6.3's report of claims
on both roles.

**(5) Are variables bound correctly?** Yes — every `var` in one role is
bound via the matching `recv_` pattern; every `fresh` is genuinely fresh
per run.

**(6) Are cryptographic abstractions correct?** The `xorf`/`hAid`/etc.
abstractions are structurally consistent (see Module 9), but see finding
below — this turned out to be the wrong place to keep looking.

**(7) Is the paper's message numbering ambiguous?** No.

**(8) Is there an inconsistency in the published protocol?** Yes, several
(`docs/paper_ambiguities.md`), but none of the previously-documented
ones directly explain Niagree/Nisynch on their own (they are formula-choice
ambiguities, not structural message-design gaps).

**(9) Is the Scyther version different?** Yes — we use a modern rebuild
from `github.com/cascremers/scyther`'s current source, not the paper's
stated Scyther 1.1.3. This remains a residual, unquantifiable variable
(see "What we cannot fully rule out" below) — but see finding below,
which explains the result independently of version differences.

**(10) Are the verification settings different?** We used `-r 100 -m 0
-A` (100 runs, typed matching, find-all-attacks); the paper's GUI-only
"patterns per claim" setting isn't exposed by our CLI build (Module 11).
Re-tested at multiple bounds (`-r 50`, `-r 100`, `--max-of-role=1`,
`--max-of-role=3`) — **the Ok/Fail pattern is stable across all of
them**, ruling out "just need a bigger/smaller bound" as the explanation.

**(11) Is the issue caused by our reconstructed SPDL rather than PSLAE
itself?** This is the key question. **Three controlled diagnostic
experiments were run** (not just inspection) to isolate the actual
cause, saved in `results/scyther/diagnostics/`:

### Diagnostic A — sanity check: can Niagree/Nisynch hold at all for a 2-message protocol in this Scyther build?

A minimal, plain (non-XOR, textbook-style) 2-message challenge-response
protocol (`minimal2msg.spdl`) was built and run: `I` sends a nonce `Ni`
plus `{Ni}k(I,R)`; `R` replies with `Nr` plus `{Ni,Nr}k(I,R)`; both
roles claim `Niagree`/`Nisynch` immediately after their own final
protocol event (mirroring PSLAE's claim placement exactly, including
`R`'s claim right after its own final `send`, with no further round
trip — the same placement as PSLAE's `SixLC`).

**Result: Niagree and Nisynch both hold (Ok) for both roles.** This
conclusively rules out two candidate explanations: (a) that 2-message
protocols with the responder claiming immediately after its final send
can *never* satisfy Niagree/Nisynch in this Scyther build (the "last
message problem" hypothesis), and (b) that this specific rebuilt Scyther
binary/version cannot prove these claims at all for short protocols.

### Diagnostic B — isolating PSLAE's actual structural difference from Diagnostic A

Diagnostic A's message 2 re-includes `Ni` (message 1's nonce) **inside**
its own encrypted payload (`{Ni,Nr}k(I,R)`), cryptographically binding
the two messages together. **PSLAE's own M2 does not do this**: per
Section 5.2, `M2 = (T6C || A1 || M || (CT1||Tag6LC) || RN2)`, and the
encrypted part, `CT1`, only contains `(Sc1||RN2)` — **`RN1` is never
re-included inside any encrypted/authenticated payload in M2.** `RN1`'s
only binding to M2 is via `A1 = B1 ⊕ RN1`, sent as a **plaintext** field,
**outside** the ACE-protected `CT1||Tag6LC` container.

A second minimal protocol (`minimal2msg_v2.spdl`) was built, changing
**exactly this one variable**: message 2's encrypted part no longer
contains `Ni`; instead, binding to `Ni` is expressed only via a
plaintext hash-commitment field sent alongside the encryption (directly
mirroring PSLAE's plaintext `A1` field, and also mirroring PSLAE's
plaintext `M = H(SK)` confirmation field — both send-in-the-clear
values that are hash/XOR functions of earlier nonces without
cryptographically embedding them).

**Result: Niagree and Nisynch both FAIL for both roles** — the same
Ok/Fail pattern PSLAE itself exhibits.

### Diagnostic C — ruling out key reuse across the two message directions

PSLAE's own Step AKE2 text implies the same initialization state
(`Si`) encrypts both directions (our Reconstruction #5,
`Si''=Si'`). To check whether this reuse — not the missing-nonce-binding
finding above — was the actual cause, the model was modified to use a
**distinct** key for M2's encryption and re-run.

**Result: Niagree and Nisynch still FAIL, identically ("exactly 2
attacks").** This rules out key-reuse-across-directions as the cause.

### Conclusion

The balance of evidence from these three controlled experiments points
to a specific, identifiable structural property: **PSLAE's own message
design (Section 5.2) sends `A1` — the value that cryptographically binds
`RN1`, the 6LN's freshness contribution, into the session — in the
clear, outside the AEAD-protected `CT1||Tag6LC` container, and `RN1` is
never re-included inside any encrypted/authenticated payload anywhere in
`M2`.** A plain hash/XOR commitment sent alongside an unrelated
encryption (exactly PSLAE's `A1` and `M` fields) is not, on this
evidence, sufficient for Scyther's Niagree/Nisynch synchronization proof
to succeed, even though it is sufficient for `Secret`, `Alive`, and
`Weakagree` — all of which have weaker requirements than full
synchronized agreement.

**This is stated as our best-supported technical finding, not an
absolute certainty.** What we can say with confidence, backed by the
controlled experiments above: it is **not** primarily an artifact of
(a) the XOR-abstraction technique in general (Diagnostic A shows
Niagree/Nisynch CAN hold in models built with the same general Scyther
idioms), (b) claim placement / the "last message problem" (Diagnostic A
directly refutes this for the exact same role-claim positions PSLAE
uses), or (c) key reuse across directions (Diagnostic C). What remains
consistent with all evidence is that it traces to PSLAE's own choice to
send `A1`/`M` unauthenticated in the clear rather than binding `RN1`
inside an encrypted payload — a property of the **paper's own protocol
design as described**, not primarily an artifact of our reconstruction.

**What we cannot fully rule out:** a different Scyther version (the
paper's stated 1.1.3 vs. our modern rebuild) could in principle behave
differently on this exact question, and we have no way to test the
paper's exact historical version (see Module 11). We report this
residual uncertainty rather than papering over it.

**We did NOT modify the PSLAE protocol model to force Niagree/Nisynch to
pass.** `scyther/pslae.spdl` is unchanged from the version analyzed
above; the diagnostic variants live only in `results/scyther/diagnostics/`
and `/tmp` (not part of the shipped protocol model).

---

## 5. CK/eCK vs. Dolev-Yao — explicit distinction

The paper's Section 4.2 discusses both the Dolev-Yao (DY) model and an
extended Canetti-Krawczyk (CK) / eCK-style adversary (session-state and
ephemeral-secret compromise). **Standard Scyther, as run here, verifies
only the Dolev-Yao network-attacker model** — an adversary that can
intercept, alter, insert, block, and replay network messages, but does
**not** natively model session-state-reveal or ephemeral-key-compromise
queries the way an eCK security proof would. The paper's own Section 6.3
also only reports standard Scyther claim types (`Secret`, `Alive`,
`Weakagree`, `Niagree`, `Nisynch`), which are themselves DY-model
claims — the paper does not describe using any Scyther eCK-extension
tool, so we do not claim Scyther "verifies" PSLAE's eCK/CK-style claims
(Propositions 2 and 8, PFS and ESL) either — those remain **theoretical
claims** (see Module 8, informal security analysis), consistent with how
the paper itself separates its "Scyther" results from its "informal"
CK-model discussion of PFS/ESL.

**4. Files involved:** `scyther/pslae.spdl`, `results/scyther/*`,
`results/scyther/diagnostics/*`.

**8. How to run it yourself:**
```bash
cd scyther
./bin/scyther-linux -r 100 -m 0 -A pslae.spdl
```

**9. Expected result:** exactly the table in Section 3 above.

**10. How to verify:** re-run; deterministic given the same bounds.
Re-run the diagnostics (`results/scyther/diagnostics/*.spdl`) to
independently confirm the isolation experiments.

**11. Paper ambiguity:** the paper's Scyther source was never published;
an exact reproduction of its screenshots is not possible in principle.

**12. Status:** **VERIFIED** for Secret/Alive/Weakagree (matches paper).
**INVESTIGATED, DISCREPANCY DOCUMENTED — NOT REPRODUCED** for
Niagree/Nisynch, with a specific, evidence-backed structural finding
(not merely "unknown" or "modelling artifact, cause unclear") about
PSLAE's own message design. **NOT ATTEMPTED (theoretical only)** for
CK/eCK-specific claims, consistent with the paper's own scope for
Scyther.
