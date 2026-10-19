# Complete SVO Derivation — G1 (published) and G2 (reconstructed)

This document reproduces the paper's G1 exactly as published, then
attempts a G2 derivation using the minimum necessary additional
premises, with every one clearly labelled `[PUBLISHED]` or
`[RECONSTRUCTED]`. This is NOT claimed to be the paper's own G2 proof
— it does not exist in the source (confirmed by exhaustive search,
`docs/issue9_svo_g2.md`) — it is an explicit, honestly-labelled
completion attempt, built only for this project's reconstructed implementation (src/).

---

## G1 — published in full (Fig. 6)

### Initial assumptions

| ID | Statement | Type |
|---|---|---|
| IS1 | `6LN⊨ #(T1) ∧ #(RN1) ∧ #(Sc1)` (6LN believes its own M1-side values are fresh) | `[PUBLISHED]` |
| IS2 | `6LN⊨ 6LN(D,(CT‖Tag6LN))⇄6LC` (shared association for M1's fields) | `[PUBLISHED]` |
| IS3 | `6LN∋(CT‖Tag6LN)` (6LN possesses its own built ciphertext) | `[PUBLISHED]` |
| IS4 | `6LC∋(T1,RN1,RN2,(CT‖Tag6LN))` (6LC possesses received M1 values) | `[PUBLISHED]` |
| IS5 | `6LN(CT‖Tag6LN)⇄6LC` (shared key for M1's protection) | `[PUBLISHED]` |

### Rules used

- **Message Meaning Rule** (played by SA1/SA2, Source Association axioms): `P⇄k Q ∧ R received {X}k ⊃ (Q↦X ∧ Q∋K)`
- **Belief Combination** (BA1): `P believes φ ∧ P believes(φ⊃ψ) ⊃ P believes ψ`
- **Receiving Rule** (R1): `P⊲(X1,...,Xn) ⊃ P⊲Xi`
- **Necessitation**: `⊢φ infer ⊢P believes φ`

### Derivation

| Step | Premises | Rule | Conclusion |
|---|---|---|---|
| X1 | IS3, IS4, IS5 | Necessitation | `6LC⊨6LC(CT‖Tag6LN)⇄6LN` |
| X2 | IS2, IS5 | R1 | `6LC⊲(D)(CT‖Tag6LN)` |
| X3 | X1, X2 | R1 | `6LC⊨6LN(CT‖Tag6LN)` |
| **G1** | X3 | (conclusion) | **6LC authenticates 6LN's M1 — "G1 is verified"** |

Every premise here is `[PUBLISHED]`. This is a complete, faithful
reproduction with nothing added.

---

## G2 — attempted reconstruction (NOT published)

**Goal statement (by symmetry with G1):** `6LN⊨6LC(CT1‖Tag6LC)` —
6LN's belief that M2's ciphertext genuinely originated from 6LC.

### Reconstructed initial assumptions

| ID | Statement | Type | Justification |
|---|---|---|---|
| IS1′ | `6LC⊨ #(T2) ∧ #(RN2) ∧ #(Sc1)` | `[RECONSTRUCTED]` | Direct structural mirror of IS1, substituting 6LC/M2's fields for 6LN/M1's |
| IS2′ | `6LC⊨ 6LC(A1,(CT1‖Tag6LC))⇄6LN` | `[RECONSTRUCTED]` | Direct structural mirror of IS2 |
| IS3′ | `6LC∋(CT1‖Tag6LC)` | `[RECONSTRUCTED, but trivial]` | 6LC built M2's ciphertext itself — a description of what the protocol literally does, not a new assumption about security properties |
| IS4′ | `6LN∋(T2,RN1,RN2,(CT1‖Tag6LC))` | `[RECONSTRUCTED, but trivial]` | 6LN receives M2 — again a description of what happens, not a new security assumption |
| **IS5′** | `6LC(CT1‖Tag6LC)⇄6LN` | **`[RECONSTRUCTED — LOAD-BEARING]`** | See below — justified for this project's implementation, unsafe for the paper's literal one |

### Why IS5′ is now justified — the key insight from this round's ID6LC reconstruction

In the faithful protocol, IS5′ is false: 6LN cannot independently
derive the key protecting M2 (its own recomputation formula requires
`ID6LC`, which it never receives). **This is where the earlier
investigation correctly stopped.**

`docs/id6lc_ake3_reconstruction.md` (this round) establishes something
different for this project's reconstructed implementation specifically: under the
redesigned `Mk`-derivation mechanism (`Mk` computed from `(Sc, K6LN)`,
both already registration-established for both parties, rather than
from `Ms/R6LC` on 6LC's side and unreachable `ID6LC` on 6LN's), **6LN
genuinely, independently derives the same decryption key `Si'''` that
6LC used to encrypt M2** (`ake.py::step_ake3`, `si_triple_prime =
sess["si"]`, itself a pure function of `sensor.mk`/`sensor.sc`,
computed without any input from 6LC beyond what registration already
established). Decryption only succeeds, and `Tag6LC` only verifies,
if this independently-derived key matches 6LC's.

**This makes IS5′ a true statement about this project's reconstructed
mechanism specifically** — not an assumption, but a description of
what the implemented key-derivation scheme actually guarantees.

### `[RECONSTRUCTED PREMISE]` — IS5′, justified

```
IS5′ [RECONSTRUCTED PREMISE, this project's reconstructed src/ only]:
    6LC(CT1‖Tag6LC)⇄6LN

Justification: under the Mk=H(Sc,K6LN) derivation scheme
(registration.py/entities.py, this round), both 6LC and 6LN compute
the identical key Si''/Si''' from registration-established shared
secrets (Sc, K6LN), independently and without transmission of the key
itself. This is the SAME kind of key-sharing relationship IS5
(published, for M1) already asserts -- IS5′ extends it to M2 using
the mechanism that actually protects M2 in this variant.

NOT claimed as the paper's own literal justification (the paper's own
Mk=Ms⊕H(R6LC) formula does NOT have this property in the faithful
protocol) -- explicitly scoped to this project's reconstructed src/'s own
reconstructed mechanism.
```

### Completing G2

| G2 step | Premises | Rule | Conclusion |
|---|---|---|---|
| X1′ | IS3′, IS4′, IS5′ | Necessitation | `6LN⊨6LN(CT1‖Tag6LC)⇄6LC` |
| X2′ | IS2′, IS5′ | R1 | `6LN⊲(A1)(CT1‖Tag6LC)` |
| X3′ | X1′, X2′ | R1 | `6LN⊨6LC(CT1‖Tag6LC)` |
| **G2** | X3′ | (conclusion) | **6LN authenticates 6LC's M2 — "G2 is reconstructed"** |

**This derivation is `[RECONSTRUCTED]` in full, and specifically NOT
claimed to be the paper's intended G2** — the paper's own literal
mechanism (via `ID6LC`) does not support IS5′, only this variant's
redesigned key-derivation scheme does. Presented as: *the paper's
stated goal (mutual authentication, both directions) IS reproducible,
given a documented, minimal reconstruction of the one mechanism that
was actually broken — not word-for-word from the paper, but
faithful to its intent, exactly as the task's Part 15 policy permits.*

---

## Contrast — status for the FAITHFUL (non-reconstructed) protocol

The completion above applies **only** to this project's reconstructed
implementation (`src/`, single-tree structure, `Mk` derived from
`Sc`/`K6LN`). For the paper's protocol taken literally — `Mk =
Ms⊕H(R6LC)`, `ID6LC` never reaching 6LN — **IS5′ is false, not merely
unstated**, exactly as the earlier investigation established (see
`docs/issue8_aid6ln_id6lc.md`, `docs/issue9_svo_g2.md`). A frozen copy
of that literal, non-reconstructed implementation is kept at
`docs/baseline_original_src_reference/` for anyone who wants to
verify this directly: running the same derivation attempt against
that code's actual `Mk` formula confirms 6LN cannot independently
derive M2's key there, and G2 remains genuinely non-derivable for
that version. **This is not a contradiction with the completion
above — it is two different implementations (literal vs.
reconstructed) having two different, individually correct SVO
statuses.**


---

## Summary — distinguishing three things, as requested

- **Published premise:** IS1-IS5, the G1 derivation, "G1 is verified."
  Nothing more exists in the source.
- **Inference (safe):** IS3′/IS4′ — trivial possession statements that
  merely restate what the protocol does, carrying no independent
  security content.
- **Reconstructed and now justified (this project's implementation,
  `src/`, only):** IS1′/IS2′ (structural mirrors of IS1/IS2) and IS5′
  (justified by the actual implemented key-derivation mechanism — see
  above), which together complete G2 for this project.
- **Remains genuinely non-derivable for the paper's literal protocol**
  (frozen reference copy: `docs/baseline_original_src_reference/`,
  NOT the current `src/`): IS5′ is false there, given the confirmed
  `ID6LC` gap (`docs/issue8_aid6ln_id6lc.md`). This is not an
  editorial oversight a careful reader could patch — that protocol's
  own AKE3 mechanism cannot support the belief a symmetric proof would
  need to state. That version's G2 status is unchanged: NOT
  DERIVABLE, and correctly so.
