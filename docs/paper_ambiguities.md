# Paper Ambiguities and Reconstruction Decisions

This file consolidates **every** place where the published PSLAE paper
(Ashrif et al., Computer Communications 218 (2024) 263-275) is internally
inconsistent, under-specified, or otherwise cannot be implemented exactly
as literally printed, together with the decision made and why. Each entry
is also flagged inline in the source file(s) listed.

Per the project rules: nothing below was silently patched. Every decision
is presented as a decision, not as "the paper said so."

---

### 1. "265 bits" vs 256 bits

**Where:** Step RP-2 ("The master key Ms of 265 bits...") and Step RP-4
("Si is 265 bits (Nc||Kc) = 128 bits +128 bits").

**Problem:** 128 + 128 = 256, not 265. The paper's own arithmetic
contradicts its stated figure.

**Decision:** Treat every "265 bits" as a typo for 256 bits, applied
consistently to `Ms`, `Mk`, `Sm`, `X`, `Si`, `Fr`.

**Files:** `src/crypto_utils.py`, `src/registration.py`.

---

### 2. Hash-output width vs XOR operand width mismatches

**Where:** throughout Section 5.1/5.2 -- e.g. `Mk = Ms XOR H(R6LC)`,
`Sm = Mk XOR H(ID6LN)`, `Fr = Mk XOR H(K6LN)`, all XOR a native 160-bit
SHA-1 output against a 256-bit operand, with no reconciliation rule
given.

**Decision:** A documented SHA-1-based KDF, `H_bits(data, nbits)`,
extends/truncates hash output to whatever width a formula needs. This is
a reconstruction, not part of the original paper.

**Files:** `src/crypto_utils.py`.

---

### 3. `X = Mk XOR Sc` mixes a 256-bit and a 64-bit operand

**Where:** Step RP-4. `Sc` is built from four 64-bit XOR chunks (so is
64 bits), but is XORed directly against 256-bit `Mk`.

**Decision:** Tile (repeat) the shorter operand to the longer operand's
length before XORing (`tile_to()`), applied consistently everywhere this
pattern recurs.

**Files:** `src/crypto_utils.py`, `src/registration.py`.

---

### 4. 6LC's Step RP-3 database record is incomplete for Step AKE2 to work

**Where:** Step RP-3 lists only `{TID6LC, Sc, K6LN, AID6LN}` for the
6LC's stored record. Step AKE2 requires the 6LC to recompute
`Mk' = Ms XOR H(R6LC)` and to know `ID6LN`, `K6LC` -- none of which are
in the Step RP-3 list.

**Decision:** Add `Ms`, `R6LC`, `ID6LN`, `K6LC` to the 6LC's stored
record, clearly marked as additions beyond the literal Step RP-3 text.

**Files:** `src/entities.py`, `src/registration.py`.

---

### 5. `Si` derivation conflict: Step RP-4 vs Step AKE1's restatement

**Where:** Step RP-4 defines `Si` from `X = Mk XOR Sc`. Step AKE1's prose
separately says "Mk is divided into 128 bits by the 6LC, KC, and Nc...
Si <- ACE(Nc||Kc)" -- i.e. splitting `Mk` directly, not `X`.

**Decision:** Step RP-4's definition (`Si` from `X = Mk XOR Sc`) is
treated as canonical and used consistently at every phase
(`compute_Si()`).

**Files:** `src/registration.py`, `src/ake.py`.

---

### 6. `Si''` (used to encrypt M2's CT1) has no distinct derivation given

**Where:** Step AKE2: "during the initialization phase, Si' is
considered by the encryption algorithm... to generate {CT1||Tag6LC}".

**Decision:** `Si'' = Si'` (the 6LC reuses the initialization state it
already derived earlier in the same step).

**Files:** `src/ake.py`.

---

### 7. `R2` vs `RN2` in the CT1 plaintext

**Where:** Step AKE2 prose says PT1 = "(Sc1||RN2)"; the printed formula
says `{CT1||Tag6LC} = ESi''{AD', (Sc1||R2)}`. `R2` is "selected" once
alongside `RN2` and never used or mentioned again, including in Step
AKE3's own decryption description ("decrypting the message to get
(Sc1|| RN2)").

**Decision:** `R2` is treated as a typographical artifact. `PT1 =
(Sc1||RN2)` is used throughout, consistent with the rest of the protocol.

**Files:** `src/ake.py`.

---

### 8. `Sc' = ID6LN XOR RN1 XOR A` is algebraically impossible to satisfy

**Where:** Step AKE2's legitimacy check.

**Problem:** Substituting Step AKE1's own definition of `A = AID6LN XOR
RN1 XOR Sc`:

```
ID6LN XOR RN1 XOR A = ID6LN XOR RN1 XOR (AID6LN XOR RN1 XOR Sc)
                     = ID6LN XOR AID6LN XOR Sc
```

This equals `Sc` only if `AID6LN = ID6LN`, contradicting Step RP-2's own
definition `AID6LN = ID6LN XOR K6LN XOR K6LC`. As literally printed, a
legitimate 6LN could never pass this check.

**Decision:** Substitute `AID6LN` for the paper's literal `ID6LN` in this
one formula (`Sc' = AID6LN XOR RN1 XOR A`), the only reading under which
the check is satisfiable by a legitimate 6LN.

**Files:** `src/ake.py`.

---

### 9. Step AKE3's `A1' = B1 XOR RN1` reuses the *received* B1, making the check vacuous

**Where:** Step AKE3: "calculate B1' = RN2 XOR K6LN and A1' = B1 XOR
RN1".

**Problem:** As literally printed, `A1'` uses the *received* `B1` (from
M2), not the independently-recomputed `B1'` from the immediately
preceding clause. Using the received value makes the check `A1' = A1`
true unconditionally, regardless of message authenticity -- it would
never catch tampering.

**Decision:** Use `A1' = B1' XOR RN1`, the independently recomputed
value, the only reading that gives this step a genuine verification
purpose.

**Files:** `src/ake.py`.

---

### 10. Step AKE3's independent recomputation of `Sc1'` requires `ID6LC`, never given to the 6LN

**Where:** Step AKE3: "The 6LN computes T' to get Sc1'" via
`T' = Mk XOR H(ID6LC)`.

**Problem:** `ID6LC` is chosen unilaterally by the 6LC in Step RP-1 and
never described as being shared with the 6LN during registration (Step
RP-3's stored-field lists for both sides omit it entirely).

**Decision: this is a case where the paper does not provide enough
information to reproduce the step exactly.** Rather than inventing an
undocumented `ID6LC`-sharing channel, the implementation uses the `Sc1`
value recovered directly from decrypting `CT1` (already implicitly
authenticated by the `Tag6LC` check, since `Sc1` is part of the
AEAD-protected plaintext).

**Files:** `src/ake.py`.

---

### 11. Secret-rotation mechanism (`Sc -> Sc1`) is implied, not explicitly stated

**Where:** Section 4.3's forward/backward-secrecy goal, the SLAP
cryptanalysis's `bi`/`r` rotation pattern (Section 3.2), and Step AKE2
calling `Sc1` "a new security temporal parameter" all strongly imply a
rotation happens, but the paper never states in so many words which
stored variable `Sc1` replaces.

**Decision:** Both sides replace their stored `Sc` with `Sc1` after a
successful AKE run.

**Files:** `src/ake.py`.

---

### 12. `AID6LN` is never actually rotated by any described protocol operation, despite Proposition 3's claim

**Exact paper reference:** Section 6.1, Proposition 3: *"Each session's
`AID6LN` is changed."* Contrast with Section 5.1, Step RP-2: `AID6LN =
ID6LN ⊕ K6LN ⊕ K6LC`, computed once during registration; and Section
5.2, Steps AKE1–AKE3, which never write a new value into `AID6LN`.

**Issue:** the paper's formal security *claim* (Prop. 3) is stronger
than what its own protocol *steps* implement.

**Evidence:**
1. `AID6LN` is defined exactly once, in Step RP-2 (registration), from
   `ID6LN`, `K6LN`, `K6LC` — none of which the AKE phase (Section 5.2)
   ever recomputes or reassigns.
2. Step AKE2's own list of updated/regenerated per-session values (`r'`,
   `b'i`-style temporal parameters, called `Sc1` in PSLAE) does not
   include `AID6LN`.
3. Every message field that depends on `AID6LN` (`D`, `A`, `B` in M1)
   uses the *same* `AID6LN` value in every session for a given sensor —
   confirmed empirically by
   `tests/test_replay_and_traceability.py::test_documented_gap_D_is_linkable_across_sessions`,
   which runs two real consecutive sessions with this implementation and
   shows `D` (which is `AID6LN ⊕ TID6LC`, both static) is byte-identical
   across them.
4. We checked whether the rotation might be *implicit* through another
   variable: `Sc` genuinely does rotate (`Sc → Sc1`, our Reconstruction
   #11, itself only inferred, not explicit — see entry #11 above), but
   `Sc`'s rotation does not touch `AID6LN`, which is defined purely from
   `ID6LN`/`K6LN`/`K6LC`. No other variable's rotation implies or causes
   `AID6LN` to change.

**Interpretation:** this is a genuine inconsistency between the paper's
security-proof section and its protocol-description section, not a
notational ambiguity we can resolve by re-reading more carefully — we
re-read Sections 5.1, 5.2, and 6.1 specifically looking for an implicit
update mechanism (per the task's explicit request) and found none.

**Implementation decision: NOT patched.** We considered, and rejected,
inventing an `AID6LN`-rotation formula (e.g., mirroring how `Sc1` is
computed) because the paper provides no formula for it whatsoever — any
such addition would be pure invention, not a defensible reconstruction
supported by another part of the paper (unlike, say, Reconstruction #11,
which at least has Section 4.3's forward-secrecy goal and the SLAP
cryptanalysis's `bi`/`r` rotation pattern as textual support). This gap
is left as-is and demonstrated by a test, per the project's ground rule
against inventing missing information.

**Files:** `tests/test_replay_and_traceability.py`.

---

### 17. Scyther's Niagree/Nisynch claims fail, traced to a specific structural property of PSLAE's own M2 design

**Exact paper reference:** Section 5.2's definition of
`M2 = (T6C || A1 || M || (CT1||Tag6LC) || RN2)`, where `A1 = B1 ⊕ RN1`
and `CT1` encrypts only `(Sc1||RN2)`.

**Issue:** `RN1` (the 6LN's freshness contribution, and a required input
to `SK`) is bound into `M2` only via the plaintext field `A1`, never via
inclusion inside the AEAD-protected `CT1||Tag6LC`.

**Evidence:** three controlled Scyther experiments, fully documented in
`docs/module_10_scyther.md` and saved in
`results/scyther/diagnostics/`. Summary: a minimal 2-message protocol
that re-includes the first message's nonce inside the second message's
ciphertext satisfies Niagree/Nisynch; an otherwise-identical variant
that instead sends only a plaintext hash-commitment of that nonce
(mirroring PSLAE's `A1`/`M` fields exactly) reproduces PSLAE's own
Fail pattern. Key-reuse-across-directions was separately ruled out as
an alternative cause.

**Interpretation:** this is best explained as a genuine structural
property of the paper's own described message design (not primarily an
artifact of our XOR-abstraction reconstruction), though we cannot fully
rule out a residual Scyther-version effect (paper's stated 1.1.3 vs. our
modern rebuild — see Module 11).

**Implementation decision:** not patched or hidden. `scyther/pslae.spdl`
continues to model `M2` exactly as the paper describes it (`A1`, `M`
in the clear; only `Sc1||RN2` encrypted). Changing this to make
Niagree/Nisynch pass would mean modelling a different protocol than the
one the paper describes, which the task instructions explicitly
prohibit.

**Files:** `docs/module_10_scyther.md`,
`results/scyther/diagnostics/`.

---

### 13. ACE's internal permutation is not in the paper

**Where:** Section 4.4 cites ACE as an external NIST-LWC round-1
submission and only specifies its black-box AEAD interface.

**Decision:** A standard AES-128-CTR + HMAC-SHA256 construction with a
matching interface and matching "inverse-free" structural property is
used, **clearly labelled "RECONSTRUCTED FROM THE PAPER" and explicitly
NOT claimed to be the real ACE cipher** (see `src/ace.py`'s module
docstring for exactly what the paper does and does not specify).

**Files:** `src/ace.py`.

---

### 14. Communication-overhead Table 5's own row arithmetic doesn't add up

**Where:** Section 7.3, Table 5, Ref. [24]'s row: "544 bits/160 bits"
listed for 6LN->6LC, "480 bits" for 6LC->6LN, but the row total is
printed as "1184 bits" -- 544 + 480 = 1024, not 1184.

**Decision:** Not corrected; reported as-is in
`performance/overhead.py::PAPER_TABLE5` with this note attached, since
this is the paper's own arithmetic error, not something this
implementation can resolve.

**Files:** `performance/overhead.py`.

---

### 15. No numeric value given for the freshness window `ΔT`

**Where:** Section 5.2 references "the allowance maximum transmission
delay (ΔT)" without giving a concrete number.

**Decision:** A configurable 5-second window (`DELTA_T` in `src/ake.py`)
is used -- a deployment parameter, not a protocol constant, and freely
adjustable.

**Files:** `src/ake.py`.

---

### 16. Scyther CLI parameters vs the paper's GUI-only advanced parameters

**Where:** Section 6.3 describes GUI-specific parameters ("number of
patterns per claim", "graph output font size (in points)") for its three
configurations.

**Decision:** The rebuilt, modern Scyther CLI backend used in this
project (see `docs/module_10_scyther_configurations.md`) does not expose
"patterns per claim" as a CLI flag -- it appears to be a GUI-only display
/ bounded-search parameter from the legacy Scyther GUI not present in the
CLI backend's flag set. Configuration 2 and Configuration 3 are run with
identical CLI flags as a result (`-r 100 -m 0 -A`); this is documented as
a tooling limitation, not silently hidden by inventing a flag that
doesn't exist.

**Files:** `scyther/configurations/`, `docs/module_10_scyther_configurations.md`.
