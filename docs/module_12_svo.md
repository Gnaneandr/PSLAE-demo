# Module 12 — SVO Formal Security Analysis

**1. Purpose:** Reproduce, as a structured document (NOT as code — SVO
is a hand-written mathematical proof method, not an executable
artifact), the paper's SVO logic analysis.

**2. What the paper says (Section 6.2, Fig. 6, Table 2):** SVO logic
(Syverson & Van Oorschot) is used to formally analyse mutual
authentication. The paper's Fig. 6 gives: Inference Rules (Modus Ponens,
Necessitation), Axioms (Belief axiom BA1, Source Association axioms
SA1/SA2, Receiving axiom R1), Initial Assumptions (IS1-IS5), and a final
Formal Verification derivation (X1, X2, X3 → "G1 is verified").

**3. What we implemented:** This module is **explicitly NOT presented as
Scyther** and **explicitly NOT executable** — SVO is a manual
mathematical derivation. What follows is a structured reproduction of
the paper's own Fig. 6 derivation, transcribed into explicit
assumptions/beliefs/goals/rules/conclusion form for clarity, strictly
following what the paper itself states (not inventing new axioms).

### Notations used (paper's Table 2)
`A|≡M` = A believes M · `A⊲M` = A received M · `A|~M` = A once said M ·
`A ↔k B` = k is a good shared key between A,B · `#(M)` = M is fresh ·
`{M}k` = M encrypted under k.

### Inference rules (paper's Fig. 6)
- **Modus Ponens (MP):** from `φ` and `φ ⊃ ψ`, infer `ψ`.
- **Necessitation (Nec):** from `⊢ φ`, infer `⊢ P believes φ`.

### Axioms (paper's Fig. 6)
- **BA1 (Belief axiom):** `P believes φ ∧ P believes (φ⊃ψ) ⊃ P believes ψ`.
- **SA1/SA2 (Source Association axioms):**
  `P (k/↔) Q ∧ R received {X}k ⊃ (Q ↦ X ∧ Q ∋ K)` (both directions, for
  the two message-encrypting keys used in PSLAE's two directions).
- **R1 (Receiving axiom):** `P ⊲ (X1,...,Xn) ⊃ P ⊲ Xi` (receiving a
  tuple implies receiving each component).

### Initial assumptions (paper's Fig. 6, IS1-IS5)
- IS1: `6LN|≡ #(T1) ∧ #(RN1) ∧ #(Sc1)` — freshness of the 6LN's own
  generated values.
- IS2: `6LN|≡ 6LN (D,(CT||Tag6LN))↔ 6LC` — shared-secret assumption for
  message 1's protected fields.
- IS3: `6LN ∋ (CT||Tag6LN)` — 6LN possesses the encrypted tuple it built.
- IS4: `6LC ∋ (T1,RN1,RN2,(CT||Tag6LN))` — 6LC possesses the received
  values after M1.
- IS5: `6LN (CT||Tag6LN)↔ 6LC` — the two parties share the key
  protecting M1's ciphertext.

### Idealization (paper's Fig. 6)
- `M1: 6LC → 6LN: (T2||A1||(CT1||Tag6LC)||R2)` (M2, idealized)
- `M1: 6LN → 6LC: (T1||D||(CT||Tag6LN)||R1)` (M1, idealized)

### Formal verification / goal derivation (paper's Fig. 6)
- **X1:** `6LC |≡ 6LC (CT||Tag6LN)↔ 6LN`, derived from IS3, IS4, S5, and
  Necessitation.
- **X2:** `6LC ⊲ (D)(CT||Tag6LN)`, derived from IS2, IS5, and R1.
- **X3:** `6LC |≡ 6LN (CT||Tag6LN)`, derived from X1, X2, and R1.
- **Conclusion:** "G1 is verified" — mutual authentication goal G1 (the
  6LC's belief that it is genuinely communicating with the 6LN, keyed to
  the encrypted M1 payload) follows from X1-X3 by chained application of
  the axioms above.

**Our assessment of this derivation:** the paper's own Fig. 6 only
carries the derivation through to a single goal (`G1`, the 6LC's side of
mutual authentication for message 1). It does **not** show the symmetric
derivation for the 6LN's belief about message 2 (`G2`, by the obvious
naming), nor for session-key agreement specifically — the paper's prose
after Fig. 6 asserts these "mathematically" follow but does not print
the additional derivation steps. **We do not invent the missing G2
derivation** — this is flagged as a real gap in the published paper
(it asserts a stronger conclusion, full mutual authentication, than the
one formal derivation it actually shows).

**4. Files involved:** this document only (by design — SVO is not
executable).

**5-9. Input/Processing/Output/How to run/Expected result:** N/A — this
is a manual proof reproduction, not software.

**10. How to verify it is correct:** cross-check each axiom/assumption/
step above against the paper's own Fig. 6 and Table 2 (Section 6.2).

**11. Paper ambiguity:** the derivation for `G2` (6LN's belief about
message 2 / session-key agreement) is asserted but never shown in the
paper — this reproduction only formalizes what the paper's Fig. 6
actually contains (`G1`), and explicitly does not fabricate the missing
half.

**12. Status:** **COMPLETED** (structured reproduction of exactly what
the paper shows) / the paper's own G2 derivation: **NOT REPRODUCIBLE
FROM PAPER** (never published).
