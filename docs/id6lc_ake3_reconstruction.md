# ID6LC / AKE3 — Complete Reconstruction

## 1. Trace: where ID6LC is generated, stored, known

- **Generated:** Step RP-1, unilaterally by 6LC (*"the 6LC ... pick[s]
  up a unique real identity ID6LC"*) — no formula, no derivation.
- **Stored:** by 6LC itself, implicitly (never explicitly stated, but
  obviously required for 6LC's own later use).
- **Known by 6LN?** No — confirmed by exhaustive search of Step RP-3's
  storage lists for both parties: neither the 6LC's database record
  nor 6LN's own memory ever lists `ID6LC`.
- **Transmitted?** No — absent from both `M1` and `M2`'s printed field
  tuples.
- **Derivable from another published value?** No — no formula anywhere
  expresses `ID6LC` in terms of anything 6LN holds.

## 2. Where the paper's literal AKE3 equation needs it

Step AKE3's text: *"the 6LN calculates AD by computing X'=Mk⊕Sc and
Fr''=Mk⊕H(K6LN)... The 6LN computes T' to get Sc1'"* — with `T'`
elsewhere defined (by direct analogy to AKE2's own `T=Mk'⊕H(ID6LC)`)
as requiring `ID6LC`. This is the one point in the entire protocol
where 6LN's own equations need a value it structurally cannot have.

## 3. The reconstruction: independent key-derivation verification

**Rejected option — literal recomputation:** give 6LN `ID6LC` (or
`H(ID6LC)`) via an invented registration-time channel. Rejected
because it requires inventing a distribution mechanism the paper
never describes anywhere, and — critically — it would also require
extra persistent storage on 6LN's side (`+8 bytes`, breaking the
32-byte storage target) for a value whose only purpose is to let 6LN
redundantly recompute something the AEAD tag already verifies (see
below). This is not the *minimum* mechanism the task asks for.

**Adopted option — key-derivation-based independent verification.**
Under this round's storage redesign (`registration.py`,
`entities.py` — `Mk` is derived on demand from `(Sc, K6LN)` rather
than stored/transmitted), 6LN does not receive or trust anything
6LC computed for M2's protection key. It **independently derives**
the exact same decryption key (`si_triple_prime`, reused from Step
AKE1's own computation, itself a pure function of `sensor.mk` /
`sensor.sc`) that 6LC used to encrypt `CT1`. Decryption and the
subsequent `Tag6LC` comparison **only succeed if 6LN's independently-
derived key matches 6LC's** — which happens if and only if both
parties hold the same genuine `(Sc, K6LN)`, i.e., if and only if
they are who Step RP-3's registration says they are.

**This is genuine independent verification, not blind trust of a
transmitted value** — it verifies the same underlying fact the
paper's literal `T'=Mk⊕H(ID6LC)`-then-compare approach was meant to
verify (that `Sc1` genuinely originated from the legitimate 6LC), via
a different, smaller, already-necessary mechanism (matching key
derivation + AEAD authentication) instead of a redundant second
value-recomputation the paper's own equations never even state is
compared against anything.

**Storage impact: none.** No new field is needed on 6LN's side — the
32-byte total is preserved (see `docs/storage_6lc_reconstruction.md`
for 6LC's separate storage discussion).

## 4. Consequence for SVO G2

Because 6LN's decryption key for M2 is now (in this variant)
genuinely, independently derivable and matches 6LC's by construction
(both derive it from the same registration-established `Sc`/`K6LN`),
the SVO premise that blocked G2 in the faithful track —
`6LC(CT1‖Tag6LC)⇄6LN` (shared key possession for M2) — is **now true
of the actual implemented mechanism**, not merely assumed. See
`svo/complete_svo_derivation.md` for the completed G2 derivation this
enables. This is the direct payoff of solving ID6LC/AKE3 properly
before returning to SVO G2, as requested.

## 5. Tests added (`tests/test_ake3_id6lc_reconstruction.py`)

1. **Normal AKE3 success** — full session, key agreement.
2. **Wrong/mismatched long-term secret** (simulating "wrong ID6LC" in
   spirit — since ID6LC itself is never held by 6LN, the equivalent
   failure mode is a party holding the wrong `K6LN`) — verification
   fails.
3. **Tampered CT1** — rejected via the AEAD tag check.
4. **Incorrect Sc1** (M2 constructed with a substituted `Sc1` value,
   simulating an attacker who doesn't know the shared key) — rejected.
5. **Session key agreement** — confirmed across the same successful
   run as test 1, and independently in the AID6LN-rotation test suite.
