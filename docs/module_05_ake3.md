# Module 5 — AKE3 / Final AKE Verification

**1. Purpose:** The 6LN verifies M2, confirms the session key, and
finalizes the session.

**2. What the paper says (Section 5.2, Step AKE3):** Checks `T6C`
freshness; computes `B1' = RN2 XOR K6LN`, `A1' = B1 XOR RN1` [see
ambiguity #9: we use the independently-recomputed `B1'`, not the
paper's literal, vacuous formula reusing the received `B1`] and checks
`A1'=A1`; decrypts `CT1` under `Si'''` to get `(Sc1||RN2)`, checking
`Tag6LC`; computes `SK' = H(AID6LN||B1'||Sc1||RN1||RN2)`, `M' = H(SK')`,
checks `M'=M`; updates stored secrets.

**3. What we implemented:** `src/ake.py::step_ake3()` — every step
above in order, raising `AuthenticationError` on any failure. Applies
reconstructions #9 (`A1'` formula) and #10 (`Sc1` recomputation
infeasibility — documented as "paper does not provide enough
information," falls back to the AEAD-authenticated decrypted value), and
#11 (rotates stored `Sc -> Sc1`, mirroring the 6LC).

**4. Files involved:** `src/ake.py`.

**5. Input:** The `SixLN` object (with session state stashed by Module
3) and the `M2` dict (from Module 4).

**6. Processing:** `step_ake3(sensor, m2)` → the verified `SK'` (raw
bytes), or raises `AuthenticationError`.

**7. Output:** `SK'` — the 6LN's own computed session key.

**8. How to run it:** see Module 6 below (this step is only meaningful
chained after Modules 3-4).

**9. Expected result:** `SK'` (160-bit / 20-byte) equal to the 6LC's
`SK` from Module 4.

**10. How to verify it is correct:**
`tests/test_ake_success.py::test_full_ake_session_key_agreement` and 4
of the 9 cases in `tests/test_ake_failures.py` target M2 tampering here.

**11. Paper ambiguity:** `docs/paper_ambiguities.md` #9, #10, #11.

**12. Status:** **VERIFIED**.
