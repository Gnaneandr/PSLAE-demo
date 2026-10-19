# Module 6 — Session-Key Establishment

**1. Purpose:** Explicitly demonstrate and verify that 6LN and 6LC,
running independently, arrive at the identical session key `SK`.

**2. What the paper says:** Section 5.2 and Fig. 5: the 6LC computes
`SK = H(AID6LN||B1||Sc1||RN1||RN2)` in Step AKE2; the 6LN computes
`SK' = H(AID6LN||B1'||Sc1||RN1||RN2)` in Step AKE3; for the protocol to
be correct these must be equal (Proposition 1, mutual authentication +
implicit key confirmation via `M=H(SK)`).

**3. What we implemented:** `src/demo.py` runs Modules 2→3→4→5 in
sequence and asserts `sk_controller == sk_sensor` with a hard `assert`
(not just a print) — the script raises `AssertionError` and exits
non-zero if they ever diverge, so this is an executable check, not just
a demonstration.

**4. Files involved:** `src/demo.py` (orchestration), depends on
Modules 2-5.

**5. Input:** None (generates its own fresh 6LC/6LN and identities).

**6. Processing:** Registration → AKE1 → AKE2 → AKE3 → explicit
equality assertion.

**7. Output:** Console transcript of every intermediate value plus the
final `SUCCESS` line; see `results/protocol/demo_output.txt` for a real
captured run.

**8. How to run it:**
```bash
python -m src.demo
```

**9. Expected result:**
```
[6LC] Session key SK  = <40-hex-char value>
[6LN] Session key SK' = <the identical 40-hex-char value>

SUCCESS: 6LN and 6LC derived the identical session key.
```

**10. How to verify it is correct:** The script itself asserts equality
(hard failure if not equal); additionally
`tests/test_ake_success.py::test_full_ake_session_key_agreement` and
`::test_two_consecutive_sessions_succeed_after_rotation` (verifying
agreement holds across a *second*, post-rotation session too) both pass.

**11. Paper ambiguity:** Inherits all of Modules 2-5's flagged points.

**12. Status:** **VERIFIED** — real executed output in
`results/protocol/demo_output.txt` shows matching 160-bit keys.
