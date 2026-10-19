# Module 4 — AKE2 / Second AKE Message

**1. Purpose:** The 6LC verifies M1, authenticates the 6LN, and
generates the second AKE message, `M2`.

**2. What the paper says (Section 5.2, Step AKE2):** Checks `T6LN`
freshness; derives `AID6LN = TID6LC XOR D`, looks it up; recomputes
`Mk' = Ms XOR H(R6LC)` and `Si'`; decrypts `(A||B)` from `CT`, checking
`Tag6LN`; recovers `RN1 = AID6LN XOR B`; checks `Sc' = ID6LN XOR RN1 XOR
A` [see ambiguity #8: we use `AID6LN` here, not the paper's literal,
algebraically-impossible `ID6LN`] against stored `Sc`; on success,
generates `T6C`, `RN2`; computes `Sc1` (via `T = Mk' XOR H(ID6LC)`),
`B1`, `A1`, `SK = H(AID6LN||B1||Sc1||RN1||RN2)`, `M = H(SK)`; encrypts
`(Sc1||RN2)` under `Si''` to get `(CT1||Tag6LC)`; sends
`M2 = (T6C, A1, M, CT1||Tag6LC, RN2)`.

**3. What we implemented:** `src/ake.py::step_ake2()` — every step
above, in order, raising `AuthenticationError` on any freshness/lookup/
tag/`Sc`-mismatch failure (matching "the AKE process will be aborted").
Applies reconstructions #5 (`Si''=Si'`), #7 (`PT1=Sc1||RN2`), #8
(`Sc'=AID6LN...`), and #11 (rotates stored `Sc -> Sc1`).

**4. Files involved:** `src/ake.py`.

**5. Input:** A `SixLC` object and an `M1` dict (from Module 3).

**6. Processing:** `step_ake2(controller, m1)` → `dict` with keys `m2`,
`session_key`.

**7. Output:** `M2` message dict, plus the 6LC's own computed `SK` (for
Module 6's cross-check), and an in-place update of the 6LC's stored
`Sc` for that sensor.

**8. How to run it:**
```bash
python3 -c "
from src.registration import make_controller, register_sensor
from src.ake import step_ake1, step_ake2
from src.crypto_utils import random_bytes
c = make_controller(); s = register_sensor(c, random_bytes(8))
m1 = step_ake1(s)
r = step_ake2(c, m1)
print('M2 fields:', {k: len(v) for k,v in r['m2'].items()})
print('SK (6LC):', r['session_key'].hex())
"
```

**9. Expected result:** `M2 fields: {'T6C': 4, 'A1': 8, 'M': 20, 'CT1':
16, 'Tag6LC': 16, 'RN2': 8}` (bytes, matching 32/64/160/128/128/64
bits); a 40-hex-char (160-bit) `SK`.

**10. How to verify it is correct:**
`tests/test_ake_success.py::test_ake2_message_shape`; all 9 failure-mode
cases in `tests/test_ake_failures.py` that target M1 tampering are
handled here (`AuthenticationError` raised correctly).

**11. Paper ambiguity:** `docs/paper_ambiguities.md` #5, #6, #7, #8, #11.

**12. Status:** **VERIFIED**.
