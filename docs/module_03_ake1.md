# Module 3 — AKE1 / First AKE Message

**1. Purpose:** The 6LN generates the first AKE message, `M1`.

**2. What the paper says (Section 5.2, Step AKE1):** 6LN generates
`RN1` (64 bits) and `T6LN` (32 bits); computes
`A = AID6LN XOR RN1 XOR Sc`, `B = AID6LN XOR RN1`; encrypts `(A||B)`
under `Si` with associated data `AD` via ACE to get `(CT||Tag6LN)`;
computes `D = AID6LN XOR TID6LC`; sends
`M1 = (T6LN, D, CT||Tag6LN, RN1)`.

**3. What we implemented:** `src/ake.py::step_ake1()` — implements the
formula exactly as printed (no ambiguity in this step beyond the
Module-1-level bit-width reconstructions already applied to `Si`/`AD`).
Session-local state (`RN1`, `A`, `B`, `Si`, `AD`) is stashed on the
sensor object for Module 5 (Step AKE3) to use later.

**4. Files involved:** `src/ake.py`.

**5. Input:** A registered `SixLN` object (from Module 2).

**6. Processing:** One function call, `step_ake1(sensor)`.

**7. Output:** `dict` with keys `T6LN, D, CT, Tag6LN, RN1` (message M1).

**8. How to run it:**
```bash
python3 -c "
from src.registration import make_controller, register_sensor
from src.ake import step_ake1
from src.crypto_utils import random_bytes
c = make_controller(); s = register_sensor(c, random_bytes(8))
m1 = step_ake1(s)
print({k: v.hex() for k, v in m1.items()})
"
```

**9. Expected result:** A dict of 5 hex strings with lengths (in bytes)
`T6LN=4, D=8, CT=16, Tag6LN=16, RN1=8` — matching the paper's declared
bit-widths (32, 64, 128, 128, 64 bits respectively).

**10. How to verify it is correct:**
`tests/test_ake_success.py::test_ake1_message_shape` checks every
field's exact length; passes (see `results/protocol/pytest_output.txt`).

**11. Paper ambiguity:** None specific to this step beyond Module 1/2's
carried-over `Si`/`AD` reconstructions.

**12. Status:** **VERIFIED**.
