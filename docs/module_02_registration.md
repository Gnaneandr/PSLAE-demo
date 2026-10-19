# Module 2 — Registration Phase

**1. Purpose:** Provision a 6LN with all the secrets it needs, and store
the corresponding record in the 6LC's database, exactly per Steps
RP-1..RP-5.

**2. What the paper says (Section 5.1):** RP-1: 6LC receives ID6LN over
a secure channel, picks ID6LC/R6LC/K6LC/K6LN, has TID6LC. RP-2: computes
`AID6LN = ID6LN XOR K6LN XOR K6LC`, `Mk = Ms XOR H(R6LC)`,
`Sm = Mk XOR H(ID6LN)`, `Sc = Sc1 XOR Sc2 XOR Sc3 XOR Sc4` (four 64-bit
chunks of `Sm`). RP-3: 6LC stores `{TID6LC, Sc, K6LN, AID6LN}`; 6LN
stores `{TID6LC, Sc, K6LN, K6LC, AID6LN, Mk}`. RP-4/RP-5: derive `Si`
and `AD` from the stored secrets.

**3. What we implemented:** `src/registration.py::register_sensor()`
implements RP-1 through RP-3 exactly (with the bit-width reconstructions
from Module 1 applied), and `compute_Si()`/`compute_AD()` implement
RP-4/RP-5 as reusable functions (also used later by Modules 3-5, per the
paper's own "Remark 2" that RP-4/RP-5's computation recurs at every AKE
step).

**4. Files involved:** `src/registration.py`, `src/entities.py`.

**5. Input:** A fresh 64-bit `ID6LN` (and an existing `SixLC` instance
from `make_controller()`).

**6. Processing:** RP-1 → RP-2 → RP-3, in order, as one function call.

**7. Output:** A fully-provisioned `SixLN` object; a matching
`SensorRecord` stored in the `SixLC`'s database, keyed by `AID6LN`.

**8. How to run it:**
```bash
python3 -c "
from src.registration import make_controller, register_sensor
from src.crypto_utils import random_bytes
c = make_controller()
s = register_sensor(c, random_bytes(8))
print('AID6LN:', s.aid6ln.hex())
print('6LC record found:', c.lookup(s.aid6ln) is not None)
"
```

**9. Expected result:** `AID6LN` printed as 16 hex chars (64 bits);
`6LC record found: True`.

**10. How to verify it is correct:** `tests/test_registration.py` (4
tests: matching records, `AID6LN` formula correctness, uniqueness across
registrations, bad-length rejection) — all pass, see
`results/protocol/pytest_output.txt`.

**11. Paper ambiguity:** See `docs/paper_ambiguities.md` #1, #2, #3, #4.

**12. Status:** **VERIFIED** (implemented, tested, and executed with
real passing output).
