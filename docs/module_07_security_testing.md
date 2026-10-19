# Module 7 — Protocol Validation / Security Testing

**1. Purpose:** Executable tests of the *implemented protocol logic*
(distinct from Scyther's formal, symbolic verification — Modules 8-10).

**2. What the paper says:** Propositions 1-11 (Section 6.1) claim
resistance to replay, DoS, impersonation, MITM, ESL, modification,
compromise, and desynchronization attacks, plus mutual authentication
and PFS. These are informal/prose claims in the paper; this module turns
the directly-testable ones into executable assertions against our
implementation.

**3. What we implemented:** 21 tests across 4 files:
- `tests/test_registration.py` (4 tests): successful registration,
  `AID6LN` formula correctness, per-registration uniqueness, bad-input
  rejection.
- `tests/test_ake_success.py` (5 tests): full session-key agreement,
  M1/M2 message-shape correctness, secret rotation, two consecutive
  sessions.
- `tests/test_ake_failures.py` (9 tests): modified `CT`/`Tag6LN`/`D` in
  M1, unregistered-sensor rejection, modified `CT1`/`Tag6LC`/`A1` in M2,
  expired `T6LN`/`T6C`.
- `tests/test_replay_and_traceability.py` (3 tests): exact-replay
  rejection (via the Sc-rotation reconstruction), fresh-nonce
  divergence across sessions, and an intentionally-documented gap test
  (D is linkable across sessions — see ambiguity #12) that demonstrates
  a real limitation rather than hiding it.

**4. Files involved:** all files under `tests/`.

**5. Input:** None (each test generates its own fresh registration/AKE
state).

**6. Processing:** `pytest` auto-discovers and runs all 21 tests.

**7. Output:** Pass/fail per test; see `results/protocol/pytest_output.txt`
for the real captured run.

**8. How to run it:**
```bash
pytest tests/ -v
```

**9. Expected result:** `21 passed` (0 failed).

**10. How to verify it is correct:** Re-run the command yourself — every
test is a plain assertion against real function calls into `src/`, no
mocking.

**11. Paper ambiguity:** N/A for this module itself; individual tests
reference the ambiguity numbers they exercise (see docstrings in
`tests/test_replay_and_traceability.py` in particular).

**12. Status:** **VERIFIED** — 21/21 passing, real output saved.
