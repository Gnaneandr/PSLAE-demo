# Module 8 — Informal Security Analysis (paper Section 6.1)

**Purpose:** Reproduce the paper's own informal (prose) security
analysis — Propositions 1–11 — distinct from Module 7's executable
implementation-level tests, Module 12's SVO formal-logic analysis, and
Module 10's Scyther symbolic verification. These are three genuinely
different kinds of evidence and the paper itself keeps them in separate
sections (6.1 informal, 6.2 SVO, 6.3 Scyther); this module preserves
that separation rather than blending them.

For each property: **paper's claim → how PSLAE is intended to provide
it → relevant protocol values/messages → can this be demonstrated by
our executable testing? → theoretical-only aspects flagged as such.**

---

### Proposition 1 — Mutual authentication
**Paper's claim:** 6LC authenticates 6LN via 3 conditions (timestamp
freshness, `TID6LC⊕D=AID6LN`, `Tagd=Tag6LN`); 6LN authenticates 6LC via
2 conditions (timestamp freshness, `TagN=Tag6LC`).
**PSLAE's mechanism:** the AEAD tag comparisons in Steps AKE2/AKE3.
**Relevant values:** `D`, `Tag6LN`, `Tag6LC`.
**Executable? YES** — `tests/test_ake_success.py::test_full_ake_session_key_agreement`
exercises a full successful mutual-auth run; `tests/test_ake_failures.py`
exercises the negative side (each condition's failure independently).

### Proposition 2 — Perfect Forward Secrecy
**Paper's claim:** past/future session keys stay secret even if the
current one leaks, because the alias identity and fresh per-session
parameters change.
**PSLAE's mechanism:** `AID6LN`-based session key + our Reconstruction
#11 (`Sc → Sc1` rotation).
**Executable? PARTIALLY** — `tests/test_ake_success.py::
test_two_consecutive_sessions_succeed_after_rotation` shows keys differ
session-to-session, which is necessary but not sufficient evidence for
formal PFS (formal PFS requires showing no algorithm can derive a past
key from a compromised current one — that is a cryptographic reduction
argument, theoretical, not something a functional test can establish).
**Theoretical-only aspect flagged:** the *proof* of PFS is theoretical;
our test only demonstrates the observable precondition (key freshness).

### Proposition 3 — Anonymity and untraceability
**Paper's claim:** "Each session's `AID6LN` is changed," preventing an
attacker from linking sessions.
**Executable? Directly contradicted by our testing.**
`tests/test_replay_and_traceability.py::
test_documented_gap_D_is_linkable_across_sessions` demonstrates that, as
literally described in Section 5.2, no protocol operation actually
rotates `AID6LN` — see `docs/paper_ambiguities.md` for the full
evidence-based analysis. This is not a theoretical aspect we can't test;
it is directly testable, and the test shows the paper's own claim does
not hold against its own protocol description.

### Proposition 4 — Replay resistance
**Paper's claim:** timestamps (`T6LN`, `T6C`) and random numbers protect
against replay.
**Executable? YES** — `tests/test_ake_failures.py::
test_expired_m1_timestamp_rejected` / `test_expired_m2_timestamp_rejected`,
and `tests/test_replay_and_traceability.py::
test_exact_replay_of_m1_rejected_after_first_success` (via the
Sc-rotation mechanism, not timestamp checking alone — an implementation
nuance documented there).

### Proposition 5 — DoS resistance
**Paper's claim:** forging a valid `Tag6LN` requires secret parameters
an attacker doesn't have.
**Executable? YES** — every tamper test in `tests/test_ake_failures.py`
that modifies `CT`/`Tag6LN` demonstrates the AEAD tag check rejects
forged/modified messages.

### Proposition 6 — Impersonation resistance
**Paper's claim:** neither 6LN nor 6LC impersonation is possible without
the secret parameters.
**Executable? YES** — `tests/test_ake_failures.py::
test_unregistered_sensor_rejected` demonstrates a party without the
correct pairwise secrets cannot successfully impersonate a registered
6LN.

### Proposition 7 — MITM resistance
**Paper's claim:** an attacker cannot forge `M1` without guessing the
real identity, protected by `AID6LN`.
**Executable? PARTIALLY** — our tests demonstrate tamper-detection
(Proposition 9's mechanism) but a true MITM scenario (attacker
relaying/substituting between two otherwise-honest parties across a full
session) is closer to what Module 10 (Scyther, a genuine network-level
Dolev-Yao attacker) is suited to test, not a unit test. We do not
over-claim: MITM resistance beyond simple tampering is **theoretical /
Scyther's domain**, not separately unit-tested here.

### Proposition 8 — ESL resistance
**Paper's claim:** compromising ephemeral values (`RN1`, `RN2`) alone
isn't enough; the long-term-secret-hiding `AID6LN`/`Sc` are also needed.
**Executable? NO — theoretical.** Demonstrating resistance to an
ephemeral-secret-leakage adversary requires reasoning about what an
attacker *could* compute given partial knowledge, which is a
cryptographic/formal argument, not a runtime behavior our test suite (or
even Scyther's standard Dolev-Yao configuration) directly models — this
is exactly the eCK/CK-style claim Module 10 explicitly does **not**
attempt to formally verify (see Module 10's CK/eCK vs. Dolev-Yao
distinction). Flagged as theoretical-only.

### Proposition 9 — Modification resistance
**Paper's claim:** the AEAD tag detects any modification to `M1`/`M2`.
**Executable? YES** — this is the most directly testable claim; 7 of the
9 tests in `tests/test_ake_failures.py` are exactly this.

### Proposition 10 — Compromise resistance (per-sensor isolation)
**Paper's claim:** compromising one sensor's `Sc`/`Mk` doesn't expose
other sensors' data, since `AID6LN` is an alias and `CT` is
independently encrypted.
**Executable? PARTIALLY** — `tests/test_registration.py::
test_each_registration_is_unique` shows distinct sensors get distinct,
independent secrets, which is the necessary precondition; a full
"compromise one, attack another" scenario is not separately
implemented, since it follows directly from the independence already
demonstrated (each sensor's `Mk`/`Sc` are derived from independent fresh
randomness per `src/registration.py`).

### Proposition 11 — Desynchronization resistance
**Paper's claim:** the protocol resists desynchronization because both
sides verify identities/random numbers before updating stored data.
**Executable? YES** — `tests/test_ake_success.py::
test_secret_rotation_after_successful_session` shows the 6LN and 6LC
stay in sync (`record.sc == sensor.sc`) after a rotation; implicitly,
`tests/test_ake_failures.py` shows a failed session does **not** trigger
a rotation on either side (since `AuthenticationError` is raised before
the rotation code path executes in `src/ake.py`), which is exactly the
"jammed/blocked message doesn't desync state" property claimed.

---

## Summary

| Proposition | Directly testable? | Our test result |
|---|---|---|
| 1 Mutual auth | Yes | Demonstrated (positive + negative) |
| 2 PFS | Partially | Precondition shown; full proof is theoretical |
| 3 Untraceability | Yes | **Paper's claim NOT supported** — documented gap |
| 4 Replay | Yes | Demonstrated |
| 5 DoS | Yes | Demonstrated |
| 6 Impersonation | Yes | Demonstrated |
| 7 MITM | Partially | Tamper-detection shown; full MITM is Scyther's domain |
| 8 ESL | No | Theoretical only |
| 9 Modification | Yes | Demonstrated (most thoroughly tested) |
| 10 Compromise isolation | Partially | Precondition shown |
| 11 Desynchronization | Yes | Demonstrated |

**Status:** COMPLETED. This module deliberately does not re-run Module
7's tests — it cross-references them — and deliberately does not
duplicate Module 10/12's formal analyses, keeping the paper's own
three-way separation (informal / SVO / Scyther) intact.
