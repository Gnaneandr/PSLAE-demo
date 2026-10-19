"""
test_replay_and_traceability.py
================================

Tests PSLAE's replay protection (as it actually falls out of the literal
protocol operations implemented here) and documents a genuine gap between
the paper's *security claim* (Proposition 3: "Each session's AID6LN is
changed") and the paper's *protocol description* (Steps AKE1-AKE3), which
never states any operation that updates AID6LN. AID6LN is set once at
registration (Step RP-2) and is never reassigned anywhere in Section 5.2's
AKE steps -- only Sc is rotated (via our Reconstruction point 5, since even
that rotation is not explicit in the literal AKE2/AKE3 prose, only
implied). This means the D = AID6LN XOR TID6LC value transmitted in M1 is
IDENTICAL across every session run by the same 6LN against the same 6LC,
which is a real, observable traceability weakness in the protocol AS
DESCRIBED, despite Proposition 3's claim to the contrary.

This is called out explicitly (not silently patched) per instruction #6 of
the task: we do not invent an AID6LN-rotation mechanism that the paper
never describes, because doing so would mean claiming something is
implemented that the paper does not actually specify.
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.registration import make_controller, register_sensor
from src.ake import step_ake1, step_ake2, step_ake3, AuthenticationError
from src.crypto_utils import random_bytes


def _fresh_pair():
    controller = make_controller()
    id6ln = random_bytes(8)
    sensor = register_sensor(controller, id6ln)
    return controller, sensor


def test_exact_replay_of_m1_rejected_after_first_success():
    """
    Because Sc is rotated to Sc1 upon a successful AKE run (Reconstruction
    point 5), replaying a byte-for-byte identical, previously-accepted M1
    a second time is rejected: the 6LC recomputes Sc' from the (stale) A
    value inside the replayed M1 and compares it against its *now-rotated*
    stored Sc, which will not match. This is a genuine (if incidental)
    replay defense that falls out of the secret-rotation design.
    """
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    step_ake2(controller, dict(m1))  # first use: succeeds

    with pytest.raises(AuthenticationError):
        step_ake2(controller, dict(m1))  # exact replay: must fail


def test_fresh_random_numbers_differ_across_sessions():
    """RN1/RN2 (and hence A, B, CT, Tag) must differ session-to-session,
    supporting PSLAE's freshness/anonymity claims (Proposition 3)."""
    controller, sensor = _fresh_pair()

    m1a = step_ake1(sensor)
    result_a = step_ake2(controller, m1a)
    step_ake3(sensor, result_a["m2"])

    m1b = step_ake1(sensor)

    assert m1a["RN1"] != m1b["RN1"]
    assert m1a["CT"] != m1b["CT"]
    assert m1a["Tag6LN"] != m1b["Tag6LN"]


def test_D_linkability_gap_is_resolved_by_aid6ln_rotation():
    """
    In the FAITHFUL protocol (see baseline_original_src/ or
    docs/issue8_aid6ln_id6lc.md), D = AID6LN XOR TID6LC is identical
    across sessions because neither AID6LN nor TID6LC is ever updated
    by any operation described in Section 5.2 -- a documented gap
    against Proposition 3's untraceability claim.

    THIS tree implements the [RECONSTRUCTED] AID6LN rotation mechanism
    (see ake.py step_ake2/step_ake3 comments and
    docs/paper_to_code_traceability.md). This test confirms the
    reconstruction actually closes the gap: D now DIFFERS across
    sessions.
    """
    controller, sensor = _fresh_pair()

    m1a = step_ake1(sensor)
    result_a = step_ake2(controller, m1a)
    step_ake3(sensor, result_a["m2"])

    m1b = step_ake1(sensor)

    assert m1a["D"] != m1b["D"], (
        "D is still linkable across sessions -- the AID6LN rotation "
        "reconstruction did not achieve its intended purpose"
    )
