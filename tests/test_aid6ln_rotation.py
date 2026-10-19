"""
test_aid6ln_rotation.py
========================
Tests the src/ variant's AID6LN rotation mechanism
(Part 2 of the full-reproduction task; see the RECONSTRUCTION comment
in src/ake.py::step_ake2/step_ake3 and
docs/issue4_aid6ln_rotation.md for the full justification).

NOT applicable to the faithful src/ implementation, which correctly
does NOT rotate AID6LN (see docs/issue8_aid6ln_id6lc.md) since the
paper provides no update equation.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from src.registration import make_controller, register_sensor
from src import ake
from src.crypto_utils import random_bytes


def _fresh_session():
    controller = make_controller()
    sensor = register_sensor(controller, random_bytes(8))
    return controller, sensor


def test_aid6ln_rotates_after_one_session():
    controller, sensor = _fresh_session()
    aid_initial = sensor.aid6ln

    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)
    sk = ake.step_ake3(sensor, r2["m2"])

    assert sk == r2["session_key"]
    assert sensor.aid6ln != aid_initial, "AID6LN did not change after Session 1"


def test_aid6ln_differs_across_two_consecutive_sessions():
    controller, sensor = _fresh_session()

    m1a = ake.step_ake1(sensor)
    r2a = ake.step_ake2(controller, m1a)
    ake.step_ake3(sensor, r2a["m2"])
    aid_after_session1 = sensor.aid6ln

    m1b = ake.step_ake1(sensor)
    r2b = ake.step_ake2(controller, m1b)
    ake.step_ake3(sensor, r2b["m2"])
    aid_after_session2 = sensor.aid6ln

    assert aid_after_session1 != aid_after_session2, \
        "AID6LN identical across two consecutive sessions (A1 == A2)"


def test_authentication_succeeds_after_rotation():
    """Confirms the protocol keeps working correctly across a rotation,
    not just that the value changes."""
    controller, sensor = _fresh_session()

    for _ in range(3):
        m1 = ake.step_ake1(sensor)
        r2 = ake.step_ake2(controller, m1)
        sk = ake.step_ake3(sensor, r2["m2"])
        assert sk == r2["session_key"]


def test_controller_db_rekeyed_correctly():
    """The controller's database is keyed by AID6LN (Step RP-3) -- after
    rotation, lookups by the OLD key must fail and by the NEW key must
    succeed, with no duplicate/stale entries left behind."""
    controller, sensor = _fresh_session()
    aid_initial = sensor.aid6ln
    assert controller.lookup(aid_initial) is not None

    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)
    ake.step_ake3(sensor, r2["m2"])

    assert controller.lookup(aid_initial) is None, \
        "Stale entry for old AID6LN still present after rotation"
    assert controller.lookup(sensor.aid6ln) is not None, \
        "No entry found for new (rotated) AID6LN"
    assert len(controller.db) == 1, \
        "Rotation left more than one record for a single sensor"


def test_rotation_closes_the_D_linkability_gap():
    """Direct evidence that this mechanism fixes the specific
    untraceability weakness documented in docs/issue8_aid6ln_id6lc.md
    (D = AID6LN xor TID6LC is provably static across sessions in the
    faithful baseline, since AID6LN never rotates there)."""
    controller, sensor = _fresh_session()

    m1_session1 = ake.step_ake1(sensor)
    d_session1 = m1_session1["D"]
    r2 = ake.step_ake2(controller, m1_session1)
    ake.step_ake3(sensor, r2["m2"])

    m1_session2 = ake.step_ake1(sensor)
    d_session2 = m1_session2["D"]

    assert d_session1 != d_session2, (
        "D is still linkable across sessions even after AID6LN rotation "
        "-- rotation mechanism did not achieve its purpose"
    )


def test_multiple_sensors_independently_rotate_without_collision():
    controller = make_controller()
    s1 = register_sensor(controller, random_bytes(8))
    s2 = register_sensor(controller, random_bytes(8))

    for sensor in (s1, s2):
        m1 = ake.step_ake1(sensor)
        r2 = ake.step_ake2(controller, m1)
        sk = ake.step_ake3(sensor, r2["m2"])
        assert sk == r2["session_key"]

    assert s1.aid6ln != s2.aid6ln
    assert len(controller.db) == 2
    assert controller.lookup(s1.aid6ln) is not None
    assert controller.lookup(s2.aid6ln) is not None


# ---------------------------------------------------------------------
# Part 3 -- dedicated test for ID6LC handling in AKE3 (see the
# RECONSTRUCTION point 4 comment in ake.py::step_ake3 for the full
# trace: ID6LC is never transmitted to or stored by 6LN anywhere in
# the paper's own RP-3 storage lists, so Step AKE3's literal
# T'=Mk xor H(ID6LC) cannot execute; the implementation instead
# trusts sc1_from_ct, the Sc1 value recovered from AEAD-authenticated
# decryption of CT1, which is already tamper-evident via the Tag6LC
# check performed immediately before it is used).
# ---------------------------------------------------------------------

def test_ake3_does_not_require_id6lc_and_still_authenticates():
    """6LN never receives or stores ID6LC anywhere (confirmed: SixLN has
    no id6lc attribute at all), yet AKE3 completes and authenticates
    correctly -- proving the Sc1-from-decryption substitute is
    sufficient without the missing value."""
    controller, sensor = _fresh_session()
    assert not hasattr(sensor, "id6lc"), (
        "6LN unexpectedly has an id6lc attribute -- ID6LC should never "
        "be transmitted to or stored by 6LN per Step RP-3's own lists"
    )

    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)
    sk = ake.step_ake3(sensor, r2["m2"])
    assert sk == r2["session_key"]


def test_ake3_sc1_integrity_is_still_enforced_without_id6lc():
    """The AEAD tag check (not an independent ID6LC-based recomputation)
    is what actually protects Sc1's integrity here -- confirm a
    tampered CT1 (which changes the decrypted Sc1) is still detected
    and rejected, proving the substitute preserves the intended
    security property even though it uses a different mechanism than
    the paper's literal (unexecutable) description."""
    controller, sensor = _fresh_session()
    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)

    m2_tampered = dict(r2["m2"])
    tampered_ct1 = bytes([r2["m2"]["CT1"][0] ^ 0xFF]) + r2["m2"]["CT1"][1:]
    m2_tampered["CT1"] = tampered_ct1

    with pytest.raises(ake.AuthenticationError):
        ake.step_ake3(sensor, m2_tampered)
