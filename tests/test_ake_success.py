import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.registration import make_controller, register_sensor
from src.ake import step_ake1, step_ake2, step_ake3
from src.crypto_utils import random_bytes


def _fresh_pair():
    controller = make_controller()
    id6ln = random_bytes(8)
    sensor = register_sensor(controller, id6ln)
    return controller, sensor


def test_full_ake_session_key_agreement():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    sk_controller = result["session_key"]
    sk_sensor = step_ake3(sensor, result["m2"])
    assert sk_controller == sk_sensor
    assert len(sk_controller) == 20  # SHA-1 160-bit output


def test_ake1_message_shape():
    _, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    for key, expected_len in [
        ("T6LN", 4), ("D", 8), ("CT", 16), ("Tag6LN", 16), ("RN1", 8)
    ]:
        assert len(m1[key]) == expected_len, f"{key} wrong length"


def test_ake2_message_shape():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    m2 = result["m2"]
    for key, expected_len in [
        # T6C: 8 bytes (64 bits) -- [RECONSTRUCTED FIELD SIZE], see
        # docs/communication_overhead_reconstruction.md. Widened from
        # the paper's stated 32 bits to arithmetically reproduce the
        # paper's own reported M2=608/Total=1024 bit totals.
        ("T6C", 8), ("A1", 8), ("M", 20), ("CT1", 16), ("Tag6LC", 16),
        ("RN2", 8),
    ]:
        assert len(m2[key]) == expected_len, f"{key} wrong length"


def test_secret_rotation_after_successful_session():
    """RECONSTRUCTION point 5 (see ake.py docstring): Sc is rotated to Sc1
    after a successful AKE run, on both sides, and remains synchronized."""
    controller, sensor = _fresh_pair()
    sc_before = sensor.sc
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    step_ake3(sensor, result["m2"])

    record = controller.lookup(sensor.aid6ln)
    assert sensor.sc != sc_before
    assert record.sc == sensor.sc, "6LN and 6LC must stay in sync after rotation"


def test_two_consecutive_sessions_succeed_after_rotation():
    """Verifies that after Sc rotates, a second full AKE session still
    succeeds (i.e. the rotation is consistent and not one-shot)."""
    controller, sensor = _fresh_pair()

    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    sk1_c = result["session_key"]
    sk1_s = step_ake3(sensor, result["m2"])
    assert sk1_c == sk1_s

    m1_b = step_ake1(sensor)
    result_b = step_ake2(controller, m1_b)
    sk2_c = result_b["session_key"]
    sk2_s = step_ake3(sensor, result_b["m2"])
    assert sk2_c == sk2_s

    assert sk1_c != sk2_c, "each session must derive a fresh session key"
