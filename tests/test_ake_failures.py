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


def _flip_byte(b: bytes, idx: int = 0) -> bytes:
    ba = bytearray(b)
    ba[idx] ^= 0xFF
    return bytes(ba)


def test_modified_ciphertext_rejected_by_controller():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    m1["CT"] = _flip_byte(m1["CT"])
    with pytest.raises(AuthenticationError):
        step_ake2(controller, m1)


def test_modified_tag_rejected_by_controller():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    m1["Tag6LN"] = _flip_byte(m1["Tag6LN"])
    with pytest.raises(AuthenticationError):
        step_ake2(controller, m1)


def test_modified_D_rejected_unknown_sensor():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    m1["D"] = _flip_byte(m1["D"])
    with pytest.raises(AuthenticationError):
        step_ake2(controller, m1)


def test_unregistered_sensor_rejected():
    controller, _ = _fresh_pair()
    rogue = register_sensor(make_controller(), random_bytes(8))  # different 6LC!
    m1 = step_ake1(rogue)
    with pytest.raises(AuthenticationError):
        step_ake2(controller, m1)


def test_modified_m2_ciphertext_rejected_by_sensor():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    m2 = result["m2"]
    m2["CT1"] = _flip_byte(m2["CT1"])
    with pytest.raises(AuthenticationError):
        step_ake3(sensor, m2)


def test_modified_m2_tag_rejected_by_sensor():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    m2 = result["m2"]
    m2["Tag6LC"] = _flip_byte(m2["Tag6LC"])
    with pytest.raises(AuthenticationError):
        step_ake3(sensor, m2)


def test_modified_a1_rejected_by_sensor():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    m2 = result["m2"]
    m2["A1"] = _flip_byte(m2["A1"])
    with pytest.raises(AuthenticationError):
        step_ake3(sensor, m2)


def test_expired_m1_timestamp_rejected():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    # simulate an old timestamp (far outside the allowed delay window)
    m1["T6LN"] = (0).to_bytes(4, "big")
    with pytest.raises(AuthenticationError):
        step_ake2(controller, m1)


def test_expired_m2_timestamp_rejected():
    controller, sensor = _fresh_pair()
    m1 = step_ake1(sensor)
    result = step_ake2(controller, m1)
    m2 = result["m2"]
    m2["T6C"] = (0).to_bytes(4, "big")
    with pytest.raises(AuthenticationError):
        step_ake3(sensor, m2)
