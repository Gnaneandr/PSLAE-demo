import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.registration import make_controller, register_sensor
from src.crypto_utils import random_bytes, xor_many


def test_registration_creates_matching_records():
    controller = make_controller()
    id6ln = random_bytes(8)
    sensor = register_sensor(controller, id6ln)

    record = controller.lookup(sensor.aid6ln)
    assert record is not None, "6LC must be able to look up sensor by AID6LN"
    assert record.k6ln == sensor.k6ln
    assert record.sc == sensor.sc
    assert record.tid6lc == sensor.tid6lc == controller.tid6lc
    assert record.id6ln == id6ln


def test_aid6ln_matches_definition():
    controller = make_controller()
    id6ln = random_bytes(8)
    sensor = register_sensor(controller, id6ln)
    record = controller.lookup(sensor.aid6ln)
    expected = xor_many(id6ln, record.k6ln, record.k6lc)
    assert sensor.aid6ln == expected


def test_each_registration_is_unique():
    controller = make_controller()
    id6ln = random_bytes(8)
    sensor1 = register_sensor(controller, id6ln)
    sensor2 = register_sensor(controller, id6ln)
    # Fresh random K6LN/K6LC/R6LC/Ms each time -> different AID6LN, Sc, Mk
    assert sensor1.aid6ln != sensor2.aid6ln
    assert sensor1.sc != sensor2.sc
    assert sensor1.mk != sensor2.mk


def test_bad_id_length_rejected():
    controller = make_controller()
    try:
        register_sensor(controller, b"short")
        assert False, "expected ValueError for wrong-length ID6LN"
    except ValueError:
        pass
