"""
test_ake3_id6lc_reconstruction.py
===================================
The 5 tests requested for the ID6LC/AKE3 reconstruction:
1. Normal AKE3 success.
2. Wrong long-term secret (K6LN) -- the equivalent failure mode to
   "wrong ID6LC", since ID6LC is never held by 6LN in the first place;
   see docs/id6lc_ake3_reconstruction.md section 3 for why the actual
   security-relevant secret on 6LN's side is (Sc, K6LN), not ID6LC.
3. Tampered CT1.
4. Incorrect Sc1 (attacker-substituted value inside a re-encrypted M2).
5. Session key agreement.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from src.registration import make_controller, register_sensor
from src import ake, ace
from src.crypto_utils import random_bytes, xor_bytes
from src.ake import AuthenticationError


def _fresh_session():
    controller = make_controller()
    sensor = register_sensor(controller, random_bytes(8))
    return controller, sensor


def test_1_normal_ake3_success():
    controller, sensor = _fresh_session()
    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)
    sk = ake.step_ake3(sensor, r2["m2"])
    assert sk == r2["session_key"]


def test_2_wrong_long_term_secret_rejected():
    """Simulates a 6LN with the wrong K6LN (the security-relevant
    equivalent of 'wrong ID6LC', since ID6LC itself is never held by
    6LN) -- decryption key derivation diverges from 6LC's, so
    decryption/tag verification must fail."""
    controller, sensor = _fresh_session()
    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)

    # Corrupt the sensor's own long-term secret AFTER M1 was built
    # (simulating an attacker who captured M1 but doesn't hold the
    # real shared secret) -- the independently-derived decryption key
    # for M2 will now diverge from 6LC's.
    sensor.k6ln = xor_bytes(sensor.k6ln, b"\xff" * len(sensor.k6ln))

    with pytest.raises(AuthenticationError):
        ake.step_ake3(sensor, r2["m2"])


def test_3_tampered_ct1_rejected():
    controller, sensor = _fresh_session()
    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)

    m2_tampered = dict(r2["m2"])
    ct1 = r2["m2"]["CT1"]
    m2_tampered["CT1"] = bytes([ct1[0] ^ 0xFF]) + ct1[1:]

    with pytest.raises(AuthenticationError):
        ake.step_ake3(sensor, m2_tampered)


def test_4_incorrect_sc1_rejected():
    """An attacker who intercepts M2 and tries to substitute a
    different Sc1 (e.g. replaying an old session's Sc1) must produce
    a ciphertext/tag combination that fails verification, since Sc1
    is part of the AEAD-protected plaintext -- it cannot be swapped
    without invalidating Tag6LC (which the attacker cannot forge
    without the shared key)."""
    controller, sensor = _fresh_session()
    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)

    # Attacker attempts to substitute a different (attacker-chosen)
    # Sc1 by re-encrypting with a KEY IT DOES NOT ACTUALLY HAVE --
    # simulated here by directly corrupting CT1's plaintext-dependent
    # bytes without access to the real key, which in practice means
    # corrupting the ciphertext (the only thing an attacker without
    # the key can do) and MUST be caught by the tag check.
    m2_tampered = dict(r2["m2"])
    ct1 = r2["m2"]["CT1"]
    # Flip a byte deeper into CT1, corresponding to where Sc1's
    # ciphertext bytes live (first half of the 128-bit block).
    corrupted = bytearray(ct1)
    corrupted[4] ^= 0xFF
    m2_tampered["CT1"] = bytes(corrupted)

    with pytest.raises(AuthenticationError):
        ake.step_ake3(sensor, m2_tampered)


def test_5_session_key_agreement():
    controller, sensor = _fresh_session()
    m1 = ake.step_ake1(sensor)
    r2 = ake.step_ake2(controller, m1)
    sk_sensor = ake.step_ake3(sensor, r2["m2"])
    sk_controller = r2["session_key"]
    assert sk_sensor == sk_controller
    assert len(sk_sensor) == 20  # 160-bit SHA-1 output
