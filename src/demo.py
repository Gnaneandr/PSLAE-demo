"""
demo.py
=======
Runs one full PSLAE Registration + AKE session end-to-end and prints the
intermediate and final values, including proof that the 6LN and 6LC derive
the identical session key SK.
"""

from src.registration import make_controller, register_sensor
from src.ake import step_ake1, step_ake2, step_ake3
from src.crypto_utils import random_bytes


def hexs(b: bytes) -> str:
    return b.hex()


def main():
    print("=" * 70)
    print("PSLAE end-to-end demo: Registration + AKE")
    print("=" * 70)

    controller = make_controller()
    print(f"[6LC] ID6LC   = {hexs(controller.id6lc)}")
    print(f"[6LC] TID6LC  = {hexs(controller.tid6lc)}")

    id6ln = random_bytes(8)
    print(f"[6LN] ID6LN   = {hexs(id6ln)}")

    sensor = register_sensor(controller, id6ln)
    print("\n--- Registration complete ---")
    print(f"[6LN] AID6LN  = {hexs(sensor.aid6ln)}")
    print(f"[6LN] Sc      = {hexs(sensor.sc)}")
    print(f"[6LN] Mk      = {hexs(sensor.mk)}")

    print("\n--- AKE phase ---")
    m1 = step_ake1(sensor)
    print(f"[6LN -> 6LC] M1 = T6LN:{hexs(m1['T6LN'])} D:{hexs(m1['D'])} "
          f"CT:{hexs(m1['CT'])} Tag6LN:{hexs(m1['Tag6LN'])} "
          f"RN1:{hexs(m1['RN1'])}")

    result2 = step_ake2(controller, m1)
    m2 = result2["m2"]
    sk_controller = result2["session_key"]
    print(f"[6LC -> 6LN] M2 = T6C:{hexs(m2['T6C'])} A1:{hexs(m2['A1'])} "
          f"M:{hexs(m2['M'])} CT1:{hexs(m2['CT1'])} "
          f"Tag6LC:{hexs(m2['Tag6LC'])} RN2:{hexs(m2['RN2'])}")
    print(f"[6LC] Session key SK  = {hexs(sk_controller)}")

    sk_sensor = step_ake3(sensor, m2)
    print(f"[6LN] Session key SK' = {hexs(sk_sensor)}")

    assert sk_controller == sk_sensor, "Session keys DO NOT match!"
    print("\nSUCCESS: 6LN and 6LC derived the identical session key.")


if __name__ == "__main__":
    main()
