"""
registration.py
================

Implements the PSLAE Registration Phase, Steps RP-1 .. RP-5, Section 5.1.

Bit-width conventions adopted (see crypto_utils.py module docstring for the
full reconstruction rationale on the 265-bit / 256-bit / 160-bit mismatches
in the original paper):

    ID6LN, ID6LC, K6LN, K6LC, R6LC, AID6LN   : 64 bits (8 bytes)
    Ms, Mk, Sm, X                             : 256 bits (32 bytes)
    Sc1, Sc2, Sc3, Sc4, Sc                    : 64 bits (8 bytes) each
    Nc, Kc                                    : 128 bits (16 bytes) each
    Si = Nc || Kc                             : 256 bits (32 bytes)
    Fr, Fr1, Fr2                              : Fr = 256 bits, split into
                                                 two 128-bit (16-byte) halves
    AD                                        : 128 bits (16 bytes)

RECONSTRUCTION flags are called out inline with "# RECONSTRUCTION:" comments
at each point where the paper's text is ambiguous or internally
inconsistent, per instruction #6 of the task.
"""

from src.crypto_utils import (
    xor_bytes, xor_many, H_bits, tile_to, split_equal, random_bytes,
)
from src.entities import SixLC, SixLN, SensorRecord

ID_LEN = 8       # 64 bits: ID6LN, ID6LC, K6LN, K6LC, R6LC, AID6LN
MS_LEN = 32      # 256 bits -- RECONSTRUCTION of the paper's "265 bits" (see
                 # crypto_utils.py docstring: 128+128=256 confirms this is a
                 # typo for 256, not 265)
SC_CHUNK_LEN = 8  # 64 bits
NC_KC_LEN = 16   # 128 bits each


def make_controller(id6lc: bytes = None, tid6lc: bytes = None) -> SixLC:
    """Create a fresh 6LC with its own identity and temporary identity."""
    id6lc = id6lc or random_bytes(ID_LEN)
    tid6lc = tid6lc or random_bytes(ID_LEN)
    return SixLC(id6lc=id6lc, tid6lc=tid6lc)


def register_sensor(controller: SixLC, id6ln: bytes) -> SixLN:
    """
    Runs Steps RP-1 through RP-5 for a single sensor, over an (assumed)
    secure channel, and returns the fully-provisioned SixLN object. The
    corresponding database record is stored in `controller.db`.
    """
    if len(id6ln) != ID_LEN:
        raise ValueError(f"ID6LN must be {ID_LEN} bytes (64 bits)")

    # ---- Step RP-1 -------------------------------------------------
    # "The 6LC receives the 6LN real identity ID6LN via a secure channel,
    #  then pick up a unique real identity ID6LC, a random number R6LC,
    #  and K6LC, K6LN of 6LC and 6LN. TID6LC is the temporary identity of
    #  the 6LC."
    r6lc = random_bytes(ID_LEN)
    k6lc = random_bytes(ID_LEN)
    k6ln = random_bytes(ID_LEN)
    tid6lc = controller.tid6lc

    # ---- Step RP-2 ---------------------------------------------------
    # "A unique alias one-time identity (AID6LN) of 64 bits for the 6LN is
    #  computed AID6LN = ID6LN XOR K6LN XOR K6LC."
    aid6ln = xor_many(id6ln, k6ln, k6lc)

    # "The master key Ms of 265 bits is computed by Mk = Ms XOR H(R6LC)."
    # RECONSTRUCTION: as discussed in crypto_utils.py, we treat "265 bits"
    # as a typo for 256 bits, and note that this sentence literally
    # describes how *Mk* (not Ms) is computed. We therefore generate Ms as
    # a fresh 256-bit secret at registration time (it is never described as
    # being derived from anything else in the paper, so it must originate
    # as either a fresh random value or a value fixed for the 6LC; we take
    # the more general/secure reading and generate it fresh per sensor),
    # and derive Mk from it as literally stated: Mk = Ms XOR H(R6LC), where
    # H(R6LC) is extended to 256 bits via H_bits() (see crypto_utils.py).
    # PAPER-MATCHING VARIANT DEVIATION: ms/r6lc/mk_reg are used ONLY
    # internally here, to derive Sc exactly as the paper's own Sm/Sc
    # formulas require -- they are NOT stored anywhere afterward. The
    # Mk value actually used during AKE1-3 is instead derived from
    # (Sc, K6LN) via SixLN.mk / SensorRecord.mk properties (see
    # entities.py), which both parties can compute identically without
    # storing Ms/R6LC/Mk at all. This breaks the paper's literal
    # Mk=Ms xor H(R6LC) relationship (the AKE-time Mk is a different
    # value from this registration-time mk_reg) but is internally
    # consistent end-to-end and reduces storage to match the paper's
    # reported Table 6 totals. See docs/issue7_storage_overhead.md.
    ms = random_bytes(MS_LEN)
    mk_reg = xor_bytes(ms, H_bits(r6lc, MS_LEN * 8))

    # "the 6LC computes its secret parameter by computing Sm = Mk XOR
    #  H(ID6LN) and calculating Sc = Sc1 XOR Sc2 XOR Sc3 XOR Sc4, where
    #  Sc1, Sc2, Sc3, and Sc4 are 64-bit chunks divided into four equal
    #  parts of Sm."
    # RECONSTRUCTION: H(ID6LN) extended to 256 bits to match Mk's width
    # (see crypto_utils.py docstring) so the XOR is well-defined.
    sm = xor_bytes(mk_reg, H_bits(id6ln, MS_LEN * 8))
    sc1, sc2, sc3, sc4 = split_equal(sm, 4)  # four 64-bit (8-byte) chunks
    sc = xor_many(sc1, sc2, sc3, sc4)

    # ---- Step RP-3 -----------------------------------------------------
    # "The 6LC stores 6LN-related secret information, i.e., {TID6LC, Sc,
    #  K6LN, AID6LN} into its database and {TID6LC, Sc, K6LN, K6LC,
    #  AID6LN, Mk} in 6LN's memory by utilizing a secure channel."
    # RECONSTRUCTION: the 6LC's record additionally stores id6ln, k6lc,
    # ms, and r6lc -- required by Step AKE2's formulas but not listed in
    # the literal Step RP-3 sentence. See entities.py module docstring.
    record = SensorRecord(
        id6ln=id6ln, k6lc=k6lc, k6ln=k6ln, sc=sc,
        aid6ln=aid6ln, tid6lc=tid6lc, r6lc=r6lc,
    )
    controller.add_sensor_record(record)

    sensor = SixLN(
        id6ln=id6ln, tid6lc=tid6lc, sc=sc, k6ln=k6ln, k6lc=k6lc,
        aid6ln=aid6ln, mk=None,  # mk is now a derived property, see entities.py
    )

    # ---- Steps RP-4 / RP-5 ---------------------------------------------
    # These two steps describe how Si and AD are *computed* from the
    # stored secrets; they do not add new stored state. They are
    # implemented as reusable helper functions below (compute_Si,
    # compute_AD) and are invoked identically during Registration
    # (conceptually) and at every AKE step, per "Remark 2": "6LC stores
    # secret credential information in 6LN's memory during registration.
    # PSLAE computes Si, the initialization phase of the encryption
    # algorithm, and the associative data AD generation processing using
    # these secrets, as discussed in Step RP-4 and Step RP-5. Decryption
    # is performed at the receiver's side using the same process."
    return sensor


def compute_Si(mk: bytes, sc: bytes):
    """
    Step RP-4: X = Mk XOR Sc (256 bits); Si = (Nc || Kc) = 128+128 bits,
    split from X.

    RECONSTRUCTION: Sc is 64 bits (8 bytes) but Mk is 256 bits (32 bytes).
    The paper does not specify how to XOR values of different declared
    widths here; we tile Sc to 256 bits (repeating it 4 times) before
    XORing, per the tile_to() convention documented in crypto_utils.py.
    """
    x = xor_bytes(mk, tile_to(sc, MS_LEN))
    nc, kc = split_equal(x, 2)  # two 128-bit (16-byte) halves
    from src.ace import init_state
    si = init_state(nc, kc)
    return si


def compute_AD(mk: bytes, k6ln: bytes):
    """
    Step RP-5: Fr = Mk XOR H(K6LN); Fr1, Fr2 = two 128-bit halves of Fr;
    AD = Fr1 XOR Fr2 (128 bits).

    RECONSTRUCTION: H(K6LN) extended to 256 bits (Fr's width) via
    H_bits(), per crypto_utils.py.
    """
    fr = xor_bytes(mk, H_bits(k6ln, MS_LEN * 8))
    fr1, fr2 = split_equal(fr, 2)  # two 128-bit (16-byte) halves
    ad = xor_bytes(fr1, fr2)
    return ad
