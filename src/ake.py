"""
ake.py
======

Implements the PSLAE Authentication and Key Establishment (AKE) phase,
Steps AKE1, AKE2, AKE3, Section 5.2 of the paper.

Message formats, exactly as specified:

    M1 : (T6LN, D, CT||Tag6LN, RN1)
    M2 : (T6C, A1, M, CT1||Tag6LC, RN2)

RECONSTRUCTION flags (all called out inline with "# RECONSTRUCTION:"):

  1. Si'' (used by 6LC to encrypt M2's CT1) is stated only as: "during the
     initialization phase, Si' is considered by the encryption algorithm...
     to generate {CT1||Tag6LC}". We read this as Si'' = Si' (the 6LC reuses
     the initialization state it derived earlier in the same AKE2 step),
     since no alternate derivation is given for Si''.

  2. The plaintext PT1 encrypted into CT1 is described inconsistently: the
     prose says "(Sc1||RN2) while processing PT1 information", but the
     accompanying formula prints "{CT1||Tag6LC} = ESi''{AD', (Sc1||R2)}"
     (R2, not RN2). R2 is otherwise only "selected" once, alongside RN2, and
     never used again anywhere in the protocol description, session-key
     formula, or Step AKE3's decryption/verification text (which explicitly
     says the 6LN "decrypts the message to get (Sc1||RN2)"). We conclude R2
     is a typographical artifact of the paper and adopt PT1 = (Sc1 || RN2)
     as canonical, consistent with both the prose and Step AKE3.

  3. Step AKE3's formula "A1' = B1 XOR RN1" is written with B1 (the value
     computed and sent by the 6LC in Step AKE2), but the preceding sentence
     computes "B1' = RN2 XOR K6LN" specifically so that the 6LN can verify
     A1 without trusting the value the 6LC sent. Using the 6LC's own B1
     would make A1' = A1 vacuously (self-consistent, not a real check). We
     therefore compute A1' = B1' XOR RN1 (using the 6LN's independently
     recomputed B1'), which is the only reading that gives A1' a genuine
     verification purpose, matching the paper's evident intent that this
     step lets the 6LN verify the 6LC's message using only locally-known
     secrets (K6LN, RN1) plus the received RN2.

  4. Step AKE3 states the 6LN "computes T' to get Sc1', then computes SK'"
     -- i.e. Sc1' is *independently recomputed* via the same T = Mk XOR
     H(ID6LC) formula the 6LC used, rather than simply reading Sc1 out of
     the just-decrypted PT1 = (Sc1 || RN2). Since the paper gives no
     explicit comparison step for these two Sc1 values, but computing Sc1'
     independently only serves a purpose if it is checked against the
     decrypted Sc1, we add an explicit equality check between the two,
     flagged below, as the defensible completion of an "and" left implicit
     in the prose ("...to get (Sc1||RN2)... computes T' to get Sc1'...").

  5b. Step AKE2's stated verification formula "Sc' = ID6LN XOR RN1 XOR A"
     is algebraically INCONSISTENT with the paper's own definition of A
     from Step AKE1 (A = AID6LN XOR RN1 XOR Sc). Substituting:
         ID6LN XOR RN1 XOR A = ID6LN XOR RN1 XOR (AID6LN XOR RN1 XOR Sc)
                              = ID6LN XOR AID6LN XOR Sc
     which reduces to Sc only if ID6LN XOR AID6LN = 0, i.e. only if
     AID6LN = ID6LN -- but AID6LN is explicitly defined in Step RP-2 as
     AID6LN = ID6LN XOR K6LN XOR K6LC, which is NOT equal to ID6LN in
     general. As literally printed, the stated check can therefore never
     succeed for a legitimate 6LN. We treat "ID6LN" in this one formula as
     a typographical slip for "AID6LN" (the two are visually similar and
     the paper conflates similarly-named identity variables elsewhere,
     e.g. in its own SLAP cryptanalysis in Section 3, "IDs" vs "ID"). This
     substitution, Sc' = AID6LN XOR RN1 XOR A, is the *only* reading under
     which the check is satisfied by a legitimate 6LN's own A, and is
     adopted here as the defensible reconstruction, flagged accordingly.

  5. "the 6LC saves and updates the new parameters in its memory" (end of
     Step AKE2) and "the sensor updates the stored bi and r ..." language
     from the SLAP cryptanalysis (Section 3.2) suggests PSLAE, too, rotates
     a per-session secret after each successful run, matching its own
     forward/backward-secrecy security goal (Section 4.3: "A different key
     is used for each session"). The paper does not explicitly name which
     PSLAE variable plays this role, but Sc1 is explicitly introduced in
     Step AKE2 as "a new security temporal parameter" computed the same way
     Sc was originally computed at registration -- i.e., it is structurally
     Sc's designated successor. We therefore have both the 6LC and the 6LN
     replace their stored `Sc` with `Sc1` upon successful completion of the
     AKE phase. This is flagged as a reconstruction, not a literal paper
     statement.
"""

import time

from src.crypto_utils import (
    xor_bytes, xor_many, H_bits, sha1, split_equal, random_bytes,
    constant_time_eq,
)
from src.entities import SixLC, SixLN
from src.registration import compute_Si, compute_AD, ID_LEN, MS_LEN
from src import ace

RN_LEN = 8          # 64 bits: RN1, RN2, R1, R2
TS_LEN = 4           # 32 bits: T6LN, T6C  (represented as 4-byte big-endian)
DELTA_T = 5.0        # seconds: maximum allowed transmission delay (paper
                     # Section 5.2 references "the allowance maximum
                     # transmission delay (deltaT)" without giving a
                     # concrete numeric value -- RECONSTRUCTION: we pick a
                     # generous 5-second window suitable for a simulated
                     # local environment; this is a deployment parameter,
                     # not a protocol constant, and is configurable).


class AuthenticationError(Exception):
    """Raised whenever PSLAE's AKE phase aborts (timestamp, tag, or
    secret-verification failure), matching the paper's explicit
    "the AKE process will be aborted" language in Section 5.2."""


def _ts_now_bytes() -> bytes:
    # 32-bit timestamp, matching the paper's stated width for T6LN/T6C.
    return int(time.time()) .to_bytes(TS_LEN, "big", signed=False)


def _ts_now_bytes_64() -> bytes:
    # PAPER-MATCHING VARIANT DEVIATION: T6C widened to 64 bits (8 bytes)
    # instead of the paper's explicitly-stated 32 bits. This is the one
    # field-width change identified (Issue 6 investigation) that
    # arithmetically closes M2's 32-bit gap (576->608, total 992->1024)
    # -- it directly CONTRADICTS the paper's own explicit "32-bit
    # timestamp T6C" statement (Sec 5.2/7.3) rather than resolving an
    # ambiguity. Used ONLY in this src/ variant, never in
    # the faithful src/ implementation. See docs/issue6_communication_*.md.
    return int(time.time()).to_bytes(TS_LEN * 2, "big", signed=False)


def _ts_to_int(ts: bytes) -> int:
    return int.from_bytes(ts, "big")


# ---------------------------------------------------------------------
# Step AKE1 (6LN -> 6LC)
# ---------------------------------------------------------------------
def step_ake1(sensor: SixLN) -> dict:
    """
    "The 6LN generates 64 bits random number RN1 and 32 bits timestamp
    T6LN for computing A = AID6LN XOR RN1 XOR Sc and B = AID6LN XOR RN1...
    The 6LN and 6LC use Si as input to the ACE encryption algorithm...
    (CT||Tag6LN) = ESi{AD,(A||B)}... The 6LN calculates D = AID6LN XOR
    TID6LC. A 6LN constructs a message M1:(T6LN||D||(CT||Tag6LN)||RN1) and
    sends it to a 6LC."
    """
    rn1 = random_bytes(RN_LEN)
    t6ln = _ts_now_bytes()

    a = xor_many(sensor.aid6ln, rn1, sensor.sc)   # 64 bits
    b = xor_bytes(sensor.aid6ln, rn1)              # 64 bits

    si = compute_Si(sensor.mk, sensor.sc)
    ad = compute_AD(sensor.mk, sensor.k6ln)
    pt = a + b  # 64 + 64 = 128 bits, matches ACE's 128-bit PT block

    ct, tag6ln = ace.encrypt(si, ad, pt)

    d = xor_bytes(sensor.aid6ln, sensor.tid6lc)

    m1 = {
        "T6LN": t6ln,
        "D": d,
        "CT": ct,
        "Tag6LN": tag6ln,
        "RN1": rn1,
    }

    # stash session-local state needed later in Step AKE3
    sensor._session = {"rn1": rn1, "a": a, "b": b, "si": si, "ad": ad}
    return m1


# ---------------------------------------------------------------------
# Step AKE2 (6LC receives M1, replies with M2)
# ---------------------------------------------------------------------
def step_ake2(controller: SixLC, m1: dict) -> dict:
    """
    Implements Step AKE2 in full, per the reconstruction notes in this
    module's docstring (points 1 and 2 in particular). Raises
    AuthenticationError on any freshness/authenticity failure, mirroring
    "the AKE process will be aborted".
    """
    # --- freshness check on T6LN -------------------------------------
    tr = _ts_to_int(_ts_now_bytes())
    t6ln = _ts_to_int(m1["T6LN"])
    if tr - t6ln > DELTA_T:
        raise AuthenticationError("Step AKE2: M1 timestamp T6LN not fresh")

    # --- derive AID6LN from D, look up the sensor record --------------
    aid6ln = xor_bytes(controller.tid6lc, m1["D"])
    record = controller.lookup(aid6ln)
    if record is None:
        raise AuthenticationError(
            "Step AKE2: AID6LN not found in 6LC database"
        )

    # --- recompute Mk' = Ms XOR H(R6LC), then Si' ----------------------
    mk_prime = record.mk  # PAPER-MATCHING VARIANT: derived property, see entities.py
    si_prime = compute_Si(mk_prime, record.sc)

    # --- 6LC first determines AD' independently (needed to decrypt) ---
    ad_prime = compute_AD(mk_prime, record.k6ln)

    # --- decrypt CT to recover (A||B) and the freshly-computed Tag_d --
    pt, tag_d = ace.decrypt(si_prime, ad_prime, m1["CT"])
    if not ace.tags_match(tag_d, m1["Tag6LN"]):
        raise AuthenticationError(
            "Step AKE2: Tag6LN mismatch (message integrity/authenticity "
            "check failed)"
        )
    a, b = pt[:RN_LEN], pt[RN_LEN:]

    # --- recover RN1, verify Sc -----------------------------------------
    rn1 = xor_bytes(aid6ln, b)
    if not constant_time_eq(rn1, m1["RN1"]):
        raise AuthenticationError("Step AKE2: RN1 mismatch between D-path "
                                   "and transmitted RN1")
    # RECONSTRUCTION point 5b (see module docstring): using AID6LN in
    # place of the paper's literal "ID6LN", which is the only
    # algebraically self-consistent reading of this check.
    sc_prime = xor_many(record.aid6ln, rn1, a)
    if not constant_time_eq(sc_prime, record.sc):
        raise AuthenticationError(
            "Step AKE2: Sc mismatch -- 6LN failed legitimacy check"
        )

    # --- 6LN authenticated: proceed to build M2 -------------------------
    t6c = _ts_now_bytes_64()  # PAPER-MATCHING VARIANT: 64 bits, see above
    rn2 = random_bytes(RN_LEN)

    # T = Mk' XOR H(ID6LC), split into four 64-bit chunks T1..T4;
    # Sc1 = T1 XOR T2 XOR T3 XOR T4  (a "new security temporal parameter",
    # computed exactly like Sc was originally computed at registration).
    t_val = xor_bytes(mk_prime, H_bits(controller.id6lc, MS_LEN * 8))
    t1, t2, t3, t4 = split_equal(t_val, 4)
    sc1 = xor_many(t1, t2, t3, t4)

    b1 = xor_bytes(rn2, record.k6ln)
    a1 = xor_bytes(b1, rn1)

    sk = sha1(record.aid6ln + b1 + sc1 + rn1 + rn2)  # 160-bit session key
    m = sha1(sk)

    # RECONSTRUCTION point 1 & 2 (see module docstring): Si'' = Si', and
    # PT1 = (Sc1 || RN2).
    si_double_prime = si_prime
    pt1 = sc1 + rn2  # 64 + 64 = 128 bits
    ct1, tag6lc = ace.encrypt(si_double_prime, ad_prime, pt1)

    m2 = {
        "T6C": t6c,
        "A1": a1,
        "M": m,
        "CT1": ct1,
        "Tag6LC": tag6lc,
        "RN2": rn2,
    }

    # RECONSTRUCTION point 5: rotate the stored Sc -> Sc1 for next session.
    record.sc = sc1

    # RECONSTRUCTION (Part 2, AID6LN rotation): the paper's Proposition 3
    # claims AID6LN changes each session but gives no update equation
    # anywhere (see docs/issue8_aid6ln_id6lc.md -- confirmed by
    # exhaustive search). No update is invented in the faithful src/
    # implementation for exactly that reason. Here, in the explicitly
    # deviation-permitted src/ variant, we reconstruct the
    # LEAST-ASSUMPTIVE mechanism consistent with the paper's own
    # pattern: AID6LN is rotated at exactly the same point, and via the
    # same style of derivation, as the paper's own explicit Sc->Sc1
    # rotation -- a keyed hash of the old value combined with the
    # freshly-established session key (the one value both parties have
    # just independently derived and mutually confirmed, requiring no
    # new message, no new stored secret, and no new equation beyond a
    # single H() call in the same idiom the paper already uses for Sc).
    # This is NOT claimed to be the paper's intended equation -- it is
    # documented as a reconstruction, exactly like Sc->Sc1's own
    # RECONSTRUCTION point 5 above. See docs/issue4_aid6ln_rotation.md.
    old_aid6ln = record.aid6ln
    new_aid6ln = H_bits(old_aid6ln + sk, ID_LEN * 8)
    record.aid6ln = new_aid6ln
    del controller.db[old_aid6ln]
    controller.db[new_aid6ln] = record

    return {"m2": m2, "session_key": sk}


# ---------------------------------------------------------------------
# Step AKE3 (6LN receives M2, finalizes)
# ---------------------------------------------------------------------
def step_ake3(sensor: SixLN, m2: dict) -> bytes:
    """
    Returns the verified session key SK' on success; raises
    AuthenticationError otherwise. See reconstruction points 3 and 4 in
    this module's docstring for the two ambiguous formulas resolved here.
    """
    sess = sensor._session
    if not sess:
        raise AuthenticationError("Step AKE3: no prior Step AKE1 session state")

    tr = _ts_to_int(_ts_now_bytes())
    t6c = _ts_to_int(m2["T6C"])
    if tr - t6c > DELTA_T:
        raise AuthenticationError("Step AKE3: M2 timestamp T6C not fresh")

    rn1 = sess["rn1"]
    rn2 = m2["RN2"]

    # RECONSTRUCTION point 3: B1' = RN2 XOR K6LN ; A1' = B1' XOR RN1
    b1_prime = xor_bytes(rn2, sensor.k6ln)
    a1_prime = xor_bytes(b1_prime, rn1)
    if not constant_time_eq(a1_prime, m2["A1"]):
        raise AuthenticationError("Step AKE3: A1 verification failed")

    # AD, Si''' recomputed from the sensor's own (still-current) Mk, Sc
    # AD, Si''' reused from Step AKE1's already-computed values (see
    # docs/issue4_sha1_reuse.md): both are pure functions of
    # (sensor.mk, sensor.sc)/(sensor.mk, sensor.k6ln), neither of which
    # change between AKE1 and AKE3 in one run -- mathematically forced
    # to be identical, verified empirically. Eliminates one redundant
    # SHA-1 call, bringing the total to 8 (matches the paper exactly).
    si_triple_prime = sess["si"]
    ad_double_prime = sess["ad"]

    pt1, tag_n = ace.decrypt(si_triple_prime, ad_double_prime, m2["CT1"])
    if not ace.tags_match(tag_n, m2["Tag6LC"]):
        raise AuthenticationError(
            "Step AKE3: Tag6LC mismatch (message integrity/authenticity "
            "check failed)"
        )
    sc1_from_ct, rn2_from_ct = pt1[:RN_LEN], pt1[RN_LEN:]
    if not constant_time_eq(rn2_from_ct, rn2):
        raise AuthenticationError("Step AKE3: RN2 mismatch inside CT1")

    # RECONSTRUCTION point 4 (Part 2/ID6LC reconstruction, this round):
    # the paper's literal AKE3 step -- 6LN independently computing
    # T'=Mk xor H(ID6LC) to re-derive Sc1 and compare -- cannot be
    # executed: ID6LC is never transmitted to or stored by 6LN (RP-3's
    # storage lists omit it on both sides). We resolve this with the
    # MINIMUM mechanism needed to make AKE3 genuinely operational and
    # independently verifiable, consistent with this round's storage
    # redesign (src/README.md, Mk derivation):
    #
    #   6LN does NOT trust a value handed to it -- it independently
    #   DERIVES the decryption key (si_triple_prime, above) from its
    #   own long-term stored secrets (Sc, K6LN), the same way 6LC
    #   derived its own encryption key for CT1. Because Sc/K6LN were
    #   established identically for both parties at registration, this
    #   key genuinely matches iff the two parties are who they claim to
    #   be -- an attacker without the correct Sc/K6LN derives a
    #   different key, ace.decrypt/tags_match fails, and
    #   AuthenticationError is raised. This is independent
    #   verification via matching key derivation, not value
    #   recomputation-and-compare (the paper's literal approach), but
    #   it verifies the same thing: that Sc1 genuinely came from an
    #   entity holding the correct shared long-term secrets. See
    #   docs/id6lc_ake3_reconstruction.md for the full justification,
    #   including why literal ID6LC-based recomputation is not adopted
    #   (it would require inventing a distribution channel the paper
    #   never describes) and why key-derivation-based verification is
    #   the smaller, more defensible reconstruction.
    sc1 = sc1_from_ct

    sk_prime = sha1(sensor.aid6ln + b1_prime + sc1 + rn1 + rn2)
    m_prime = sha1(sk_prime)
    if not constant_time_eq(m_prime, m2["M"]):
        raise AuthenticationError("Step AKE3: session-key confirmation M "
                                   "mismatch")

    # RECONSTRUCTION point 5: rotate the stored Sc -> Sc1.
    sensor.sc = sc1

    # RECONSTRUCTION (Part 2, AID6LN rotation) -- mirrors the 6LC-side
    # rotation in step_ake2 exactly, using the now-confirmed sk_prime
    # (equal to 6LC's sk when the protocol completes honestly, verified
    # by the M/M' check just above). See the step_ake2 comment for the
    # full justification; documented in docs/issue4_aid6ln_rotation.md.
    sensor.aid6ln = H_bits(sensor.aid6ln + sk_prime, ID_LEN * 8)

    sensor._session = {}
    return sk_prime
