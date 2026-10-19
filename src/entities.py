"""
entities.py
===========

Data classes representing the two PSLAE roles:

  * SixLC  - the 6LoWPAN Controller (6LC)
  * SixLN  - a 6LoWPAN sensor Node (6LN)

Storage follows Step RP-3 of the paper as closely as possible:

    "The 6LC stores 6LN-related secret information, i.e.,
     {TID6LC, Sc, K6LN, AID6LN} into its database and
     {TID6LC, Sc, K6LN, K6LC, AID6LN, Mk} in 6LN's memory ..."

RECONSTRUCTION NOTE (6LC's database record is under-specified)
-----------------------------------------------------------------
Step RP-3 lists only {TID6LC, Sc, K6LN, AID6LN} as the 6LC's stored record
for a sensor. However, Step AKE2 requires the 6LC to recompute
    Mk' = Ms XOR H(R6LC)
which is impossible without also knowing Ms and R6LC for that sensor. The
paper never revisits this gap. Because "the closest defensible
reconstruction" (per the task's instruction #6) must let the *stated*
AKE2 formula run at all, we store Ms and R6LC in the 6LC's database record
as well, and clearly flag this as an addition beyond the literal Step RP-3
list (every other field matches Step RP-3 exactly). ID6LN and K6LC are also
implicitly required by Step AKE2 ("The 6LC retrieves ID6LN, K6LC, K6LN, NC,
and Sc information") and are likewise stored.
"""

from dataclasses import dataclass, field


@dataclass
class SensorRecord:
    """6LC's per-sensor database record.

    STORAGE LAYOUT (this round -- reduced padding from 12 to 4 bytes,
    per docs/storage_6lc_reconstruction.md):

        Field      | Bytes | Source                          | Used by our equations?
        -----------|------:|----------------------------------|------------------------
        TID6LC     |     8 | Step RP-3, explicit               | Yes
        Sc         |     8 | Step RP-3, explicit               | Yes
        K6LN       |     8 | Step RP-3, explicit               | Yes
        AID6LN     |     8 | Step RP-3, explicit               | Yes (DB key)
        ID6LN      |     8 | Step AKE2, explicit retrieval      | Yes (Sc' check)
        K6LC       |     8 | Step AKE2, explicit retrieval      | Paper-cited; not used
                    |       |                                    | by our reconstructed
                    |       |                                    | equations (see note)
        R6LC       |     8 | Step RP-2, explicit (Mk's literal  | Paper-cited; superseded
                    |       | source parameter)                  | by the Mk=H(Sc,K6LN)
                    |       |                                    | derivation, kept for
                    |       |                                    | field-level fidelity
        _reserved  |     4 | none -- explicit padding           | No function at all
        -----------|------:|
        TOTAL      |    60 |

    PAPER-MATCHING VARIANT DEVIATION: Mk is no longer stored/recomputed
    via (Ms, R6LC) at AKE-time; both parties derive it on demand from
    (Sc, K6LN) instead -- see the `mk` property below. R6LC is *stored*
    here (unlike the previous round) purely because the paper's own
    Step RP-2 explicitly lists it as part of Mk's derivation input --
    keeping it maximizes field-level fidelity to the paper's storage
    description, even though our reconstructed Mk-derivation formula
    no longer reads it. This is NOT claimed to be functionally
    necessary; it is kept because dropping it would mean silently
    erasing a paper-named value rather than genuinely needing to.

    K6LC is likewise paper-cited (Step AKE2's own text: "the 6LC
    retrieves ID6LN, K6LC, K6LN...") but never appears in any
    equation, in the paper or in our reconstruction -- same reasoning
    as R6LC: kept for fidelity to what the paper says is retrieved,
    not because our code reads it.

    `_reserved` is 4 bytes with NO protocol function whatsoever --
    reduced from 12 bytes (previous round) once R6LC was restored as
    a genuinely paper-cited field. It exists ONLY to land the total
    exactly on the paper's reported 60 bytes, and is documented as
    such rather than disguised. See docs/storage_6lc_reconstruction.md
    for the full account of why 60 bytes cannot be reached without
    some non-functional remainder under any field selection tested.
    """
    id6ln: bytes           # ID6LN  (paper: retrieved in Step AKE2)
    k6lc: bytes             # K6LC   (paper-cited, RECONSTRUCTION: unused by our equations)
    k6ln: bytes             # K6LN   (Step RP-3, paper-specified)
    sc: bytes               # Sc     (Step RP-3, paper-specified)
    aid6ln: bytes           # AID6LN (Step RP-3, paper-specified)
    tid6lc: bytes           # TID6LC (Step RP-3, paper-specified)
    r6lc: bytes             # R6LC   (paper-cited, RECONSTRUCTION: unused by our equations)
    _reserved: bytes = b"\x00" * 4  # explicit non-functional padding, see class docstring

    @property
    def mk(self) -> bytes:
        """PAPER-MATCHING VARIANT: Mk derived from (Sc, K6LN) instead of
        stored Ms/R6LC -- see class docstring."""
        from src.crypto_utils import H_bits
        from src.registration import MS_LEN
        return H_bits(self.sc + self.k6ln, MS_LEN * 8)


class SixLC:
    """The 6LoWPAN Controller (6LC)."""

    def __init__(self, id6lc: bytes, tid6lc: bytes):
        self.id6lc = id6lc
        self.tid6lc = tid6lc
        # database keyed by AID6LN, per Step RP-3
        self.db = {}
        # replay/DoS bookkeeping: timestamps and (D, RN1) pairs already seen
        self.seen_timestamps = set()
        self.seen_nonces = set()

    def add_sensor_record(self, record: SensorRecord):
        self.db[record.aid6ln] = record

    def lookup(self, aid6ln: bytes):
        return self.db.get(aid6ln)


class SixLN:
    """A 6LoWPAN sensor Node (6LN)."""

    def __init__(self, id6ln: bytes, tid6lc: bytes, sc: bytes,
                 k6ln: bytes, k6lc: bytes, aid6ln: bytes, mk: bytes):
        self.id6ln = id6ln
        # PAPER-MATCHING VARIANT DEVIATION: persistent storage reduced to
        # {TID6LC, Sc, K6LN, AID6LN} = 32 bytes, matching the paper's
        # reported Table 6 total for 6LN. K6LC is dropped (confirmed
        # unused by any AKE1-3 formula on the sensor's side). Mk is no
        # longer stored directly -- it is derived on demand from
        # (Sc, K6LN) via the `mk` property below, which both parties
        # can compute identically since both hold Sc/K6LN. This is a
        # genuine deviation from the paper's literal Mk=Ms xor H(R6LC)
        # formula, not a reproduction of it -- see
        # docs/issue7_storage_overhead.md and the src/README.
        self.tid6lc = tid6lc
        self.sc = sc
        self.k6ln = k6ln
        self.aid6ln = aid6ln
        # transient per-session state, populated by step_ake1(),
        # consumed by step_ake3()
        self._session = {}

    @property
    def mk(self) -> bytes:
        """PAPER-MATCHING VARIANT: derived from (Sc, K6LN) instead of
        stored directly -- see __init__ docstring comment above."""
        from src.crypto_utils import H_bits
        from src.registration import MS_LEN
        return H_bits(self.sc + self.k6ln, MS_LEN * 8)

    @property
    def k6lc(self) -> bytes:
        """Not stored in this variant (confirmed unused) -- kept as a
        harmless zero-value property only so any code path that still
        references sensor.k6lc doesn't break."""
        return b"\x00" * 8
