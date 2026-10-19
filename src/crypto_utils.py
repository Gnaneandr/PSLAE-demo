"""
crypto_utils.py
================

Low-level cryptographic helpers used throughout the PSLAE implementation.

RECONSTRUCTION NOTE (bit-length mismatches in the source paper)
-----------------------------------------------------------------
PSLAE ("Provably secured and lightweight authenticated encryption protocol
in machine-to-machine communication in industry 4.0", Ashrif et al.,
Computer Communications 218 (2024) 263-275) states that it uses a single
hash function, SHA-160 (i.e. SHA-1, which produces a fixed 160-bit / 20-byte
digest). However, the protocol description XORs SHA-1 outputs together with
operands of many different declared bit-widths in different places, e.g.:

  * AID6LN is declared 64 bits (Step RP-2).
  * "The master key Ms of 265 bits is computed by Mk = Ms XOR H(R6LC)"
    (Step RP-2) -- this sentence is self-contradictory (it describes how to
    compute Mk, not Ms, and 265 is not a multiple of 8, so it cannot be a
    byte-aligned quantity; and H() is a 160-bit SHA-1 output, which cannot be
    XORed with a value that is declared to be 265 bits without additional,
    unstated padding/truncation rules).
  * X = Mk XOR Sc is declared to be 256 bits (Section 5.1, Step RP-4), which
    implies Mk itself is (at least) 256 bits -- inconsistent with the 265-bit
    figure above, and requiring Sc (which is built from 64-bit XOR chunks,
    so is only 64 bits) to somehow be XORed against a 256-bit value.
  * Si = (Nc || Kc) is stated to be "265 bits (Nc||Kc) = 128 bits + 128 bits"
    -- 128 + 128 = 256, not 265, confirming 265 is very likely a typographical
    error for 256 throughout the paper.
  * Fr = Mk XOR H(K6LN) is later split into two 128-bit chunks Fr1, Fr2,
    implying Fr (and hence Mk) is 256 bits -- again inconsistent with a
    160-bit SHA-1 output being XORed directly against it without extension.

The paper gives NO explicit rule for reconciling a fixed 160-bit SHA-1
digest with operands that are declared 64, 128, or 256 bits, nor any rule
for XORing a 64-bit value (Sc) against a 256-bit value (Mk) as required by
X = Mk XOR Sc.

Per the task instructions, this is exactly the kind of information gap that
must be flagged rather than silently patched. The reconstruction adopted
here (and used consistently everywhere in this codebase) is:

  1. All occurrences of "265 bits" in the paper are treated as a
     typographical error for 256 bits (this is directly supported by the
     paper's own arithmetic: 128 + 128 = 256, not 265).
  2. Wherever a hash output of a specific bit-length other than the native
     160-bit SHA-1 digest is required (64, 128, or 256 bits), we derive it
     with a documented SHA-1-based KDF, `H_bits(data, nbits)`, defined below.
     This is a standard counter-mode hash-extension construction
     (H(data||0) || H(data||1) || ... truncated to nbits) and is NOT part of
     the original PSLAE paper -- it is our reconstruction, needed only
     because the paper itself never specifies how to reconcile the fixed
     160-bit SHA-1 output with its many differently-sized operands.
  3. Wherever a paper formula XORs values of genuinely different declared
     bit-lengths (e.g., Sc [64 bits] XOR Mk [256 bits] in X = Mk XOR Sc), we
     tile/repeat the shorter value to the length of the longer one before
     XORing (`tile_to`). This is the simplest, most standard convention for
     extending a short XOR mask and is flagged at every call site.

Every function below that performs one of these reconstructions is
commented at its call site in registration.py / ake.py with a pointer back
to this note.
"""

import hashlib
import hmac
import os


def sha1(data: bytes) -> bytes:
    """The paper's H(.) - plain SHA-1, native 160-bit / 20-byte output."""
    return hashlib.sha1(data).digest()


def H_bits(data: bytes, nbits: int) -> bytes:
    """
    RECONSTRUCTION (see module docstring): SHA-1-based KDF that produces
    exactly `nbits` bits of pseudorandom output, used wherever the paper's
    algebra requires a hash output of a size other than SHA-1's native 160
    bits. Not present in the original paper.
    """
    if nbits % 8 != 0:
        raise ValueError("nbits must be a multiple of 8 in this reconstruction")
    nbytes = nbits // 8
    out = b""
    counter = 0
    while len(out) < nbytes:
        out += hashlib.sha1(data + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:nbytes]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError(
            f"xor_bytes requires equal-length operands, got {len(a)} vs {len(b)} "
            f"bytes. If the paper's formula mixes different declared bit "
            f"widths, use tile_to() first (see crypto_utils module docstring)."
        )
    return bytes(x ^ y for x, y in zip(a, b))


def xor_many(*args: bytes) -> bytes:
    """XOR an arbitrary number of equal-length byte strings together."""
    result = args[0]
    for a in args[1:]:
        result = xor_bytes(result, a)
    return result


def tile_to(data: bytes, nbytes: int) -> bytes:
    """
    RECONSTRUCTION (see module docstring): repeat/tile `data` until it is
    at least `nbytes` long, then truncate to exactly `nbytes`. Used only
    where the paper XORs a short value (e.g. 64-bit Sc) against a longer
    one (e.g. 256-bit Mk) without specifying how the size mismatch should
    be resolved.
    """
    if len(data) >= nbytes:
        return data[:nbytes]
    reps = (nbytes // len(data)) + 1
    return (data * reps)[:nbytes]


def split_equal(data: bytes, n: int) -> list:
    """Split `data` into `n` equal-length chunks."""
    if len(data) % n != 0:
        raise ValueError("data length not evenly divisible")
    chunk = len(data) // n
    return [data[i * chunk:(i + 1) * chunk] for i in range(n)]


def random_bytes(nbytes: int) -> bytes:
    return os.urandom(nbytes)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
