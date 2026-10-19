"""
ace.py
======

Implementation of the ACE (Authenticated Encryption and hash) primitive
interface as described in Section 4.4 and used throughout Section 5 of the
PSLAE paper.

RECONSTRUCTION NOTE (ACE internal permutation not specified in the paper)
-----------------------------------------------------------------------------
The paper explicitly identifies "ACE" as an *external* algorithm: "The ACE
... algorithm used for this study was selected from the first round of the
NIST lightweight cryptography competition" (Section 4.4). ACE is a real,
published NIST-LWC round-1 submission (a sponge construction built on a
320-bit permutation, by Aagaard, Fan, Gong et al.). The PSLAE paper itself
does NOT reproduce ACE's internal permutation, round function, or sponge
parameters anywhere -- it only specifies the EXTERNAL INTERFACE that PSLAE
relies on:

    Si <- ACE(Nc || Kc)                     # initialization state,
                                             # Nc, Kc each 128 bits
    (CT || Tag) = E_Si{AD, PT}               # encryption
    (PT || Tag') = D_Si{AD, CT}              # decryption
    CT, PT, Tag each 128 bits.

Per instruction #6/#7 of the task: because the paper does not provide the
ACE permutation itself (it is out-of-paper, external, cited work), we
cannot reproduce ACE bit-for-bit. We therefore implement a **faithful
reconstruction of the described AEAD interface and its stated structural
property** ("inverse-free": PT is always recoverable from CT via the
keystream operation regardless of whether the authentication tag matches,
so tag verification is a separate, explicit step performed by the caller --
this is exactly how Section 5.2 / Fig. 4 describes PSLAE using ACE, e.g.
"the proposed AKE cannot authenticate if the communicated message has been
modified, resulting in a difference in the generated authentication tag"),
using a standard, well-vetted, NIST-approved substitute construction:

    * Keystream / PT<->CT transform: AES-128 in CTR mode, keyed by the
      128-bit Kc half of Si, using the 128-bit Nc half of Si as the
      nonce/counter block. This gives an "inverse-free" stream cipher
      exactly like the paper's description (PT XOR keystream = CT, and
      CT XOR keystream = PT, deterministically, independent of AD).
    * Authentication tag: Tag = HMAC-SHA256(Kc, AD || CT) truncated to
      128 bits. This gives the AEAD "authenticate AD and CT together"
      property PSLAE requires (Section 4.4), and is verified as a
      constant-time compare by the caller (registration.py / ake.py),
      matching the paper's description that PSLAE explicitly compares the
      received tag to a freshly generated one after decryption.

This substitution is clearly labelled here and at every call site. It is
NOT the authors' ACE permutation -- it is a drop-in AEAD with matching
interface (128-bit key/nonce/CT/PT/Tag) and matching structural semantics,
built entirely from standard primitives (AES-CTR + HMAC-SHA256) because the
real ACE permutation is not reproducible from the information given in the
paper.
"""

from Crypto.Cipher import AES
from src.crypto_utils import hmac_sha256, constant_time_eq

TAG_LEN = 16   # 128 bits
BLOCK_LEN = 16  # 128 bits (CT, PT, AD are all 128 bits per the paper)


def _keystream_cipher(Kc: bytes, Nc: bytes):
    """
    AES-128-CTR keyed by Kc (16 bytes), with the 16-byte nonce/counter block
    Nc used as the CTR initial counter value directly (matches ACE's
    stated Si <- ACE(Nc||Kc) initialization-state semantics: nonce and key
    both 128 bits).
    """
    if len(Kc) != 16 or len(Nc) != 16:
        raise ValueError("ACE requires 128-bit (16-byte) Kc and Nc")
    ctr = int.from_bytes(Nc, "big")
    return AES.new(Kc, AES.MODE_CTR, nonce=b"", initial_value=ctr)


def init_state(Nc: bytes, Kc: bytes) -> bytes:
    """Si <- ACE(Nc || Kc). Si is simply the concatenation (256 bits)."""
    if len(Nc) != 16 or len(Kc) != 16:
        raise ValueError("Nc and Kc must each be 128 bits (16 bytes)")
    return Nc + Kc


def split_state(Si: bytes):
    if len(Si) != 32:
        raise ValueError("Si must be 256 bits (32 bytes) = Nc(128)||Kc(128)")
    return Si[:16], Si[16:]


def encrypt(Si: bytes, AD: bytes, PT: bytes):
    """
    (CT || Tag) = E_Si{AD, PT}
    Returns (CT, Tag), each 16 bytes (128 bits), per the paper.
    """
    if len(AD) != BLOCK_LEN or len(PT) != BLOCK_LEN:
        raise ValueError("ACE operates on 128-bit AD and 128-bit PT blocks")
    Nc, Kc = split_state(Si)
    cipher = _keystream_cipher(Kc, Nc)
    CT = cipher.encrypt(PT)
    Tag = hmac_sha256(Kc, AD + CT)[:TAG_LEN]
    return CT, Tag


def decrypt(Si: bytes, AD: bytes, CT: bytes):
    """
    (PT || Tag') = D_Si{AD, CT}

    Per the paper's "inverse-free" description, PT is always structurally
    recoverable; the caller is responsible for comparing the returned
    Tag' against the Tag that was transmitted alongside CT to decide
    whether to accept or abort (exactly as Section 5.2 describes for both
    Step AKE2 and Step AKE3).
    Returns (PT, Tag_prime).
    """
    if len(AD) != BLOCK_LEN or len(CT) != BLOCK_LEN:
        raise ValueError("ACE operates on 128-bit AD and 128-bit CT blocks")
    Nc, Kc = split_state(Si)
    cipher = _keystream_cipher(Kc, Nc)
    PT = cipher.decrypt(CT)
    Tag_prime = hmac_sha256(Kc, AD + CT)[:TAG_LEN]
    return PT, Tag_prime


def tags_match(tag_a: bytes, tag_b: bytes) -> bool:
    return constant_time_eq(tag_a, tag_b)
