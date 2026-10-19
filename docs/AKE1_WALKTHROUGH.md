# AKE1 - the sensor builds M1

Run: `python demo.py ake1  [--reveal-secrets]`

The sensor picks a fresh random number RN1 and a timestamp, masks its alias with XOR (A, B, D), encrypts A||B with the ACE-interface stand-in (AES-128-CTR + HMAC tag) and sends M1.

**Key facts:** M1 is 416 bits and matches the paper because every field width is stated. T6LN, D and RN1 travel in clear; only CT is encrypted; the tag covers AD||CT but NOT the timestamp. XOR, hash and encryption are different operations: XOR masks, SHA-1 fingerprints, AES-CTR hides.


## Live output: `ake1` (seed 2024, secrets redacted)

```text

==============================================================================
DEMO C - AKE1: the 6LN builds and sends M1 (Sec.5.2 Step AKE1)
==============================================================================
Configuration : RECONSTRUCTED implementation (audited src/)
Randomness    : seeded demo DRBG (seed=2024) - DISPOSABLE DEMONSTRATION KEYS
Secrets       : redacted (use --reveal-secrets for the educational insecure mode)
Prerequisite: registration (executed deterministically if not already done).

--- Inputs read from the 6LN's stored state
  AID6LN         64 bits   8 B  [secret   ] <redacted 8 B secret>
  Sc             64 bits   8 B  [secret   ] <redacted 8 B secret>
  TID6LC         64 bits   8 B  [secret   ] <redacted 8 B secret>

--- Fresh values
  RN1            64 bits   8 B  [public   ] b00e9ed1dbeef46d   # fresh 64-bit random; sent in clear AND hidden inside B
  T6LN           32 bits   4 B  [public   ] 6553f100   # clock = 1700000000 (32-bit seconds)

--- Masked values (XOR only - no hashing here)
  A              64 bits   8 B  [secret   ] <redacted 8 B secret>   # A = AID6LN xor RN1 xor Sc  (LITERAL)
  B              64 bits   8 B  [secret   ] <redacted 8 B secret>   # B = AID6LN xor RN1  (LITERAL)
  D              64 bits   8 B  [public   ] 3636f912aa2ee796   # D = AID6LN xor TID6LC  (LITERAL; Fig.5 prints AID6LC - paper inconsistency)

--- Encryption / authentication interface (ACE reconstruction)
  Algorithm: AES-128 in CTR mode (keystream: CT = PT xor keystream)  +  Tag = HMAC-SHA256(Kc, AD||CT) truncated to 128 bits.
  NOT the authors' ACE (a NIST-LWC sponge permutation whose internals the paper does not give).
  Key Kc        128 bits  16 B  [secret   ] <redacted 16 B secret>   # 128-bit AES key (second half of Si)
  Nonce Nc      128 bits  16 B  [secret   ] <redacted 16 B secret>   # 128-bit initial counter block (first half of Si)
  AD            128 bits  16 B  [secret   ] <redacted 16 B secret>   # 128-bit associated data: authenticated, not encrypted, not transmitted
  Plaintext     128 bits  16 B  [secret   ] <redacted 16 B secret>   # A||B = 128 bits passed to ACE
  What is encrypted: A||B.  What is authenticated: AD (derived secret) and CT.  Nonce/key reuse: Si depends only on Mk and Sc - see docs/CRYPTOGRAPHIC_OPERATIONS.md.

--- Output
  CT            128 bits  16 B  [public   ] 9f151904aeb2c00adada9b4858ae2367
  Tag6LN        128 bits  16 B  [public   ] b4d47ffc26a73ae2ebd31d2d90dd65b3

--- M1 = T6LN || D || CT || Tag6LN || RN1

  M1 packet - fields in wire order (sizes measured from the real message object)
  Field     Bits  Bytes Paper bits  Source                  Protection
  T6LN        32      4         32  clock (AKE1)            clear; freshness window only - NOT covered by the tag
  D           64      8         64  AID6LN xor TID6LC       clear; masks AID6LN; used for DB lookup
  CT         128     16        128  ACE encrypt of A||B     encrypted (AES-CTR) + covered by tag
  Tag6LN     128     16        128  ACE tag over AD||CT     authenticator (HMAC-SHA256/128)
  RN1         64      8         64  fresh random (AKE1)     clear; cross-checked against B inside CT
  TOTAL      416     52        416
  Paper-reported M1: 416 bits; measured: 416 bits -> MATCHES directly (every field width is stated in the paper)

--- Operations executed by the real step_ake1() (logical = calls made by the protocol code)
  #  Operation    Algorithm                                         Input B       Out B Purpose (source line)
  1  random       seeded DRBG (demo)                                []            8     RN1: sensor's fresh random number
  2  xor          bytewise XOR (n operands)                         [8, 8, 8]     8     A = AID6LN xor RN1 xor Sc
  3  xor          bytewise XOR                                      [8, 8]        8     B = AID6LN xor RN1
  4  hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [16]          32    Mk = H_bits(Sc||K6LN,256) derived on demand (reconstruction)
  5  xor          bytewise XOR                                      [32, 32]      32    X = Mk xor tile(Sc)  (RP-4)
  6  hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [16]          32    Mk = H_bits(Sc||K6LN,256) derived on demand (reconstruction)
  7  hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [8]           32    Fr = Mk xor H(K6LN)  (RP-5)
  8  xor          bytewise XOR                                      [32, 32]      32    Fr = Mk xor H(K6LN)  (RP-5)
  9  xor          bytewise XOR                                      [16, 16]      16    AD = Fr1 xor Fr2 (associated data)
  10 aead-encrypt AES-128-CTR + HMAC-SHA256 truncated to 128 bit (  [32, 16, 16]  32    (CT||Tag6LN) = E_Si{AD, A||B}
  11 xor          bytewise XOR                                      [8, 8]        8     D = AID6LN xor TID6LC
  logical: {'random': 1, 'xor': 6, 'hash': 3, 'aead-encrypt': 1}
  physical primitive calls: {'random': 1, 'xor': 7, 'sha1': 6, 'aes_ctr': 1, 'hmac': 1}

  Next: python demo.py ake2   (the controller receives this M1)
```
