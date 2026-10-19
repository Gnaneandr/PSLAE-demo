# AKE2 - the controller verifies M1 and builds M2

Run: `python demo.py ake2  [--reveal-secrets]`

The controller checks freshness, finds the alias, derives the same key material, decrypts, verifies the tag, checks RN1 and Sc', then builds the session key SK and M2.

**Rejection conditions (in code order):** stale timestamp; alias not found; tag mismatch; RN1 mismatch; Sc mismatch. Wrong field lengths are rejected by an unhandled `ValueError` (no explicit validation). **Measured, reconstructed config:** M2 = 608 bits only because T6C is 64 bits there (paper: 32; literal field widths give 576).


## Live output: `ake2` (seed 2024, secrets redacted)

```text

==============================================================================
DEMO D - AKE2: the 6LC verifies M1 and builds M2 (Sec.5.2 Step AKE2)
==============================================================================
Configuration : RECONSTRUCTED implementation (audited src/)
Randomness    : seeded demo DRBG (seed=2024) - DISPOSABLE DEMONSTRATION KEYS
Secrets       : redacted (use --reveal-secrets for the educational insecure mode)
Prerequisite: registration + AKE1 (real M1 produced deterministically if needed).

--- M1 as received
  T6LN           32 bits   4 B  [public   ] 6553f100
  D              64 bits   8 B  [public   ] 3636f912aa2ee796
  CT            128 bits  16 B  [public   ] 9f151904aeb2c00adada9b4858ae2367
  Tag6LN        128 bits  16 B  [public   ] b4d47ffc26a73ae2ebd31d2d90dd65b3
  RN1            64 bits   8 B  [public   ] b00e9ed1dbeef46d

--- Parsing / length validation
  The code does NOT validate field lengths explicitly: a wrong-length field raises ValueError inside xor/ACE (see attack lab A10/A16).
  Observed lengths: {'T6LN': 4, 'D': 8, 'CT': 16, 'Tag6LN': 16, 'RN1': 8}

--- Recomputation of the controller's checks (same helper functions; the real function accepted the message)
  [PASS] freshness  tr - T6LN <= DeltaT (one-sided check in code)   tr=1700000000, T6LN=1700000000, DeltaT=5.0s
  [PASS] alias lookup  AID6LN = TID6LC xor D found in DB   
  [PASS] tag  Tag_d == Tag6LN (constant-time)   ACE tag over AD||CT
  [PASS] RN1 derived from B equals transmitted RN1   AUDITED-CODE CHECK (not stated in the paper)
  [PASS] Sc' = AID6LN xor RN1 xor A equals stored Sc   RECONSTRUCTION: paper prints ID6LN, which never equals Sc

--- Derived values
  AID6LN         64 bits   8 B  [secret   ] <redacted 8 B secret>   # TID6LC xor D
  Mk'           256 bits  32 B  [secret   ] <redacted 32 B secret>
  Si'           256 bits  32 B  [secret   ] <redacted 32 B secret>
  AD'           128 bits  16 B  [secret   ] <redacted 16 B secret>
  PT=A||B       128 bits  16 B  [secret   ] <redacted 16 B secret>   # decrypted

--- Controller's fresh values and new parameters
  T6C            64 bits   8 B  [public   ] 000000006553f100   # 64-bit timestamp
  RN2            64 bits   8 B  [public   ] dc2a90182e23b9d0   # fresh random
  T             256 bits  32 B  [secret   ] <redacted 32 B secret>   # Mk' xor H_bits(ID6LC,256)
  Sc1            64 bits   8 B  [secret   ] <redacted 8 B secret>   # T1^T2^T3^T4  (new Sc)
  B1             64 bits   8 B  [secret   ] <redacted 8 B secret>   # RN2 xor K6LN
  A1             64 bits   8 B  [public   ] e8e89c6588b76309   # B1 xor RN1; equals real A1: True
  SK            160 bits  20 B  [secret   ] <redacted 20 B secret>   # SHA-1(AID6LN||B1||Sc1||RN1||RN2) - 160 bits; recomputed equal: True
  M             160 bits  20 B  [public   ] 8892c7d9e656893900f9666cb5dbc544881c41e0   # SHA-1(SK): a SECOND, separate hash; equals real M: True
  PT1           128 bits  16 B  [secret   ] <redacted 16 B secret>   # Sc1||RN2 = 128 bits encrypted into CT1

--- M2 = T6C || A1 || M || CT1 || Tag6LC || RN2

  M2 packet - fields in wire order (sizes measured from the real message object)
  Field     Bits  Bytes Paper bits  Source                  Protection
  T6C         64      8         32  clock (AKE2)            clear; freshness window only - NOT covered by the tag
  A1          64      8         64  B1 xor RN1              clear; recomputed by 6LN from K6LN, RN1, RN2
  M          160     20        160  SHA-1(SK)               clear; key-confirmation hash H(SK)
  CT1        128     16        128  ACE encrypt of Sc1||RN2 encrypted (AES-CTR) + covered by tag
  Tag6LC     128     16        128  ACE tag over AD||CT1    authenticator (HMAC-SHA256/128)
  RN2         64      8         64  fresh random (AKE2)     clear; cross-checked against RN2 inside CT1
  TOTAL      608     76        576
  Paper-reported M2: 608 bits (fields listed in the paper add up to 576 with a 32-bit T6C and 160-bit M).
  Measured here  : 608 bits (64-bit T6C). Literal-width calculation: 576 bits. Reconstructed calculation: 608 bits.
  -> The 608 figure depends on the reconstructed 64-bit T6C, which CONTRADICTS the paper's explicit '32 bits timestamp'. Reported, not hidden.

--- State change after AKE2 (reconstruction)
  6LC stores Sc := Sc1 (reading of 'saves and updates the new parameters'); AID6LN := H_bits(AID6LN||SK,64) (alias rotation, RECONSTRUCTION).
  NOTE: the controller updates its state BEFORE the sensor confirms. If M2 is lost the two sides desynchronise (attack lab A11b).

--- Operations executed by the real step_ake2()
  #  Operation    Algorithm                                         Input B       Out B Purpose (source line)
  1  xor          bytewise XOR                                      [8, 8]        8     AID6LN = TID6LC xor D (alias recovery)
  2  hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [16]          32    Mk = H_bits(Sc||K6LN,256) derived on demand (reconstruction)
  3  xor          bytewise XOR                                      [32, 32]      32    X = Mk xor tile(Sc)  (RP-4)
  4  hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [8]           32    Fr = Mk xor H(K6LN)  (RP-5)
  5  xor          bytewise XOR                                      [32, 32]      32    Fr = Mk xor H(K6LN)  (RP-5)
  6  xor          bytewise XOR                                      [16, 16]      16    AD = Fr1 xor Fr2 (associated data)
  7  aead-decrypt AES-128-CTR + HMAC-SHA256 truncated to 128 bit (  [32, 16, 16]  32    decrypt CT, recompute tag Tag_d
  8  compare      constant-time compare                             [16, 16]      0     compare received tag with recomputed tag
  9  xor          bytewise XOR                                      [8, 8]        8     RN1 = AID6LN xor B (recovered from decrypted B)
  10 compare      constant-time compare                             [8, 8]        0     RN1 = AID6LN xor B (recovered from decrypted B)
  11 xor          bytewise XOR (n operands)                         [8, 8, 8]     8     Sc' = AID6LN xor RN1 xor A (reconstruction of the paper's check)
  12 compare      constant-time compare                             [8, 8]        0     equality check (RN1 / Sc' consistency)
  13 random       seeded DRBG (demo)                                []            8     RN2: controller's fresh random number
  14 hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [8]           32    T = Mk' xor H(ID6LC)
  15 xor          bytewise XOR                                      [32, 32]      32    T = Mk' xor H(ID6LC)
  16 xor          bytewise XOR (n operands)                         [8, 8, 8, 8]  8     Sc1 = T1^T2^T3^T4 (new Sc)
  17 xor          bytewise XOR                                      [8, 8]        8     B1 = RN2 xor K6LN
  18 xor          bytewise XOR                                      [8, 8]        8     A1 = B1 xor RN1
  19 hash         SHA-1 (160-bit)                                   [40]          20    SK = H(AID6LN||B1||Sc1||RN1||RN2)
  20 hash         SHA-1 (160-bit)                                   [20]          20    M = H(SK) (key-confirmation value)
  21 aead-encrypt AES-128-CTR + HMAC-SHA256 truncated to 128 bit (  [32, 16, 16]  32    (CT1||Tag6LC) = E_Si{AD, Sc1||RN2}
  22 hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [28]          8     AID6LN' = H_bits(AID6LN||SK, 64) (rotation; reconstruction)
  logical: {'xor': 10, 'hash': 6, 'aead-decrypt': 1, 'compare': 3, 'random': 1, 'aead-encrypt': 1}
  physical primitive calls: {'xor': 13, 'sha1': 9, 'aes_ctr': 2, 'hmac': 2, 'compare': 3, 'random': 1}

  Next: python demo.py ake3
```
