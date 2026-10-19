# AKE3 - the sensor verifies M2

Run: `python demo.py ake3  [--reveal-secrets]`

The sensor checks freshness, recomputes A1', verifies the tag, takes Sc1 and RN2 out of the decrypted CT1, derives SK' and checks M' = M.

**Substitution vs the paper:** the paper says the sensor computes T' = Mk xor H(ID6LC) to get Sc1', but the sensor never receives ID6LC; the code takes Sc1 from the decrypted CT1 instead. The controller updates its state before the sensor confirms (see attack A11b).


## Live output: `ake3` (seed 2024, secrets redacted)

```text

==============================================================================
DEMO E - AKE3: the 6LN verifies M2 and derives SK' (Sec.5.2 Step AKE3)
==============================================================================
Configuration : RECONSTRUCTED implementation (audited src/)
Randomness    : seeded demo DRBG (seed=2024) - DISPOSABLE DEMONSTRATION KEYS
Secrets       : redacted (use --reveal-secrets for the educational insecure mode)
Prerequisite: registration + AKE1 + AKE2 (real M2 produced deterministically if needed).

--- M2 as received
  T6C            64 bits   8 B  [public   ] 000000006553f100
  A1             64 bits   8 B  [public   ] e8e89c6588b76309
  M             160 bits  20 B  [public   ] 8892c7d9e656893900f9666cb5dbc544881c41e0
  CT1           128 bits  16 B  [public   ] 9dd290f7dea713e5bec36d4268aa73b5
  Tag6LC        128 bits  16 B  [public   ] 134d4e8c821d8c30d251fefac2ddc872
  RN2            64 bits   8 B  [public   ] dc2a90182e23b9d0

--- Recomputation of the sensor's checks (the real function accepted the message)
  [PASS] freshness  tr - T6C <= DeltaT   tr=1700000000, T6C=1700000000
  [PASS] A1' = (RN2 xor K6LN) xor RN1 equals received A1   uses 6LN's own K6LN and RN1
  [PASS] tag  Tag_N == Tag6LC   
  [PASS] RN2 inside CT1 equals transmitted RN2   AUDITED-CODE CHECK
  [PASS] session-key confirmation  M' = SHA-1(SK') equals received M   

--- Recovered / derived values
  B1'            64 bits   8 B  [secret   ] <redacted 8 B secret>
  A1'            64 bits   8 B  [public   ] e8e89c6588b76309
  Sc1            64 bits   8 B  [secret   ] <redacted 8 B secret>   # recovered by DECRYPTING CT1
  RN2            64 bits   8 B  [public   ] dc2a90182e23b9d0   # recovered from CT1
  SK'           160 bits  20 B  [secret   ] <redacted 20 B secret>   # SHA-1(AID6LN||B1'||Sc1||RN1||RN2); recomputed equal: True
  M'            160 bits  20 B  [public   ] 8892c7d9e656893900f9666cb5dbc544881c41e0   # SHA-1(SK'); must equal M

--- SUBSTITUTION vs the literal paper (AKE3)
  Paper: '6LN computes T' to get Sc1''. T' = Mk xor H(ID6LC) needs ID6LC, which the 6LN never receives. The code takes Sc1 from the decrypted CT1
  (it is already inside M2). See docs/id6lc_ake3_reconstruction.md and docs/RECONSTRUCTION_DECISIONS.md.

--- Session-key agreement
  Sensor session key:     [redacted by default]
  Controller session key: [redacted by default]
  Session key lengths:    sensor 160 bits, controller 160 bits
  Keys equal:             True

--- State change after AKE3 (reconstruction)
  Sc replaced by Sc1: True;  AID6LN rotated: True

--- Operations executed by the real step_ake3()
  #  Operation    Algorithm                                         Input B       Out B Purpose (source line)
  1  xor          bytewise XOR                                      [8, 8]        8     B1' = RN2 xor K6LN (sensor's own recomputation)
  2  xor          bytewise XOR                                      [8, 8]        8     A1' = B1' xor RN1
  3  compare      constant-time compare                             [8, 8]        0     equality check (A1' / RN2 / M')
  4  aead-decrypt AES-128-CTR + HMAC-SHA256 truncated to 128 bit (  [32, 16, 16]  32    decrypt CT1, recompute tag Tag_N
  5  compare      constant-time compare                             [16, 16]      0     compare received tag with recomputed tag
  6  compare      constant-time compare                             [8, 8]        0     equality check (A1' / RN2 / M')
  7  hash         SHA-1 (160-bit)                                   [40]          20    SK' = H(AID6LN||B1'||Sc1||RN1||RN2)
  8  hash         SHA-1 (160-bit)                                   [20]          20    M' = H(SK')
  9  compare      constant-time compare                             [20, 20]      0     equality check (A1' / RN2 / M')
  10 hash         H_bits = SHA-1 counter-mode KDF (reconstruction)  [28]          8     sensor.aid6ln = H_bits(sensor.aid6ln + sk_prim
  logical: {'xor': 2, 'compare': 4, 'aead-decrypt': 1, 'hash': 3}
  physical primitive calls: {'xor': 2, 'compare': 4, 'aes_ctr': 1, 'hmac': 1, 'sha1': 3}
```

## Live output: `session-key` (seed 2024, secrets redacted)

```text

==============================================================================
SESSION KEY - derivation on both sides (Sec.5.2)
==============================================================================
Configuration : RECONSTRUCTED implementation (audited src/)
Randomness    : seeded demo DRBG (seed=2024) - DISPOSABLE DEMONSTRATION KEYS
Secrets       : redacted (use --reveal-secrets for the educational insecure mode)
SK = SHA-1( AID6LN || B1 || Sc1 || RN1 || RN2 )  -> 160 bits.   M = SHA-1( SK ) is a different hash, sent in M2.   SK itself is NEVER transmitted.

  Input    Bits  6LC obtains it from                       6LN obtains it from
  AID6LN     64  TID6LC xor D, then DB record              own stored AID6LN
  B1         64  RN2 xor K6LN (record)                     B1' = RN2(received) xor own K6LN
  Sc1        64  fold(Mk' xor H_bits(ID6LC))               decrypting CT1 (sent encrypted in M2)
  RN1        64  AID6LN xor B (decrypted), checked vs clear RN1own fresh value
  RN2        64  own fresh value                           received in clear and inside CT1

  SK at 6LC [redacted]   SK at 6LN [redacted]
  Keys equal: True   length 160 bits
  Is SK in M1 or M2 on the wire? False
```
