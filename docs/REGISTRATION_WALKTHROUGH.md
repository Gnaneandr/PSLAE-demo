# Registration RP-1 to RP-5

Run: `python demo.py registration  [--stop-after N] [--reveal-secrets]`

Registration happens once, before the sensor is deployed, over a secure channel. The controller (6LC) creates the sensor's secrets and both sides store what they need. Nothing here is sent over the air.

**What to point out:** (1) RP-2 contains the paper's '265 bit' inconsistency and the reconstructed H_bits extension. (2) RP-3 shows the *actual* attributes stored: the audited 6LC record contains a 4-byte non-functional `_reserved` padding and the 6LN also stores `id6ln`. (3) RP-4/RP-5 show Si and AD, which are never stored. (4) The step-by-step recomputation is checked against the real `register_sensor()` output.

| Step | Paper equation | Status in the audited code |
|---|---|---|
| RP-1 | 6LC picks ID6LC, R6LC, K6LC, K6LN, TID6LC | literal values; widths of ID6LC/R6LC assumed 64 bit; TID6LC generation rule not given |
| RP-2 | AID = ID xor K6LN xor K6LC; Mk = Ms xor H(R6LC); Sm = Mk xor H(ID6LN); Sc = Sc1^Sc2^Sc3^Sc4 | AID, Sc literal; Ms 256 bit (paper '265'); H extended with H_bits (reconstruction) |
| RP-3 | storage sets | differs from the paper's list (see output); reconstructed config derives Mk instead of storing it |
| RP-4 | X = Mk xor Sc; Si = Nc||Kc | Sc tiled to 256 bit (reconstruction) |
| RP-5 | Fr = Mk xor H(K6LN); AD = Fr1 xor Fr2 | H_bits extension (reconstruction) |


## Live output: `registration` (seed 2024, secrets redacted)

```text

==============================================================================
DEMO B - REGISTRATION RP-1 .. RP-5 (Sec.5.1)
==============================================================================
Configuration : RECONSTRUCTED implementation (audited src/)
Randomness    : seeded demo DRBG (seed=2024) - DISPOSABLE DEMONSTRATION KEYS
Secrets       : redacted (use --reveal-secrets for the educational insecure mode)

--- System initialisation (Demo A content): entities and algorithms
  6LC (controller) object : SixLC - holds ID6LC, TID6LC and a database keyed by AID6LN
  6LN (sensor) object     : type - holds its own secrets only
  Hash H            : SHA-1 (160-bit) - the paper's 'SHA-160'; H_bits = SHA-1 counter-mode extension (RECONSTRUCTION, not in paper)
  Authenticated enc.: ACE interface reconstruction = AES-128-CTR + HMAC-SHA256 truncated to 128 bits (NOT the authors' ACE)
  Randomness        : 64-bit identifiers/nonces, 256-bit master secret (demo: seeded DRBG)

--- RP-1  6LC receives ID6LN over a secure channel, picks ID6LC, R6LC, K6LC, K6LN   [paper: Sec.5.1 Step RP-1]
  Status: LITERAL for the values; bit-lengths of ID6LC/R6LC are not stated in the paper (64 assumed). TID6LC: generation rule not stated.
  ID6LN          64 bits   8 B  [secret   ] <redacted 8 B secret>   # given to 6LC over the secure channel
  ID6LC          64 bits   8 B  [secret   ] <redacted 8 B secret>   # controller's real identity (chosen in make_controller)
  TID6LC         64 bits   8 B  [secret   ] <redacted 8 B secret>   # controller's temporary identity; later masks AID6LN inside D
  R6LC           64 bits   8 B  [secret   ] <redacted 8 B secret>   # random 64-bit value (CSPRNG)
  K6LC           64 bits   8 B  [secret   ] <redacted 8 B secret>   # random 64-bit value (CSPRNG)
  K6LN           64 bits   8 B  [secret   ] <redacted 8 B secret>   # random 64-bit value (CSPRNG)

--- RP-2  AID6LN = ID6LN xor K6LN xor K6LC;  Mk(reg) = Ms xor H(R6LC);  Sm = Mk(reg) xor H(ID6LN);  Sc = Sc1^Sc2^Sc3^Sc4   [Sec.5.1 Step RP-2]
  PAPER AMBIGUITY: the paper says 'master key Ms of 265 bits ... Mk = Ms xor H(R6LC)'. 265 is not byte-aligned (typo for 256: 128+128), and a 160-bit SHA-1
  cannot be XORed with 256 bits. RECONSTRUCTION: Ms = 256 bits; H(.) is extended to 256 bits with H_bits (SHA-1 counter mode, not in paper).
  AID6LN         64 bits   8 B  [secret   ] <redacted 8 B secret>   # LITERAL: ID6LN xor K6LN xor K6LC (64 bits)
  Ms            256 bits  32 B  [secret   ] <redacted 32 B secret>   # RECONSTRUCTED width 256 bits (paper text: '265')
  Mk(reg)       256 bits  32 B  [secret   ] <redacted 32 B secret>   # Ms xor H_bits(R6LC,256)  [H_bits is a reconstruction]
  Sm            256 bits  32 B  [secret   ] <redacted 32 B secret>   # Mk(reg) xor H_bits(ID6LN,256)
  Sc             64 bits   8 B  [secret   ] <redacted 8 B secret>   # XOR of four 64-bit chunks of Sm (LITERAL structure)

--- RP-3  Storage: 6LC database record and 6LN memory   [Sec.5.1 Step RP-3]
  Step-by-step recomputation equals the REAL register_sensor() output: True
  6LC database record (actual attributes of the stored object):
     id6ln       8 B
     k6lc        8 B
     k6ln        8 B
     sc          8 B
     aid6ln      8 B
     tid6lc      8 B
     r6lc        8 B
     _reserved   4 B   <- NON-FUNCTIONAL PADDING added in the audited baseline to reach 60 B (docs/storage_6lc_reconstruction.md)
  6LN memory (actual attributes of the stored object):
     id6ln       8 B
     tid6lc      8 B
     sc          8 B
     k6ln        8 B
     aid6ln      8 B
  Paper RP-3 lists 6LN: {TID6LC, Sc, K6LN, K6LC, AID6LN, Mk}; 6LC: {TID6LC, Sc, K6LN, AID6LN}. The code differs; see docs/PAPER_VS_IMPLEMENTATION.md.

--- RP-4  X = Mk xor Sc (256 bits);  Si = (Nc || Kc), 128 + 128 bits   [Sec.5.1 Step RP-4]
  PAPER AMBIGUITY: Sc is 64 bits, Mk is 256 bits; the paper does not say how to XOR them ('265 bits' again for Si). RECONSTRUCTION: tile Sc four times.
  RECONSTRUCTED Mk: Mk = H_bits(Sc || K6LN, 256) is derived on demand on BOTH sides (paper: Mk = Ms xor H(R6LC), stored). Not stored.
  Mk            256 bits  32 B  [secret   ] <redacted 32 B secret>   # key actually used by AKE1..AKE3 in this configuration
  X             256 bits  32 B  [secret   ] <redacted 32 B secret>   # Mk xor tile(Sc)
  Nc            128 bits  16 B  [secret   ] <redacted 16 B secret>   # first 128 bits of X (ACE nonce/counter)
  Kc            128 bits  16 B  [secret   ] <redacted 16 B secret>   # last 128 bits of X (ACE key)
  Si            256 bits  32 B  [secret   ] <redacted 32 B secret>   # = Nc||Kc; verified equal to real compute_Si(): True

--- RP-5  Fr = Mk xor H(K6LN);  AD = Fr1 xor Fr2 (128 bits)   [Sec.5.1 Step RP-5]
  Note: RP-5 in the paper also says the 6LN 'generates a random number R1 (64 bits)'; in the code that value is RN1, generated in AKE1.
  Fr            256 bits  32 B  [secret   ] <redacted 32 B secret>   # Mk xor H_bits(K6LN,256)
  AD            128 bits  16 B  [secret   ] <redacted 16 B secret>   # Fr1 xor Fr2; verified equal to real compute_AD(): True
  Si and AD are NOT stored: they are recomputed from the stored secrets whenever a message is built or verified.

  Registration complete. Next: python demo.py ake1
```
