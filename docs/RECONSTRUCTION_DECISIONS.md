# RECONSTRUCTION_DECISIONS

Every element that is not literally in the paper, in the audited code. `tests/...` entries are new tests of this package; others are the audited project's own tests (`tests/test_*.py`).

## R1. H_bits (hash width)
- **Paper statement:** Sec.5: 'SHA-160'; RP-2: Mk = Ms xor H(R6LC), 256-bit; Sm split into four 64-bit chunks
- **Ambiguity/omission/inconsistency:** A 160-bit hash cannot be XORed with 256 bits
- **Implementation decision:** H_bits(x,n) = SHA-1(x‖ctr32) concatenated and truncated to n bits; SHA-1 kept for SK and M
- **Why:** keeps the paper's hash name and 160-bit SK/M while making every XOR well-formed
- **Source file / function:** src/crypto_utils.py: H_bits
- **Tests:** test_crypto_utils / test_registration (audited), tests/test_packets_parameters_ops.py
- **Security effect:** none claimed beyond SHA-1; not in the paper
- **Performance effect:** +1 logical hash per use (counted)

## R2. Ms = 256 bits
- **Paper statement:** 'Ms of 265 bits'; Si '265 bits = 128+128'
- **Ambiguity/omission/inconsistency:** 265 is not 128+128
- **Implementation decision:** 256 bits (MS_LEN = 32)
- **Why:** 128+128 = 256
- **Source file / function:** src/registration.py
- **Tests:** audited registration tests; tests/test_packets_parameters_ops.py::test_parameter_widths_match_declarations
- **Security effect:** none
- **Performance effect:** none

## R3. tile_to (X = Mk xor Sc)
- **Paper statement:** RP-4: X = Mk xor Sc, 256-bit
- **Ambiguity/omission/inconsistency:** Sc is 64 bits
- **Implementation decision:** Sc repeated four times
- **Why:** smallest parameter-free widening
- **Source file / function:** src/crypto_utils.py: tile_to; registration.compute_Si
- **Tests:** audited tests
- **Security effect:** Si secrecy rests on Mk; independent implementations may not interoperate
- **Performance effect:** none

## R4. Sc' = AID xor RN1 xor A
- **Paper statement:** AKE2: Sc' = ID6LN xor RN1 xor A, check Sc' = Sc
- **Ambiguity/omission/inconsistency:** printed form equals Sc xor K6LN xor K6LC, so honest runs abort
- **Implementation decision:** AID6LN instead of ID6LN
- **Why:** one-symbol change; consistent with A's definition
- **Source file / function:** src/ake.py: step_ake2
- **Tests:** audited AKE2 tests; attack A06b-1
- **Security effect:** check is the possession proof for Sc
- **Performance effect:** none

## R5. Sc1 from CT1 in AKE3
- **Paper statement:** AKE3: sensor computes T' = Mk xor H(ID6LC)
- **Ambiguity/omission/inconsistency:** ID6LC is never given to the sensor
- **Implementation decision:** Sc1 read from decrypted CT1 (already in M2)
- **Why:** adds no field and no stored value
- **Source file / function:** src/ake.py: step_ake3; docs/id6lc_ake3_reconstruction.md
- **Tests:** audited AKE3 tests; tests/test_demo_cli.py::test_full_session...
- **Security effect:** SK's Sc1 comes from the controller under the AEAD
- **Performance effect:** none

## R6. RN1/RN2 consistency checks
- **Paper statement:** not in the paper
- **Ambiguity/omission/inconsistency:** clear RN1/RN2 are redundant with the hidden copies
- **Implementation decision:** explicit equality checks
- **Why:** cheap hardening
- **Source file / function:** src/ake.py
- **Tests:** attacks A06-M1.RN1, A06-M2.RN2, A10c
- **Security effect:** detects substitution of clear nonces
- **Performance effect:** +compare ops

## R7. 64-bit T6C (reconstructed config)
- **Paper statement:** '32 bits timestamp'
- **Ambiguity/omission/inconsistency:** paper's field widths give M2 = 576, reported 608
- **Implementation decision:** T6C = 64 bits in src/ only
- **Why:** reaches 608/1024
- **Source file / function:** src/ake.py (_ts_now_bytes_64 in step_ake2)
- **Tests:** tests/test_packets_parameters_ops.py::test_reconstructed_total_is_1024_only_through_64bit_T6C
- **Security effect:** none on security; a width change made to approach a published number
- **Performance effect:** M2 +32 bits

## R8. Mk = H_bits(Sc‖K6LN) (reconstructed config)
- **Paper statement:** RP-2/RP-3: Mk = Ms xor H(R6LC), stored
- **Ambiguity/omission/inconsistency:** reduces stored 6LN fields
- **Implementation decision:** derive Mk on demand on both sides
- **Why:** per-device key; Mk evolves with Sc
- **Source file / function:** src/entities.py: mk property
- **Tests:** attack A17 context; tests/test_packets_parameters_ops.py::test_operation_counts...
- **Security effect:** Mk no longer controller-wide; evolution is a deterministic chain
- **Performance effect:** 12 vs 8 logical hashes

## R9. Alias rotation (reconstructed config)
- **Paper statement:** Prop.3: 'each session's AID6LN is changed'; no equation
- **Ambiguity/omission/inconsistency:** no update equation
- **Implementation decision:** AID' = H_bits(AID‖SK, 64) at both ends
- **Why:** hash of old alias and fresh key
- **Source file / function:** src/ake.py: step_ake2/step_ake3
- **Tests:** attack A15, A01a
- **Security effect:** D changes per session; but see A11b (no recovery after a lost M2)
- **Performance effect:** +1 hash per side

## R10. Sc := Sc1 update
- **Paper statement:** AKE2: 'saves and updates the new parameters'
- **Ambiguity/omission/inconsistency:** parameters to update are not listed
- **Implementation decision:** Sc replaced by Sc1 on both sides
- **Why:** Sc1 is called the new security temporal parameter
- **Source file / function:** src/ake.py
- **Tests:** audited AKE tests; A01a/A01c
- **Security effect:** state transition is what stops replays
- **Performance effect:** none

## R11. ACE stand-in
- **Paper statement:** Sec.4.4: ACE, 128-bit key/nonce/AD/tag; 'inverse-free'
- **Ambiguity/omission/inconsistency:** internals unspecified
- **Implementation decision:** AES-128-CTR + HMAC-SHA256/128 (encrypt-then-MAC)
- **Why:** matches the interface and the inverse-free description
- **Source file / function:** src/ace.py
- **Tests:** audited ACE tests; A04/A05/A08
- **Security effect:** none about ACE's own security; key reuse across AES/HMAC and nonce reuse (A17)
- **Performance effect:** not comparable to ACE's

## R12. Storage padding (_reserved)
- **Paper statement:** Sec.7.4: 6LC = 60 B
- **Ambiguity/omission/inconsistency:** fields listed do not add to 60 B
- **Implementation decision:** 4-byte non-functional `_reserved` in the 6LC record
- **Why:** only to reach 60 B - reported as such
- **Source file / function:** src/entities.py: SensorRecord
- **Tests:** tests/test_packets_parameters_ops.py::test_storage_report_distinguishes_stored_and_used
- **Security effect:** none
- **Performance effect:** none (storage counted separately for stored vs used)

