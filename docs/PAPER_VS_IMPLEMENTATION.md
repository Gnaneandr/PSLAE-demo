# PAPER_VS_IMPLEMENTATION (what the paper states vs what this implementation does)
Status: **L** literal, **R** reconstruction, **I** implementation-specific addition, **D** discrepancy reported.

| # | Topic | Paper | Our implementation | Status |
|---|---|---|---|---|
| 1 | Hash | "SHA-160" and 256-bit `Mk = Ms xor H(R6LC)` | SHA-1 + H_bits (SHA-1 counter mode) for 256-bit values | R |
| 2 | Ms width | "265 bits" | 256 bits | R |
| 3 | X = Mk xor Sc | 256 xor 64 bits is undefined | Sc repeated four times | R |
| 4 | Sc' check | `Sc' = ID6LN xor RN1 xor A` (never equals Sc) | `AID6LN xor RN1 xor A` | R, D |
| 5 | AKE3 Sc1 | sensor computes T' from ID6LC (never provisioned) | Sc1 taken from the decrypted CT1 | R |
| 6 | RN1/RN2 consistency | not stated | extra check of the clear value against the hidden copy | I |
| 7 | T6C width | 32 bits | 64 bits (so M2 = 608) | R, D |
| 8 | Mk | `Ms xor H(R6LC)`, stored at the 6LN (RP-3) | `H_bits(Sc‖K6LN)` derived on demand | R |
| 9 | AID6LN update | claimed ("changes every session"), no equation | `H_bits(AID‖SK, 64)` | R |
| 10 | Sc update | "saves and updates the new parameters" | Sc := Sc1 | R |
| 11 | Storage | 6LN 32 B, 6LC 60 B | 6LN 40 B stored (32 B read); 6LC record 60 B incl. 4 B padding | D |
| 12 | Freshness | `Tr - T <= DeltaT` (absolute value in Prop.4) | one-sided test, DeltaT = 5 s | D |
| 13 | Replay protection | timestamps + nonces | state change only; `seen_*` sets exist but are never filled | D |
| 14 | ACE | NIST-LWC ACE, internals unspecified | AES-128-CTR + HMAC-SHA256/128 | R |
| 15 | Hash-op count | 8 (+2 ACE) | 12 measured (the audited script hard-codes 8) | D |
| 16 | M1 size | 416 bits | 416 bits | L |
| 17 | M2 / total | 608 / 1024 (text also ~1010) | 608 / 1024 through the 64-bit T6C (literal paper widths: 576 / 992) | D |
| 18 | Scyther | all Ok, model unpublished | 10 Ok in our model, where timestamps are authenticated | D |
| 19 | SVO | one goal G1 derived | G1 as published (not strictly derivable), G2 reconstructed | R, D |
| 20 | Loss of M2 | not discussed | permanent desynchronisation (attack A11b) | D |

Authoritative detail: `docs/paper_ambiguities.md`, `docs/discrepancy_report.md`, `docs/RECONSTRUCTION_DECISIONS.md`.
