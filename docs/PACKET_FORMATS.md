# PACKET_FORMATS

Generated from the real message objects. 'Paper' = width the paper states for the field. No framing, header or padding is added by the code.

## reconstructed

```text
==============================================================================
PACKET INSPECTOR - RECONSTRUCTED implementation (audited src/)
==============================================================================

M1   direction: 6LN -> 6LC   (fields in wire order)
| Field  | Purpose                                         | Bits | Bytes | Paper | Source                | Protection
| T6LN   | sensor timestamp (freshness)                    |   32 |     4 |    32 | clock (AKE1)          | clear; freshness window only - NOT covered by the tag
| D      | alias mask AID6LN xor TID6LC (lookup key)       |   64 |     8 |    64 | AID6LN xor TID6LC     | clear; masks AID6LN; used for DB lookup
| CT     | encrypted A||B                                  |  128 |    16 |   128 | ACE encrypt of A||B   | encrypted (AES-CTR) + covered by tag
| Tag6LN | authentication tag of M1                        |  128 |    16 |   128 | ACE tag over AD||CT   | authenticator (HMAC-SHA256/128)
| RN1    | sensor fresh random                             |   64 |     8 |    64 | fresh random (AKE1)   | clear; cross-checked against B inside CT
| TOTAL  |                                                 |  416 |    52 |   416 |
  Paper-reported total        : 416 bits
  Literal paper field widths  : 416 bits (sum of the widths the paper states for each field; M uses 160 bits = SHA-1)
  Measured from real message  : 416 bits  (52 bytes concatenated)
  Difference vs paper-reported: +0 bits;  vs literal fields: +0 bits
  Framing / headers / padding : none: messages are Python dicts of byte strings; no framing/header/padding is added by the code (the demo's wire length is the plain concatenation)

M2   direction: 6LC -> 6LN   (fields in wire order)
| Field  | Purpose                                         | Bits | Bytes | Paper | Source                | Protection
| T6C    | controller timestamp (freshness)                |   64 |     8 |    32 | clock (AKE2)          | clear; freshness window only - NOT covered by the tag
| A1     | B1 xor RN1 (lets the sensor verify the controller)|   64 |     8 |    64 | B1 xor RN1            | clear; recomputed by 6LN from K6LN, RN1, RN2
| M      | SHA-1(SK) key confirmation                      |  160 |    20 |   160 | SHA-1(SK)             | clear; key-confirmation hash H(SK)
| CT1    | encrypted Sc1||RN2                              |  128 |    16 |   128 | ACE encrypt of Sc1||RN2| encrypted (AES-CTR) + covered by tag
| Tag6LC | authentication tag of M2                        |  128 |    16 |   128 | ACE tag over AD||CT1  | authenticator (HMAC-SHA256/128)
| RN2    | controller fresh random                         |   64 |     8 |    64 | fresh random (AKE2)   | clear; cross-checked against RN2 inside CT1
| TOTAL  |                                                 |  608 |    76 |   576 |
  Paper-reported total        : 608 bits
  Literal paper field widths  : 576 bits (sum of the widths the paper states for each field; M uses 160 bits = SHA-1)
  Measured from real message  : 608 bits  (76 bytes concatenated)
  Difference vs paper-reported: +0 bits;  vs literal fields: +32 bits
  Framing / headers / padding : none: messages are Python dicts of byte strings; no framing/header/padding is added by the code (the demo's wire length is the plain concatenation)
  EXPLANATION: the 64-bit T6C is a RECONSTRUCTION (paper: '32 bits timestamp'). With T6C = 32 bits the total is 576 bits (= literal), not 608.
  The 608/1024 targets are therefore reached only through that field-width change; both figures are reported.

TOTAL M1+M2: measured 1024 bits | literal field widths 992 | paper-reported 1024 (paper text also says ~1010: inconsistent)
```
