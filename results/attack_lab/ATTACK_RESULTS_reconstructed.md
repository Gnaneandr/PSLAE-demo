# Attack laboratory results - reconstructed configuration

| ID | Scenario | Outcome | Check | Classification |
|---|---|---|---|---|
| A01a | Exact replay of M1 after a completed session | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A01b | Replay of M1 before the sensor has processed M2 | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A01c | Replay of M1 from the SECOND completed session | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A02a | Stale M1 (60 s old) | REJECT | freshness window | Protected in the tested configuration |
| A02b | Stale M2 (60 s old) | REJECT | freshness window | Protected in the tested configuration |
| A02c | Future-dated timestamp (+3600 s) | ACCEPT | - | Vulnerable in the tested configuration |
| A03a | Timestamp refresh on an intercepted, undelivered M1 (delay attack) | ACCEPT | - | Vulnerable in the tested configuration |
| A03b | Timestamp refresh on an already-completed M1 | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A04a | M1 ciphertext modified | REJECT | tag verification of M1 | Protected in the tested configuration |
| A04b | M1 ciphertext (last bit) modified | REJECT | tag verification of M1 | Protected in the tested configuration |
| A05a | M1 authentication tag modified | REJECT | tag verification of M1 | Protected in the tested configuration |
| A05b | M1 authentication tag (last bit) modified | REJECT | tag verification of M1 | Protected in the tested configuration |
| A04c | M2 CT1 modified | REJECT | tag verification of M2 | Protected in the tested configuration |
| A05c | M2 Tag6LC modified | REJECT | tag verification of M2 | Protected in the tested configuration |
| A06-M1.T6LN | M1 field T6LN modified | ACCEPT | - | Vulnerable in the tested configuration |
| A06-M1.D | M1 field D modified | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A06-M1.CT | M1 field CT modified | REJECT | tag verification of M1 | Protected in the tested configuration |
| A06-M1.Tag6LN | M1 field Tag6LN modified | REJECT | tag verification of M1 | Protected in the tested configuration |
| A06-M1.RN1 | M1 field RN1 modified | REJECT | RN1 consistency (clear RN1 vs RN1 hidden in B) | Protected in the tested configuration |
| A06-M2.T6C | M2 field T6C modified | ACCEPT | - | Vulnerable in the tested configuration |
| A06-M2.A1 | M2 field A1 modified | REJECT | A1 recomputation at the 6LN | Protected in the tested configuration |
| A06-M2.M | M2 field M modified | REJECT | session-key confirmation M' == M | Protected in the tested configuration |
| A06-M2.CT1 | M2 field CT1 modified | REJECT | tag verification of M2 | Protected in the tested configuration |
| A06-M2.Tag6LC | M2 field Tag6LC modified | REJECT | tag verification of M2 | Protected in the tested configuration |
| A06-M2.RN2 | M2 field RN2 modified | REJECT | A1 recomputation at the 6LN | Protected in the tested configuration |
| A06b-1 | [white-box] valid tag but wrong Sc inside A | REJECT | Sc' legitimacy check | Protected in the tested configuration |
| A06b-2 | [white-box] clear RN1 differs from RN1 hidden in B | REJECT | RN1 consistency (clear RN1 vs RN1 hidden in B) | Protected in the tested configuration |
| A07a | Unknown alias (random D) | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A07b | Sensor registered with a different controller | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A08 | Wrong key | REJECT | tag verification of M1 | Protected in the tested configuration |
| A09a | Identity substitution: D of sensor Y on sensor X's ciphertext | REJECT | tag verification of M1 | Protected in the tested configuration |
| A09b | Cross-delivery of M2 (X's reply delivered to Y) | REJECT | A1 recomputation at the 6LN | Protected in the tested configuration |
| A10a | Impersonation with random fields | REJECT | alias lookup in the 6LC database | Protected in the tested configuration |
| A10b | Impersonation with a captured alias (D) and random CT/Tag | REJECT | tag verification of M1 | Protected in the tested configuration |
| A10c | New session built from captured CT/Tag with a fresh RN1 | REJECT | RN1 consistency (clear RN1 vs RN1 hidden in B) | Protected in the tested configuration |
| A11a | M1 dropped | ACCEPT | - | Protected in the tested configuration |
| A11b | M2 dropped (desynchronisation) | REJECT | alias lookup / tag check | Vulnerable in the tested configuration |
| A12a | Duplicate M2 | REJECT | no pending AKE1 session at the 6LN | Protected in the tested configuration |
| A12b | Old M2 delivered into a newer session | REJECT | A1 recomputation at the 6LN | Protected in the tested configuration |
| A12c | M2 arrives with no pending AKE1 (out of order) | REJECT | no pending AKE1 session at the 6LN | Protected in the tested configuration |
| A14 | Session-key agreement and cross-session isolation | ACCEPT | - | Protected in the tested configuration |
| A15 | Alias rotation and traceability | REJECT | - | Protected in the tested configuration |
| A16 | Denial-of-service considerations (local processing cost only) | REJECT | various | Partially protected |
| A17 | Passive keystream-reuse analysis of one session (M1 xor M2) | ACCEPT | - | Vulnerable in the tested configuration |
| A18 | Passive attempt to compute SK from the transcript (with AID6LN recovered via A17) | REJECT | - | Partially protected |
| A13 | Altered identity, nonce and session values (summary of A06) | MIXED | see steps | Partially protected |
