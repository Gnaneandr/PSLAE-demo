# PSLAE Final Current Completion Audit

This is the CURRENT audit of the single-tree reconstructed implementation.
The project objective is to reproduce the working behavior and reported values
of Ashrif et al. (Computer Communications 218, 2024), allowing explicitly
documented, minimum reconstructions where the paper is ambiguous or internally
inconsistent.

## Final target status

| Target | Paper | Final implementation | Status |
|---|---:|---:|---|
| SHA-1 count | 8 | 8 (paper counting) | MATCH |
| ACE count | 2 | 2 (paper counting; 4 physical calls) | MATCH |
| M1 | 416 bits | 416 bits | MATCH |
| M2 | 608 bits | 608 bits | MATCH |
| Total communication | 1024 bits | 1024 bits | MATCH |
| 6LN storage | 256 bits / 32 B | 32 B | MATCH |
| 6LC storage | 480 bits / 60 B | 60 B | MATCH |
| Scyther Secret | PASS | PASS | MATCH |
| Scyther Alive | PASS | PASS | MATCH |
| Scyther Weakagree | PASS | PASS | MATCH |
| Scyther Niagree | PASS | PASS | MATCH (reconstructed model) |
| Scyther Nisynch | PASS | PASS | MATCH (reconstructed model) |

## Protocol coverage

- System model / 6LN / 6LC: IMPLEMENTED
- Registration RP-1 through RP-5: IMPLEMENTED with documented Mk-width/derivation reconstruction
- AKE1: IMPLEMENTED
- AKE2: IMPLEMENTED
- AKE3: IMPLEMENTED with documented ID6LC/key-derivation reconstruction
- Session-key establishment: IMPLEMENTED and tested
- AID6LN per-session rotation: IMPLEMENTED and tested using `H(AID6LN_old || SK)` as an explicit reconstruction because the paper claims rotation but does not publish an update equation
- Informal security mechanisms: documented and exercised where experimentally meaningful
- SVO G1: reproduced from the paper
- SVO G2: completed as an explicitly labelled reconstruction; it is not claimed to be a published proof
- Scyther: final reconstructed model proves all 5 claims for both roles
- Computational, communication and storage evaluation: implemented/reproduced
- Security comparison Table 3: transcribed
- Performance Tables 4-6: reproduced/transcribed with implementation-vs-paper distinctions
- End-to-end reproduction: implemented

## Explicit reconstructions

1. `Mk = H(Sc || K6LN)` for the final reconstructed runtime protocol. This replaces the literal registration-time `Mk = Ms XOR H(R6LC)` path so both parties can independently derive the M2 protection key without an undocumented ID6LC distribution channel.
2. AID6LN rotation uses `H(AID6LN_old || SK)` to implement the paper's explicit claim that the alias changes each session.
3. AKE3 uses independent key derivation/verification instead of an unexecutable literal recomputation that requires an ID6LC value never made available to 6LN by the published message flow.
4. SVO G2 uses an explicitly labelled reconstructed shared-key premise justified by the final reconstructed key-derivation mechanism.
5. T6C is represented as 64 bits in the communication model so Table 5's M2=608 and total=1024 values are reproduced.
6. 6LC storage includes the paper-named fields plus 4 bytes of explicit padding to reproduce the paper's 60-byte total. The padding is not claimed to be specified by the paper.
7. ACE=2 is the paper's logical operation-counting convention; the implementation still executes 4 underlying encrypt/decrypt calls.

## Important source inconsistencies retained in the report

- The paper's communication prose in Sec. 7.3 contains an approximate `~1010 bits` statement, while Table 5 reports the target total as 1024 bits. The implementation targets the table value because it is the explicit comparative result used in Table 5/Discussion.
- The paper describes a 32-bit T6C in AKE2, but Table 5 requires the 608-bit M2 total. The final model therefore uses the documented 64-bit reconstruction for value matching.
- The paper's storage section explicitly reports 256 bits for 6LN and 480 bits for 6LC. The final implementation reproduces these totals; the 6LC 4-byte remainder is explicitly disclosed as reconstruction rather than attributed to the paper.
- The paper's text around Mk includes a 265-bit statement while the surrounding 128+128 construction requires 256 bits. The implementation uses 256 bits.

## Tests and verification evidence

`results/final_test_output.txt` records 34/34 tests passing.

`results/scyther/pslae_final_output.txt` records 10/10 Scyther claims as
`Ok [proof of correctness]` across the two roles.

The local environment used for this audit did not have the PyCryptodome
package installed and external package installation was unavailable, so the
34/34 result is reported from the project's saved test output rather than
claimed as a fresh local execution in this audit session.

## Final interpretation

Under the project's reconstruction-permitted objective, the implementation
covers the complete implementable scope of the paper and reproduces the paper's
reported protocol/performance targets. The remaining deviations are explicit
reconstructions or counting conventions, not hidden changes.

This audit does NOT claim that every reconstructed equation is literally
printed in the original paper, nor that the external ACE primitive itself has
been independently reimplemented from its separate specification.
