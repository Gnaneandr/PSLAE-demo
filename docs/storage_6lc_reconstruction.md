# 6LC = 60 Bytes — Storage Reconstruction

## Target vs. what's genuinely functionally necessary

Under this round's Mk=H(Sc,K6LN) derivation scheme (replacing
Mk=Ms xor H(R6LC)), 6LC's genuinely functionally necessary storage is:

| Field | Bytes | Why needed |
|---|---:|---|
| TID6LC | 8 | D verification (Step AKE1/2) |
| Sc | 8 | Multiple checks; also feeds Mk derivation |
| K6LN | 8 | AD derivation; also feeds Mk derivation |
| AID6LN | 8 | Database key |
| ID6LN | 8 | Sc' verification (Step AKE2) |
| **Subtotal (functionally necessary)** | **40** | |

40 bytes is the true minimum under this reconstruction -- 20 bytes
short of the paper's reported 60.

## What was tried, and why 60 can't be reached with every byte functional

- **Re-deriving Mk from a smaller stored seed** (previously tried):
  saves bytes rather than adding them -- moves further from 60, not
  closer.
- **Re-adding K6LC** (paper-cited, Step AKE2's own retrieval
  sentence): +8 bytes = 48. Genuinely unused by any equation, ours or
  the paper's own printed formulas -- kept for field-level fidelity
  to what the paper says is retrieved, not because it does anything.
- **Re-adding R6LC** (paper-cited, Step RP-2's own Mk formula):
  +8 bytes = 56. Same reasoning -- the paper explicitly names this
  value as part of Mk's derivation; our reconstructed derivation
  formula no longer reads it, but keeping it stored is more faithful
  to the paper's own storage description than silently deleting a
  named value.
- **Remaining gap:** 60 - 56 = 4 bytes, with no remaining paper-cited
  candidate field. Ms itself was considered (the paper's other named
  parameter feeding Mk) but its natural size (32 bytes, matching the
  corrected Mk width) overshoots the entire remaining budget by 28
  bytes -- not usable without either truncating it arbitrarily (which
  would be exactly the kind of unjustified invention this exercise is
  trying to avoid) or abandoning the 60-byte target itself.

## Conclusion

60 bytes cannot be reached through field selection alone without at
least a small non-functional remainder, given the paper's own set of
named RP-1/RP-2/RP-3/AKE2 values and their paper-stated widths. This
round reduces that remainder from 12 bytes (previous round) to 4
bytes by restoring R6LC and K6LC as genuinely paper-cited (if
functionally unused) fields, rather than treating the entire gap as
arbitrary padding.

The remaining 4 bytes are explicit, labeled padding with no protocol
function (SensorRecord._reserved, entities.py). This is reported
plainly, not disguised -- the honest position is that the paper's own
storage claim of 60 bytes is not achievable from its own named fields
at their own stated widths without SOME unexplained remainder; this
reconstruction minimizes that remainder to the extent a genuine
field-by-field accounting allows, rather than eliminating it by fiat.

## Final layout

| Field | Bytes | Source | Functionally used? |
|---|---:|---|---|
| TID6LC | 8 | RP-3 | Yes |
| Sc | 8 | RP-3 | Yes |
| K6LN | 8 | RP-3 | Yes |
| AID6LN | 8 | RP-3 | Yes |
| ID6LN | 8 | AKE2 | Yes |
| K6LC | 8 | AKE2 | No -- paper-cited only |
| R6LC | 8 | RP-2 | No -- paper-cited only |
| _reserved | 4 | none | No -- explicit padding |
| **Total** | **60** | | |
