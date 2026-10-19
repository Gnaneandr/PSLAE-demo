# SVO_EXPLANATION
SVO (Syverson-van Oorschot) is a logic for reasoning about what a party can *believe* after a protocol (e.g. "the controller believes the sensor recently said this message"). It is done on paper; **the derivation here is manual and NOT machine-verified.**

`python demo.py svo` prints `docs/svo/complete_svo_derivation.md` with this header. Labels: **[PUBLISHED]** = from the paper's Fig.6 as read by the audited project; **[RECONSTRUCTED]** = added by the audited project (not in the paper).

| Item | Status | Note |
|---|---|---|
| Idealisation of M1/M2 | published (partly) | the figure labels both messages "M1" and a wrong direction; timestamps are dropped from the idealisation |
| Premises IS1-IS5 | published | IS1 gives freshness belief to the sensor only; IS5 treats the ciphertext||tag as a shared secret |
| Rules (MP, Nec, BA1, SA1/SA2, R1) | published | |
| G1: 6LC believes 6LN said M1's ciphertext | published | see caution |
| G2: 6LN believes 6LC said M2's ciphertext | **reconstructed** | the paper has no G2; its extra premise (IS5') is justified only for the reconstructed Mk derivation, not for the paper's literal protocol |

## Caution about G1 (our independent reading; verify against Fig.6 of the PDF)
* The figure is partly illegible in the text layer; some symbols were read, not verified.
* IS5 is not a meaningful key-goodness premise (a ciphertext is not a key).
* Freshness for the **controller** (needed to conclude "recently said") is not among the premises.
* Necessitation applies to theorems, not to assumptions; X1's justification cites "S5", which is not defined.
So G1's published steps do not follow strictly from the listed premises. We do **not** conclude that PSLAE is insecure; only that the published derivation, as legible, does not establish G1.

## Relation to the other evidence
The freshness premise the 6LC would need is exactly what attack scenarios A03a and A06-M1.T6LN contradict for a bare timestamp; the Scyther model avoids the issue by authenticating the timestamps.
