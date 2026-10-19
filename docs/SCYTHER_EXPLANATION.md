# SCYTHER_EXPLANATION

Scyther is an automatic checker for security protocols. You describe the protocol as a model (SPDL); Scyther searches, within a bound (here 100 protocol runs), for an attack in which an attacker who controls the network violates a **claim**.

## The model file
| File | What it is |
|---|---|
| `scyther/pslae.spdl` | **Reconstructed model** (the audited project's model). The timestamps are bound into the encrypted/authenticated part of M1 and M2. The paper sends them as bare fields, so this is a deliberate change. |
| `results/baseline/scyther_saved/` | the original saved output of the audited project (preserved before any new run). |

It is not the authors' model: the paper does not publish its SPDL.

## Claims
Secret (session key unknown to the attacker), Alive, Weakagree (the partner really ran the protocol), Niagree (agreement on all exchanged data), Nisynch (agreement on data AND message order) - checked for both roles.

## What the result means
* **10 Ok.** Because the timestamps are authenticated in this model. This does **not** show that the protocol exactly as written in the paper passes: with a bare timestamp an attacker can substitute it (compare attack lab A03a and A06-M1.T6LN).
* We did not delete a failing claim, drop a field, or weaken the attacker.

## What Scyther does not prove
It cannot compute XOR: the model abstracts XOR as an opaque function (`xorf`). Timestamps are variables. The state updates (Sc and alias rotation), concrete AES/HMAC/SHA-1 behaviour, key/nonce reuse (attack A17), local desynchronisation (A11b) and implementation bugs are outside the model. 'Ok' is a statement about the abstract model within the run bound.

## Fresh run (generated)

```text
==============================================================================
SCYTHER FORMAL VERIFICATION
==============================================================================
Binary: /home/claude/PSLAE_DEMO/scyther/bin/scyther-linux | 'scyther' model checker for security protocols.
------------------------------------------------------------------------------
Model: scyther/pslae.spdl   [RECONSTRUCTED model: timestamps bound into the authenticated ciphertext (a deliberate change from the paper, which sends them as bare fields)]
  roles: ['SixLC', 'SixLN']
  events: 4 send/recv statements (message tuples are in the model file)
  claims declared: ['Secret', 'Alive', 'Weakagree', 'Niagree', 'Nisynch', 'Secret', 'Alive', 'Weakagree', 'Niagree', 'Nisynch']
  command: scyther/bin/scyther-linux -r 100 -m 0 -A scyther/pslae.spdl
  Role   Claim         Result Scyther comment
  SixLN  Secret_i1     Ok     [proof of correctness]
  SixLN  Alive_i2      Ok     [proof of correctness]
  SixLN  Weakagree_i3  Ok     [proof of correctness]
  SixLN  Niagree_i4    Ok     [proof of correctness]
  SixLN  Nisynch_i5    Ok     [proof of correctness]
  SixLC  Secret_r1     Ok     [proof of correctness]
  SixLC  Alive_r2      Ok     [proof of correctness]
  SixLC  Weakagree_r3  Ok     [proof of correctness]
  SixLC  Niagree_r4    Ok     [proof of correctness]
  SixLC  Nisynch_r5    Ok     [proof of correctness]
  -> 10 Ok, 0 Fail

Original saved output preserved (not overwritten): results/baseline/scyther_saved/pslae_final_output.txt

HOW TO READ THIS (no formal-methods background needed)
  * Scyther tries to build an attack on a symbolic model of the protocol within a bound (100 runs here). 'Ok' = no attack found / proof within that model; 'Fail' = an attack exists.
  * Secret  : the session key stays unknown to the attacker.   Alive/Weakagree : the partner really ran the protocol.
    Niagree/Nisynch : both sides agree on all exchanged data / message order (the strongest claims).
  * IMPORTANT: this model puts the timestamps INSIDE the authenticated part of M1 and M2. The paper sends them as bare fields, and the paper does not publish its own model. So these Ok results
    are results for the reconstructed model; they do not show that the protocol exactly as written in the paper passes.
  * LIMITATIONS: Scyther cannot compute XOR; the model abstracts XOR as an opaque function (xorf). Timestamps are modelled as variables. State updates (Sc/alias rotation) are not modelled.
    Symbolic 'Ok' is not a proof about the real implementation or about concrete AES/HMAC/SHA-1.
```

## Original saved output of the audited project (preserved, not overwritten)

```text
claim	pslae,SixLN	Secret_i1	H(xorf(hAid(k(SixLN,SixLC)),xorf(RN2,hKsn(k(SixLN,SixLC))),xorf(hSc(k(SixLN,SixLC)),hIdc(k(SixLN,SixLC))),RN1,RN2))	Ok	[proof of correctness]
claim	pslae,SixLN	Alive_i2	-	Ok	[proof of correctness]
claim	pslae,SixLN	Weakagree_i3	-	Ok	[proof of correctness]
claim	pslae,SixLN	Niagree_i4	-	Ok	[proof of correctness]
claim	pslae,SixLN	Nisynch_i5	-	Ok	[proof of correctness]
claim	pslae,SixLC	Secret_r1	H(xorf(hAid(k(SixLN,SixLC)),xorf(RN2,hKsn(k(SixLN,SixLC))),xorf(hSc(k(SixLN,SixLC)),hIdc(k(SixLN,SixLC))),RN1,RN2))	Ok	[proof of correctness]
claim	pslae,SixLC	Alive_r2	-	Ok	[proof of correctness]
claim	pslae,SixLC	Weakagree_r3	-	Ok	[proof of correctness]
claim	pslae,SixLC	Niagree_r4	-	Ok	[proof of correctness]
claim	pslae,SixLC	Nisynch_r5	-	Ok	[proof of correctness]
```
