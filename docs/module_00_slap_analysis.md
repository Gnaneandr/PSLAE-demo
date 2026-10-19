# Module 0 — SLAP Cryptanalysis (paper Section 3)

**Purpose:** Reproduce, as a structured document, the paper's own
cryptanalysis of the prior SLAP scheme (Suryakanta et al., 2022) — this
is the paper's stated motivation for proposing PSLAE, and is
**theoretical/prose analysis in the paper, not an executable attack
simulator**. Per the task instructions, this module is a structured
explanation, not Python code, and invents nothing beyond what Section 3
of the paper actually states.

**Distinguishing "paper's security analysis" from "our reproduction":**
Every attack description below is a direct, faithful restatement of the
paper's own Section 3.3 prose (paraphrased, not verbatim-copied, per
citation norms), organized into the requested
step→capability→procedure→reason→conclusion→motivation structure. We do
not add, extend, or "improve" any attack the paper doesn't describe.

---

## SLAP protocol recap (paper Section 3.1–3.2)

**Initialization phase:** the trusted Authentication Server (AS) gives
the controller a secret key `PSK` over a secure channel. For each
sensor, AS assigns identity `IDs`, generates random `r`, and computes
`ai = H(IDs || PSK)`, `bi = H(r || PSK)`. The sensor stores `ai, bi, r`.

**Authentication phase (3 messages):**
- *Sensor → Controller:* generates random `R1`; computes
  `D1 = bi ⊕ R1`, `D2 = H(R1) ⊕ IDs`, `D3 = H(IDs||R1||r||TS0)`; sends
  `M1 = {D1, D2, D3, r, TS0}`.
- *Controller → Sensor:* verifies `TS0` freshness, recovers `R1, IDs`
  from `D1, D2`, checks `D3`; if valid, computes new `r', b'i`; computes
  `D4..D7` and `SK = H(IDs||R1||R2)`; sends `M2 = {D4,D5,D6,D7,TS1}`.
- *Sensor verification:* verifies `TS1`, recovers `R2, b'i, r'`, checks
  `D'7`; computes `SK`; updates stored `bi, r` to `b'i, r'`.

## Attacks (paper Section 3.3)

### 1. Perfect Forward Secrecy (PFS) attack

- **SLAP step exploited:** the session key formula
  `SK = H(IDs || R1 || R2)`.
- **Attacker capability assumed:** compromise of long-term secrets
  (`PSK`, and the sensor's real `IDs` recovered from its memory).
- **Attack procedure (paper's own description):** `D1, D2, D3` are built
  only from random numbers `r, R1, R2`, which the paper says an attacker
  "can guess" once long-term secrets are known; with `PSK` and `IDs`
  compromised, the attacker can reconstruct enough to compute
  `SK = H(IDs||R1||R2)` directly.
- **Why the attack works:** the session key depends on nothing that
  isn't recoverable once the long-term secrets are known — there is no
  independent ephemeral/asymmetric contribution that would keep past
  session keys safe after a long-term compromise.
- **Paper's conclusion:** SLAP does not provide PFS — "the attacker can
  access the session key if the long-term credentials are compromised."
- **How this motivates PSLAE:** PSLAE's own Section 4.3 explicitly lists
  "Forward/backward secrecy" as a required security goal, and
  Proposition 2 (Section 6.1) specifically argues PSLAE's use of a
  changing alias identity `AID6LN` and fresh `RN1/RN2/B1` parameters
  each session addresses this gap.

### 2. Denial-of-Service (DoS) attack

- **SLAP step exploited:** the initialization message format and the
  predictability of `r`.
- **Attacker capability assumed:** ability to repeatedly send forged
  initialization messages under a victim sensor's identity.
- **Attack procedure:** the paper states `r` is "a repeating random
  number, which can be predicted by the attacker," who can then guess
  `bi` and successfully retrieve `D1, D2, D3`, acting as a legitimate
  sensor; once the controller "receives many messages containing the
  same ID, it refuses to serve, assuming the corresponding device has
  been compromised."
- **Why the attack works:** SLAP's controller-side revocation/defense
  logic reacts to repeated-identity messages by refusing service
  altogether — including to the legitimate sensor — once the predictable
  `r` lets an attacker spoof enough traffic under that identity.
- **Paper's conclusion:** a legitimate sensor can be denied service by
  an attacker who never needed to break any cryptographic primitive,
  only predict `r`.
- **How this motivates PSLAE:** Section 4.3's "Insensitive to various
  attacks" goal explicitly calls out DoS resistance; Proposition 5
  argues PSLAE's AEAD-tag verification (`Tagd = Tag6LN`) requires secret
  parameters (`ID6LN, Sc, Mk`) an attacker cannot guess, so forged
  traffic is rejected without triggering any service-refusal side effect
  against the legitimate device.

### 3. Ephemeral Secret Leakage (ESL) attack

- **SLAP step exploited:** the session-key formula
  `SK = H(IDs||R1||R2)` again, this time under the CK (Canetti-Krawczyk)
  threat model rather than a long-term-secret compromise.
- **Attacker capability assumed:** the CK model's ephemeral-state
  compromise — the attacker learns the session-specific random values
  `R1, R2` (but not necessarily the long-term `PSK`).
- **Attack procedure:** once `R1, R2` are known (leaked as ephemeral
  session state) and the attacker already knows `IDs` (not treated as
  secret in this attack), `SK = H(IDs||R1||R2)` is directly computable.
- **Why the attack works:** the session key mixes only short-term
  values with a non-secret identity — no independent long-term secret
  contribution is needed to reconstruct it once the ephemeral values
  leak.
- **Paper's conclusion:** "the attacker can easily determine the session
  key if he already knows `IDs`, `SK = H(IDs||R1||R2)`" once ephemeral
  values are compromised — SLAP does not resist ESL under the CK model.
- **How this motivates PSLAE:** Proposition 8 argues PSLAE's session key
  `SK = H(AID6LN||B1||Sc1||RN1||RN2)` mixes fresh ephemeral terms
  (`RN1, RN2`) with a long-term secret hidden inside `AID6LN` and `Sc`,
  so leaking only the ephemeral terms is claimed to be insufficient.

### 4. Traceability attack

- **SLAP step exploited:** the fact that `R1` and the message structure
  repeat recognizable patterns across sessions.
- **Attacker capability assumed:** the ability to intercept messages
  from multiple distinct authentication sessions over the public
  channel.
- **Attack procedure:** the paper states `R1` "is a simple random number
  that repeats" (predictable), so an attacker can link `D1, D2, D3`
  values across sessions and match them to the same real sensor
  identity, since "each sensor message and each controller message
  contain the same values."
- **Why the attack works:** SLAP does not use any one-time alias
  identity — the underlying structure exposed in each session's messages
  is directly comparable across sessions.
- **Paper's conclusion:** an attacker who intercepts two messages from
  distinct sessions "can link the sensor by matching random numbers and
  IDs" — SLAP does not provide untraceability/privacy preservation.
- **How this motivates PSLAE:** this is PSLAE's headline design feature
  — Section 5.1's `AID6LN` one-time alias identity and Proposition 3's
  untraceability argument are direct, explicit responses to this exact
  weakness (see also `docs/paper_ambiguities.md` entry on whether
  `AID6LN` is genuinely rotated every session as Proposition 3 claims).

---

## Summary table (paper's own framing, Section 3.3 → Section 1.1)

| Attack | SLAP vulnerable? (paper's finding) | PSLAE's claimed countermeasure |
|---|---|---|
| PFS | Yes | Alias identity + fresh per-session parameters (Prop. 2) |
| DoS | Yes | AEAD-tag verification requiring secret parameters (Prop. 5) |
| ESL | Yes | Session key mixes long-term-hidden + ephemeral terms (Prop. 8) |
| Traceability | Yes | One-time alias identity `AID6LN` (Prop. 3) |
| Modification, MITM, replay, impersonation | Paper states SLAP resists these (Suryakanta et al.'s own claim, not re-broken by this paper) | PSLAE also claims these (Props. 4, 6, 7, 9) |

**Status:** COMPLETED — structured, faithful reproduction of the paper's
own Section 3.3 analysis. Not executable by design (the paper itself
presents this as theoretical/prose cryptanalysis, not a Scyther/code
artifact), and nothing above extends beyond what Section 3.3 states.
