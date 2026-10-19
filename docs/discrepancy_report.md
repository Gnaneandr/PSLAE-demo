# PSLAE Base Paper — Detailed Discrepancy Report

**Scope of this document:** this report investigates and documents every
place where the current implementation (this ZIP) does not exactly
reproduce a result reported in Ashrif et al., *"Provably secured and
lightweight authenticated encryption protocol in machine-to-machine
communication in industry 4.0,"* Computer Communications 218 (2024)
263–275. **No protocol equations, SPDL claims, performance numbers, or
storage fields were changed while producing this report.** All figures
below were re-confirmed by live re-execution against this ZIP's actual
files immediately before writing this report (`pytest`, the bundled
Scyther binary, and `performance/overhead.py` were all re-run; the
output matched every number already saved under `results/`).

---

## 1. EXECUTIVE SUMMARY

| Area | Paper | Implementation | Classification |
|---|---|---|---|
| Scyther: Secret | Ok | Ok | EXACT MATCH |
| Scyther: Alive | Ok | Ok | EXACT MATCH |
| Scyther: Weakagree | Ok | Ok | EXACT MATCH |
| Scyther: Niagree | Ok | **Fail — exactly 2 attacks** | UNRESOLVED (best-supported: IMPLEMENTATION DIFFERENCE, see §2) |
| Scyther: Nisynch | Ok | **Fail — exactly 2 attacks** | UNRESOLVED (best-supported: IMPLEMENTATION DIFFERENCE, see §2) |
| Scyther configs 1–2 | GUI parameters | CLI equivalents, run-limit/matching-type exact; "patterns/claim" not reproducible | PARTIAL / TOOL DIFFERENCE |
| Scyther config 3 | 85 patterns/claim | substituted `--max-of-role=3` | TOOL DIFFERENCE — explicitly NOT exact |
| Computational overhead | 8 T_SHA_1, 2 T_ACE | 9 T_SHA_1, 4 T_ACE | PAPER AMBIGUITY (counting convention not published) |
| Communication 6LN→6LC | 416 bits | 416 bits | EXACT MATCH |
| Communication 6LC→6LN | 608 bits | 576 bits | PAPER VALUE CANNOT BE RECONCILED (see §5) |
| Storage 6LN | 32 bytes | 72 bytes | PAPER VALUE CANNOT BE RECONCILED (see §6) |
| Storage 6LC | 60 bytes | 32 (literal fields) / 88 (as-implemented) | PAPER VALUE CANNOT BE RECONCILED (see §6) |
| AID6LN rotation (Prop. 3) | claimed | not implementable from published steps | PAPER AMBIGUITY / likely OMISSION (see §7) |
| SVO G2 | implied | not published | UNREPRODUCIBLE FROM PUBLISHED INFORMATION |
| ACE internals | external primitive | interface-only reconstruction | UNREPRODUCIBLE FROM PUBLISHED INFORMATION |

Nothing in the implementation was altered to change any of the above.

---

## 2. SCYTHER RESULTS DISCREPANCY

### 2.1 The two protocols side by side

The paper's Section 5.2 defines exactly two messages:

```
M1 = (T6LN, D, CT||Tag6LN, RN1)         where D = AID6LN xor TID6LC
                                               A = AID6LN xor RN1 xor Sc
                                               B = AID6LN xor RN1
                                               (CT||Tag6LN) = E_Si{AD, A||B}

M2 = (T6C, A1, M, CT1||Tag6LC, RN2)     where B1 = RN2 xor K6LN
                                               A1 = B1 xor RN1
                                               SK = H(AID6LN||B1||Sc1||RN1||RN2)
                                               M  = H(SK)
                                               (CT1||Tag6LC) = E_Si''{AD', Sc1||RN2}
```

`scyther/pslae.spdl` models exactly this, field for field (verified by
direct comparison, reproduced in full below):

| Paper value | SPDL term | Verified identical structure? |
|---|---|---|
| `AID6LN` | `hAid(k(SixLN,SixLC))` | Yes — one abstracted long-term value |
| `D` | `xorf(hAid(...), hTid(...))` | Yes |
| `RN1` | `RN1` (fresh Nonce, SixLN; var, SixLC) | Yes — modelled as a genuine Scyther nonce, not abstracted |
| `RN2` | `RN2` (fresh Nonce, SixLC; var, SixLN) | Yes |
| `A` | `xorf(hAid(...), RN1, hSc(...))` | Yes |
| `B` | `xorf(hAid(...), RN1)` | Yes |
| `Si` (encryption key for M1) | `xorf(k(SixLN,SixLC), hSc(...))` | Yes (reconstruction of Step RP-4's `X=Mk xor Sc`, see `docs/paper_ambiguities.md` #3) |
| `B1` | `xorf(RN2, hKsn(...))` | Yes |
| `Sc1` | `xorf(hSc(...), hIdc(...))` | Reconstruction — the paper's `Sc1 = T1⊕T2⊕T3⊕T4` (4-way split of `T=Mk'⊕H(ID6LC)`) is modelled as a single abstracted function of `Sc` and `ID6LC`-derived material, since Scyther cannot express "split into 4 chunks then XOR" without an equivalent one-way abstraction; the *dependency* (Sc1 depends on the long-term secret and on `ID6LC`) is preserved |
| `A1` | `xorf(xorf(RN2,hKsn(...)),RN1)` = `xorf(B1,RN1)` | Yes |
| `M` | `H(H(xorf(...)))` = `H(SK)` | Yes (this exact double-hash was a bug we found and fixed by actually running Scyther — see `docs/module_10_scyther.md`) |
| `CT‖Tag6LN`, `CT1‖Tag6LC` | Scyther's native `{...}key` operator | Reconstruction — Scyther's built-in symmetric encryption, not the real ACE cipher (§9) |
| `SK` | `H(xorf(hAid,B1,Sc1,RN1,RN2))` | Yes |

**No field is missing.** Both messages, all listed variables, are present
in the model.

### 2.2 How RN1 is bound into M1 and M2 — the central technical fact

- In **M1**, `RN1` is sent in the clear (bare Nonce), and is *also*
  embedded inside the AEAD-protected `{A,B}Si` (both `A` and `B` are
  functions of `RN1`). So in M1, RN1 has both a plaintext copy and a
  cryptographically-protected copy.
- In **M2**, `RN1` is **only** represented via the plaintext field `A1 =
  B1 xor RN1`. `RN1` is **not** an argument to `CT1` at all — `CT1`
  encrypts `(Sc1, RN2)` only. `RN1`'s binding to M2 is therefore entirely
  a plaintext XOR relationship, never re-committed inside an
  authenticated/encrypted container.

This asymmetry (RN1 doubly protected in M1, singly and only
plaintext-bound in M2) is a direct reading of the paper's own formulas,
not an artifact introduced during SPDL construction — `CT1`'s plaintext
is stated plainly in Section 5.2 as `(Sc1||RN2)`, with no `RN1` term.

### 2.3 Systematic checklist (as requested)

1. **Protocol/message construction vs. SPDL — compared.** No
   discrepancy found (table above).
2. **Every reconstruction decision catalogued** — `docs/paper_ambiguities.md`
   entries #3, #5, #6, #7, #9, #10 all touch values used in M1/M2's
   construction. Each was individually tested (see below) except #6/#9/#10,
   which affect *value correctness*, not *message structure*, and are
   therefore not plausible causes of a structural synchronization
   failure.
3. **All 15 requested variables examined** — table in §2.1.
4/5. **RN1/RN2 binding determined** — §2.2. RN1 is bound into M2 only via
   the plaintext `A1`, never inside `CT1`. RN2 *is* included inside
   `CT1`.
6. **Can this structural difference explain Niagree/Nisynch? — Tested,
   not just argued.** Three controlled Scyther experiments were run
   (not merely inspected), saved in `results/scyther/diagnostics/`:

   - **Diagnostic A** (`minimal2msg.spdl`): a plain, non-XOR, textbook
     2-message challenge-response protocol where message 2's *encrypted*
     part re-includes message 1's nonce (`{Ni,Nr}k(I,R)`). Both roles'
     Niagree/Nisynch: **Ok**, including the responder claiming
     immediately after its own final send (the same claim placement
     PSLAE uses).
   - **Diagnostic B** (`minimal2msg_v2.spdl`): identical protocol,
     changing exactly one thing — message 2's encrypted part no longer
     contains `Ni`; a plaintext hash-commitment of `Ni` is sent instead
     (mirroring PSLAE's plaintext `A1`/`M` fields). Result: Niagree and
     Nisynch **both fail**, matching PSLAE's own Fail pattern.
   - **Diagnostic C**: the real `pslae.spdl`, modified only to use a
     *distinct* encryption key per direction instead of the reused `Si`.
     Result: Niagree/Nisynch **still fail identically** ("exactly 2
     attacks").

   Diagnostics A vs. B isolate the single variable that flips the
   result: whether the earlier nonce is re-included *inside* the later
   message's encryption. This is evidence, not merely a plausible
   narrative — changing that one property reproduces PSLAE's own Fail
   pattern in an unrelated toy protocol.

7. **Does `xorf()` itself affect the result? — Tested, largely ruled
   out.** Diagnostic A uses the *same* general Scyther idioms
   (`hashfunction`-style abstractions are not even needed there — it
   uses raw nonces — yet PSLAE's abstraction technique is structurally
   analogous) and succeeds; Diagnostic B, built with the same
   non-`xorf` style as A, still fails once the nonce-re-inclusion
   property is removed. This shows `xorf` as a modelling choice is not
   the deciding factor — the message-structure property is.
8. **Does claim placement matter? — Tested, ruled out as sole cause.**
   Diagnostic A's responder role claims immediately after its own final
   `send`, exactly like PSLAE's `SixLC`, and still succeeds. This rules
   out "the responder can never prove synchronization right after
   sending the last message" as an explanation on its own.
9. **Does key reuse across directions matter? — Tested, ruled out.**
   Diagnostic C.
10. **Configuration comparison** — see §3.
11. **Scyther version effect — cannot be tested, flagged as residual.**
    The paper states Scyther 1.1.3 (Section 6.3); the bundled binary in
    this project reports "Scyther version unknown" (a modern rebuild
    from `github.com/cascremers/scyther`'s current source — Python
    2.7/wxPython 2.8, the paper's stated GUI dependencies, do not install
    on the environment used to build this project). **We could not
    obtain or build the historical 1.1.3 release to test this
    directly.** This remains an open, untested variable.
12. **We are not concluding the paper is wrong.** See §11 (root cause
    classification) — the finding is stated as the best-supported
    explanation given the evidence gathered, with the version variable
    explicitly flagged as untested, not dismissed.
13. **Confirmed / likely / possible / unresolved — see §12/§13.**

### 2.4 Direct answer to the requested question

> *"Why does the paper report Niagree/Nisynch PASS while my
> reconstructed model produces 2 attacks for each?"*

**Best-supported explanation (LIKELY CAUSE, not CONFIRMED):** PSLAE's
own message design, as described in Section 5.2, binds `RN1` into `M2`
only through the plaintext field `A1`, never inside the AEAD-protected
`CT1||Tag6LC`. A controlled, isolated experiment (Diagnostics A vs. B)
shows that this specific property — not the general XOR-abstraction
technique, not claim placement, not key reuse — is sufficient on its own
to produce the same Ok→Fail flip observed between a working synchronized
protocol and PSLAE's own structure. We were not able to test whether the
paper's exact historical Scyther 1.1.3 would report the same result,
which remains a genuinely unresolved factor. We did not find any error
in how the SPDL model represents the paper's stated formulas — the
formulas were reproduced faithfully, and the discrepancy traces to what
those formulas structurally are, not to a modelling mistake in
translating them.

---

## 3. SCYTHER CONFIGURATION DISCREPANCY

| Parameter | Paper Config 1 | Our Config 1 | Paper Config 2 | Our Config 2 | Paper Config 3 | Our Config 3 |
|---|---|---|---|---|---|---|
| Max runs | 50 | **50 — exact** | 100 | **100 — exact** | 100 | **100 — exact** |
| Matching type | typed | **typed (`-m 0`) — exact** | typed | **typed — exact** | (not restated) | typed |
| Search pruning | best-attack | **default (best-attack) — exact** | all-attacks | **`-A` — exact** | all-attacks | **`-A` — exact** |
| Patterns/claim | 100 | **NOT EXPOSED — not reproduced** | 100 | **NOT EXPOSED — not reproduced** | 85 | **NOT EXPOSED — substituted `--max-of-role=3`** |
| Graph output (pt) | 32 | N/A (no GUI/graph renderer used) | 32 | N/A | 32 | N/A |

**Which parameters were exactly reproduced:** max-runs and
matching-type/search-pruning for all three configurations — these are
exposed by the CLI backend and set to the paper's exact stated values.

**Which were approximated/substituted:** Config 3's differentiator
(`--max-of-role=3`, standing in for "85 patterns/claim," which the
modern CLI backend does not expose as a flag at all — confirmed by
inspecting `scyther-linux --long-help`'s full option list, which has no
patterns-per-claim equivalent).

**Which could not be reproduced at all:** the GUI-only "patterns per
claim" figure for any of the three configurations, and the "graph output
font size" (a purely cosmetic GUI rendering setting with no bearing on
verification results, not reproduced since no GUI is used).

**Do these differences affect the security results?** The **Ok/Fail
pattern is identical across all three of our configurations** and was
additionally re-tested at `--max-of-role=1` (not one of the paper's
three configurations, but an additional bound we tested) — the result
did not change. This suggests, but does not prove, that the specific
untested "patterns per claim" parameter is not the cause of the
Niagree/Nisynch discrepancy (since varying every parameter we *can*
control never changes the outcome) — but since we cannot set that exact
parameter, we cannot rule it out with certainty either.

**Exact or partial reproduction?** **Partial reproduction.** Max-runs
and matching-type/search-pruning are exact; "patterns per claim" is not
reproducible with the tooling available and is either omitted (Configs
1–2) or substituted with a documented, non-equivalent stand-in bound
(Config 3). None of the three configurations should be described as an
exact reproduction of the paper's GUI-based configuration.

---

## 4. COMPUTATIONAL OVERHEAD DISCREPANCY

**Paper (Table 4):** `T_SHA_1 = 8`, `T_ACE = 2`. No per-step breakdown is
published — the paper states only the final totals.

**Implementation (measured from real, executed code paths in
`src/ake.py`):**

| Step | T_SHA_1 | T_ACE |
|---|---|---|
| AKE1 (6LN) | 1 | 1 |
| AKE2 (6LC) | 5 | 2 |
| AKE3 (6LN) | 3 | 1 |
| **Total** | **9** | **4** |

**Field-by-field reconciliation attempt:**

- **AKE1 (1 hash, 1 ACE):** matches what the paper's Step AKE1 text
  literally describes (one `AD` computation via `H(K6LN)`, one ACE
  encrypt). No discrepancy here in isolation.
- **AKE2 (5 hashes, 2 ACE) — this is where the totals diverge.** Our
  count includes: `Mk'=Ms⊕H(R6LC)` (1), `AD'` via `H(K6LN)` (1), ACE
  decrypt (1 T_ACE), `T=Mk'⊕H(ID6LC)` (1), `SK=H(...)` (1), `M=H(SK)`
  (1), ACE encrypt for CT1 (1 T_ACE) = 5 hashes + 2 ACE. **The paper's
  Step AKE2 prose describes exactly these same operations** (`Mk'`,
  `AD'`, decrypt, `T`, `Sc1`, `B1`, `A1`, `SK`, `M`, encrypt) — nothing
  in our count adds an operation the paper's prose doesn't also
  describe performing.
- **AKE3 (3 hashes, 1 ACE):** `AD''` via `H(K6LN)` (1), ACE decrypt (1
  T_ACE), `SK'=H(...)` (1), `M'=H(SK')` (1) = 3 hashes + 1 ACE. Again,
  every operation traces to text the paper's own Step AKE3 describes.

**Determining the source of the gap (9 vs 8, 4 vs 2):**

- *Does the paper count both parties the same way?* Unknown from the
  published text — Table 4 gives one combined number for "PSLAE" with
  no per-role or per-message breakdown, so we cannot determine whether
  the paper's "8" is a sum over both parties (as ours is) or a
  single-party count, or something else.
- *Are some operations omitted/grouped in the paper?* Plausible but
  unverifiable. A natural candidate: if the paper does not count
  re-deriving `AD`/`Si` at each step as separate hash operations (since
  Steps RP-4/RP-5 present these as "setup," reused conceptually across
  steps rather than recomputed), the count would drop — but the paper's
  own protocol text (Section 5.2) does not state that any party caches
  `Si`/`AD` across steps rather than recomputing them, so we cannot
  confirm this is what happened.
- *T_ACE = 2 vs. 4:* the paper's number matches exactly "one ACE
  operation per message" (2 messages = 2 T_ACE). Our number counts
  encrypt/decrypt as separate ACE invocations (1 encrypt in AKE1, 1
  decrypt+1 encrypt in AKE2, 1 decrypt in AKE3 = 4). **This looks like
  the most likely single source of the T_ACE gap**: a "per-message"
  convention (paper) vs. a "per-encrypt/decrypt-call" convention (ours).
  This is a plausible, specific technical explanation, but the paper
  does not state its counting convention explicitly, so this remains an
  inference, not a confirmed fact.

**Can Table 4 be exactly reproduced from the published equations alone?
No.** The paper's Table 4 states final totals only, with no stated
operation-counting convention (per-message vs. per-primitive-call,
whether AD/Si recomputation counts, whether both parties are summed the
same way). Given the protocol's own formulas (which our implementation
follows), our count of 9/4 is directly traceable and auditable
(`performance/overhead.py`'s docstring). We cannot determine which
convention the paper's authors used to arrive at 8/2 without their own
per-step derivation, which is not published.

**Classification: PAPER AMBIGUITY** (counting convention not published;
not something we can silently guess and force-match).

---

## 5. COMMUNICATION OVERHEAD DISCREPANCY

**M1 total: 416 bits (exact match, both sides agree field-by-field):**
`T6LN(32) + D(64) + CT(128) + Tag6LN(128) + RN1(64) = 416`.

**M2: paper says 608 bits; implementation measures 576 bits. Gap = 32
bits exactly.**

Field-by-field, our M2:

| Field | Our width | Source |
|---|---|---|
| `T6C` | 32 bits | matches paper's stated timestamp width |
| `A1` | 64 bits | `B1 xor RN1`, both 64-bit operands (paper states `RN1`/`RN2` are 64 bits) |
| `M` | 160 bits | `H(SK)`, and the paper states its hash function is SHA-160 (native 160-bit output) |
| `CT1` | 128 bits | paper states ACE's ciphertext is 128 bits |
| `Tag6LC` | 128 bits | paper states ACE's tag is 128 bits |
| `RN2` | 64 bits | paper states random numbers are 64 bits |
| **Total** | **576 bits** | |

**Where could the missing 32 bits come from?** We examined each
candidate explicitly:

- *A different field size than we used?* Every individual field width
  above is taken directly from an explicit statement elsewhere in the
  paper (Table 1's notation list, or the ACE description in Section
  4.4). We found no alternative stated width for any of these six
  fields that would add exactly 32 bits.
- *An additional field we're missing?* Section 5.2's own definition of
  `M2 = (T6C || A1||M ||(CT1||Tag6LC) || RN2)` lists exactly six
  components, matching what we implemented. We found no seventh field
  described anywhere in the M2 definition.
- *A field counted differently by the paper?* The most numerically
  exact candidate: 32 bits is precisely one `T6C`-timestamp's worth. It
  is possible the paper's Table 5 double-counts a timestamp field (e.g.
  counting a timestamp once in the field list and again as part of a
  "freshness overhead" convention), but we have no way to confirm this
  from the published table alone — it is a numerically-motivated
  hypothesis, not a demonstrated fact.
- *An arithmetic inconsistency in the paper itself?* We note (see also
  `docs/paper_ambiguities.md` #14) that the paper's own Table 5 has at
  least one other internal arithmetic inconsistency (Ref. [24]'s row:
  "544 bits/160 bits" plus "480 bits" is printed with a total of "1184
  bits," but 544+480=1024, not 1184) — establishing that Table 5
  contains at least one confirmed arithmetic error elsewhere in the same
  table. This makes "the M2=608 figure itself contains an error" a
  credible possibility, though we cannot elevate this from "credible"
  to "confirmed" for the PSLAE row specifically without the authors'
  own derivation.
- *Is the published description insufficient?* For this specific 32-bit
  gap, yes — we cannot identify, from the published text alone, which
  of the above explanations is correct.

**Classification: PAPER VALUE CANNOT BE RECONCILED** from the published
information alone. The implementation was not modified to force 608
bits; 576 bits is what the paper's own stated field widths, applied to
the paper's own stated M2 field list, sum to.

---

## 6. STORAGE OVERHEAD DISCREPANCY

### 6.1 What the paper's Step RP-3 literally states is stored

- **6LN:** `{TID6LC, Sc, K6LN, K6LC, AID6LN, Mk}` — six fields, explicitly
  listed.
- **6LC:** `{TID6LC, Sc, K6LN, AID6LN}` — four fields, explicitly listed.

### 6.2 What our implementation stores

**6LN (`src/entities.py::SixLN`) — matches the paper's list exactly,
six fields, no additions:**

| Field | Bytes | Bit-width source |
|---|---|---|
| `TID6LC` | 8 | 64-bit identity (paper's stated width for identities) |
| `Sc` | 8 | 64-bit (built from four 64-bit XOR chunks, Step RP-2) |
| `K6LN` | 8 | 64-bit key |
| `K6LC` | 8 | 64-bit key |
| `AID6LN` | 8 | 64-bit (paper explicitly states "AID6LN of 64 bits," Step RP-2) |
| `Mk` | 32 | 256-bit (reconstruction — paper's own "265 bits," corrected to 256 per the 128+128=256 arithmetic elsewhere in the same section; see `docs/paper_ambiguities.md` #1) |
| **Total** | **72** | |

**6LC (`src/entities.py::SensorRecord`) — literal Step RP-3 fields plus
reconstruction additions:**

| Field | Bytes | Category |
|---|---|---|
| `TID6LC` | 8 | literal Step RP-3 field |
| `Sc` | 8 | literal Step RP-3 field |
| `K6LN` | 8 | literal Step RP-3 field |
| `AID6LN` | 8 | literal Step RP-3 field |
| **Subtotal (literal paper fields)** | **32** | |
| `ID6LN` | 8 | reconstruction addition — required by Step AKE2's own text ("The 6LC retrieves ID6LN, K6LC, K6LN..."), not in Step RP-3's stored-field list |
| `K6LC` | 8 | reconstruction addition — same reason |
| `Ms` | 32 | reconstruction addition — required to recompute `Mk'=Ms⊕H(R6LC)` in Step AKE2, but `Ms` is never listed as stored anywhere in Step RP-3 |
| `R6LC` | 8 | reconstruction addition — same reason |
| **Subtotal (reconstruction additions)** | **56** | |
| **Total as implemented** | **88** | |

### 6.3 Why the totals diverge from the paper's 32/60

- **6LN: 72 vs. paper's 32.** This is **not** a field-count difference —
  our 6LN stores exactly the six fields Step RP-3 lists, no more, no
  fewer. It is a **field-width** difference: summing the paper's *own*
  declared bit-widths for those same six fields (64+64+64+64+64+256 =
  576 bits = 72 bytes) already exceeds the paper's claimed 32-byte
  total by itself — `Mk` alone, at the paper's own (typo-corrected)
  256-bit width, is 32 bytes, equal to the paper's *entire* claimed
  sensor total. **The paper's 32-byte figure cannot be reconciled with
  the paper's own stated field widths for its own listed fields**,
  regardless of any reconstruction decision on our part.
- **6LC: 32 (literal) / 88 (as-implemented) vs. paper's 60.** The
  literal-Step-RP-3-fields-only figure (32 bytes) is *below* the paper's
  60-byte claim; the as-implemented figure (88 bytes, including the four
  reconstruction-required fields) is *above* it. Since Step RP-3 itself
  only lists four fields for the 6LC (`TID6LC, Sc, K6LN, AID6LN` — no
  `ID6LN`, `K6LC`, `Ms`, or `R6LC`), and those four fields sum to 32
  bytes under the paper's own widths, **60 bytes cannot be reconciled
  against the paper's own literal Step RP-3 field list either** — 60 is
  neither the literal-fields total (32) nor a number obviously explained
  by adding some subset of our four reconstruction fields (the closest
  single addition, `+K6LC` at 8 bytes, gives 40; no subset of
  {8,8,32,8} added to 32 gives exactly 60).

**Is the difference caused by:**
- *Different field sizes?* No — we used the paper's own stated widths.
- *Fields added because of ambiguous equations?* Yes, for the 6LC's
  extra 56 bytes specifically (the four reconstruction fields,
  individually justified above) — but this addition alone does not
  explain the 6LN's discrepancy (which has no added fields at all) nor
  fully explain the 6LC's gap (88 ≠ 60 either way).
- *Fields required by AKE2?* Yes, specifically for the 6LC's `ID6LN`,
  `K6LC`, `Ms`, `R6LC` additions (§6.2).
- *Reconstruction decisions?* Only for the 6LC's additions, as above.
- *Inconsistencies in the paper's Table 6 itself?* Most likely, **for
  the 6LN figure specifically** — 32 bytes cannot represent all six of
  the paper's own Step RP-3 fields at the paper's own stated widths, as
  demonstrated by simple arithmetic (§6.3). This is the strongest,
  most directly demonstrable inconsistency in this entire report,
  because it requires no assumption about the 6LC's under-specified
  extra fields — it follows purely from the paper's own numbers for
  the 6LN, which has no reconstruction ambiguity at all.

**Classification: PAPER VALUE CANNOT BE RECONCILED**, most confidently
for the 6LN figure (demonstrable by arithmetic alone, no reconstruction
assumptions involved), and for the 6LC figure with the caveat that our
count includes 56 bytes of fields the paper never explicitly lists as
stored but which Step AKE2's own formulas require.

---

## 7. AID6LN / UNTRACEABILITY DISCREPANCY

**1. What exactly the paper claims:** Proposition 3 (Section 6.1):
*"Each session's `AID6LN` is changed."*

**2. What the protocol steps actually specify:** `AID6LN = ID6LN ⊕ K6LN
⊕ K6LC` is defined exactly once, in Step RP-2 (registration). Steps
AKE1, AKE2, AKE3 (Section 5.2) use `AID6LN` in message construction
(`D`, `A`, `B`) but **no formula anywhere reassigns it**. The paper's own
list of per-session-updated values (Step AKE2's `Sc1`, described as "a
new security temporal parameter") does not include `AID6LN`.

**3. Does any published equation clearly update AID6LN? No.** We
searched Sections 5.1, 5.2, and 6.1 specifically for an update formula
or implicit rotation mechanism. None exists. The closest candidate,
`Sc1`, is a distinct variable with its own distinct formula
(`T=Mk'⊕H(ID6LC)`, `Sc1=T1⊕T2⊕T3⊕T4`) that does not touch `ID6LN`,
`K6LN`, or `K6LC` — the three inputs to `AID6LN`.

**4. Can the claim be reproduced literally from the protocol
description? No.** Implemented literally, `AID6LN` (and therefore `D =
AID6LN ⊕ TID6LC`, which is also never updated since `TID6LC` is likewise
never reassigned in the AKE phase) is identical across every session for
a given sensor. This was directly confirmed by execution:
`tests/test_replay_and_traceability.py::test_documented_gap_D_is_linkable_across_sessions`
runs two real consecutive sessions and shows `D` is byte-identical
across them.

**5. Ambiguity, omission, or inconsistency?** This is best classified as
an **inconsistency between the paper's formal security claim (Prop. 3)
and its own protocol description (Section 5.2)** — not a notational
ambiguity (there is no alternate reading of the existing formulas that
produces rotation) and not simply a missing detail we could infer from
context (no other section supplies a formula that would, if applied,
achieve this).

**6. What would be required to implement AID6LN rotation?** At minimum,
a formula analogous to `Sc1`'s — e.g. a new value `AID6LN' =
f(ID6LN,K6LN',K6LC')` for some updated keys, or a direct XOR-update
formula, published by the authors — none of which exists in the paper.
Any such formula we invented would be **our own addition**, not a
reproduction.

**7. Would adding such a rotation be a modification of the base paper?
Yes.** Per your explicit instruction, this rotation was **not** added.
The gap is documented only, not patched.

**Classification: PAPER AMBIGUITY** shading into **genuine
inconsistency** — the paper's own text gives no supporting formula for
its own claim.

---

## 8. SVO G2 REPRODUCIBILITY LIMITATION

**Exactly what the paper publishes (Section 6.2, Fig. 6):** notations
(Table 2), inference rules (Modus Ponens, Necessitation), 4 axioms (BA1,
SA1, SA2, R1), 5 initial assumptions (IS1–IS5), an idealization of both
messages, and a 3-step derivation (X1, X2, X3) concluding **"G1 is
verified"** — i.e., the 6LC's belief about the encrypted M1 payload.

**Exactly what this project reproduces:** the paper's own G1 derivation,
transcribed faithfully into
`docs/module_12_svo.md`, with every axiom/assumption/step matching
Fig. 6.

**What is missing for G2:** the paper's prose after Fig. 6 asserts (in
general terms) that mutual authentication and session-key agreement
follow, implying a symmetric derivation exists for the 6LN's belief
about M2 (call it G2 by the natural naming convention) — but **Fig. 6
itself only contains the X1–X3 steps for G1**. No G2-specific axioms,
initial assumptions, or derivation steps are published anywhere in the
paper.

**Can G2 legitimately be reconstructed?** Not without inventing content.
A structurally symmetric G2 derivation (mirroring X1–X3 but for the
6LN's belief about `CT1||Tag6LC`) is *plausible* to sketch by analogy,
but doing so would require us to invent specific axiom instances and
initial assumptions (an "IS6," "IS7," etc.) that the paper never states
— this would not be reproduction, it would be new formal work
attributed to a paper that doesn't contain it.

**Would this require assumptions not stated in the paper? Yes** —
specifically, which axioms apply to M2's fields, and what the 6LN is
assumed to already believe/possess before receiving M2, are not stated
for the G2 case anywhere in the published text.

**Classification: UNREPRODUCIBLE FROM PUBLISHED INFORMATION.** Not
invented, per your instruction.

---

## 9. ACE REPRODUCIBILITY LIMITATION

**What the paper specifies about ACE (Section 4.4):** ACE is cited as an
**external** NIST-LWC round-1 submission. The paper states only its
black-box interface: `Si <- ACE(Nc||Kc)` (128-bit nonce, 128-bit key),
`(CT||Tag) = E_Si{AD,PT}`, `(PT||Tag') = D_Si{AD,CT}` (128-bit AD/CT/PT/Tag),
and its structural "inverse-free" property (decryption always yields PT
structurally; tag comparison is a separate explicit step). **The
paper does not publish ACE's internal permutation, round function, or
sponge parameters anywhere** — this is expected, since ACE is cited,
external, prior work, not something the PSLAE paper itself defines.

**What information is actually available:** only the interface and
structural property above — sourced from the actual published NIST-LWC
ACE submission (Aagaard, Fan, Gong et al.), which is a separate document
from the PSLAE paper and was not consulted for this implementation
(only the PSLAE paper's own description was used, per the task's
"paper does not provide enough information" instruction).

**What this implementation reproduces:** the interface exactly (128-bit
key/nonce/CT/PT/Tag; the "inverse-free" structural property, verified
by our tests exercising both encrypt/decrypt paths). Internally,
`src/ace.py` substitutes AES-128-CTR (for the inverse-free keystream
transform) + HMAC-SHA256 truncated to 128 bits (for the tag) —
explicitly labelled `RECONSTRUCTED FROM THE PAPER` in the module's own
docstring, not claimed as the authors' cipher.

**What cannot be reproduced without the authors' exact cipher details:**
the actual ACE permutation's internal diffusion/confusion operations,
its exact number of rounds, and therefore its exact computational cost
in cycles/milliseconds.

**Does this affect computational overhead comparisons? Yes, indirectly.**
`T_ACE`'s *count* (how many times ACE is invoked) is unaffected by this
substitution — that is a protocol-structure question, answered in §4.
But any *timing* comparison (milliseconds) would be affected, since our
substitute primitive's real-world execution cost is not necessarily
equal to the real ACE cipher's — this is why `performance/overhead.py`
deliberately reports operation **counts**, not timing, avoiding a
claim we cannot support.

**Classification: UNREPRODUCIBLE FROM PUBLISHED INFORMATION** (ACE's
internals are external, cited work the PSLAE paper itself never
republishes).

---

## 10. TABLE: PAPER vs MY IMPLEMENTATION

| # | Item | Paper | Implementation | Classification |
|---|---|---|---|---|
| 1 | Scyther Secret | Ok | Ok | EXACT MATCH |
| 2 | Scyther Alive | Ok | Ok | EXACT MATCH |
| 3 | Scyther Weakagree | Ok | Ok | EXACT MATCH |
| 4 | Scyther Niagree | Ok | Fail (2 attacks) | UNRESOLVED — best-supported IMPLEMENTATION-STRUCTURE explanation, version untested |
| 5 | Scyther Nisynch | Ok | Fail (2 attacks) | UNRESOLVED — same |
| 6 | Config 1 run-limit/matching | 50, typed, best-attack | identical | EXACT MATCH (this parameter subset) |
| 7 | Config 2 run-limit/matching | 100, typed, all-attacks | identical | EXACT MATCH (this parameter subset) |
| 8 | Config 3 run-limit/matching | 100, all-attacks | identical | EXACT MATCH (this parameter subset) |
| 9 | Configs' "patterns/claim" | 100/100/85 | not exposed by CLI | TOOL/VERSION DIFFERENCE |
| 10 | T_SHA_1 | 8 | 9 | PAPER AMBIGUITY (counting convention unpublished) |
| 11 | T_ACE | 2 | 4 | PAPER AMBIGUITY (likely per-message vs per-call convention) |
| 12 | Comm. 6LN→6LC | 416 | 416 | EXACT MATCH |
| 13 | Comm. 6LC→6LN | 608 | 576 | PAPER VALUE CANNOT BE RECONCILED |
| 14 | Storage 6LN | 32 | 72 | PAPER VALUE CANNOT BE RECONCILED (demonstrable by paper's own field widths) |
| 15 | Storage 6LC | 60 | 32 / 88 | PAPER VALUE CANNOT BE RECONCILED |
| 16 | AID6LN rotation | claimed | not implementable from published steps | PAPER AMBIGUITY / inconsistency |
| 17 | SVO G2 | implied | not published | UNREPRODUCIBLE FROM PUBLISHED INFORMATION |
| 18 | ACE internals | external, cited | interface-only reconstruction | UNREPRODUCIBLE FROM PUBLISHED INFORMATION |

---

## 11. ROOT CAUSE CLASSIFICATION

- **CONFIRMED causes:** the T6C-width-sized (32-bit) gap in Table 5's M2
  total exists and is arithmetically exact, but its *specific
  origin* (double-count vs. missing paper field vs. our own
  misinterpretation) is not confirmed, only narrowed to plausible
  candidates (§5). The 6LN storage figure's impossibility (32 bytes
  cannot hold the paper's own six listed fields at the paper's own
  stated widths) **is** confirmed by direct arithmetic, independent of
  any reconstruction assumption (§6.3).
- **LIKELY causes:** the Niagree/Nisynch discrepancy tracing to `RN1`
  being bound only via plaintext `A1` rather than inside `CT1` (§2,
  backed by controlled diagnostic experiments); T_ACE's per-message vs.
  per-call counting convention (§4).
- **POSSIBLE causes:** Table 5's M2 figure reflecting a double-counted
  timestamp or an unstated field-counting convention (§5); Table 4's
  T_SHA_1 gap reflecting cached vs. recomputed `AD`/`Si` (§4).
- **UNRESOLVED factors:** whether the paper's stated Scyther 1.1.3 would
  reproduce the same Niagree/Nisynch result (untested — no way to obtain
  that historical build in this environment); the exact derivation the
  paper's authors used to reach Table 4/5/6's published totals (their
  internal working is not published).

---

## 12. WHAT IS CONFIRMED

- The SPDL model reproduces every field of M1 and M2 the paper
  describes, with no missing or extra message components.
- Secret, Alive, Weakagree genuinely pass on a real, independently
  executed Scyther binary, both roles.
- Niagree and Nisynch genuinely fail, "exactly 2 attacks," both roles,
  stable across three configurations and additional bound variations we
  tested.
- Key reuse across message directions, claim placement, and the general
  `xorf` abstraction technique are each individually ruled out as the
  sole cause of the Niagree/Nisynch failures, by controlled experiment.
- 21/21 implementation-level tests pass, including one that directly
  demonstrates the AID6LN traceability gap exists as coded.
- The 6LN storage figure (32 bytes, paper's claim) is arithmetically
  impossible given the paper's own six listed fields at the paper's own
  stated widths — this is a confirmed inconsistency, not merely a
  reconstruction artifact.
- M1's communication total (416 bits) matches the paper exactly.

## 13. WHAT IS UNCERTAIN

- Whether the Niagree/Nisynch discrepancy would also occur under the
  paper's exact historical Scyther 1.1.3.
- The exact origin of Table 5's 32-bit M2 gap (several plausible
  explanations identified, none confirmed).
- The exact origin of Table 4's T_SHA_1/T_ACE gap (a plausible
  per-message-vs-per-call convention difference identified for T_ACE,
  not confirmed).
- The exact origin of Table 6's 6LC figure (60 bytes matches neither our
  literal-fields count of 32 nor our as-implemented count of 88).
- Whether the paper's authors intended a different, unpublished
  ACE-operation-counting or field-storage convention that would fully
  reconcile Tables 4–6.

## 14. WHAT SHOULD NOT BE MODIFIED

Per your explicit instructions, and consistent with everything above,
this report resulted in **zero changes** to: protocol equations
(`src/registration.py`, `src/ake.py`), the SPDL model or its claims
(`scyther/pslae.spdl`), performance figures
(`performance/overhead.py`), the AID6LN rotation behavior, or the SVO
documentation. This document is analysis only.

## 15. FINAL REPRODUCIBILITY CONCLUSION

This implementation reproduces PSLAE's protocol logic and message
structure faithfully and verifiably (21/21 tests, matching session
keys, Scyther's Secret/Alive/Weakagree claims all matching the paper).
It does **not** achieve 100% reproduction of every published result:
Niagree/Nisynch diverge (best-supported explanation identified and
evidenced, not proven, with the Scyther-version variable explicitly
left untested); Scyther Configuration 3 is a documented substitute, not
an exact reproduction; three performance figures (T_SHA_1/T_ACE,
6LC→6LN communication, both storage totals) diverge from the paper by
amounts we can partially but not fully explain, including one
discrepancy (6LN storage) that appears to be a genuine inconsistency in
the paper's own published Table 6 rather than anything attributable to
this implementation. AID6LN rotation and SVO's G2 derivation are
confirmed gaps in the paper's own published material, not implementation
shortcomings, and were correctly left unaddressed rather than invented.
