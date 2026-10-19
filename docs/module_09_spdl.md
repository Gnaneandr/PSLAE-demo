# Module 9 — SPDL Model

**1. Purpose:** Build an executable SPDL model of PSLAE's AKE phase for
Scyther, corresponding to the actual protocol (not a generic/unrelated
example).

**2. What the paper says (Section 6.3):** "Scyther is used to verify
PSLAE's security properties... supports various adversary models
involving the CK, the eCK, and the Dolev-Yao... it is evident that PSLAE
offers all security claims, including Weakagree..., Nisynch, Alive...,
and secrecy." The paper does **not** publish its own `.spdl` source file
— only screenshots of the GUI's claim-status table (Figs. 7-9).

**3. What we implemented:** `scyther/pslae.spdl` — **PSLAE SPDL model
reconstructed from the published protocol description**, explicitly NOT
the authors' original source (which was never published). It defines two
roles, `SixLN` and `SixLC`, with the exact 2-message flow of Steps
AKE1/AKE2 (message contents match `src/ake.py::step_ake1/step_ake2`
field-for-field), and 5 claims per role (`Secret`, `Alive`, `Weakagree`,
`Niagree`, `Nisynch`), matching the 5 claim types the paper reports.

**Key modelling decision — XOR abstraction:** Scyther has **no native
XOR operator**; its Dolev-Yao intruder model reasons over free/black-box
terms and standard encryption/hashing, not algebraic properties like
`a XOR a = 0`. This is a well-known, standard limitation whenever
XOR-heavy lightweight protocols are analysed in Scyther (this applies
equally to any hypothetical analysis of SLAP or similar schemes). We
model every XOR-derived composite value (`A`, `B`, `D`, `Sc1`, `B1`,
`A1`, `SK`, `M`) as the output of a distinct one-way `hashfunction`
combinator (`xorf`) applied to its real constituent inputs. Consequence:
this model can prove/refute standard Dolev-Yao network-level claims
(exactly what the paper says it tested) but **cannot** capture attacks
that specifically exploit XOR's algebraic cancellation properties — that
is outside what a function/hash abstraction can express in Scyther.

**Key modelling decision — per-pair long-term secrets:** `AID6LN`, `Sc`,
`K6LN`, `K6LC`, `TID6LC`, `ID6LC` are all modelled as distinct
hash-labelled derivatives (`hAid`, `hSc`, `hKsn`, `hKsc`, `hTid`,
`hIdc`) of Scyther's built-in per-agent-pair symmetric key `k(I,R)`, so
every long-term secret remains specific to one (6LN,6LC) pair — matching
how Registration (Section 5.1, assumed to run over a secure channel per
Section 4.1/4.2) actually establishes pair-specific secrets. Registration
itself is **not** modelled as a Scyther role — only the AKE phase is
within the Dolev-Yao network scope, matching the paper's own stated
adversary model.

**ACE abstraction:** `{...}Si` (Scyther's native shared-key encryption
operator) is used to represent PSLAE's `(CT||Tag) = E_Si{AD,PT}`, since
Scyther's built-in encryption already assumes the IND-CPA/IND-CCA +
integrity guarantee that PSLAE explicitly relies on via ACE's
"inverse-free" property.

**Identifier syntax note:** Scyther's real lexer (confirmed by reading
`scyther/src/scanner.l` in the official source, and by trial-and-error
against the real compiled binary) only allows letters, digits, `^`, `-`,
`!`, `'` in identifiers — **not underscores** (underscore is reserved
specifically for the `send_N`/`recv_N`/`claim_N` label separator). Our
first draft of this file (before Module 9's real execution) used
underscored names like `h_aid` and failed to parse; all identifiers were
renamed (`hAid`, `hSc`, `hKsn`, `hKsc`, `hTid`, `hIdc`) to fix this.

**4. Files involved:** `scyther/pslae.spdl`.

**5-7. Input/Processing/Output:** N/A for this module alone — Module 9
actually executes it.

**8. How to run it:** see Module 9.

**9-10. Expected result / how to verify:** see Module 9.

**11. Paper ambiguity:** the Niagree/Nisynch modelling limitation
described above; also inherits ambiguities #6, #7, #9 (each formula
choice is mirrored exactly in the SPDL, with matching inline comments).

**12. Status:** **COMPLETED** — parses and executes cleanly against a
real, locally-built Scyther binary (see Module 9). Explicitly labelled
as a reconstruction, not the authors' source.
