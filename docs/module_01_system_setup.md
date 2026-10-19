# Module 1 — System Setup & Cryptographic Primitives

**1. Purpose:** Provide the shared building blocks (identities, keys,
nonces, timestamps, hashing, XOR, authenticated encryption, entity
state) that every later module depends on.

**2. What the paper says:** Section 4.4 specifies ACE as a 4-stage AEAD
(init state, AD processing, PT processing, finalization) with 128-bit
key/nonce/CT/PT/Tag, cited from an external NIST-LWC round-1 submission.
Section 5 states PSLAE uses SHA-160 (SHA-1) as its sole hash function,
plus bitwise XOR. Table 1 lists all notations used.

**3. What we implemented:**
- `src/crypto_utils.py`: `sha1()` (native SHA-1), `H_bits()` (a
  RECONSTRUCTION — a KDF that extends/truncates SHA-1 to arbitrary
  widths, needed because the paper's formulas XOR SHA-1 output against
  operands of many different declared bit-widths with no reconciliation
  rule given — see `docs/paper_ambiguities.md` #2), `xor_bytes`/
  `xor_many`, `tile_to()` (RECONSTRUCTION for width-mismatched XORs, see
  ambiguities #3), `split_equal()`, `random_bytes()`.
- `src/ace.py`: **RECONSTRUCTED FROM THE PAPER.** The paper only
  specifies ACE's black-box interface, not its internal permutation (it
  is an external, cited NIST-LWC candidate). We substitute AES-128-CTR
  (for the "inverse-free" PT<->CT transform) + HMAC-SHA256 truncated to
  128 bits (for the authentication tag), matching the paper's stated
  interface exactly (128-bit key/nonce/CT/PT/Tag) and its "inverse-free"
  structural property, but this is **explicitly not the real ACE
  cipher** — see the large module docstring in `src/ace.py` for exactly
  what information the paper does and does not provide.
- `src/entities.py`: `SixLN` and `SixLC` classes holding exactly the
  fields Step RP-3 specifies (plus documented additions — ambiguities
  #4).

**4. Files involved:** `src/crypto_utils.py`, `src/ace.py`,
`src/entities.py`.

**5. Input:** None (these are library modules).

**6. Processing:** N/A — pure utility functions/classes.

**7. Output:** N/A — imported by Modules 2-6.

**8. How to run it:** Not run standalone; exercised indirectly by every
other module's tests. To sanity-check in isolation:
```bash
python3 -c "from src.ace import encrypt, decrypt, init_state; \
Si=init_state(b'0'*16,b'1'*16); ct,tag=encrypt(Si,b'A'*16,b'B'*16); \
pt,tag2=decrypt(Si,b'A'*16,ct); print(pt==b'B'*16, tag==tag2)"
```
Expected output: `True True`

**9. Expected result:** ACE round-trips correctly; hash/XOR helpers
produce exact-length output as declared.

**10. How to verify it is correct:** `tests/test_registration.py` and
`tests/test_ake_success.py` exercise every primitive here transitively
and all 21 tests pass (see `results/protocol/pytest_output.txt`).

**11. Paper ambiguity:** See `docs/paper_ambiguities.md` entries #1, #2,
#3, #13.

**12. Status:** **COMPLETED** (ACE explicitly labelled as a
reconstruction, not the authors' cipher).
