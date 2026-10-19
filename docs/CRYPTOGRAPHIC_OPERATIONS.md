# CRYPTOGRAPHIC_OPERATIONS
Everything below was read from `src/ace.py`, `src/crypto_utils.py`, `src/ake.py`, `src/registration.py` and confirmed by `python demo.py operations --detail`.

## What each operation is (they are NOT interchangeable)
| Operation | What it does | Where used |
|---|---|---|
| XOR | combines two equal-length byte strings; reversible if you know one operand; hides a value only if the other operand is secret and not reused | AID6LN, A, B, D, A1, B1, Mk(reg), Sm, X, Fr, AD, T |
| SHA-1 (160 bit) | one-way fingerprint, no key | SK = SHA-1(AID‖B1‖Sc1‖RN1‖RN2); M = SHA-1(SK) (a *second* hash) |
| H_bits | SHA-1(x‖counter) concatenated to the requested width - a **reconstruction** to obtain 256-bit values the paper's algebra needs | Mk(reg), Sm, Fr, T, Mk (reconstructed), alias rotation |
| AES-128-CTR | keystream encryption: CT = PT xor keystream(Kc, Nc) | A‖B → CT, Sc1‖RN2 → CT1 |
| HMAC-SHA256 truncated to 128 bits | keyed authenticator Tag = HMAC(Kc, AD‖CT)[:16] | Tag6LN, Tag6LC |
| constant-time compare | tag/value equality without timing leak | every check |
| random | 64-bit RN1, RN2, identifiers and keys; 256-bit Ms (demo: seeded generator; real: os.urandom) | registration, AKE1, AKE2 |

## The ACE stand-in (interface-level reconstruction)
* Library: **pycryptodome** (`Crypto.Cipher.AES`) for AES; Python `hmac`/`hashlib` for HMAC-SHA256/SHA-1.
* **This is not the authors' ACE.** The paper (Sec.4.4/5) gives only an interface: 128-bit key, 128-bit nonce, 128-bit AD, 128-bit plaintext/ciphertext, 128-bit tag, "inverse-free" tag checking. ACE itself (a NIST lightweight-crypto candidate) is not specified in the paper and not implemented here. The audited project uses AES-CTR + HMAC to match the interface; it does **not** use AES-GCM.
* Sizes: key Kc 128 bit, nonce/initial counter Nc 128 bit, AD 128 bit, PT 128 bit, CT 128 bit, tag 128 bit.
* Encryption and authentication are combined in `ace.encrypt` (encrypt-then-MAC): CT = AES-CTR(PT); Tag = HMAC(Kc, AD‖CT).
* **Encrypted:** A‖B (M1), Sc1‖RN2 (M2). **Authenticated but not encrypted:** AD (a derived secret, not transmitted) and CT. **Not authenticated by the tag:** T6LN, T6C, D, RN1, RN2, A1, M (they are checked separately or only by freshness).
* Decryption: `ace.decrypt` always returns a plaintext and a recomputed tag (inverse-free); the *caller* compares tags (`ace.tags_match`, constant time) and aborts on mismatch. Plaintext is produced before the check but never used before it. Wrong key → garbage plaintext and a different tag (attack A08). Altered tag/CT → mismatch (A04, A05).
* Key use: the same Kc is used as the AES key and the HMAC key (key reuse across two primitives; acceptable here only for a demonstration).

## Key / nonce / AD reuse (supported by the code, demonstrated by A17)
* **Within one session** M1 and M2 are encrypted with the **same** Si (key, counter block) and AD (paper: Si' for CT1; audited code uses Si'' = Si'). Both plaintexts are one block, so both use the same keystream block: CT xor CT1 = (A‖B) xor (Sc1‖RN2). With RN1 and RN2 public, an eavesdropper recovers AID6LN and TID6LC. *Demonstrated (A17).*
* **Across sessions:** Sc is replaced by Sc1 every session and Mk = H_bits(Sc‖K6LN) follows, so Si changes each session (measured).
* No mitigation was added to `src/`. A fix (per-message nonce) would be a *separately named experimental implementation*; none is included in this package.

## Operation counts (measured, AKE phase; `python demo.py operations`)
| | logical hash calls | SHA-1 invocations (physical) | AEAD ops executed | paper |
|---|---|---|---|---|
| measured | 12 | see output | 4 (2 enc + 2 dec; each = 1 AES-CTR pass + 1 HMAC) | 8 SHA-1, 2 ACE |
The paper's "2 ACE" is a convention (one per message). The audited `performance/overhead.py` hard-codes 8 hashes; the measured reconstructed count is 12 because `Mk` is re-derived (one `H_bits`) on every access and again for the alias rotation.
