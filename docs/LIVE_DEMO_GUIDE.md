# LIVE_DEMO_GUIDE - running order for the review (about 30 minutes)
Use `--reveal-secrets` only when explaining an equation, and say it is an educational insecure mode with disposable keys.

| # | Command | Say (plain words) | Point out |
|---|---|---|---|
| 1 | `python demo.py overview` | "A sensor and a controller must prove who they are and agree a key." | roles, algorithms, which values are public/secret/stored |
| 2 | `python demo.py registration` | "Registration happens once, safely, before deployment." | RP-2 '265 bit' ambiguity; RP-3 stored attributes incl. padding; Si/AD not stored |
| 3 | `python demo.py ake1` | "The sensor hides its alias and sends M1." | field table; 416 bits = paper; tag does not cover the timestamp |
| 4 | `python demo.py packet-breakdown --message M1` | "Every field and its size." | protection column |
| 5 | `python demo.py ake2` | "The controller checks, decrypts and builds M2." | the 5 checks; 608 vs 576 (T6C) |
| 6 | `python demo.py packet-breakdown --message M2` | "Reply fields." | paper vs literal vs reconstructed |
| 7 | `python demo.py ake3` | "The sensor verifies and derives the same key." | Sc1 taken from CT1 (paper's T' not possible); keys equal |
| 8 | `python demo.py session-key` | "The key is never sent; both sides compute it." | derivation table |
| 9 | `python demo.py operations` | "What cryptography actually ran." | logical 12 vs paper 8 |
| 10 | `python demo.py security --scenario A01` | "Replay: resend a recorded message." | rejected by state change, not by a replay cache |
| 11 | `python demo.py security --scenario A04` and `A05` | "Flip one bit of ciphertext / tag." | tag verification |
| 12 | `python demo.py security --scenario A03` | "Change the timestamp of a held message." | **accepted** → desync (a weakness we report) |
| 13 | `python demo.py security --scenario A17` | "XOR the two ciphertexts of one session." | AID6LN recovered (key/nonce reuse) |
| 14 | `python demo.py security --scenario A11` | "Drop the reply." | permanent desynchronisation |
| 15 | `python demo.py security --scenario A14` and `A15` | "Many sessions: keys differ, and the alias changes." | keys equal inside a session, different across; D changes (a reconstruction) |
| 16 | `python demo.py scyther` | "Automatic attack search." | 10 Ok in our model; timestamps authenticated there (paper: bare); XOR abstraction |
| 17 | `python demo.py svo --summary` | "Belief logic, manual." | PUBLISHED vs RECONSTRUCTED, not machine-verified |
| 18 | `python demo.py performance --part summary` | "Numbers, side by side." | nothing forced |
| 19 | `python demo.py menu` | live Q&A | any item on request |

Every stage command can be run alone; each states its prerequisites.
