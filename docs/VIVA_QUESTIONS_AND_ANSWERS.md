# VIVA_QUESTIONS_AND_ANSWERS

Each answer: a simple version first, then a technical one. References: A.. = attack lab ids, R.. = docs/RECONSTRUCTION_DECISIONS.md.

**Q1. What is PSLAE?**
- *Simple:* A two-message protocol for a sensor and a controller to authenticate each other and agree a session key.
- *Technical:* Ashrif et al. 2024: M1 (6LN→6LC) and M2 (6LC→6LN) from XOR, SHA-1 and an ACE-interface AEAD.

**Q2. What are 6LN and 6LC?**
- *Simple:* The sensor node and the controller.
- *Technical:* 6LoWPAN node and 6LoWPAN controller; the controller keeps a record per sensor.

**Q3. Why registration?**
- *Simple:* So both sides share secrets before any message is sent.
- *Technical:* RP-1..RP-5 create ID/AID/K/Sc/Mk/Si/AD; AKE security rests on them.

**Q4. What is AID6LN?**
- *Simple:* A nickname used instead of the sensor's real ID.
- *Technical:* AID = ID6LN xor K6LN xor K6LC; sent only as D = AID xor TID6LC. Reconstructed config rotates it with H_bits(AID‖SK).

**Q5. Why is D = AID xor TID6LC?**
- *Simple:* To avoid sending the alias in clear.
- *Technical:* The controller recovers AID = TID xor D and looks it up. In this implementation D changes every session because the alias rotates (A15); that rotation is a reconstruction.

**Q6. What is Sc and why?**
- *Simple:* A shared 64-bit secret the sensor proves it knows.
- *Technical:* Sc = XOR of four 64-bit chunks of Sm; hidden in A; checked as Sc' at the controller.

**Q7. Why RN1 and RN2?**
- *Simple:* To make each session different.
- *Technical:* 64-bit random values; both enter SK and are sent in clear and hidden.

**Q8. Why timestamps?**
- *Simple:* To reject old messages.
- *Technical:* Freshness window DeltaT = 5 s. They are not authenticated by the tag (A03a, A06).

**Q9. Is the freshness check symmetric?**
- *Simple:* No.
- *Technical:* `tr - T > DeltaT` only; a future timestamp passes (A02c).

**Q10. What is M1's exact size?**
- *Simple:* 416 bits.
- *Technical:* 32+64+128+128+64; matches the paper.

**Q11. What is M2's exact size?**
- *Simple:* 576 bits with the paper's widths; 608 in the reconstructed config.
- *Technical:* The reconstructed T6C is 64 bits; the paper says 32. Packet inspector shows both.

**Q12. Does 608 prove the paper's table?**
- *Simple:* No.
- *Technical:* It is reached by a width change that contradicts the paper's text.

**Q13. Is the session key sent?**
- *Simple:* No.
- *Technical:* Both sides hash the same inputs; only M = SHA-1(SK) is sent.

**Q14. Why two hashes SK and M?**
- *Simple:* M proves knowledge without revealing SK.
- *Technical:* M = SHA-1(SK) is a separate hash of SK.

**Q15. How does the sensor get Sc1?**
- *Simple:* It decrypts it from CT1.
- *Technical:* The paper's T' needs ID6LC, which the sensor lacks (reconstruction R5).

**Q16. What is ACE?**
- *Simple:* A lightweight AEAD from a NIST competition.
- *Technical:* The paper gives only its interface; here AES-CTR + HMAC stand in.

**Q17. Do you use AES-GCM?**
- *Simple:* No.
- *Technical:* AES-128-CTR for encryption and HMAC-SHA256 truncated to 128 bits for the tag.

**Q18. What is encrypted?**
- *Simple:* A||B in M1 and Sc1||RN2 in M2.
- *Technical:* AES-CTR single block each; everything else travels in clear.

**Q19. What is authenticated?**
- *Simple:* AD and the ciphertext.
- *Technical:* Tag = HMAC(Kc, AD‖CT)[:16]; AD is a derived secret, not transmitted.

**Q20. Is the timestamp authenticated?**
- *Simple:* No.
- *Technical:* It is outside AD and CT; attacks A03a and A06-M1.T6LN.

**Q21. Why is hashing not encryption?**
- *Simple:* Hashing is one-way and keyless.
- *Technical:* SHA-1 cannot be reversed or decrypted.

**Q22. What does XOR do here?**
- *Simple:* It masks values.
- *Technical:* Safe only if the other operand is secret and not reused.

**Q23. What is H_bits?**
- *Simple:* A reconstruction that stretches SHA-1.
- *Technical:* SHA-1(x‖ctr) concatenated to 64/128/256 bits.

**Q24. Why is the master secret 256 bits?**
- *Simple:* 128+128 = 256; the paper's 265 is a typo.
- *Technical:* R2.

**Q25. What is tile_to?**
- *Simple:* Repeating Sc to 256 bits.
- *Technical:* Needed for Mk xor Sc; reconstruction R3.

**Q26. What is the Sc' problem?**
- *Simple:* The paper's equation never equals Sc.
- *Technical:* It equals Sc xor K6LN xor K6LC; code uses AID instead of ID6LN.

**Q27. What happens if the tag is wrong?**
- *Simple:* The message is rejected.
- *Technical:* `Tag6LN mismatch` / `Tag6LC mismatch` (A04, A05).

**Q28. What happens if the ciphertext is modified?**
- *Simple:* Tag check fails.
- *Technical:* A04a/b/c.

**Q29. What happens if the timestamp is old?**
- *Simple:* Rejected.
- *Technical:* A02a/b.

**Q30. What if an attacker changes the timestamp?**
- *Simple:* It is accepted if the message was not yet delivered.
- *Technical:* A03a → controller state changes while the sensor's does not → desync.

**Q31. What does the replay of a completed M1 do?**
- *Simple:* It is rejected in the reconstructed config.
- *Technical:* A01a: the stored Sc/alias changed (state transition), not a replay cache.

**Q32. Is replay always rejected?**
- *Simple:* In our tests a completed M1 is rejected on replay.
- *Technical:* A01a-c: rejected because the stored state changes every session. A held, undelivered M1 with a refreshed timestamp is a different attack and IS accepted (A03a).

**Q33. What if M2 is dropped?**
- *Simple:* The pair desynchronises permanently.
- *Technical:* A11b: controller already updated; no recovery path.

**Q34. What if M1 is dropped?**
- *Simple:* Nothing breaks.
- *Technical:* A11a.

**Q35. Can an eavesdropper learn the alias?**
- *Simple:* Yes, from one session.
- *Technical:* A17: CT xor CT1 shares a keystream; AID = x ^ RN1 ^ RN2.

**Q36. Is that a flaw of your cipher?**
- *Simple:* No: of the construction.
- *Technical:* Any nonce-based AEAD fails under key+nonce reuse; the paper itself uses Si' for CT1.

**Q37. Can the eavesdropper then get SK?**
- *Simple:* Not in our tests.
- *Technical:* A18: SK also needs B1 (K6LN) and Sc1; tested guesses failed - not a proof.

**Q38. Are sessions linkable?**
- *Simple:* No: D changes every session.
- *Technical:* A15; the rotation equation is a reconstruction.

**Q39. Does the project show DoS resistance?**
- *Simple:* Partially.
- *Technical:* A16 measures local rejection costs; no rate limiting; malformed lengths raise ValueError.

**Q40. What is the weakest check in the code?**
- *Simple:* Unauthenticated timestamps plus immediate state update.
- *Technical:* A03a, A11b.

**Q41. What did Scyther show?**
- *Simple:* 10 Ok in our model.
- *Technical:* Niagree/Nisynch fail without authenticated timestamps.

**Q42. Does the Scyther Ok prove the paper?**
- *Simple:* No.
- *Technical:* The model authenticates timestamps (a change) and abstracts XOR.

**Q43. Did you tune the Scyther model?**
- *Simple:* The model authenticates the timestamps, which is a change from the paper; we state that openly.
- *Technical:* Both results are shown side by side.

**Q44. What is SVO?**
- *Simple:* A belief logic for authentication.
- *Technical:* Manual derivation; G1 published, G2 reconstructed.

**Q45. Is the SVO machine-verified?**
- *Simple:* No.
- *Technical:* docs/SVO_EXPLANATION.md.

**Q46. Why does the SVO matter less than the attacks?**
- *Simple:* It is an argument, not an execution.
- *Technical:* Attacks run on the real code.


**Q47. What does 'reconstructed' mean?**
- *Simple:* Built from the paper's text with documented choices, because the paper's code is unpublished.
- *Technical:* 64-bit T6C, derived Mk, alias rotation, padding.

**Q48. How many logical hashes?**
- *Simple:* 12 measured; the paper says 8.
- *Technical:* Measured by instrumentation; the audited script hard-coded 8.

**Q49. Why 12?**
- *Simple:* Mk is re-derived on each access and for rotation.
- *Technical:* Visible in `operations --detail`.

**Q50. How much does the sensor store?**
- *Simple:* 40 B stored, 32 B read (reconstructed).
- *Technical:* the paper says 32 B; 32 B are read, 40 B are stored.

**Q51. What is _reserved?**
- *Simple:* A 4-byte non-functional pad.
- *Technical:* Added to reach 60 B; reported, not defended.

**Q52. Why not remove it?**
- *Simple:* The baseline is immutable.
- *Technical:* src/ is byte-identical to the audited zip (test).

**Q53. How do I show secrets?**
- *Simple:* `--reveal-secrets`, an insecure educational mode.
- *Technical:* Default output redacts; tests assert no secret hex appears.

**Q54. Why seeded randomness?**
- *Simple:* So the demo repeats.
- *Technical:* DemoRandom; `--random` uses os.urandom.

**Q55. How do I run only AKE3?**
- *Simple:* `python demo.py ake3`.
- *Technical:* Prerequisites are created deterministically and announced.

**Q56. Is anything mocked?**
- *Simple:* No.
- *Technical:* Stages call register_sensor/step_ake1/2/3; instrumentation only records sizes.

**Q57. What can't you claim?**
- *Simple:* That this is the authors' implementation or that attacks not tested are impossible.
- *Technical:* docs/KNOWN_LIMITATIONS.md.

**Q58. What would improve the protocol?**
- *Simple:* Authenticated timestamps, per-message nonces, recovery after lost M2, a replay cache.
- *Technical:* Not implemented here (would be a separately named experimental implementation).
