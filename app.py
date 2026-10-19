"""PSLAE panel dashboard (Streamlit). Every button runs the REAL protocol code through the demo layer; nothing is mocked.
Start:  streamlit run app.py"""
import sys, pathlib, re
import streamlit as st
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from demo import stage_demos as S, packet_inspector as PI, parameters as PM, attack_lab as AL, performance_demo as PD, verification as V

st.set_page_config(page_title="PSLAE demonstration", page_icon="🔐", layout="wide")
PAGES = ["1 · The story", "2 · Registration", "3 · AKE1 – sensor sends M1", "4 · AKE2 – controller replies", "5 · AKE3 – key agreement", "6 · Packet sizes",
         "7 · Attacker lab", "8 · Formal checks", "9 · Numbers vs paper", "10 · Paper vs our implementation"]
META = {r[0]: dict(name=r[1], purpose=r[2], secret=r[4], status=r[8]) for r in PM.P}

# ------------------------------------------------------------------ sidebar
st.sidebar.title("🔐 PSLAE demo")
cfg_name = "Reconstructed implementation"
cfg = "reconstructed"
st.sidebar.caption("Implementation: **reconstructed** (the audited project).")
reveal = st.sidebar.checkbox("Educational mode: show disposable secrets", key="reveal", help="Insecure on purpose. Demo keys only; never real keys.")
notes_on = st.sidebar.checkbox("Presenter notes", value=True, key="notes")
page = st.sidebar.radio("Step", PAGES, key="page")
st.sidebar.caption("Randomness: seeded demo generator (seed 2024) so every run is repeatable. Nothing on screen is simulated: buttons call the real functions.")
if reveal: st.sidebar.warning("Showing disposable demonstration secrets.")


def ctx_for(reset=False):
    key = (cfg, reveal)
    if reset or st.session_state.get("ctx_key") != key or "ctx" not in st.session_state:
        st.session_state["ctx"] = S.Ctx(cfg, 2024, False, reveal, out=lambda *_: None)
        st.session_state["ctx_key"] = key
    return st.session_state["ctx"]


def run_quiet(fn, *a, **k):
    lines = []
    ctx = a[0]; old = ctx.out; ctx.out = lines.append
    try: fn(*a, **k)
    finally: ctx.out = old
    return "\n".join(lines)


def notes(text):
    if notes_on:
        with st.expander("🎤 What to say (plain English)", expanded=False): st.markdown(text)


def val_table(ctx, keys, extra_status=True):
    rows = []
    for k in keys:
        if k not in ctx.vals: continue
        v, m = ctx.vals[k], META.get(k, {})
        secret = m.get("secret", k in S.SECRET)
        shown = (v.hex() if (reveal or not secret) else "••• hidden •••") if isinstance(v, (bytes, bytearray)) else str(v)
        rows.append({"Value": m.get("name", k), "Meaning": m.get("purpose", ""), "Bits": len(v) * 8 if isinstance(v, (bytes, bytearray)) else "", "Public/Secret": "secret" if secret else "public",
                     "Content": shown, "Literal or reconstructed": m.get("status", "")})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def ops_table(ctx, stage):
    ops = [o for o in ctx.trace.ops if o["stage"] == stage]
    st.dataframe(pd.DataFrame([{"Operation": o["op"], "Algorithm": o["algorithm"], "Input bytes": str(o["inputs"]), "Output bytes": o["output_bytes"], "What it does": o["purpose"] or o["source"]} for o in ops]), hide_index=True, width="stretch")
    c = ctx.trace.counts(stage=stage); st.caption(f"Logical calls made by the code: {c['logical']}  |  physical primitive calls: {c['physical']}")


def checks_box(checks):
    for name, ok, note in checks:
        (st.success if ok else st.error)(f"{'✅' if ok else '❌'} {name}" + (f"  —  {note}" if note else ""))


def packet_df(ctx, which):
    a = PI.accounting(ctx)[which]
    df = pd.DataFrame([{"Field": r["field"], "Purpose": r["purpose"], "Bits": r["bits"], "Bytes": r["bytes"], "Paper bits": r["paper_bits"], "Protection": r["protection"]} for r in a["rows"]])
    return a, df


def show_packet(ctx, which):
    a, df = packet_df(ctx, which)
    st.dataframe(df, hide_index=True, width="stretch")
    c1, c2, c3 = st.columns(3)
    c1.metric(f"{which} measured", f"{a['measured_bits']} bits"); c2.metric("Paper reports", f"{a['paper_reported_bits']} bits"); c3.metric("Sum of paper's field widths", f"{a['literal_paper_field_bits']} bits")
    st.bar_chart(pd.DataFrame([{r["field"]: r["bits"] for r in a["rows"]}], index=[which]), horizontal=True, height=140)
    if which == "M2" and len(ctx.m2["T6C"]) == 8:
        st.warning("Reconstructed configuration: M2 reaches 608 bits only because T6C is **64 bits**. The paper says 32 bits, which gives 576. Both numbers are reported.")
    return a


# ------------------------------------------------------------------ pages
if page == PAGES[0]:
    st.title("PSLAE: how a sensor and a controller prove who they are")
    st.caption(f"Implementation: **{cfg_name}**")
    c = ctx_for(); c.ensure_m2()
    m1b, m2b = sum(len(v) for v in c.m1.values()) * 8, sum(len(v) for v in c.m2.values()) * 8
    st.graphviz_chart(f'''digraph G {{ rankdir=LR; node [shape=box, style="rounded,filled", fontname="Helvetica"];
        S [label="6LN\\nsensor", fillcolor="#d6ecff"]; C [label="6LC\\ncontroller", fillcolor="#d9f2d9"]; A [label="attacker\\nreads / edits / replays / drops", shape=note, fillcolor="#ffe0e0"];
        S -> C [label="M1  ({m1b} bits)\\nalias + fresh random + proof"]; C -> S [label="M2  ({m2b} bits)\\nreply + key confirmation"]; A -> S [style=dashed, color=red]; A -> C [style=dashed, color=red]; }}''')
    st.markdown("""**Goal:** both sides agree on a fresh secret **session key** without ever sending it, while an attacker who controls the radio link cannot get in.
**Three ideas to remember:** (1) *Registration* gives both sides shared secrets once, safely. (2) *M1 and M2* carry a hidden alias, random numbers and tamper-proof tags. (3) The key is **calculated on both sides**, never transmitted.""")
    st.info("**Honesty statement.** The paper's code is unpublished, so this is a *reconstruction* from the paper's text. Where the paper was unclear or contradicted itself we made documented choices (page 10 lists them). Some of the paper's claims do not hold in this implementation; the attacker lab shows which.")
    notes("1. A factory sensor must talk to its controller over a wireless link anyone can listen to.\n2. The paper proposes two short messages built from cheap operations.\n3. Everything you will click runs the real code. Where the paper was unclear, we say so.\n4. Page 10 lists every place where our implementation differs from the paper, and why.")

elif page == PAGES[1]:
    st.title("Registration: the one-time, secure set-up")
    upto = st.slider("Show steps up to", 1, 5, 5, key="upto", help="Stop after any registration step")
    if st.button("▶ Run registration", key="run_registration", type="primary"):
        c = ctx_for(reset=True); st.session_state["reg_log"] = run_quiet(S.registration_stage, c, upto); st.session_state["reg_upto"] = upto
    if "reg_log" in st.session_state and st.session_state.get("ctx_key") == (cfg, reveal):
        c, n = ctx_for(), st.session_state["reg_upto"]
        steps = [("RP-1 · pick identities and keys", ["id6ln", "id6lc", "tid6lc", "r6lc", "k6lc", "k6ln"], "Literal values. Widths of ID6LC/R6LC are not stated in the paper (64 bit assumed)."),
                 ("RP-2 · build the alias and the shared secret Sc", ["aid6ln", "ms", "mk_reg", "sm", "sc"], "Paper says the master secret is '265 bits' (typo for 256) and uses a 160-bit hash on 256-bit values: the audited project stretches SHA-1 (H_bits) — a reconstruction."),
                 ("RP-3 · what each side stores", [], "The tables below list the attributes the real objects actually hold."),
                 ("RP-4 · encryption key and nonce from Mk and Sc", ["mk", "x", "nc", "kc", "si"], "Sc is 64 bits, Mk 256: Sc is repeated four times (reconstruction)."),
                 ("RP-5 · associated data AD", ["fr", "ad"], "AD is authenticated but never transmitted or stored.")]
        for i, (title, keys, note) in enumerate(steps[:n], 1):
            with st.expander(title, expanded=(i == n)):
                st.caption(note)
                if i == 3 and c.sensor is not None:
                    rec = next(iter(c.controller.db.values()))
                    a1, a2 = st.columns(2)
                    a1.markdown("**6LN (sensor) stores**"); a1.dataframe(pd.DataFrame([{"Attribute": k, "Bytes": len(v)} for k, v in vars(c.sensor).items() if not k.startswith("_")]), hide_index=True)
                    a2.markdown("**6LC record per sensor**"); a2.dataframe(pd.DataFrame([{"Attribute": k, "Bytes": len(v), "Note": "non-functional padding in the audited baseline" if k == "_reserved" else ""} for k, v in vars(rec).items()]), hide_index=True)
                elif keys: val_table(c, keys)
        if n == 5: st.success("Registration complete: both sides now share secrets. Nothing so far was sent over the air.")
        with st.expander("Technical log (what the code printed)"): st.code(st.session_state["reg_log"])
    else:
        st.info("Press **Run registration**.")
    notes("1. Before deployment the controller creates the sensor's secrets over a safe channel.\n2. AID6LN is a nickname; the real ID never travels.\n3. Sc is a shared secret the sensor will later prove it knows.\n4. Point out: the paper's '265 bits' typo and the SHA-1 extension are flagged as reconstructions.")

elif page == PAGES[2]:
    st.title("AKE1: the sensor builds and sends M1")
    if st.button("▶ Run AKE1", key="run_ake1", type="primary"):
        c = ctx_for(reset=True); c.ensure_registered(); c.m1 = c.m2 = c.ake2_res = c.sk_sensor = None
        st.session_state["ake1_log"] = run_quiet(S.ake1_stage, c); st.session_state["ake1_key"] = (cfg, reveal)
    if st.session_state.get("ake1_key") == (cfg, reveal) and st.session_state.get("ctx_key") == (cfg, reveal):
        c = ctx_for()
        st.caption("Registration was run automatically first (deterministic).")
        st.subheader("1 · Values the sensor creates"); val_table(c, ["rn1", "t6ln", "a", "b", "d", "pt"])
        st.subheader("2 · Encryption used")
        st.info("**AES-128-CTR** hides A‖B and **HMAC-SHA256 (cut to 128 bits)** adds the tamper-proof tag. This is an *interface stand-in* for the paper's ACE, which the paper does not specify. XOR masks, SHA-1 fingerprints, AES hides, HMAC seals — different jobs.")
        val_table(c, ["kc", "nc", "ad", "ct", "tag6ln"])
        st.subheader("3 · The message M1 (what travels)"); show_packet(c, "M1") if c.m2 else (lambda a: (st.dataframe(a[1], hide_index=True, width="stretch"), st.metric("M1 measured", f"{a[0]['measured_bits']} bits (paper: 416) — matches")))(packet_df(c, "M1"))
        st.subheader("4 · Operations the code executed"); ops_table(c, "AKE1")
        with st.expander("Technical log"): st.code(st.session_state["ake1_log"])
    else:
        st.info("Press **Run AKE1**.")
    notes("1. The sensor picks a fresh random number and a timestamp.\n2. It hides its alias with XOR, encrypts the result, and attaches a tag.\n3. M1 is 416 bits — this matches the paper exactly.\n4. Mention: the timestamp travels in the clear and is NOT covered by the tag (we will exploit this in the attack lab).")

elif page == PAGES[3]:
    st.title("AKE2: the controller verifies M1 and builds M2")
    if st.button("▶ Run AKE2", key="run_ake2", type="primary"):
        c = ctx_for(reset=True); c.ensure_m1(); c.m2 = c.ake2_res = c.sk_sensor = None
        st.session_state["ake2_log"] = run_quiet(S.ake2_stage, c); st.session_state["ake2_key"] = (cfg, reveal)
    if st.session_state.get("ake2_key") == (cfg, reveal) and st.session_state.get("ctx_key") == (cfg, reveal):
        c = ctx_for()
        st.caption("Registration and AKE1 were run automatically first (a real M1 is produced).")
        st.subheader("1 · The controller's checks (in code order)"); checks_box(c.checks["ake2"])
        st.subheader("2 · What it derives and creates"); val_table(c, ["aid_from_d", "mk_prime", "t6c", "rn2", "t_val", "sc1", "b1", "a1", "sk_6lc", "m", "pt1", "ct1", "tag6lc"])
        st.subheader("3 · The message M2"); show_packet(c, "M2")
        st.subheader("4 · Operations the code executed"); ops_table(c, "AKE2")
        st.caption("If any check failed, the code raises an authentication error and no key is produced — try it in the Attacker lab.")
        with st.expander("Technical log"): st.code(st.session_state["ake2_log"])
    else:
        st.info("Press **Run AKE2**.")
    notes("1. The controller checks: is the message fresh, is the alias known, does the tag verify, are the hidden numbers consistent.\n2. Only then does it build the session key and M2.\n3. The session key is calculated, never placed in M2; M2 carries only a fingerprint M = SHA-1(SK).\n4. Mention the 608-vs-576 explanation (64-bit timestamp is our reconstruction).")

elif page == PAGES[4]:
    st.title("AKE3: the sensor verifies M2 and the keys match")
    if st.button("▶ Run AKE3", key="run_ake3", type="primary"):
        c = ctx_for(reset=True); c.ensure_m2(); c.sk_sensor = None
        st.session_state["ake3_log"] = run_quiet(S.ake3_stage, c); st.session_state["ake3_key"] = (cfg, reveal)
    if st.session_state.get("ake3_key") == (cfg, reveal) and st.session_state.get("ctx_key") == (cfg, reveal):
        c = ctx_for()
        st.caption("Registration, AKE1 and AKE2 were run automatically first (a real M2 is produced).")
        st.subheader("1 · The sensor's checks"); checks_box(c.checks["ake3"])
        st.subheader("2 · Session-key agreement")
        sk_s, sk_c = c.sk_sensor, c.ake2_res["session_key"]
        k1, k2, k3 = st.columns(3); k1.metric("Keys equal", "YES ✅" if sk_s == sk_c else "NO ❌"); k2.metric("Key length", f"{len(sk_s)*8} bits"); k3.metric("Key sent on the wire?", "never")
        st.write("Sensor key: ", sk_s.hex() if reveal else "`[redacted by default]`", " | Controller key: ", sk_c.hex() if reveal else "`[redacted by default]`")
        st.info("**Substitution vs the paper.** The paper tells the sensor to compute T' from the controller's real ID, which the sensor never has. The code reads the needed value Sc1 from the decrypted message instead.")
        val_table(c, ["b1_prime", "sc1", "sk_6ln"])
        st.subheader("3 · Operations the code executed"); ops_table(c, "AKE3")
        with st.expander("Technical log"): st.code(st.session_state["ake3_log"])
    else:
        st.info("Press **Run AKE3**.")
    notes("1. The sensor recomputes the controller's proof, checks the tag, and computes the key itself.\n2. Both keys are equal, yet the key never travelled.\n3. Be explicit about the one substitution versus the paper (Sc1 from the decrypted block).\n4. 'Redacted' hides the key on screen; toggle the educational mode only if asked.")

elif page == PAGES[5]:
    st.title("Packet sizes: every field of M1 and M2")
    c = ctx_for(); c.ensure_m2()
    tab1, tab2 = st.tabs(["M1 (sensor → controller)", "M2 (controller → sensor)"])
    with tab1: show_packet(c, "M1")
    with tab2: show_packet(c, "M2")
    acc = PI.accounting(c)["total"]
    st.metric("Total M1 + M2", f"{acc['measured_bits']} bits", delta=f"paper-reported {acc['paper_reported_bits']}  |  sum of paper's field widths {acc['literal_paper_field_bits']}", delta_color="off")
    st.caption("Sizes are measured from the real message objects. The code adds no headers, framing or padding. The paper's own text also quotes ~1010 bits, so the paper is not self-consistent.")
    notes("1. Each row is one field with its size.\n2. M1 matches the paper (416 bits).\n3. M2 depends on a choice we flag openly: the reconstructed timestamp is 64 bits; with the paper's 32 bits it would be 576.\n4. We did not change a field width to hit a published number.")

elif page == PAGES[6]:
    st.title("Attacker lab: what the protocol does when attacked")
    st.warning("A rejection shows only that **this tested input** was rejected. It is not a proof of security. Weaknesses are shown in red because they are real behaviour of the code.")
    FAM = {"Replay (resend a recorded message)": ["A01"], "Old or altered timestamps": ["A02", "A03"], "Flip a ciphertext bit": ["A04"], "Forge or change the tag": ["A05"], "Change any single field": ["A06"],
           "Unknown or fake identity": ["A07", "A08", "A10"], "Mix messages from different sensors": ["A09"], "Drop messages": ["A11"], "Duplicate / reorder messages": ["A12"],
           "Many sessions and key isolation": ["A14"], "Does the alias change? (traceability)": ["A15"], "Flooding with garbage (local cost only)": ["A16"], "Eavesdropper analysis": ["A17", "A18"], "Run EVERYTHING": [""]}
    fam = st.selectbox("Choose an attack", list(FAM), key="fam")
    if st.button("▶ Launch attack", key="run_attack", type="primary"):
        res = []
        for pre in FAM[fam]: res += AL.run_all(cfg, only=pre) if pre else AL.run_all(cfg)
        seen, out = set(), []
        for r in res:
            if r["id"] not in seen: seen.add(r["id"]); out.append(r)
        st.session_state["atk"] = (cfg, fam, out)
    if st.session_state.get("atk", (None,))[0] == cfg:
        _, f, res = st.session_state["atk"]
        st.subheader(f"{f}  —  {cfg_name}")
        st.dataframe(pd.DataFrame([{"ID": r["id"], "Scenario": r["title"], "Result": r["outcome"], "Check that decided": r["responsible_check"], "Verdict": r["classification"]} for r in res]), hide_index=True, width="stretch")
        for r in res[:40]:
            box = st.container(border=True)
            box.markdown(f"**{r['id']} — {r['title']}**")
            box.markdown(f"*What the attacker does:* {r['plain_english']}  \n*Attacker needs:* {r['attacker']}  \n*Action:* {r['action']}")
            for s in r["steps"]: box.markdown(f"- {s}")
            if r["classification"].startswith("Protected"): box.success(f"🛡️ **{r['outcome']}** — Protected in this test. Check: {r['responsible_check']}")
            elif r["classification"].startswith("Vulnerable"): box.error(f"⚠️ **{r['outcome']}** — Weakness found (reported, not hidden).")
            else: box.warning(f"◐ **{r['outcome']}** — {r['classification']}.")
            box.caption(r["interpretation"] + f"   |  test: {r['automated_test']}")
    notes("1. Pick an attack, press launch, read the green/red verdict.\n2. Green = this input was rejected, and we show which check did it.\n3. Red = a real weakness of the audited code (for example: holding a message and refreshing its timestamp; one lost reply locking the sensor out; the two ciphertexts of one session leaking the alias).")

elif page == PAGES[7]:
    st.title("Formal checks: Scyther and SVO")
    t1, t2 = st.tabs(["Scyther (automatic attack search)", "SVO (belief logic, manual)"])
    with t1:
        st.markdown("Scyther searches for attacks on a **symbolic model** of the protocol (up to 100 runs). **Ok** = no attack found in the model; **Fail** = an attack exists.")
        exe = V.find_exe()
        if not exe: st.error("Scyther binary not found. See docs/SETUP_GUIDE.md (use `--exe` / SCYTHER_EXE).")
        elif st.button("▶ Run Scyther on both models", key="run_scyther", type="primary"):
            lines = []; res = {"reconstructed": V.run_model("reconstructed", exe, out=lines.append)}
            st.session_state["scy"] = res
        if "scy" in st.session_state:
            rows = st.session_state["scy"]["reconstructed"]; st.markdown("**Model:** timestamps are authenticated inside the encrypted part (a deliberate change from the paper, which sends them as bare fields)")
            st.dataframe(pd.DataFrame([{"Role": r[0], "Claim": r[1], "Result": r[2], "Scyther comment": r[3]} for r in rows]), hide_index=True, width="stretch")
            f = sum(1 for r in rows if r[2] != "Ok"); (st.success if f == 0 else st.error)(f"{len(rows)-f} Ok, {f} Fail")
            st.info("These results are for the reconstructed model only; they do **not** show that the protocol exactly as written in the paper passes. Limits: XOR is abstracted, state updates are not modelled, bounded search (100 runs).")
    with t2:
        st.warning("Manual derivation — **not machine-verified**. PUBLISHED = from the paper's figure; RECONSTRUCTED = added by the audited project.")
        st.text(V.BANNER)
        with st.expander("Derivation summary"): st.code("\n".join(l[:200] for l in V.SVO.read_text().splitlines() if l.startswith(("|", "#")) or "PUBLISHED" in l or "RECONSTRUCTED" in l))
    notes("1. Scyther: an automatic attack-finder. It finds no attack in our model. Say clearly that the model authenticates the timestamps, which the paper does not, and that XOR is abstracted.\n2. SVO: a paper-and-pencil logic. We label what is the paper's and what is ours, and we say it is not machine-checked.\n3. Never say 'proved secure'.")

elif page == PAGES[8]:
    st.title("Numbers vs the paper")
    rows = PD.summary(out=lambda *_: None)
    df = pd.DataFrame([{"Metric": r["metric"], "Paper": r["paper"], "Measured": r["measured"], "Note": r["note"]} for r in rows])
    st.dataframe(df.style.apply(lambda s: ["background-color:#ffd9d9" if (s.name == "Measured" and str(v) != str(df.loc[i, "Paper"])) else "" for i, v in s.items()], axis=0), hide_index=True, width="stretch")
    st.caption("Red cell = differs from the paper. Nothing was forced to match. Hash count: the audited script hard-coded 8; measured values are shown.")
    st.markdown("**Storage:** what the objects hold vs what AKE actually reads")
    PD_c, reads = PD.field_usage(cfg)
    sens = {k: len(v) for k, v in vars(PD_c.sensor).items() if not k.startswith("_")}; rec = {k: len(v) for k, v in vars(next(iter(PD_c.controller.db.values()))).items()}
    a, b = st.columns(2)
    a.dataframe(pd.DataFrame([{"6LN attribute": k, "Bytes": n, "Read during AKE?": "yes" if k in reads["SixLN"] else "no"} for k, n in sens.items()]), hide_index=True)
    b.dataframe(pd.DataFrame([{"6LC record attribute": k, "Bytes": n, "Read during AKE?": "yes" if k in reads["SensorRecord"] else "no"} for k, n in rec.items()]), hide_index=True)
    notes("1. Left to right: paper value, value measured on our implementation.\n2. Red cells differ from the paper; we report them instead of adjusting the code.\n3. Storage: 'stored' is not the same as 'needed' — the table shows which fields AKE actually reads.")

else:
    st.title("Paper vs our implementation")
    txt = (ROOT / "docs" / "PAPER_VS_IMPLEMENTATION.md").read_text()
    rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in txt.splitlines() if l.startswith("|") and not l.startswith("|---") and not l.startswith("| #")]
    st.dataframe(pd.DataFrame(rows, columns=["#", "Topic", "Paper", "Our implementation", "Status"]), hide_index=True, width="stretch")
    st.caption("Status: L literal · R reconstruction · I implementation-specific addition · D discrepancy reported. Full detail: docs/RECONSTRUCTION_DECISIONS.md, docs/KNOWN_LIMITATIONS.md.")
    notes("1. This is the honest slide: twenty places where the paper and the code differ, and why.\n2. R = our reconstruction; D = a discrepancy we report rather than hide.\n3. What we can claim: the code runs, both parties agree on a key, and the listed attack inputs behave as shown. What we cannot: that this is the authors' implementation.")
