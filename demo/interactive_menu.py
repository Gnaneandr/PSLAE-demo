"""Interactive menu for a live review. Keeps one persistent session (registered sensor, M1, M2) and explains dependencies."""
import subprocess, sys
from .runtime import ROOT
from . import stage_demos as S, packet_inspector, performance_demo, verification, attack_lab, cli

TITLE = "PSLAE RESEARCH DEMONSTRATION"
ITEMS = [("1", "System initialization"), ("2", "Registration RP-1"), ("3", "Registration RP-2"), ("4", "Registration RP-3"), ("5", "Registration RP-4"), ("6", "Registration RP-5"),
         ("7", "AKE1 - Sensor sends M1"), ("8", "Inspect M1 packet"), ("9", "AKE2 - Controller receives M1"), ("10", "Inspect M2 packet"), ("11", "AKE3 - Sensor verifies M2"),
         ("12", "Compare session keys"), ("13", "Run replay attack"), ("14", "Run timestamp attack"), ("15", "Run ciphertext-tampering attack"), ("16", "Run authentication-tag attack"),
         ("17", "Run identity/impersonation scenarios"), ("18", "Run all safe attack scenarios"), ("19", "Run Scyther verification"), ("20", "View SVO derivation"),
         ("21", "View performance and storage results"), ("22", "View paper-to-code traceability"), ("23", "Run all tests"), ("0", "Exit")]
NOTE = "NOTE: a demonstration shows what the REAL code did for the tested input. It does not prove a security property beyond that scenario."


class Menu:
    def __init__(self, a, out=print):
        self.a, self.out = a, out
        self.reset()

    def reset(self):
        self.ctx = S.Ctx(self.a.config, self.a.seed, self.a.random, self.a.reveal_secrets, out=self.out)

    def need(self, what):
        self.out(f"[dependency] {what}: using the current session state; missing prerequisites are created deterministically and announced above.")

    def attacks(self, prefixes):
        for pre in prefixes:
            for r in attack_lab.run_all(self.a.config, only=pre): attack_lab.render(r, self.out)
        self.out("\n" + NOTE)

    def do(self, k):
        c, o = self.ctx, self.out
        if k == "1": self.reset(); cli.overview(self.ctx)
        elif k in "23456" and len(k) == 1:
            n = int(k) - 1; self.reset(); o(f"[dependency] RP-{n} is shown cumulatively (RP-1..RP-{n}) on a fresh deterministic registration; this resets AKE state."); S.registration_stage(self.ctx, n)
            if n == 5: o("(registration complete; the session is ready for AKE1)")
        elif k == "7": self.need("AKE1 needs registration"); c.m1 = c.m2 = c.ake2_res = c.sk_sensor = None; S.ake1_stage(c)
        elif k == "8": self.need("M1 inspection needs a real M1"); c.ensure_m1(); packet_inspector.show(c, "M1", o)
        elif k == "9": self.need("AKE2 needs M1"); c.ensure_m1(); S.ake2_stage(c)
        elif k == "10": self.need("M2 inspection needs a real M2"); c.ensure_m2(); packet_inspector.show(c, "M2", o)
        elif k == "11": self.need("AKE3 needs M2"); c.ensure_m2(); S.ake3_stage(c)
        elif k == "12": self.need("key comparison needs a completed session"); S.session_key_stage(c)
        elif k == "13": self.attacks(["A01"])
        elif k == "14": self.attacks(["A02", "A03"])
        elif k == "15": self.attacks(["A04"])
        elif k == "16": self.attacks(["A05"])
        elif k == "17": self.attacks(["A07", "A08", "A09", "A10"])
        elif k == "18":
            for r in attack_lab.run_all(self.a.config): attack_lab.render(r, o)
            o("\n" + NOTE)
        elif k == "19": verification.scyther_cmd("both", None, o)
        elif k == "20": verification.svo_cmd(False, o)
        elif k == "21": performance_demo.summary(o); performance_demo.storage(self.a.config, o)
        elif k == "22": cli.traceability(o)
        elif k == "23": subprocess.call([sys.executable, "-m", "pytest", "-q", "tests"], cwd=ROOT)
        else: o("Unknown choice.")


def run_menu(a):
    m = Menu(a)
    script = a.script.split(",") if getattr(a, "script", None) else None
    while True:
        print("\n" + TITLE + f"   [{a.config} configuration]"); [print(f"{n:>3}. {t}") for n, t in ITEMS]
        if script is not None:
            if not script: break
            k = script.pop(0).strip(); print(f"> {k}")
        else:
            try: k = input("Choose: ").strip()
            except EOFError: break
        if k == "0": print("Bye."); break
        m.do(k)
