"""Attack-lab regression tests. They call the REAL protocol code. The frozen outcomes in expected_attack_outcomes.json are the OBSERVED behaviour
(including weaknesses); a failing test means the audited behaviour changed, not that a property 'should' hold."""
import json, pathlib, pytest
from demo import attack_lab as L
EXP = json.loads((pathlib.Path(__file__).parent / "expected_attack_outcomes.json").read_text())
CASES = [("reconstructed", i) for i in EXP["reconstructed"]]


@pytest.fixture(scope="module")
def results():
    return {"reconstructed": {r["id"]: r for r in L.run_all("reconstructed")}}


@pytest.mark.parametrize("cfg,sid", CASES, ids=[f"{i}-{c}" for c, i in CASES])
def test_attack_lab(results, cfg, sid):
    r = results[cfg][sid]
    assert [r["outcome"], r["classification"]] == EXP[cfg][sid]
    if r["outcome"] == "REJECT" and r["classification"] == L.PROTECTED: assert r["responsible_check"] not in ("", "-") or sid in ("A14", "A15", "A18", "A11a")     # a rejection must name the check that did it


def test_known_weaknesses_are_reported_not_hidden(results):
    R = results["reconstructed"]
    assert R["A03a"]["outcome"] == "ACCEPT"                                              # refreshed timestamp on an intercepted M1
    assert R["A11b"]["classification"] == L.VULN                                         # lost M2 -> permanent desync
    assert R["A17"]["classification"] == L.VULN                                          # keystream reuse leaks AID6LN
    assert R["A02c"]["outcome"] == "ACCEPT"                                              # future timestamp accepted
    assert R["A01c"]["outcome"] == "REJECT" and not R["A15"]["extra"]["linkable"]


def test_state_transition_not_replay_cache_is_what_stops_replay(results):
    assert "never filled" in " ".join(results["reconstructed"]["A01a"]["steps"])


def test_each_scenario_has_required_fields(results):
    for cfg in results.values():
        for r in cfg.values():
            for k in ("id", "plain_english", "attacker", "action", "steps", "outcome", "responsible_check", "expected", "observed", "interpretation", "classification", "automated_test"):
                assert r[k] not in (None, ""), (r["id"], k)
