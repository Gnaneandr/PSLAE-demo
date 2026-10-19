import io, contextlib, subprocess, pytest
from demo.cli import main
from demo import stage_demos as S, verification


def run(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(list(argv))
    return rc, buf.getvalue()


@pytest.mark.parametrize("cmd", [["list"], ["help"], ["overview"], ["registration"], ["ake1"], ["ake2"], ["ake3"], ["session-key"], ["full"], ["parameters"], ["packet-breakdown"],
                                 ["operations"], ["security", "--list"], ["svo", "--summary"], ["performance", "--part", "comm"], ["performance", "--part", "storage"],
                                 ["performance", "--part", "summary"], ["performance", "--part", "hash"], ["performance", "--part", "crypto"], ["traceability"]])
def test_every_command_runs(cmd):
    rc, out = run(*cmd)
    assert rc == 0 and len(out) > 100


def test_there_is_no_configuration_switch():
    with pytest.raises(SystemExit):
        run("full", "--config", "faithful")
    rc, out = run("list")
    assert "--config" not in out and "faithful" not in out.lower()


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5])
def test_registration_can_stop_after_each_step(n):
    rc, out = run("registration", "--stop-after", str(n))
    assert rc == 0 and f"RP-{n}" in out
    assert f"--- RP-{n+1} " not in out


def test_full_session_reports_equal_keys():
    rc, o = run("full")
    assert "Session keys equal: True" in o and "RECONSTRUCTED" in o and "aithful" not in o


def _secrets(config, seed=2024):
    c = S.Ctx(config, seed, out=lambda *_: None); c.ensure_m2()
    from demo.stage_demos import ake3_stage; ake3_stage(c, header=False)
    return {k: v.hex() for k, v in c.vals.items() if k in S.SECRET and len(v) >= 8}


@pytest.mark.parametrize("cmd", ["registration", "ake1", "ake2", "ake3", "session-key", "full", "overview"])
def test_secrets_not_printed_in_normal_mode(cmd):
    sec = _secrets("reconstructed")
    rc, out = run(cmd)
    leaked = [k for k, h in sec.items() if h in out]
    assert not leaked, leaked


def test_reveal_mode_prints_secrets_and_is_labelled_insecure():
    sec = _secrets("reconstructed")
    rc, out = run("ake1", "--reveal-secrets")
    assert "EDUCATIONAL INSECURE MODE" in out and sec["aid6ln"] in out


def test_operations_trace_never_contains_secret_values():
    sec = _secrets("reconstructed")
    rc, out = run("operations", "--detail")
    assert not [k for k, h in sec.items() if h in out]


def test_menu_scripted_walkthrough():
    rc, out = run("menu", "--script", "1,7,8,9,10,11,12,13,0")
    assert rc == 0 and "Keys equal" in out and "A01a" in out


def test_scyther_command_runs_if_binary_present():
    exe = verification.find_exe()
    if not exe: pytest.skip("Scyther binary not available on this platform (documented in DEMO_TROUBLESHOOTING)")
    rc, out = run("scyther")
    assert "10 Ok, 0 Fail" in out and "aithful" not in out and "timestamps" in out
