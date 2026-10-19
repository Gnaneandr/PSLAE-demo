"""Dashboard smoke tests using Streamlit's AppTest: every page renders, every button runs the real code, no exception is raised."""
import pathlib, pytest
APP = str(pathlib.Path(__file__).resolve().parents[1] / "app.py")
st_testing = pytest.importorskip("streamlit.testing.v1")
AppTest = st_testing.AppTest
BUTTONS = {1: "run_registration", 2: "run_ake1", 3: "run_ake2", 4: "run_ake3", 6: "run_attack", 7: "run_scyther"}


def make():
    at = AppTest.from_file(APP, default_timeout=180); at.run(); return at


def test_every_page_and_button_runs_without_exception():
    at = make()
    assert not at.exception
    for i, p in enumerate(at.sidebar.radio(key="page").options):
        at.sidebar.radio(key="page").set_value(p).run()
        if i in BUTTONS:
            btn = [b for b in at.button if b.key == BUTTONS[i]]
            if btn: btn[0].click().run()
        assert not at.exception, (i, p, [e.value for e in at.exception])


def test_secrets_hidden_by_default_and_shown_in_educational_mode():
    from demo import stage_demos as S
    c = S.Ctx("reconstructed", 2024, out=lambda *_: None); c.ensure_m2()
    secret_hex = c.vals["aid6ln"].hex()
    at = make(); at.sidebar.radio(key="page").set_value("3 · AKE1 – sensor sends M1").run(); [b for b in at.button if b.key == "run_ake1"][0].click().run()
    page_text = " ".join(str(df.value.to_csv()) for df in at.dataframe)
    assert secret_hex not in page_text
    at.sidebar.checkbox(key="reveal").check().run(); [b for b in at.button if b.key == "run_ake1"][0].click().run()
    assert any("••• hidden •••" not in str(df.value.to_csv()) for df in at.dataframe)


def test_attack_page_reports_a_weakness_in_red_not_hidden():
    at = make(); at.sidebar.radio(key="page").set_value("7 · Attacker lab").run()
    at.selectbox(key="fam").set_value("Old or altered timestamps").run(); [b for b in at.button if b.key == "run_attack"][0].click().run()
    assert any("Weakness found" in e.value for e in at.error)


def test_dashboard_has_no_configuration_switch():
    at = make()
    assert not [r for r in at.sidebar.radio if r.key == "cfg"]
    assert "aithful" not in " ".join(str(x.value) for x in list(at.markdown) + list(at.caption) + list(at.info))
