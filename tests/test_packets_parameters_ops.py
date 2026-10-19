import pytest
from demo import packet_inspector as PI, parameters, crypto_trace, performance_demo as PD


def test_packet_sizes_come_from_real_messages():
    config, m2 = "reconstructed", 608
    a = PI.accounting(PI.build(config))
    assert a["M1"]["measured_bits"] == 416 == a["M1"]["literal_paper_field_bits"]
    assert a["M2"]["measured_bits"] == m2 and a["M2"]["literal_paper_field_bits"] == 576
    for n in ("M1", "M2"):
        assert a[n]["measured_bits"] == sum(r["bits"] for r in a[n]["rows"]) == a[n]["serialized_length_bytes"] * 8
        assert [r["field"] for r in a[n]["rows"]] == (["T6LN", "D", "CT", "Tag6LN", "RN1"] if n == "M1" else ["T6C", "A1", "M", "CT1", "Tag6LC", "RN2"])


def test_reconstructed_total_is_1024_only_through_64bit_T6C():
    c = PI.build("reconstructed"); a = PI.accounting(c)
    assert a["total"]["measured_bits"] == 1024 and len(c.m2["T6C"]) == 8
    assert a["total"]["literal_paper_field_bits"] == 992        # literal widths do NOT give 1024
    assert [r for r in a["M2"]["rows"] if r["differs"]][0]["field"] == "T6C"


def test_parameter_widths_match_declarations():
    c, rows = parameters.build("reconstructed")
    assert len(rows) >= 38 and all(r["width_matches_declaration"] for r in rows if r["declared_bits"] is not None)
    keys = {r["key"] for r in rows}
    for k in ("id6ln", "id6lc", "aid6ln", "tid6lc", "k6ln", "k6lc", "ms", "mk", "sc", "sm", "si", "nc", "kc", "fr", "ad", "rn1", "rn2", "t6ln", "t6c", "a", "b", "d", "b1", "a1", "sc1", "sk_6lc", "m", "ct", "tag6ln", "ct1", "tag6lc"):
        assert k in keys
    assert not [r for r in rows if r["key"] in ("sk_6lc", "sk_6ln") and r["transmitted"] != "no"]      # SK never transmitted


def test_parameter_register_marks_the_reconstructed_t6c():
    _, r = parameters.build("reconstructed")
    t6c = [x for x in r if x["key"] == "t6c"][0]
    assert t6c["bits"] == 64 and "RECONSTRUCTED" in t6c["literal_or_reconstructed"]


def test_operation_counts_are_measured_not_hard_coded():
    r = crypto_trace.show("reconstructed", out=lambda *_: None)
    assert r["ake_logical_hash"] == 12 and r["ake_aead_executed"] == 4      # measured; the audited overhead.py hard-codes 8


def test_storage_report_distinguishes_stored_and_used():
    c, reads = PD.field_usage("reconstructed")
    assert {"aid6ln", "k6ln", "sc", "tid6lc"} <= reads["SixLN"] and "id6ln" not in reads["SixLN"]
    assert "_reserved" not in reads["SensorRecord"] and "r6lc" not in reads["SensorRecord"]
