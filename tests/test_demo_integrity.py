"""The demonstration layer must not modify the audited protocol code (checksums in SRC_SHA256.txt)."""
import hashlib, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def test_src_is_byte_identical_to_the_audited_baseline():
    lines = (ROOT / "SRC_SHA256.txt").read_text().splitlines()
    src_lines = [l for l in lines if l.split("  ", 1)[1].startswith("src/")]
    assert len(src_lines) >= 6
    for l in src_lines:
        h, rel = l.split("  ", 1)
        assert sha(ROOT / rel) == h, f"{rel} was modified"
    assert {p.name for p in (ROOT / "src").glob("*.py")} == {l.split("  ", 1)[1][4:] for l in src_lines}, "src/ gained or lost a file"


def test_saved_original_outputs_preserved():
    lines = [l for l in (ROOT / "SRC_SHA256.txt").read_text().splitlines() if "results/baseline/" in l]
    assert len(lines) == 3
    for l in lines:
        h, rel = l.split("  ", 1)
        assert sha(ROOT / rel) == h, rel


def test_only_one_implementation_is_shipped():
    assert not (ROOT / "src_reference").exists() and not (ROOT / "scyther" / "faithful").exists()
