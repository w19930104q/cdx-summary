"""Offline fixture regression tests for multi-input CDX summarization.

Covers out-of-order records, cross-file duplicates, bad lines, empty
input, unreadable/corrupt inputs, atomic output replacement, and write
failures. All fixtures are local files under tests/fixtures/.
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

PART1 = os.path.join(FIXTURES, "part1.cdx")
PART2 = os.path.join(FIXTURES, "part2.cdx.gz")
PART3 = os.path.join(FIXTURES, "part3.cdx.bz2")
SHUFFLED = os.path.join(FIXTURES, "shuffled.cdx")
BADONLY = os.path.join(FIXTURES, "badonly.cdx")
EMPTY = os.path.join(FIXTURES, "empty.cdx")
CORRUPT = os.path.join(FIXTURES, "corrupt.cdx.gz")
GOLDEN = os.path.join(FIXTURES, "expected_summary.json")

ALL_PARTS = [PART1, PART2, PART3]

EXPECTED_KEYS = {
    "captures", "urls", "hosts", "bytes", "first", "last",
    "tophosts", "mimestatus", "pathquery", "yearmonth", "samples",
}


def run_cli(args, input_bytes=None):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run(
        [sys.executable, "-m", "cdxsummary", *args],
        capture_output=True, input=input_bytes, env=env, cwd=ROOT,
    )


def summary_json(args, input_bytes=None):
    proc = run_cli(["-j", "-s", "0", *args], input_bytes=input_bytes)
    assert proc.returncode == 0, proc.stderr.decode()
    return proc, json.loads(proc.stdout.decode())


# ---------------------------------------------------------------------------
# Merging, deduplication, and determinism
# ---------------------------------------------------------------------------

def test_merged_report_matches_golden_fixture():
    _, summary = summary_json(ALL_PARTS)
    with open(GOLDEN) as fh:
        assert summary == json.load(fh)


def test_cross_file_dedup_and_global_counts():
    _, summary = summary_json(ALL_PARTS)
    assert summary["captures"] == 6
    assert summary["urls"] == 5
    assert summary["hosts"] == 3
    assert summary["bytes"] == 7500
    assert summary["first"] == "20201231235959"
    assert summary["last"] == "20210105000000"
    assert summary["tophosts"] == {"example.com": 3, "archive.org": 2, "example.net": 1}


def test_partition_and_order_independence():
    _, merged = summary_json(ALL_PARTS)
    _, shuffled = summary_json([SHUFFLED])
    _, reversed_order = summary_json([PART3, PART1, PART2])
    _, pairwise = summary_json([PART2, PART3])
    _, rest = summary_json([PART1])
    assert merged == shuffled == reversed_order
    assert pairwise["captures"] + rest["captures"] != merged["captures"]  # sanity: inputs differ
    # distributions and extremes are identical regardless of partitioning
    for key in ["first", "last", "mimestatus", "pathquery", "yearmonth", "tophosts"]:
        assert merged[key] == shuffled[key] == reversed_order[key]


def test_single_input_json_fields_compatible():
    _, summary = summary_json([PART1])
    assert set(summary.keys()) == EXPECTED_KEYS
    assert summary["captures"] == 3
    assert summary["urls"] == 3
    assert summary["hosts"] == 2


def test_stdin_input():
    with open(PART1, "rb") as fh:
        proc, summary = summary_json(["-"], input_bytes=fh.read())
    assert summary["captures"] == 3
    assert b"STDIN" in proc.stderr


def test_mixed_stdin_and_file_inputs():
    with open(PART2, "rb") as fh:
        gz_bytes = fh.read()
    import gzip
    _, summary = summary_json([PART1, "-"], input_bytes=gzip.decompress(gz_bytes))
    # part1 (3) + part2's two new captures (one is a cross-input duplicate)
    assert summary["captures"] == 5
    assert summary["hosts"] == 3


# ---------------------------------------------------------------------------
# Diagnostics for bad lines
# ---------------------------------------------------------------------------

def test_bad_lines_produce_stable_diagnostics():
    proc = run_cli(["-j", "-s", "0", *ALL_PARTS])
    assert proc.returncode == 0
    stderr = proc.stderr.decode()
    assert f"Skipped invalid record at {PART2}:4:" in stderr
    assert f"Skipped invalid record at {PART3}:4:" in stderr
    assert "Invalid CDX line" in stderr
    assert "Skipped 3 duplicate captures" in stderr


def test_all_bad_lines_fail_without_output(tmp_path):
    out = tmp_path / "report.json"
    proc = run_cli(["-j", "-o", str(out), BADONLY])
    assert proc.returncode == 1
    assert b"No valid CDX records" in proc.stderr
    assert not out.exists()


# ---------------------------------------------------------------------------
# Failure behavior: no half-finished reports
# ---------------------------------------------------------------------------

def test_empty_input_fails_and_preserves_old_report(tmp_path):
    out = tmp_path / "report.json"
    out.write_text("OLD REPORT")
    proc = run_cli(["-j", "-o", str(out), EMPTY])
    assert proc.returncode == 1
    assert b"No valid CDX records" in proc.stderr
    assert out.read_text() == "OLD REPORT"


def test_missing_input_fails_and_preserves_old_report(tmp_path):
    out = tmp_path / "report.json"
    out.write_text("OLD REPORT")
    proc = run_cli(["-j", "-o", str(out), PART1, str(tmp_path / "missing.cdx")])
    assert proc.returncode == 1
    assert out.read_text() == "OLD REPORT"


def test_corrupt_gzip_fails_and_preserves_old_report(tmp_path):
    out = tmp_path / "report.json"
    out.write_text("OLD REPORT")
    proc = run_cli(["-j", "-o", str(out), PART1, CORRUPT])
    assert proc.returncode == 1
    assert b"Failed to read input" in proc.stderr
    assert CORRUPT.encode() in proc.stderr
    assert out.read_text() == "OLD REPORT"


def test_write_failure_preserves_old_report(tmp_path):
    outdir = tmp_path / "nowrite"
    outdir.mkdir()
    out = outdir / "report.json"
    out.write_text("OLD REPORT")
    outdir.chmod(0o555)
    try:
        proc = run_cli(["-j", "-s", "0", "-o", str(out), *ALL_PARTS])
        assert proc.returncode == 1
        assert b"Failed to write output" in proc.stderr
        assert out.read_text() == "OLD REPORT"
    finally:
        outdir.chmod(0o755)


def test_atomic_replace_on_success(tmp_path):
    out = tmp_path / "report.json"
    out.write_text("STALE")
    proc = run_cli(["-j", "-s", "0", "-o", str(out), *ALL_PARTS])
    assert proc.returncode == 0, proc.stderr.decode()
    summary = json.loads(out.read_text())
    assert summary["captures"] == 6
    # no temporary files are left behind
    leftovers = [p for p in tmp_path.iterdir() if p.name != "report.json"]
    assert leftovers == []


def test_out_dash_writes_to_stdout():
    proc = run_cli(["-j", "-s", "0", "-o", "-", PART1])
    assert proc.returncode == 0
    assert json.loads(proc.stdout.decode())["captures"] == 3


# ---------------------------------------------------------------------------
# Report/load round-trip compatibility
# ---------------------------------------------------------------------------

def test_report_and_load_round_trip(tmp_path):
    report_file = tmp_path / "report.json"
    proc = run_cli(["-r", "-s", "0", "-o", str(report_file), *ALL_PARTS])
    assert proc.returncode == 0, proc.stderr.decode()
    report = json.loads(report_file.read_text())
    assert set(report.keys()) == EXPECTED_KEYS
    assert report["captures"] == 6

    proc = run_cli(["-l", "-j", str(report_file)])
    assert proc.returncode == 0, proc.stderr.decode()
    summary = json.loads(proc.stdout.decode())
    assert summary["captures"] == 6
    assert summary["urls"] == 5


def test_rich_summary_output_fields():
    proc = run_cli(["-s", "0", PART1])
    assert proc.returncode == 0, proc.stderr.decode()
    stdout = proc.stdout.decode()
    assert "Total Captures in CDX" in stdout
    assert "Unique URLs" in stdout
    assert "Unique Hosts" in stdout


# ---------------------------------------------------------------------------
# Analyzer unit tests
# ---------------------------------------------------------------------------

def test_feed_returns_diagnostic_with_source_line_reason():
    from cdxsummary.analyzer import CDXAnalyzer
    analyzer = CDXAnalyzer(samplesize=0)
    diagnostic = analyzer.feed(b"bogus line\n", source="x.cdx", lineno=7)
    assert diagnostic["source"] == "x.cdx"
    assert diagnostic["line"] == 7
    assert diagnostic["reason"]
    assert analyzer.captures == 0


def test_feed_dedups_full_capture_identity():
    from cdxsummary.analyzer import CDXAnalyzer
    analyzer = CDXAnalyzer(samplesize=0)
    line = b"com,example)/ 20210101000000 http://example.com/ text/html 200 A1B2C3 - - 1000 100 w.warc.gz\n"
    assert analyzer.feed(line) is None
    assert analyzer.feed(line) is None
    assert analyzer.captures == 1
    assert analyzer.duplicates == 1
    # same SURT and datetime but a different digest is a distinct capture
    other = line.replace(b"A1B2C3", b"Z9Y8X7")
    assert analyzer.feed(other) is None
    assert analyzer.captures == 2
    # URL and host sets count unique values over the whole input
    report = analyzer._report()
    assert report["urls"] == 1
    assert report["hosts"] == 1


def test_feed_undecodable_bytes_diagnostic():
    from cdxsummary.analyzer import CDXAnalyzer
    analyzer = CDXAnalyzer(samplesize=0)
    diagnostic = analyzer.feed(b"\xff\xfe invalid \xff\n", source="y.cdx", lineno=2)
    assert diagnostic["source"] == "y.cdx"
    assert diagnostic["line"] == 2
    assert "Undecodable" in diagnostic["reason"]
