import bz2
import gzip
import io
import json
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from cdxsummary.analyzer import CDXAnalyzer
from cdxsummary.parser import CDXRecord
from cdxsummary.sampler import BaseSampler, DynamicRandomStreamSampler

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "fixtures-data")
FIXTURE = os.path.join(FIXTURE_DIR, "example.cdx")

# Hand-derived expectations for tests/example.cdx.
EXPECTED = {
    "captures": 10,
    "urls": 6,
    "hosts": 3,
    "dupes": 4,
    "rejected": 1,
    "bytes": 1474,
    "first": "20200101120000",
    "last": "20200910120000",
}


def fixture_bytes(name="example.cdx"):
    with open(os.path.join(FIXTURE_DIR, name), "rb") as fh:
        return fh.read()


def analyze(data, **kwargs):
    return CDXAnalyzer(**kwargs)(io.BytesIO(data))


def shuffled(data, seed):
    lines = [line for line in data.splitlines(keepends=True) if line.strip()]
    random.Random(seed).shuffle(lines)
    return b"".join(lines)


class TestParser(unittest.TestCase):
    def test_valid_line_fields(self):
        line = "com,example)/a/b?x=1 20200101120000 http://example.com/a/b?x=1 text/html 200 DIGEST - - 100 11 w.warc"
        rec = CDXRecord(line)
        self.assertEqual(rec.host, "com,example")
        self.assertEqual(rec.surt, "com,example)/a/b?x=1")
        self.assertEqual(rec.path, "/a/b")
        self.assertEqual(rec.query, "x=1")
        self.assertEqual(rec.pathlen, 2)
        self.assertEqual(rec.querylen, 1)

    def test_invalid_line_raises(self):
        with self.assertRaises(ValueError):
            CDXRecord("this is not a valid cdx line")


class TestExactCounts(unittest.TestCase):
    def test_report_counts(self):
        report = analyze(fixture_bytes(), samplesize=10)
        for key, value in EXPECTED.items():
            self.assertEqual(report[key], value, key)

    def test_dupes_plus_urls_equal_captures(self):
        report = analyze(fixture_bytes())
        self.assertEqual(report["urls"] + report["dupes"], report["captures"])

    def test_tophosts_counts_sum_to_captures(self):
        report = analyze(fixture_bytes(), maxhosts=None)
        self.assertEqual(sum(report["tophosts"].values()), report["captures"])
        self.assertEqual(report["tophosts"], {"example.com": 6, "w3.org": 3, "test.net": 1})

    def test_grid_totals_match_captures(self):
        report = analyze(fixture_bytes())
        grid_total = sum(sum(row.values()) for row in report["pathquery"].values())
        self.assertEqual(grid_total, report["captures"])
        grid_total = sum(sum(row.values()) for row in report["mimestatus"].values())
        self.assertEqual(grid_total, report["captures"])
        grid_total = sum(sum(row.values()) for row in report["yearmonth"].values())
        self.assertEqual(grid_total, report["captures"])

    def test_maxhosts_limits_listing_but_keeps_host_total(self):
        report = analyze(fixture_bytes(), maxhosts=2)
        self.assertEqual(len(report["tophosts"]), 2)
        self.assertEqual(report["hosts"], 3)


class TestOrderIndependence(unittest.TestCase):
    STABLE_KEYS = (
        "captures", "urls", "hosts", "dupes", "rejected", "bytes",
        "first", "last", "tophosts", "mimestatus", "pathquery",
        "yearmonth", "samples",
    )

    def assert_shuffle_stable(self, data, **kwargs):
        ordered = analyze(data, **kwargs)
        for seed in (1, 2, 3, 7, 99, 123456):
            shuffled_report = analyze(shuffled(data, seed), **kwargs)
            for key in self.STABLE_KEYS:
                self.assertEqual(ordered[key], shuffled_report[key], f"{key} differs under shuffle seed {seed}")

    def test_plain_input_shuffle_stable(self):
        self.assert_shuffle_stable(fixture_bytes(), samplesize=10)

    def test_small_sample_shuffle_stable(self):
        self.assert_shuffle_stable(fixture_bytes(), samplesize=3)

    def test_interleaved_shards_merge_stable(self):
        # Two shards whose hosts/SURTs interleave when concatenated in
        # either order must still yield identical aggregate statistics.
        lines = [line for line in fixture_bytes().splitlines(keepends=True) if line.strip()]
        shard_a = b"".join(lines[0::2])
        shard_b = b"".join(lines[1::2])
        ab = analyze(shard_a + shard_b, samplesize=5)
        ba = analyze(shard_b + shard_a, samplesize=5)
        for key in self.STABLE_KEYS:
            self.assertEqual(ab[key], ba[key], key)


class TestBadLines(unittest.TestCase):
    def test_malformed_line_counted_and_excluded(self):
        data = fixture_bytes()
        report = analyze(data)
        self.assertEqual(report["rejected"], 1)
        self.assertEqual(report["captures"], EXPECTED["captures"])

    def test_blank_lines_are_not_rejected(self):
        report = analyze(b"\n\n   \n" + fixture_bytes())
        self.assertEqual(report["rejected"], 1)
        self.assertEqual(report["captures"], EXPECTED["captures"])

    def test_only_bad_lines(self):
        report = analyze(b"garbage\nmore garbage\n")
        self.assertEqual(report["captures"], 0)
        self.assertEqual(report["rejected"], 2)
        self.assertEqual(report["urls"], 0)
        self.assertEqual(report["hosts"], 0)
        self.assertEqual(report["dupes"], 0)

    def test_undecodable_bytes_rejected(self):
        good = b"com,example)/a 20200101120000 http://example.com/a text/html 200 D1 - - 100 11 w.warc\n"
        report = analyze(good + b"\xff\xfe\x00not utf8\n")
        self.assertEqual(report["captures"], 1)
        self.assertEqual(report["rejected"], 1)


class TestSampler(unittest.TestCase):
    def _candidate_keys(self, data):
        keys = set()
        analyzer = CDXAnalyzer(samplesize=10)
        for line in io.BytesIO(data):
            try:
                rec = CDXRecord(line.decode())
            except ValueError:
                continue
            if analyzer._sample_candidate(rec):
                keys.add(analyzer._sample_parts(rec))
        return keys

    def test_deterministic_across_runs_and_orders(self):
        data = fixture_bytes()
        first = analyze(data, samplesize=3)["samples"]
        second = analyze(data, samplesize=3)["samples"]
        third = analyze(shuffled(data, 77), samplesize=3)["samples"]
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_sample_size_bounded(self):
        for size in (1, 2, 3, 100):
            samples = analyze(fixture_bytes(), samplesize=size)["samples"]
            self.assertLessEqual(len(samples), size)

    def test_samples_are_unique_valid_candidates(self):
        data = fixture_bytes()
        candidates = self._candidate_keys(data)
        samples = analyze(data, samplesize=10)["samples"]
        self.assertEqual(len(samples), len(set(samples)))
        self.assertTrue(set(samples).issubset(candidates))

    def test_deterministic_sampler_unit(self):
        sampler = DynamicRandomStreamSampler(size=2, seed="fixed")
        for item in range(20):
            sampler(item)
        again = DynamicRandomStreamSampler(size=2, seed="fixed")
        for item in range(20):
            again(item)
        self.assertEqual(list(sampler.samples()), list(again.samples()))

    def test_sampler_order_independent_unit(self):
        sampler_a = DynamicRandomStreamSampler(size=3, seed="fixed")
        sampler_b = DynamicRandomStreamSampler(size=3, seed="fixed")
        items = list(range(30))
        for item in items:
            sampler_a(item)
        for item in reversed(items):
            sampler_b(item)
        self.assertEqual(list(sampler_a.samples()), list(sampler_b.samples()))

    def test_duplicate_items_collapse(self):
        sampler = DynamicRandomStreamSampler(size=5, seed="fixed")
        for _ in range(100):
            sampler("same")
        for item in range(4):
            sampler(item)
        self.assertEqual(len(list(sampler.samples())), 5)

    def test_base_sampler_restores_loaded_samples(self):
        sampler = BaseSampler()
        sampler.set_samples([("20200101120000", "http://example.com/")])
        self.assertEqual(list(sampler.samples()), [("20200101120000", "http://example.com/")])


class TestCompression(unittest.TestCase):
    def test_gzip_matches_plain(self):
        plain = analyze(fixture_bytes("example.cdx"), samplesize=10)
        gz = analyze(gzip.decompress(fixture_bytes("example.cdx.gz")), samplesize=10)
        self.assertEqual(plain, gz)

    def test_bz2_matches_plain(self):
        plain = analyze(fixture_bytes("example.cdx"), samplesize=10)
        bz = analyze(bz2.decompress(fixture_bytes("example.cdx.bz2")), samplesize=10)
        self.assertEqual(plain, bz)

    def test_compressed_fixtures_are_valid_streams(self):
        self.assertEqual(gzip.decompress(fixture_bytes("example.cdx.gz")), fixture_bytes())
        self.assertEqual(bz2.decompress(fixture_bytes("example.cdx.bz2")), fixture_bytes())


class TestLoadAndFormats(unittest.TestCase):
    def test_roundtrip_load_preserves_report(self):
        report = analyze(fixture_bytes(), samplesize=10, maxhosts=2)
        reloaded = CDXAnalyzer(maxhosts=2).load(json.dumps(report))
        for key in ("captures", "urls", "hosts", "dupes", "rejected", "bytes",
                    "first", "last", "tophosts", "samples"):
            self.assertEqual(report[key], reloaded[key], key)

    def test_load_legacy_report_without_new_fields(self):
        legacy = analyze(fixture_bytes(), samplesize=5)
        for legacy_key in ("dupes", "rejected"):
            legacy.pop(legacy_key)
        reloaded = CDXAnalyzer().load(json.dumps(legacy))
        self.assertEqual(reloaded["dupes"], reloaded["captures"] - reloaded["urls"])
        self.assertEqual(reloaded["rejected"], 0)

    def test_text_and_json_summaries_share_numbers(self):
        try:
            from cdxsummary.summarizer import ReportSummarizer
        except ImportError:
            self.skipTest("summarizer dependencies not installed")
        report = analyze(fixture_bytes(), samplesize=5)
        summary = ReportSummarizer(report)()
        for key in ("captures", "urls", "hosts", "dupes", "rejected", "bytes"):
            self.assertEqual(summary[key], report[key], key)
        text_buf = io.StringIO()
        json_buf = io.StringIO()
        ReportSummarizer(report, outfile=text_buf).print_summary()
        ReportSummarizer(report, outfile=json_buf).print_summary_json()
        rendered = text_buf.getvalue()
        for number in ("10", "6", "3", "4", "1"):
            self.assertIn(number, rendered)
        parsed_json = json.loads(json_buf.getvalue())
        self.assertEqual(parsed_json["captures"], report["captures"])
        self.assertEqual(parsed_json["dupes"], report["dupes"])
        self.assertEqual(parsed_json["rejected"], report["rejected"])


class TestCommandLine(unittest.TestCase):
    REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    def setUp(self):
        try:
            import humanize  # noqa: F401
            import internetarchive  # noqa: F401
        except ImportError:
            self.skipTest("CLI dependencies (humanize, internetarchive) not installed")

    def _cli(self, *args, stdin=None):
        import subprocess
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in [self.REPO, env.get("PYTHONPATH")] if p
        )
        result = subprocess.run(
            [sys.executable, "-m", "cdxsummary", *args],
            input=stdin, capture_output=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result.stdout.decode()

    def test_gzip_file_and_stdin_match(self):
        path = os.path.join(FIXTURE_DIR, "example.cdx.gz")
        from_file = json.loads(self._cli("-r", path))
        from_stdin = json.loads(self._cli("-r", "-", stdin=fixture_bytes()))
        self.assertEqual(from_file, from_stdin)
        self.assertEqual(from_file["rejected"], 1)
        self.assertEqual(from_file["urls"], 6)

    def test_bz2_file(self):
        path = os.path.join(FIXTURE_DIR, "example.cdx.bz2")
        report = json.loads(self._cli("-r", path))
        self.assertEqual(report["captures"], 10)
        self.assertEqual(report["dupes"], 4)

    def test_load_then_summarize(self):
        report = json.loads(self._cli("-r", "-", stdin=fixture_bytes()))
        summary = json.loads(self._cli("-l", "-j", "-", stdin=json.dumps(report).encode()))
        for key in ("captures", "urls", "hosts", "dupes", "rejected", "bytes"):
            self.assertEqual(summary[key], report[key], key)

    def test_text_summary_contains_new_overview_rows(self):
        text = self._cli("-", stdin=fixture_bytes())
        self.assertIn("Unique URLs", text)
        self.assertIn("Duplicate Captures", text)
        self.assertIn("Unique Hosts", text)
        self.assertIn("Rejected Lines", text)


if __name__ == "__main__":
    unittest.main()
