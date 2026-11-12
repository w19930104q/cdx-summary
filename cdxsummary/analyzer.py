import os
import sys

from collections import Counter
from json import dumps, loads
from rich.console import Console
from rich.json import JSON

if not __package__:
    sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from cdxsummary.parser import CDXRecord
from cdxsummary.sampler import BaseSampler, DynamicRandomStreamSampler


class CDXAnalyzer():
    def _sample_candidate(self, cdxrec):
        return cdxrec.status == "200" and cdxrec.mime == "text/html" and not cdxrec.surt.endswith("/robots.txt")


    def _sample_parts(self, cdxrec):
        return (cdxrec.datetime, cdxrec.url.replace(":80/", "", 1))


    def _top_hosts(self, th):
        # Sort on count first and then on the SURT host so ties do not depend
        # on the encounter order of the input lines.
        ordered = sorted(th.items(), key=lambda item: (-item[1], item[0]))
        if self._maxhosts:
            ordered = ordered[:self._maxhosts]
        return {".".join(reversed(host.split(","))): count for host, count in ordered}


    def __init__(self, samplesize=0, urlsampler=None, maxhosts=None, outfile=sys.stdout, seed="cdxsummary"):
        self._sampler = urlsampler
        if not self._sampler:
            self._sampler = DynamicRandomStreamSampler(size=samplesize, valid=self._sample_candidate, transform=self._sample_parts, seed=seed) if samplesize else BaseSampler(size=samplesize, seed=seed)
        self._maxhosts = maxhosts
        self._captures = 0
        self._rejected = 0
        self._bytes = 0
        self._first = "9" * 14
        self._last = "0" * 14
        # Exact, order-independent uniqueness: every distinct SURT and host
        # is remembered once, regardless of how shards are interleaved.
        self._url_keys = set()
        self._host_keys = set()
        self._tophosts = Counter()
        self._mimestatus = {}
        self._pathquery = {}
        self._yearmonth = {}
        # Values loaded from an existing JSON report are filled in here.
        self._loaded_urls = None
        self._loaded_hosts = None
        self._print = Console(file=outfile).print


    @staticmethod
    def _bump(table, key, subkey):
        row = table.get(key)
        if row is None:
            table[key] = {subkey: 1}
        else:
            row[subkey] = row.get(subkey, 0) + 1


    def _report(self):
        urls = self._loaded_urls if self._loaded_urls is not None else len(self._url_keys)
        hosts = self._loaded_hosts if self._loaded_hosts is not None else len(self._host_keys)
        captures = self._captures
        return {
            "captures": captures,
            "urls": urls,
            "hosts": hosts,
            "dupes": captures - urls,
            "rejected": self._rejected,
            "bytes": self._bytes,
            "first": self._first.replace("9" * 14, ""),
            "last": self._last.replace("0" * 14, ""),
            "tophosts": self._top_hosts(self._tophosts),
            "mimestatus": {mime: dict(sorted(codes.items())) for mime, codes in sorted(self._mimestatus.items())},
            "pathquery": {path: dict(sorted(queries.items())) for path, queries in sorted(self._pathquery.items())},
            "yearmonth": {year: dict(sorted(months.items())) for year, months in sorted(self._yearmonth.items())},
            "samples": list(self._sampler.samples())
        }


    def load(self, report_json):
        report = loads(report_json)
        self._captures = report["captures"]
        self._loaded_urls = report["urls"]
        self._loaded_hosts = report["hosts"]
        self._rejected = report.get("rejected", 0)
        self._bytes = report["bytes"]
        self._first = report["first"]
        self._last = report["last"]
        # Loaded reports already hold dotted host names; keep them as-is,
        # _top_hosts() only reverses keys containing SURT commas.
        self._tophosts = Counter(report["tophosts"])
        self._mimestatus = report["mimestatus"]
        self._pathquery = report["pathquery"]
        self._yearmonth = report["yearmonth"]
        self._sampler.set_samples((dt, url) for dt, url in report.get("samples", []))
        return self._report()


    def __call__(self, cdx):
        for line in cdx:
            try:
                cr = CDXRecord(line.decode())
            except Exception:
                if line.strip():
                    self._rejected += 1
                continue
            self._captures += 1
            self._url_keys.add(cr.surt)
            self._host_keys.add(cr.host)
            if self._first > cr.datetime:
                self._first = cr.datetime
            if self._last < cr.datetime:
                self._last = cr.datetime
            try:
                self._bytes += int(cr.bytes)
            except ValueError:
                pass
            self._tophosts[cr.host] += 1
            self._bump(self._pathquery, f"P{cr.pathlen}", f"Q{cr.querylen}")
            self._bump(self._yearmonth, cr.year, cr.month)
            self._bump(self._mimestatus, cr.mime, cr.status)
            self._sampler(cr)
        return self._report()


    def __str__(self):
        return dumps(self._report())


    def print_report_json(self):
        self._print(JSON.from_data(self._report()), soft_wrap=True)
