import os
import sys

from collections import defaultdict, Counter
from json import dumps, loads
from rich.console import Console
from rich.json import JSON

if not __package__:
    sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from cdxsummary.parser import CDXRecord
from cdxsummary.sampler import BaseSampler, DynamicRandomStreamSampler


class CDXAnalyzer():
    MAXREASON = 200

    def _sample_candidate(self, cdxrec):
        return cdxrec.status == "200" and cdxrec.mime == "text/html" and not cdxrec.surt.endswith("/robots.txt")


    def _sample_parts(self, cdxrec):
        return (cdxrec.datetime, cdxrec.url.replace(":80/", "", 1))


    def _top_hosts(self):
        # Rank by capture count (desc) then SURT host (asc) so the result does
        # not depend on the order or partitioning of the input records.
        ranked = sorted(self._tophosts.items(), key=lambda kv: (-kv[1], kv[0]))
        if self._maxhosts is not None:
            ranked = ranked[:self._maxhosts]
        return {".".join(reversed(host.split(","))): count for host, count in ranked}


    @staticmethod
    def _count(value):
        # Counts are sets while analyzing CDX data, but plain integers when
        # loaded from a previously generated JSON report.
        return len(value) if isinstance(value, (set, frozenset)) else value


    @staticmethod
    def _sorted_grid(grid):
        return {key: dict(sorted(grid[key].items())) for key in sorted(grid)}


    def __init__(self, samplesize=0, urlsampler=None, maxhosts=None, outfile=sys.stdout):
        self._sampler = urlsampler
        if not self._sampler:
            self._sampler = DynamicRandomStreamSampler(size=samplesize, valid=self._sample_candidate, transform=self._sample_parts) if samplesize else BaseSampler()
        self._maxhosts = maxhosts
        self._captures = 0
        self._duplicates = 0
        self._seen = set()
        self._urls = set()
        self._hosts = set()
        self._bytes = 0
        self._first = "9" * 14
        self._last = "0" * 14
        self._tophosts = Counter()
        self._mimestatus = defaultdict(lambda: defaultdict(int))
        self._pathquery = defaultdict(lambda: defaultdict(int))
        self._yearmonth = defaultdict(lambda: defaultdict(int))
        self._print = Console(file=outfile).print


    @property
    def captures(self):
        return self._captures


    @property
    def duplicates(self):
        return self._duplicates


    def _report(self):
        return {
            "captures": self._captures,
            "urls": self._count(self._urls),
            "hosts": self._count(self._hosts),
            "bytes": self._bytes,
            "first": self._first.replace("9" * 14, ""),
            "last": self._last.replace("0" * 14, ""),
            "tophosts": self._top_hosts(),
            "mimestatus": self._sorted_grid(self._mimestatus),
            "pathquery": self._sorted_grid(self._pathquery),
            "yearmonth": self._sorted_grid(self._yearmonth),
            "samples": list(self._sampler.samples())
        }


    def load(self, report_json):
        report = loads(report_json)
        self._captures = report["captures"]
        self._urls = report["urls"]
        self._hosts = report["hosts"]
        self._bytes = report["bytes"]
        self._first = report["first"]
        self._last = report["last"]
        self._tophosts = Counter(report["tophosts"])
        self._mimestatus = report["mimestatus"]
        self._pathquery = report["pathquery"]
        self._yearmonth = report["yearmonth"]
        self._sampler._samples = [(dt, url) for dt, url in report["samples"]]
        return self._report()


    def feed(self, line, source="<input>", lineno=0):
        """Merge one raw CDX line into the running summary.

        Returns a diagnostic dict (with source, line, and reason keys) for
        lines that cannot be parsed, and None otherwise. Duplicate captures
        (same SURT, datetime, and digest) are counted and skipped silently.
        """
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError as e:
                return {"source": source, "line": lineno, "reason": f"Undecodable bytes: {e}"}
        try:
            cr = CDXRecord(line)
        except (ValueError, AttributeError) as e:
            reason = str(e)
            if len(reason) > self.MAXREASON:
                reason = f"{reason[:self.MAXREASON - 3]}..."
            return {"source": source, "line": lineno, "reason": reason}
        identity = (cr.surt, cr.datetime, cr.digest)
        if identity in self._seen:
            self._duplicates += 1
            return None
        self._seen.add(identity)
        self._captures += 1
        self._urls.add(cr.surt)
        self._hosts.add(cr.host)
        if self._first > cr.datetime:
            self._first = cr.datetime
        if self._last < cr.datetime:
            self._last = cr.datetime
        try:
            self._bytes += int(cr.bytes)
        except ValueError:
            pass
        self._tophosts[cr.host] += 1
        self._pathquery[f"P{cr.pathlen}"][f"Q{cr.querylen}"] += 1
        self._yearmonth[cr.year][cr.month] += 1
        self._mimestatus[cr.mime][cr.status] += 1
        self._sampler(cr)
        return None


    def __call__(self, cdx):
        for lineno, line in enumerate(cdx, 1):
            self.feed(line, lineno=lineno)
        return self._report()


    def __str__(self):
        return dumps(self._report())


    def print_report_json(self, outfile=None):
        printer = self._print if outfile is None else Console(file=outfile).print
        printer(JSON.from_data(self._report()), soft_wrap=True)
