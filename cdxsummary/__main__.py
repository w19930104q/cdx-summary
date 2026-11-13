#!/usr/bin/env python3

import argparse
import bz2
import gzip
import os
import sys
import re
import tempfile

from internetarchive import get_session
from requests import Session
from rich.console import Console
from urllib.parse import urlencode

if not __package__:
    sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from cdxsummary import __NAME, __VERSION
from cdxsummary.summarizer import ReportSummarizer
from cdxsummary.analyzer import CDXAnalyzer


CDXAPI = os.getenv("CDXAPI", "https://web.archive.org/cdx/search")
ITEMURL = re.compile("^https?://archive.org/(?:download|details)/(?P<id>[^/]+)/?$", re.IGNORECASE)
URLRE = re.compile("^https?://.+", re.IGNORECASE)

REQSESSION = Session()
IASESSION = get_session()
REQSESSION.headers.update({"User-Agent": f"{__NAME}/{__VERSION}"})
IASESSION.headers.update({"User-Agent": f"{__NAME}/{__VERSION}"})

errprint = Console(stderr=True, style="red", highlight=False, soft_wrap=True).print


class InputError(Exception):
    """Fatal input failure: no report may be published."""


def argument_parser():
    ap = argparse.ArgumentParser(prog=__NAME, description="Summarize web archive capture index (CDX) files.")
    ap.add_argument("-a", "--api", nargs="?", const="matchType=exact", metavar="QUERY", help="CDX API query parameters (default: 'matchType=exact'), treats the last argument as the lookup URL")
    ap.add_argument("-i", "--item", action="store_true", help="Treat the input arguments as Petabox item identifiers instead of file paths")
    ap.add_argument("-j", "--json", action="store_true", help="Generate summary in JSON format")
    ap.add_argument("-l", "--load", action="store_true", help="Load JSON report instead of CDX")
    ap.add_argument("-o", "--out", nargs="?", const="-", default=None, metavar="FILE", help="Write output to the given file, atomically replacing any previous report only after full success (default: STDOUT)")
    ap.add_argument("-r", "--report", action="store_true", help="Generate non-summarized JSON report")
    ap.add_argument("-s", "--samples", nargs="?", type=int, default=10, metavar="N", help="Number of sample memento URLs in summary (default: 10)")
    ap.add_argument("-t", "--tophosts", nargs="?", type=int, default=10, metavar="N", help="Number of hosts with maximum captures in summary (default: 10)")
    ap.add_argument("-v", "--version", action="version", version=f"{__NAME} {__VERSION}", help="Show version number")
    ap.add_argument("input", nargs="*", help="CDX file paths/URLs (plain/gz/bz2) or IA item IDs to merge into one summary (reads from the STDIN, if empty or '-')")
    return ap


def get_input_url(inp, as_item=False):
    if not inp:
        return
    m = ITEMURL.match(inp)
    if m:
        itemid = m.groupdict().get("id")
        return f"https://archive.org/download/{itemid}/{itemid}.cdx.gz"

    if as_item:
        return f"https://archive.org/download/{inp}/{inp}.cdx.gz"

    if URLRE.match(inp):
        return inp


def get_stream_from_api(url):
    pages = int(REQSESSION.get(f"{url}&showNumPages=true").text)
    for page in range(pages):
        pageurl = f"{url}&page={page}"
        errprint(f"Downloading [[cyan]{page + 1}/{pages}[/cyan]]: [magenta]{pageurl}[/magenta]")
        r = REQSESSION.get(pageurl, stream=True)
        if r.ok:
            r.raw.decode_content = True
            for line in r.raw:
                yield line


def get_stream_from_url(url):
    errprint(f"Downloading remote file: [magenta]{url}[/magenta]")
    session = IASESSION if "archive.org/download/" in url else REQSESSION
    r = session.get(url, stream=True)
    if r.ok:
        r.raw.decode_content = True
        stream = r.raw
        if url.endswith(".gz"):
            stream = gzip.GzipFile(fileobj=r.raw, mode="rb")
        if url.endswith(".bz2"):
            stream = bz2.BZ2File(fileobj=r.raw, mode="rb")
        return stream
    raise Exception(f"{r.status_code} {r.reason}: {url}")


def open_local_source(inp):
    """Return a (source_name, binary line stream) pair for a local file or STDIN.

    Compression is detected from magic bytes, so plain, gzipped, and bzip2'd
    inputs can be mixed freely regardless of file extension.
    """
    if not inp or inp == "-":
        errprint(f"Summarizing piped data: [magenta]STDIN[/magenta]")
        return "STDIN", sys.stdin.buffer
    errprint(f"Summarizing local file: [magenta]{inp}[/magenta]")
    raw = open(inp, "rb")
    magic = raw.read(4)
    raw.seek(0)
    if magic[:2] == b"\x1f\x8b":
        return inp, gzip.GzipFile(fileobj=raw, mode="rb")
    if magic[:3] == b"BZh":
        return inp, bz2.BZ2File(raw, mode="rb")
    return inp, raw


def iter_sources(args, inputs):
    for inp in inputs:
        url = get_input_url(inp, args.item)
        if url:
            yield url, get_stream_from_url(url)
        else:
            yield open_local_source(inp)


def close_stream(stream):
    if stream is sys.stdin.buffer:
        return
    try:
        stream.close()
    except Exception:
        pass


def write_output(outpath, render):
    """Render output, atomically replacing any previous file on full success.

    When writing to a file, the report is first rendered to a temporary file
    in the same directory and then moved into place with os.replace(), so a
    pre-existing report is never truncated or left half-written on failure.
    """
    if not outpath or outpath == "-":
        render(sys.stdout)
        return
    outpath = os.path.abspath(outpath)
    outdir = os.path.dirname(outpath)
    fd, tmppath = tempfile.mkstemp(dir=outdir, prefix=f".{os.path.basename(outpath)}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmpfile:
            render(tmpfile)
            tmpfile.flush()
            os.fsync(tmpfile.fileno())
        os.replace(tmppath, outpath)
    except BaseException:
        try:
            os.unlink(tmppath)
        except OSError:
            pass
        raise


def main():
    ap = argument_parser()
    args = ap.parse_args()

    if args.api and args.api != "matchType=exact" and not args.input:
        args.input = [args.api]
        args.api = "matchType=exact"

    if os.isatty(sys.stdin.fileno()) and not args.input:
        ap.print_help(file=sys.stderr)
        sys.exit()

    inputs = args.input or ["-"]

    if args.api:
        if len(inputs) != 1:
            errprint("The CDX API mode requires exactly one input URL.")
            sys.exit(1)
        url = f"{CDXAPI}?{args.api}&{urlencode({'url': inputs[0]})}"
        sources = [(url, get_stream_from_api(url))]
    else:
        sources = iter_sources(args, inputs)

    maxhosts = None if args.report else args.tophosts
    cdxanalizer = CDXAnalyzer(samplesize=args.samples, maxhosts=maxhosts)

    try:
        if args.load:
            report = cdxanalizer.load(b"".join(line for _, stream in sources for line in stream))
        else:
            for name, stream in sources:
                try:
                    for lineno, line in enumerate(stream, 1):
                        diagnostic = cdxanalizer.feed(line, source=name, lineno=lineno)
                        if diagnostic:
                            errprint(f"Skipped invalid record at {diagnostic['source']}:{diagnostic['line']}: {diagnostic['reason']}")
                except (OSError, EOFError) as e:
                    raise InputError(f"Failed to read input '{name}': {e}")
                finally:
                    close_stream(stream)
            if not cdxanalizer.captures:
                raise InputError("No valid CDX records found in the input, no report was published.")
            report = cdxanalizer._report()
    except (OSError, Exception) as e:
        errprint(e)
        if str(e).startswith("403") and "archive.org/download/" in str(e) and not IASESSION.cookies:
            errprint("\nIf you have access to this private Internet Archive file, configure your credentials using the 'ia' CLI tool and try again.\n[white]Documentation:[/white] [magenta]https://archive.org/services/docs/api/internetarchive/quickstart.html#configuring[/magenta]")
        sys.exit(1)

    if cdxanalizer.duplicates:
        errprint(f"Skipped {cdxanalizer.duplicates} duplicate captures across inputs.")

    def render(outfile):
        if args.report:
            cdxanalizer.print_report_json(outfile=outfile)
        else:
            rs = ReportSummarizer(report, outfile=outfile)
            if args.json:
                rs.print_summary_json()
            else:
                rs.print_summary()

    try:
        write_output(args.out, render)
    except OSError as e:
        errprint(f"Failed to write output, any previous report was left untouched: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
