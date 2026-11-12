#!/usr/bin/env python3
"""Regenerate the offline CDX fixtures used by the regression tests.

The plain fixture deliberately mixes three hosts and repeats SURTs so that
shuffling its lines (simulating out-of-order shard merges) changes the old
adjacency-based unique URL/host counts. It also contains a blank line and a
malformed line to exercise bad-line accounting.
"""
import bz2
import gzip
import os


LINES = [
    "com,example)/a 20200101120000 http://example.com/a text/html 200 DAAA - - 100 11 w1.warc",
    "org,w3)/ 20200202120000 https://w3.org/ text/html 200 DAAB - - 200 12 w1.warc",
    "com,example)/a 20200303120000 http://example.com/a text/html 302 DAAC - - 150 13 w1.warc",
    "com,example)/robots.txt 20200304120000 http://example.com/robots.txt text/html 200 DAAD - - 50 14 w1.warc",
    "com,example)/b?q=1 20200405120000 http://example.com/b?q=1 text/html 200 DAAE - - 300 15 w2.warc",
    "org,w3)/style.css 20200506120000 https://w3.org/style.css text/css 200 DAAF - - 75 16 w2.warc",
    "com,example)/b?q=1 20200607120000 http://example.com:80/b?q=1 text/html 200 DAAG - - 300 17 w2.warc",
    "net,test)/x/y 20200708120000 http://test.net/x/y application/pdf 404 DAAH - - 0 18 w3.warc",
    "com,example)/a 20200809120000 http://example.com/a image/png 200 DAAI - - 99 19 w3.warc",
    "org,w3)/ 20200910120000 https://w3.org/ text/html 200 DAAJ - - 200 20 w3.warc",
    "",
    "this is not a valid cdx line",
]


def main():
    here = os.path.dirname(os.path.realpath(__file__))
    fixture_dir = os.path.join(here, "fixtures-data")
    os.makedirs(fixture_dir, exist_ok=True)
    data = ("\n".join(LINES) + "\n").encode("utf-8")
    with open(os.path.join(fixture_dir, "example.cdx"), "wb") as fh:
        fh.write(data)
    with gzip.open(os.path.join(fixture_dir, "example.cdx.gz"), "wb") as fh:
        fh.write(data)
    with bz2.open(os.path.join(fixture_dir, "example.cdx.bz2"), "wb") as fh:
        fh.write(data)


if __name__ == "__main__":
    main()
