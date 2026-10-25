#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""Prints the time series of the patched instance stats from syz-diff session logs.

syz-diff logs a multi-line "STAT {...}" JSON object every 5 minutes. The script extracts
them from one or more <session>/log.txt files and prints the selected stats as a table.

Usage:
  stat_series.py <session>/log.txt [<session2>/log.txt ...] [-k "corpus,coverage,signal"]
"""

import argparse
import json
import re
import sys

DEFAULT_KEYS = ["candidates", "corpus", "coverage", "signal", "exec total [new]", "exec total [base]"]
STAT_START = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) STAT (\{.*)$")


def parse(path):
    series = []
    with open(path, errors="replace") as f:
        lines = iter(f)
        for line in lines:
            m = STAT_START.match(line.rstrip("\n"))
            if not m:
                continue
            ts, buf = m.group(1), m.group(2)
            while not buf.rstrip().endswith("}"):
                nxt = next(lines, None)
                if nxt is None:
                    break
                buf += nxt
            try:
                series.append((ts, json.loads(buf)))
            except json.JSONDecodeError:
                pass
    return series


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="+")
    parser.add_argument("-k", "--keys", default="",
                        help="comma-separated stat names (default: %s + all 'corpus [...]' areas)"
                        % ",".join(DEFAULT_KEYS))
    parser.add_argument("--list", action="store_true", help="list all available stat names")
    args = parser.parse_args()
    for path in args.logs:
        series = parse(path)
        print("== %s (%d samples)" % (path, len(series)))
        if not series:
            continue
        if args.list:
            print("\n".join(sorted(series[-1][1])))
            continue
        keys = [k.strip() for k in args.keys.split(",") if k.strip()]
        if not keys:
            keys = DEFAULT_KEYS + sorted(k for k in series[-1][1] if k.startswith("corpus ["))
        print("\t".join(["time"] + keys))
        for ts, vals in series:
            print("\t".join([ts] + [str(vals.get(k, "-")) for k in keys]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
