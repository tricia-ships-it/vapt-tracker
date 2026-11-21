#!/usr/bin/env python3
"""
feedsync.py — standalone threat-feed downloader for air-gapped deployments.

Run this on any INTERNET-CONNECTED machine (not your secure segment). It
downloads the same public vulnerability feeds the app uses and writes a single
feed file, which you then import on the offline Argus box
(Settings -> Air-gapped import).

It shares the app's fetch-only primitive: it can ONLY issue HTTP GET requests to
the hardcoded public feed URLs. It never sends anything about your environment.

Usage:
    python3 feedsync.py --out threatfeed.json
    python3 feedsync.py --out threatfeed.json --proxy http://proxy:3128
    python3 feedsync.py --out threatfeed.json --only cisa_kev
    python3 feedsync.py --list        # show available sources

Automate it on the connected box with cron, e.g. daily at 02:00:
    0 2 * * *  /usr/bin/python3 /path/feedsync.py --out /share/threatfeed.json
"""
import argparse
import datetime
import json
import sys

import threatintel


def main():
    ap = argparse.ArgumentParser(description="Download public vulnerability feeds (fetch-only).")
    ap.add_argument("--out", default="threatfeed.json", help="output feed file")
    ap.add_argument("--proxy", default=None, help="optional egress proxy URL")
    ap.add_argument("--only", nargs="*", help="only these source ids (default: all)")
    ap.add_argument("--list", action="store_true", help="list available sources and exit")
    args = ap.parse_args()

    if args.list:
        for s in threatintel.SOURCES:
            print(f"  {s['id']:<16} {s['name']}")
            print(f"  {'':<16} GET {s['url']}")
        return 0

    ids = args.only or [s["id"] for s in threatintel.SOURCES]
    records, errors = [], []
    for sid in ids:
        try:
            recs = threatintel.fetch_source(sid, proxy=args.proxy)
            records.extend(recs)
            print(f"[ok]   {sid}: {len(recs)} records", file=sys.stderr)
        except Exception as e:
            errors.append((sid, str(e)))
            print(f"[fail] {sid}: {e}", file=sys.stderr)

    payload = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "source_ids": ids,
        "count": len(records),
        "records": records,
    }
    with open(args.out, "w") as f:
        json.dump(payload, f)
    print(f"Wrote {len(records)} records to {args.out}", file=sys.stderr)
    return 1 if errors and not records else 0


if __name__ == "__main__":
    raise SystemExit(main())
