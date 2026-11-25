"""Runs the final analysis once collection is complete.

Waits (checking every 10 min) until data/code_search.finished exists and 04_fetch has caught up: every Frame 1
and Frame 2 blob sha has a final fetch status (ok / too_large / gone), or the remainder has not changed for 2 h.
Then runs 05_scan.py --workers 4, 06_stats.py --boot 1000 and 07_link.py, each logged to data/derived/auto_<step>.log. A failed step is retried
3 times, 20 minutes apart; data/analysis.finished is written only if every step succeeded.
Usage: python -u src/auto_final.py
"""
from __future__ import annotations

import subprocess
import sys
import time

from common import DATA, DERIVED, LISTS, read_jsonl

SRC = __import__("pathlib").Path(__file__).resolve().parent
STEPS = [("05_scan.py", "--workers", "4"), ("06_stats.py", "--boot", "1000"), ("07_link.py",)]


def unfetched() -> int:
    raw_url = __import__("importlib").import_module("04_fetch").raw_url
    final = {r["sha"] for r in read_jsonl(LISTS / "fetch_log.jsonl") if r.get("status") in ("ok", "too_large", "gone")}
    shas = set()
    files = [f for f in (LISTS / "code_search").glob("*.jsonl") if not f.name.endswith("_shards.jsonl")]
    for f in files + [LISTS / "frame1_files.jsonl"]:
        shas |= {r["sha"] for r in read_jsonl(f) if r.get("sha") and raw_url(r)}
    return len(shas - final)


def step(script: str, *args: str) -> bool:
    log = DERIVED / f"auto_{script.replace('.py', '')}.log"
    t0 = time.time()
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M')} {script} {' '.join(args)}\n")
        f.flush()
        rc = subprocess.run([sys.executable, "-u", str(SRC / script), *args], cwd=SRC, stdout=f,
                            stderr=subprocess.STDOUT).returncode
    print(time.strftime("%H:%M"), f"{script} {' '.join(args)} -> exit {rc} ({(time.time() - t0) / 60:.1f} min)", flush=True)
    return rc == 0


def main() -> None:
    marker = DATA / "analysis.finished"
    stalled_since, last_n = None, None
    while not marker.exists():
        if not (DATA / "code_search.finished").exists():
            time.sleep(600)
            continue
        n = unfetched()
        if n != last_n:
            stalled_since, last_n = time.time(), n
        # proceed when everything is fetched, or when the remainder has not moved for 2 h (files that keep
        # failing; the scan records them as unfetched and 06_stats reports the fetched share)
        if n and time.time() - stalled_since < 2 * 3600:
            print(time.strftime("%H:%M"), f"code search finished; {n} blobs still to fetch", flush=True)
            time.sleep(600)
            continue
        print(time.strftime("%H:%M"), "collection complete: final analysis", flush=True)
        failed = []
        for s, *args in STEPS:
            for attempt in range(3):
                if step(s, *args):
                    break
                if attempt < 2:
                    time.sleep(1200)
            else:
                failed.append(s)
                break                      # later steps depend on earlier outputs
        if failed:
            print(time.strftime("%H:%M"), "failed after retries:", failed, "- NOT marked finished; retry in 3 h", flush=True)
            time.sleep(3 * 3600)
            continue
        marker.write_text(time.strftime("%Y-%m-%dT%H:%M:%S"))
        print(time.strftime("%H:%M"), "analysis finished; see tables/", flush=True)


if __name__ == "__main__":
    main()
