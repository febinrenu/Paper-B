"""Frame 1: stratified random sample of active public repositories (denominators for prevalence).

Population: public, non-fork, non-archived repositories with >= 10 stars, pushed since 2025-07-01.
Strata by stars: [10,99], [100,999], [1000,+). Repository search returns <= 1,000 results per
query, so each stratum is cluster-sampled by creation day: every calendar day (2008-01-01 to the
freeze date) is selected independently with probability p_s, and all repositories of the stratum
created that day are enumerated (splitting the star range further when a day exceeds 1,000).
Inclusion probability = p_s for every repository in stratum s.

Output: data/lists/frame1_repos.jsonl, data/lists/frame1_days.jsonl (design + resume log).
"""
from __future__ import annotations

import argparse
import datetime as dt
import random
import time

from common import LISTS, GitHub, append_jsonl, read_jsonl

OUT, DAYS = LISTS / "frame1_repos.jsonl", LISTS / "frame1_days.jsonl"
BASE = "is:public fork:false archived:false pushed:>=2025-07-01"
STRATA = {"s1": (10, 99, 20_000), "s2": (100, 999, 12_000), "s3": (1000, 10_000_000, 8_000)}   # lo, hi, target
FREEZE = dt.date(2026, 11, 23)


def q(lo, hi, day=None):
    s = f"{BASE} stars:{lo}..{hi}"
    return s + (f" created:{day}" if day else "")


def total(gh, query):
    r = gh.get("/search/repositories", {"q": query, "per_page": 1})
    return None if r is None or r.status_code != 200 else r.json()["total_count"]


def enumerate_day(gh, stratum, lo, hi, day):
    n = total(gh, q(lo, hi, day))
    if n is None:
        return None
    if n > 1000 and hi > lo:
        mid = (lo + hi) // 2
        a = enumerate_day(gh, stratum, lo, mid, day)
        b = enumerate_day(gh, stratum, mid + 1, hi, day)
        return None if a is None or b is None else a + b
    got = 0
    for page in range(1, min(10, (n + 99) // 100) + 1):
        r = gh.get("/search/repositories", {"q": q(lo, hi, day), "per_page": 100, "page": page, "sort": "stars"})
        if r is None or r.status_code != 200:
            return None
        for it in r.json().get("items", []):
            append_jsonl(OUT, {"stratum": stratum, "day": day, "repo": it["full_name"], "repo_id": it["id"],
                               "stars": it["stargazers_count"], "created_at": it["created_at"], "pushed_at": it["pushed_at"],
                               "default_branch": it["default_branch"], "language": it.get("language"),
                               "is_template": it.get("is_template"), "size_kb": it.get("size")})
            got += 1
    return got


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1122)
    ap.add_argument("--scale", type=float, default=1.0, help="multiply targets (pilot: 0.0125)")
    a = ap.parse_args()
    gh = GitHub(min_interval=2.1)                 # search API: 30 requests / minute
    log = read_jsonl(DAYS)
    design = {d["stratum"]: d for d in log if d.get("kind") == "design"}
    done = {(d["stratum"], d["day"]) for d in log if d.get("kind") == "day" and d.get("status") == "done"}
    days = [str(FREEZE - dt.timedelta(days=i)) for i in range((FREEZE - dt.date(2008, 1, 1)).days + 1)]
    for s, (lo, hi, target) in STRATA.items():
        if s not in design:
            n = total(gh, q(lo, hi))
            p = min(1.0, target * a.scale / max(n or 1, 1))
            design[s] = {"kind": "design", "stratum": s, "lo": lo, "hi": hi, "population": n, "p": p, "seed": a.seed,
                         "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
            append_jsonl(DAYS, design[s])
        p = design[s]["p"]
        rng = random.Random(f"{a.seed}-{s}")
        chosen = [d for d in days if rng.random() < p]
        print(f"[{s}] population~{design[s]['population']} p={p:.4f} days={len(chosen)}", flush=True)
        for i, day in enumerate(chosen, 1):
            if (s, day) in done:
                continue
            got = enumerate_day(gh, s, lo, hi, day)
            append_jsonl(DAYS, {"kind": "day", "stratum": s, "day": day, "status": "done" if got is not None else "error",
                                "repos": got})
            if i % 50 == 0:
                print(f"[{s}] days {i}/{len(chosen)}", flush=True)
    (LISTS.parent / "frame1.finished").write_text(time.strftime("%Y-%m-%dT%H:%M:%S"))
    print("frame 1 sampling finished", flush=True)


if __name__ == "__main__":
    main()
