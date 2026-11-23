"""Frame 2: discover agent-configuration files through GitHub code search.

The search API returns at most 1,000 results per query, so each file type is split into file-size
bins. Design (equal-probability cluster sample):
  * a fixed grid of size bins (25 B up to 10 kB, 100 B up to 50 kB, 1 kB up to 384 kB, the
    code-search size limit);
  * each grid bin is selected independently with probability p (p = min(1, target / total));
  * every selected bin is enumerated completely, bisecting down to single byte sizes while a
    query reports more than 1,000 results. A single size with > 1,000 results is truncated
    (recorded and reported).
Every file of a type therefore has inclusion probability p. For small types p = 1, which is
a census of what code search indexes (default branches; forks only when starred above the parent).

Outputs: data/lists/code_search/<type>.jsonl (one row per hit) and <type>_shards.jsonl (shard
log, also used to resume).
Usage: python src/03_code_search.py [--types mcp_json,vscode_mcp] [--target 100000] [--seed 1122]
"""
from __future__ import annotations

import argparse
import random
import time

from common import FILE_TYPES, LISTS, GitHub, append_jsonl, read_jsonl

OUT = LISTS / "code_search"
OUT.mkdir(parents=True, exist_ok=True)
GRID = ([(a, a + 24) for a in range(0, 10_000, 25)] + [(a, a + 99) for a in range(10_000, 50_000, 100)]
        + [(a, a + 999) for a in range(50_000, 384_000, 1000)])


def search(gh: GitHub, q: str, page: int = 1, per_page: int = 100) -> dict | None:
    r = gh.get("/search/code", {"q": q, "per_page": per_page, "page": page})
    if r is None or r.status_code != 200:
        return None
    return r.json()


def total(gh: GitHub, q: str) -> tuple[int, bool] | None:
    j = search(gh, q, per_page=1)
    return None if j is None else (j["total_count"], j.get("incomplete_results", False))


def enumerate_range(gh, label, base_q, lo, hi, out, shards, done):
    key = f"{lo}..{hi}"
    if key in done:
        return
    q = f"{base_q} size:{key}"
    t = total(gh, q)
    if t is None:
        append_jsonl(shards, {"shard": key, "status": "error"})
        return
    n, incomplete = t
    if n > 1000 and hi > lo:
        mid = (lo + hi) // 2
        append_jsonl(shards, {"shard": key, "status": "split", "total": n})
        enumerate_range(gh, label, base_q, lo, mid, out, shards, done)
        enumerate_range(gh, label, base_q, mid + 1, hi, out, shards, done)
        return
    got = 0
    for page in range(1, min(10, (n + 99) // 100) + 1):
        j = search(gh, q, page=page)
        if j is None:
            break
        for it in j.get("items", []):
            repo = it.get("repository") or {}
            append_jsonl(out, {"type": label, "shard": key, "repo": repo.get("full_name"), "repo_id": repo.get("id"),
                               "fork": repo.get("fork"), "path": it.get("path"), "sha": it.get("sha"),
                               "html_url": it.get("html_url")})
            got += 1
        if len(j.get("items", [])) < 100:
            break
    append_jsonl(shards, {"shard": key, "status": "done", "total": n, "fetched": got, "truncated": n > 1000,
                          "incomplete": incomplete, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})


def run_type(gh: GitHub, label: str, target: int, seed: int) -> None:
    base_q = FILE_TYPES[label][0]
    out, shards = OUT / f"{label}.jsonl", OUT / f"{label}_shards.jsonl"
    log = read_jsonl(shards)
    done = {s["shard"] for s in log if s["status"] == "done"}
    meta = next((s for s in log if s["status"] == "design"), None)
    if meta is None:
        t = total(gh, base_q)
        if t is None:
            print(f"[{label}] could not get total; skipping for now", flush=True)
            return
        p = min(1.0, target / max(t[0], 1))
        rng = random.Random(f"{seed}-{label}")
        chosen = [g for g in GRID if rng.random() < p]
        meta = {"shard": "design", "status": "design", "total": t[0], "p": p, "bins": len(chosen), "grid": len(GRID),
                "seed": seed, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
        append_jsonl(shards, meta)
    else:
        rng = random.Random(f"{seed}-{label}")
        chosen = [g for g in GRID if rng.random() < meta["p"]]
    print(f"[{label}] total~{meta['total']}  p={meta['p']:.4f}  bins={len(chosen)}/{len(GRID)}  done={len(done)}", flush=True)
    if meta["p"] >= 1.0:
        # census: start from coarse ranges and bisect only where needed
        coarse = [(0, 999), (1000, 2999), (3000, 5999), (6000, 9999), (10_000, 19_999), (20_000, 49_999), (50_000, 384_000)]
        for lo, hi in coarse:
            enumerate_range(gh, label, base_q, lo, hi, out, shards, done)
    else:
        for i, (lo, hi) in enumerate(chosen, 1):
            enumerate_range(gh, label, base_q, lo, hi, out, shards, done)
            if i % 25 == 0:
                print(f"[{label}] bins {i}/{len(chosen)}", flush=True)
    print(f"[{label}] finished", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    small_first = ["mcp_json", "cursor_mcp", "vscode_mcp", "claude_settings", "windsurfrules", "clinerules",
                   "gemini_md", "copilot_instr", "cursorrules", "cursor_rules_mdc", "claude_md", "agents_md"]
    ap.add_argument("--types", default=",".join(small_first))
    ap.add_argument("--target", type=int, default=100_000)
    ap.add_argument("--seed", type=int, default=1122)
    a = ap.parse_args()
    gh = GitHub(min_interval=6.5)          # code search: 10 requests / minute
    for label in a.types.split(","):
        run_type(gh, label.strip(), a.target, a.seed)
    if a.types == ap.get_default("types"):
        (LISTS.parent / "code_search.finished").write_text(time.strftime("%Y-%m-%dT%H:%M:%S"))


if __name__ == "__main__":
    main()
