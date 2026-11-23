"""Fetch the content of every discovered file (Frame 1 + Frame 2) from raw.githubusercontent.com.

Code-search hits carry a commit-pinned html_url (.../blob/<commit>/<path>), so the fetched bytes are
exactly the indexed version. Frame-1 files are pinned to the commit recorded by 02_trees.py.
Deduplicated by git blob SHA; stored as data/raw/<sha[:2]>/<sha>; never executed or parsed as code.
Resumable (data/lists/fetch_log.jsonl) and keeps polling for newly discovered files until the
discovery steps have finished.
Usage: python src/04_fetch.py [--concurrency 8] [--follow]
"""
from __future__ import annotations

import argparse
import asyncio
import time
from urllib.parse import quote

import httpx

from common import LISTS, RAW, USER_AGENT, append_jsonl, read_jsonl

LOG = LISTS / "fetch_log.jsonl"
MAX_BYTES = 1_000_000


def raw_url(row: dict) -> str | None:
    u = row.get("html_url") or ""
    if "/blob/" in u:
        owner_repo, rest = u.split("github.com/", 1)[1].split("/blob/", 1)
        ref, path = rest.split("/", 1)
        return f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{quote(path)}"
    if row.get("repo") and row.get("commit") and row.get("path"):
        return f"https://raw.githubusercontent.com/{row['repo']}/{row['commit']}/{quote(row['path'])}"
    return None


def pending() -> list[dict]:
    seen = {r["sha"] for r in read_jsonl(LOG) if r.get("status") in ("ok", "too_large", "gone")}
    todo, queued = [], set()
    files = sorted((LISTS / "code_search").glob("*.jsonl")) + [LISTS / "frame1_files.jsonl"]
    for f in files:
        if f.name.endswith("_shards.jsonl"):
            continue
        for r in read_jsonl(f):
            sha = r.get("sha")
            if sha and sha not in seen and sha not in queued and raw_url(r):
                queued.add(sha)
                todo.append(r)
    return todo


async def fetch_one(c: httpx.AsyncClient, row: dict, sem: asyncio.Semaphore) -> None:
    url = raw_url(row)
    async with sem:
        for attempt in range(8):
            try:
                r = await c.get(url)
                if r.status_code == 404:
                    append_jsonl(LOG, {"sha": row["sha"], "status": "gone"})
                    return
                if r.status_code == 429 or r.status_code >= 500:
                    await asyncio.sleep(30 * (attempt + 1))
                    continue
                r.raise_for_status()
                body = r.content
                if len(body) > MAX_BYTES:
                    append_jsonl(LOG, {"sha": row["sha"], "status": "too_large", "bytes": len(body)})
                    return
                d = RAW / row["sha"][:2]
                d.mkdir(exist_ok=True)
                (d / row["sha"]).write_bytes(body)
                append_jsonl(LOG, {"sha": row["sha"], "status": "ok", "bytes": len(body)})
                return
            except (httpx.ConnectError, httpx.ConnectTimeout):
                await asyncio.sleep(60)          # offline: wait, do not count as an attempt
                continue
            except httpx.HTTPError:
                await asyncio.sleep(10 * (attempt + 1))
        append_jsonl(LOG, {"sha": row["sha"], "status": "error"})


async def run(concurrency: int, follow: bool) -> None:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, timeout=60, follow_redirects=True) as c:
        while True:
            todo = pending()
            print(time.strftime("%H:%M"), f"{len(todo)} files to fetch", flush=True)
            for i in range(0, len(todo), 500):
                await asyncio.gather(*(fetch_one(c, r, sem) for r in todo[i:i + 500]))
                print(time.strftime("%H:%M"), f"  {min(i + 500, len(todo))}/{len(todo)}", flush=True)
            discovery_done = (LISTS.parent / "code_search.finished").exists() and (LISTS.parent / "trees.finished").exists()
            if not follow or (discovery_done and not pending()):
                break
            await asyncio.sleep(600)
    if follow:
        (LISTS.parent / "fetch.finished").write_text(time.strftime("%Y-%m-%dT%H:%M:%S"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--follow", action="store_true", help="keep polling for new discoveries until discovery finishes")
    a = ap.parse_args()
    asyncio.run(run(a.concurrency, a.follow))


if __name__ == "__main__":
    main()
