"""Frame 1: which agent-configuration files does each sampled repository contain?

One recursive tree request per repository for the default-branch head (core API, 5,000/h; 8 worker
threads share one request spacing of 0.75 s). Records every path matching a studied file type, with
blob SHA, so 04_fetch.py can download it (by branch, within hours; fetch time logged). Repositories
without any such file are recorded too (they are the denominator).

Outputs: data/lists/frame1_trees.jsonl (one row per repository), data/lists/frame1_files.jsonl
(one row per agent file, consumed by 04_fetch.py).
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from common import LISTS, GitHub, append_jsonl, file_type, read_jsonl

TREES, FILES = LISTS / "frame1_trees.jsonl", LISTS / "frame1_files.jsonl"
lock = threading.Lock()


def scan(gh: GitHub, r: dict) -> None:
    full, br = r["repo"], r["default_branch"]
    t = gh.get(f"/repos/{full}/git/trees/{quote(br, safe='')}", {"recursive": "1"})
    if t is None or t.status_code != 200:
        with lock:
            append_jsonl(TREES, {"repo": full, "status": "no_tree"})
        return
    tj = t.json()
    agent = [{"type": ft, "path": e["path"], "sha": e["sha"], "size": e.get("size")}
             for e in tj.get("tree", []) if e.get("type") == "blob" and (ft := file_type(e["path"]))]
    with lock:
        for x in agent:
            append_jsonl(FILES, {"frame": 1, "repo": full, "commit": br, **x})
        append_jsonl(TREES, {"repo": full, "status": "ok", "truncated": tj.get("truncated", False),
                             "n_entries": len(tj.get("tree", [])), "types": sorted({x["type"] for x in agent}),
                             "n_agent_files": len(agent), "tree_sha": tj.get("sha"),
                             "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})


def main() -> None:
    gh = GitHub(min_interval=0.75)
    done = {r["repo"] for r in read_jsonl(TREES)}
    n = 0
    while True:
        repos = [r for r in read_jsonl(LISTS / "frame1_repos.jsonl") if r["repo"] not in done]
        if not repos:
            if (LISTS.parent / "frame1.finished").exists():
                break
            time.sleep(300)                      # sampling still running: wait for more repositories
            continue
        with ThreadPoolExecutor(8) as ex:
            for i, _ in enumerate(ex.map(lambda r: scan(gh, r), repos), 1):
                if (n + i) % 500 == 0:
                    print(time.strftime("%H:%M"), f"{n + i} repositories scanned", flush=True)
        n += len(repos)
        done |= {r["repo"] for r in repos}
    (LISTS.parent / "trees.finished").write_text(time.strftime("%Y-%m-%dT%H:%M:%S"))
    print("trees finished", flush=True)


if __name__ == "__main__":
    main()
