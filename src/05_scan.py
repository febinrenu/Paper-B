"""Run every detector over every fetched file. Content-addressed: each blob is analysed once.

Inputs: data/lists/frame1_files.jsonl (Frame 1) and data/lists/code_search/<type>.jsonl (Frame 2), blobs in
data/raw/<sha[:2]>/<sha>. Nothing is executed; files are read as text.

Outputs (all private, name-level; aggregates are made by 06_stats.py):
  data/derived/files.parquet        one row per (frame, repo, path): type, inclusion weight, detector flags
  data/derived/mcp_servers.parquet  one row per MCP server entry: launch kind, ecosystem, package, pin, secrets
  data/derived/details.jsonl        per blob: suspicious Unicode runs (with decoded text), instruction-like HTML
                                    comments and non-negated rule matches, for validation
Usage: python src/05_scan.py [--workers 4]
"""
from __future__ import annotations

import argparse
import json
from multiprocessing import Pool

import pandas as pd

from common import DERIVED, LISTS, MARKDOWN_TYPES, RAW, read_jsonl
from configs import load_json, parse_claude_settings, parse_mcp, parse_vscode_settings
from hidden import analyse

MCP_TYPES = {"mcp_json", "cursor_mcp", "vscode_mcp"}


def kind_of(t: str) -> str:
    if t in MARKDOWN_TYPES:
        return "md"
    if t in MCP_TYPES:
        return "mcp"
    return t                     # claude_settings | vscode_settings


def records() -> pd.DataFrame:
    rows = []
    p_s = {d["stratum"]: d["p"] for d in read_jsonl(LISTS / "frame1_days.jsonl") if d["kind"] == "design"}
    stratum = {r["repo"]: r["stratum"] for r in read_jsonl(LISTS / "frame1_repos.jsonl")}
    for r in read_jsonl(LISTS / "frame1_files.jsonl"):
        rows.append({"frame": 1, "type": r["type"], "repo": r["repo"], "path": r["path"], "sha": r.get("sha"), "fork": False,
                     "stratum": stratum.get(r["repo"]), "p_incl": p_s.get(stratum.get(r["repo"]))})
    for f in sorted((LISTS / "code_search").glob("*.jsonl")):
        if f.name.endswith("_shards.jsonl"):
            continue
        design = next((s for s in read_jsonl(f.with_name(f.stem + "_shards.jsonl")) if s["status"] == "design"), {})
        for r in read_jsonl(f):
            rows.append({"frame": 2, "type": r["type"], "repo": r["repo"], "path": r["path"], "sha": r.get("sha"),
                         "fork": bool(r.get("fork")), "p_incl": design.get("p", 1.0), "shard": r.get("shard")})
    df = pd.DataFrame(rows).drop_duplicates(["frame", "repo", "path"])
    df["weight"] = 1 / df.p_incl.fillna(1.0)
    return df


def scan(job: tuple[str, str]) -> dict:
    try:
        return _scan(job)
    except Exception as ex:  # noqa: BLE001  (one malformed file must not stop the census; counted and reported)
        return {"sha": job[0], "kind": job[1], "fetched": True, "scan_error": f"{type(ex).__name__}: {ex}"[:200],
                "_servers": [], "_detail": None}


def _scan(job: tuple[str, str]) -> dict:
    sha, kind = job
    p = RAW / sha[:2] / sha
    if not p.exists():
        return {"sha": sha, "kind": kind, "fetched": False}
    text = p.read_bytes().decode("utf-8", errors="replace")
    hs = analyse(text, markdown=(kind == "md"))
    out = {"sha": sha, "kind": kind, "fetched": True, "chars": hs.chars, "lines": text.count("\n") + 1,
           "decode_errors": text.count("�"), **hs.flags()}
    detail = {"unicode": [u for u in hs.unicode if u["verdict"] == "suspicious"][:20],
              "comments": [c for c in hs.comments if c["instruction_like"]][:10],
              "rules": [r for r in hs.rules if not r["negated"]][:20]}
    servers = []
    if kind != "md":
        obj, status = load_json(text)
        out["json_status"] = status
        if kind == "mcp":
            servers = parse_mcp(obj)
        elif kind == "claude_settings":
            s = parse_claude_settings(obj)
            out.update({f"cs_{k}": (json.dumps(v) if isinstance(v, list) else v) for k, v in s.items()})
            servers = parse_mcp(obj)
        elif kind == "vscode_settings":
            s = parse_vscode_settings(obj)
            servers = s.pop("mcp_servers")
            out.update({f"vs_{k}": v for k, v in s.items()})
        out["n_servers"] = len(servers)
        out["n_server_secrets"] = sum(len(s["secrets"]) for s in servers)
    out["_servers"] = servers
    out["_detail"] = detail if any(detail.values()) else None
    return out


PARTS = DERIVED / "scan_parts"
CHECKPOINT = 20000


def flush(k: int, res: list, servers: list, details: list) -> None:
    """Write one checkpoint: blob results, server rows and validation details of the same batch together, so a run
    that is stopped part-way resumes without losing or duplicating anything."""
    pd.DataFrame(res).to_parquet(PARTS / f"blobs_{k:04d}.parquet", index=False)
    pd.DataFrame(servers or [{"sha": None}]).to_parquet(PARTS / f"servers_{k:04d}.parquet", index=False)
    with open(PARTS / f"details_{k:04d}.jsonl", "w", encoding="utf-8") as f:
        f.writelines(details)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--fresh", action="store_true", help="discard checkpoints of an earlier, unfinished run")
    a = ap.parse_args()
    rec = records()
    rec = rec[rec.sha.notna()]
    rec["kind"] = rec.type.map(kind_of)
    jobs = sorted(set(zip(rec.sha, rec.kind)))
    PARTS.mkdir(exist_ok=True)
    if a.fresh:
        for f in PARTS.iterdir():
            f.unlink()
    done = set()
    for f in sorted(PARTS.glob("blobs_*.parquet")):
        b = pd.read_parquet(f, columns=["sha", "kind"])
        done |= set(zip(b.sha, b.kind))
    k0 = len(list(PARTS.glob("blobs_*.parquet")))
    todo = [j for j in jobs if j not in done]
    print("records:", len(rec), "| unique (blob, kind):", len(jobs), "| already scanned:", len(done), flush=True)
    res, servers, details, k = [], [], [], k0
    with Pool(a.workers) as pool:
        for i, r in enumerate(pool.imap_unordered(scan, todo, chunksize=200), 1):
            for s in r.pop("_servers", []):
                # "kind" of a server is its launch kind (npx, uvx, docker, remote, ...); the blob's kind is kept apart
                servers.append({"sha": r["sha"], "blob_kind": r["kind"], **{k_: (json.dumps(v) if isinstance(v, list) else v)
                                                                           for k_, v in s.items()}})
            d = r.pop("_detail", None)
            if d:
                details.append(json.dumps({"sha": r["sha"], "kind": r["kind"], **d}, ensure_ascii=False) + "\n")
            res.append(r)
            if i % CHECKPOINT == 0:
                flush(k, res, servers, details)
                k += 1
                res, servers, details = [], [], []
                print(f"  {len(done) + i}/{len(jobs)}", flush=True)
    if res:
        flush(k, res, servers, details)
    # assemble the checkpoints
    blobs = pd.concat([pd.read_parquet(f) for f in sorted(PARTS.glob("blobs_*.parquet"))], ignore_index=True)
    blobs = blobs.drop_duplicates(["sha", "kind"])
    assert len(blobs) == len(jobs), (len(blobs), len(jobs))
    servers = pd.concat([pd.read_parquet(f) for f in sorted(PARTS.glob("servers_*.parquet"))], ignore_index=True)
    servers = servers[servers.sha.notna()]
    with open(DERIVED / "details.jsonl", "w", encoding="utf-8") as det:
        for f in sorted(PARTS.glob("details_*.jsonl")):
            det.write(f.read_text(encoding="utf-8"))
    files = rec.merge(blobs, on=["sha", "kind"], how="left")
    files.to_parquet(DERIVED / "files.parquet", index=False)
    servers.to_parquet(DERIVED / "mcp_servers.parquet", index=False)
    if "scan_error" in files:
        print("scan errors:", int(files.scan_error.notna().sum()))
    print(files.groupby(["frame", "type"]).agg(n=("sha", "size"), fetched=("fetched", "mean")).round(3).to_string())


if __name__ == "__main__":
    main()
