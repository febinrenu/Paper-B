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
    for r in read_jsonl(LISTS / "frame1_files.jsonl"):
        rows.append({"frame": 1, "type": r["type"], "repo": r["repo"], "path": r["path"], "sha": r.get("sha"), "fork": False})
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    rec = records()
    rec = rec[rec.sha.notna()]
    rec["kind"] = rec.type.map(kind_of)
    jobs = sorted(set(zip(rec.sha, rec.kind)))
    print("records:", len(rec), "| unique (blob, kind):", len(jobs), flush=True)
    res, servers = [], []
    with Pool(a.workers) as pool, open(DERIVED / "details.jsonl", "w", encoding="utf-8") as det:
        for i, r in enumerate(pool.imap_unordered(scan, jobs, chunksize=200), 1):
            for s in r.pop("_servers", []):
                servers.append({"sha": r["sha"], "kind": r["kind"], **{k: (json.dumps(v) if isinstance(v, list) else v)
                                                                      for k, v in s.items()}})
            d = r.pop("_detail", None)
            if d:
                det.write(json.dumps({"sha": r["sha"], "kind": r["kind"], **d}, ensure_ascii=False) + "\n")
            res.append(r)
            if i % 20000 == 0:
                print(f"  {i}/{len(jobs)}", flush=True)
    blobs = pd.DataFrame(res)
    files = rec.merge(blobs, on=["sha", "kind"], how="left")
    files.to_parquet(DERIVED / "files.parquet", index=False)
    pd.DataFrame(servers).to_parquet(DERIVED / "mcp_servers.parquet", index=False)
    if "scan_error" in files:
        print("scan errors:", int(files.scan_error.notna().sum()))
    print(files.groupby(["frame", "type"]).agg(n=("sha", "size"), fetched=("fetched", "mean")).round(3).to_string())


if __name__ == "__main__":
    main()
