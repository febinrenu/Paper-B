"""Checks on the two sampling frames and on headline measures (reviewer-requested). Aggregates only.

(a) Frame 1 integrity: duplicate repositories, repositories without a tree, truncated trees.
(b) Frame 2 enumeration: per type, shards whose last status is done / truncated / incomplete / error, and the share of
    the search-reported total that was enumerated in the selected bins.
(c) Index coverage: for every Frame-1 agent file (an independent probability sample), is the same (repository,
    path) in the code-search lists? For census types any indexed file must be listed; for sampled types only files
    whose size falls in a selected bin are expected.
(d) Location: root vs nested path vs dotfiles repositories, for Claude settings and MCP configuration files.
(e) Per-repository rates in Frame 2 (a repository counts once, whatever its number of files).
(f) Literal secrets by detector type.
(g) Copy families: number of distinct owners per family.
Outputs: tables/b12_frame_checks.csv, b12_coverage.csv, b12_location.csv, b12_secrets.csv, b12_owners.csv.
"""
from __future__ import annotations

import json
import re
from collections import Counter

import numpy as np
import pandas as pd
from statsmodels.stats.proportion import proportion_confint

from common import DERIVED, LISTS, TABLES, read_jsonl

CENSUS = None


def wilson(k, n):
    if not n:
        return (np.nan, np.nan)
    return proportion_confint(k, n, method="wilson")


def frame1_integrity(out):
    repos = pd.DataFrame(read_jsonl(LISTS / "frame1_repos.jsonl"))
    trees = pd.DataFrame(read_jsonl(LISTS / "frame1_trees.jsonl"))
    last = trees.drop_duplicates("repo", keep="last")
    out.append({"check": "frame1_repo_rows", "value": len(repos)})
    out.append({"check": "frame1_distinct_repos", "value": repos.repo.nunique()})
    out.append({"check": "frame1_duplicate_rows", "value": len(repos) - repos.repo.nunique()})
    out.append({"check": "frame1_repos_in_two_strata", "value": int((repos.groupby("repo").stratum.nunique() > 1).sum())})
    out.append({"check": "frame1_no_tree", "value": int((last.status == "no_tree").sum())})
    out.append({"check": "frame1_truncated_trees", "value": int(last.truncated.fillna(False).astype(bool).sum())})


def frame2_enumeration(out):
    rows = []
    for f in sorted((LISTS / "code_search").glob("*_shards.jsonl")):
        t = f.name.replace("_shards.jsonl", "")
        sh = pd.DataFrame(read_jsonl(f))
        design = sh[sh.status == "design"].iloc[-1]
        sh = sh[sh.status != "design"].drop_duplicates("shard", keep="last")
        leaf = sh[sh.status != "split"]
        listed = sum(1 for _ in open(LISTS / "code_search" / f"{t}.jsonl", encoding="utf-8"))
        tot = leaf.total.fillna(0).sum()
        rows.append({"type": t, "p": design.p, "shards": len(leaf),
                     "done": int((leaf.status == "done").sum()), "error_last": int((leaf.status == "error").sum()),
                     "truncated": int(leaf.get("truncated", pd.Series(False)).fillna(False).astype(bool).sum()),
                     "incomplete": int(leaf.get("incomplete", pd.Series(False)).fillna(False).astype(bool).sum()),
                     "reported_total_in_selected_bins": int(tot), "listed": listed,
                     "listed_over_reported": listed / tot if tot else np.nan})
    d = pd.DataFrame(rows)
    d.to_csv(TABLES / "b12_enumeration.csv", index=False)
    print(d.to_string(index=False))
    for _, r in d.iterrows():
        out.append({"check": f"enum_{r.type}_listed_over_reported", "value": r.listed_over_reported})
    out.append({"check": "enum_truncated_shards_total", "value": int(d.truncated.sum())})
    out.append({"check": "enum_error_shards_total", "value": int(d.error_last.sum())})


def coverage(files):
    f1 = pd.DataFrame(read_jsonl(LISTS / "frame1_files.jsonl"))
    f1 = f1[f1.type != "vscode_settings"]
    cs = {}
    for f in (LISTS / "code_search").glob("*.jsonl"):
        if f.name.endswith("_shards.jsonl"):
            continue
        for d in read_jsonl(f):
            cs.setdefault(d["type"], set()).add((d["repo"].lower(), d["path"]))
    # selected size bins per type: a Frame-1 file is expected in the lists only if its size is in a selected bin
    bins = {}
    for f in (LISTS / "code_search").glob("*_shards.jsonl"):
        t = f.name.replace("_shards.jsonl", "")
        sel = []
        for d in read_jsonl(f):
            if d.get("status") in ("done", "split", "error") and ".." in str(d.get("shard")):
                a, b = d["shard"].split("..")
                sel.append((int(a), int(b)))
        bins[t] = sel
    rows = []
    for t, g in f1.groupby("type"):
        in_bin = g["size"].map(lambda s: any(a <= s <= b for a, b in bins.get(t, [])))
        e = g[in_bin]
        found = e.apply(lambda r: (r.repo.lower(), r.path) in cs.get(t, set()), axis=1) if len(e) else pd.Series(dtype=bool)
        k, n = int(found.sum()), len(e)
        lo, hi = wilson(k, n)
        rows.append({"type": t, "frame1_files": len(g), "in_selected_bins": n, "found_in_search": k,
                     "coverage": k / n if n else np.nan, "lo": lo, "hi": hi})
    d = pd.DataFrame(rows)
    k, n = d.found_in_search.sum(), d.in_selected_bins.sum()
    lo, hi = wilson(k, n)
    d = pd.concat([d, pd.DataFrame([{"type": "all", "frame1_files": d.frame1_files.sum(), "in_selected_bins": n,
                                      "found_in_search": k, "coverage": k / n, "lo": lo, "hi": hi}])])
    d.to_csv(TABLES / "b12_coverage.csv", index=False)
    print(d.round(3).to_string(index=False))


def coverage_bias(files):
    """Does index coverage depend on content? Compare Frame-1 files the code-search index found with those it missed
    (restricted to files whose size lies in a selected bin), on each content measure and on repository traits."""
    f1 = pd.DataFrame(read_jsonl(LISTS / "frame1_files.jsonl"))
    f1 = f1[f1.type != "vscode_settings"]
    cs = set()
    for f in (LISTS / "code_search").glob("*.jsonl"):
        if not f.name.endswith("_shards.jsonl"):
            cs |= {(d["type"], d["repo"].lower(), d["path"]) for d in read_jsonl(f)}
    bins = {}
    for f in (LISTS / "code_search").glob("*_shards.jsonl"):
        t = f.name.replace("_shards.jsonl", "")
        bins[t] = [tuple(map(int, d["shard"].split(".."))) for d in read_jsonl(f)
                   if d.get("status") in ("done", "split", "error") and ".." in str(d.get("shard"))]
    f1 = f1[[any(a <= s <= b for a, b in bins.get(t, [])) for t, s in zip(f1.type, f1["size"])]]
    f1["found"] = [(t, r.lower(), p) in cs for t, r, p in zip(f1.type, f1.repo, f1.path)]
    sc = files[files.frame == 1][["repo", "path", "type", "n_instruction_comments", "n_suspicious_unicode",
                                  "cs_dangerous", "sha", "fetched"]]
    d = f1.merge(sc, on=["repo", "path", "type"], how="left")
    d = d[d.fetched.fillna(False)]
    rules = files[files.frame == 1][[c for c in files.columns if c.startswith("rule_") and not c.endswith("_negated")]]
    rr = files[files.frame == 1][["repo", "path", "type"]].assign(any_rule=rules.fillna(0).sum(axis=1) > 0)
    d = d.merge(rr, on=["repo", "path", "type"], how="left")
    servers = pd.read_parquet(DERIVED / "mcp_servers.parquet")
    unp = set(servers[servers.eco.notna() & ~servers.pin.isin(["exact", "digest"])].sha)
    md = {"agents_md", "claude_md", "gemini_md", "copilot_instr", "cursor_rules_mdc", "cursorrules", "windsurfrules",
          "clinerules"}
    measures = {
        "instruction_comment (instruction files)": (d.type.isin(md), d.n_instruction_comments.fillna(0) > 0),
        "any_rule (instruction files)": (d.type.isin(md), d.any_rule.fillna(False).astype(bool)),
        "suspicious_unicode (instruction files)": (d.type.isin(md), d.n_suspicious_unicode.fillna(0) > 0),
        "dangerous_grant (Claude settings)": (d.type.eq("claude_settings"),
                                              d.cs_dangerous.fillna("[]").map(lambda x: any(y != "mcp_tool" for y in json.loads(x)))),
        "unpinned_launch (MCP configs)": (d.type.isin(["mcp_json", "cursor_mcp", "vscode_mcp"]), d.sha.isin(unp)),
    }
    from scipy.stats import fisher_exact
    from statsmodels.stats.proportion import confint_proportions_2indep
    rows = []
    for name, (base, val) in measures.items():
        g = d[base]
        v = val[base].astype(bool)
        a, b = g.found, ~g.found
        ka, na, kb, nb = int(v[a].sum()), int(a.sum()), int(v[b].sum()), int(b.sum())
        p = fisher_exact([[ka, na - ka], [kb, nb - kb]])[1] if na and nb else np.nan
        # absolute difference (found - missed) with a Newcombe score interval, and the smallest difference this
        # comparison could detect (two-sided 5%, power 80%): non-significance is not equivalence
        lo, hi = confint_proportions_2indep(ka, na, kb, nb, method="newcomb") if na and nb else (np.nan, np.nan)
        pp = (ka + kb) / (na + nb) if na + nb else np.nan
        mde = 2.80 * np.sqrt(pp * (1 - pp) * (1 / na + 1 / nb)) if na and nb else np.nan
        rows.append({"measure": name, "found_k": ka, "found_n": na, "found_rate": ka / na if na else np.nan,
                     "missed_k": kb, "missed_n": nb, "missed_rate": kb / nb if nb else np.nan,
                     "diff": (ka / na - kb / nb) if na and nb else np.nan, "diff_lo": lo, "diff_hi": hi,
                     "mde_80": mde, "fisher_p": p})
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b12_coverage_bias.csv", index=False)
    print(out.round(4).to_string(index=False))


def location(files):
    f = files[(files.frame == 2) & files.fetched.fillna(False)].copy()
    dot = f.repo.str.contains(r"dotfiles|dot-files|\.dotfiles|config-files|my-config", case=False, regex=True) | \
        f.path.str.contains(r"(^|/)(dotfiles|home)/", case=False, regex=True)
    root_paths = {"claude_settings": ".claude/settings.json", "mcp_json": ".mcp.json", "cursor_mcp": ".cursor/mcp.json",
                  "vscode_mcp": ".vscode/mcp.json"}
    f["location"] = np.where(dot, "dotfiles", np.where(f.path.eq(f.type.map(root_paths)), "root", "nested"))
    servers = pd.read_parquet(DERIVED / "mcp_servers.parquet")
    unp = servers[servers.eco.notna() & ~servers.pin.isin(["exact", "digest"])].sha.unique()
    rows = []
    for t in root_paths:
        g = f[f.type == t]
        for loc, h in g.groupby("location"):
            r = {"type": t, "location": loc, "files": len(h), "repos": h.repo.nunique()}
            if t == "claude_settings":
                dang = h.cs_dangerous.fillna("[]").map(json.loads)
                r["any_dangerous_grant"] = float(dang.map(lambda d: any(x != "mcp_tool" for x in d)).mean())
                r["bypass_mode"] = float(dang.map(lambda d: "bypass_permissions_mode" in d).mean())
                r["literal_secret"] = float(h.cs_secrets.fillna("[]").map(lambda x: bool(json.loads(x))).mean())
            else:
                r["unpinned_launch"] = float(h.sha.isin(unp).mean())
                r["literal_secret"] = float((h.n_server_secrets.fillna(0) > 0).mean())
            rows.append(r)
    d = pd.DataFrame(rows)
    d.to_csv(TABLES / "b12_location.csv", index=False)
    print(d.round(3).to_string(index=False))


def per_repo(files):
    f = files[(files.frame == 2) & files.fetched.fillna(False)]
    md = f[f.kind == "md"] if "kind" in f else f
    rows = []
    for name, col in (("instruction_comment", md.n_instruction_comments.fillna(0) > 0),
                      ("any_rule", md[[c for c in md.columns if c.startswith("rule_") and not c.endswith("_negated")]]
                       .fillna(0).sum(axis=1) > 0),
                      ("suspicious_unicode", md.n_suspicious_unicode.fillna(0) > 0)):
        by = col.groupby(md.repo).any()
        rows.append({"signal": name, "files_rate": float(col.mean()), "repos": len(by), "repos_with": int(by.sum()),
                     "repo_rate": float(by.mean())})
    d = pd.DataFrame(rows)
    d.to_csv(TABLES / "b12_per_repo.csv", index=False)
    print(d.round(4).to_string(index=False))


def secrets(files):
    f = files[(files.frame == 2) & files.fetched.fillna(False)]
    c = Counter()
    for x in f.cs_secrets.dropna():
        for s in json.loads(x):
            c[s] += 1
    servers = pd.read_parquet(DERIVED / "mcp_servers.parquet")
    for x in servers.secrets.dropna():
        vals = json.loads(x) if isinstance(x, str) else list(x)
        for s in vals:
            c[s] += 1
    d = pd.DataFrame(sorted(c.items(), key=lambda kv: -kv[1]), columns=["secret_type", "occurrences"])
    d.to_csv(TABLES / "b12_secrets.csv", index=False)
    print(d.to_string(index=False))


def owners(files):
    f = files[(files.frame == 2) & files.fetched.fillna(False) & (files.chars.fillna(0) >= 200)
              & (files.json_status.fillna("") != "symlink")]
    f = f.assign(owner=f.repo.str.split("/").str[0].str.lower())
    g = f.groupby("sha").agg(repos=("repo", "nunique"), owners=("owner", "nunique"))
    fam = g[g.repos >= 2]
    rows = [{"families": len(fam), "files_in_families": int(f.sha.isin(fam.index).sum()),
             "families_single_owner": int((fam.owners == 1).sum()),
             "share_single_owner": float((fam.owners == 1).mean()),
             "median_owners": float(fam.owners.median()), "max_owners": int(fam.owners.max())}]
    d = pd.DataFrame(rows)
    d.to_csv(TABLES / "b12_owners.csv", index=False)
    print(d.to_string(index=False))


def main():
    files = pd.read_parquet(DERIVED / "files.parquet")
    out = []
    frame1_integrity(out)
    frame2_enumeration(out)
    pd.DataFrame(out).to_csv(TABLES / "b12_frame_checks.csv", index=False)
    print(pd.DataFrame(out).to_string(index=False))
    coverage(files)
    coverage_bias(files)
    location(files)
    per_repo(files)
    secrets(files)
    owners(files)


if __name__ == "__main__":
    main()
