"""Design-based estimates from the scan outputs. Aggregates only; everything written here may be published.

Frame 1 (repository prevalence; population = public non-fork non-archived repos, >= 10 stars, pushed since
2025-07-01). Stratified (stars) cluster sample of creation days, inclusion probability p_s. Estimates are
Horvitz-Thompson totals and weighted ratios; 95% CIs from a stratified cluster bootstrap that resamples the
selected days (including days with no repository) within each stratum.

Frame 2 (file-level content; population = files of a type that GitHub code search indexes). Size-bin cluster
sample with equal inclusion probability p per type (p = 1 is a census). Rates are per file; 95% CIs from a
cluster bootstrap over the selected grid bins (superpopulation view, also reported for census types).

Outputs (tables/):
  b1_frame1_prevalence.csv   share and estimated number of repos with each agent-file type, by stratum and overall
  b2_frame1_risk.csv         share of repos with >= 1 file showing each detector signal
  b3_frame2_detectors.csv    per type: files, fetched share, rate of each detector signal
  b4_mcp_launch.csv          MCP server entries by launch kind and pinning (per file type)
  b5_mcp_remote_secrets.csv  remote transport (http vs https), literal secrets, auto-approval of MCP tools
  b6_autonomy.csv            Claude settings / VS Code settings autonomy grants
  b7_top_mcp_packages.csv    most-referenced npm / PyPI MCP packages (public package names; repo-free)
Private: data/derived/mcp_packages.parquet (package list for the Paper A registry check).
Usage: python src/06_stats.py [--boot 1000]
"""
from __future__ import annotations

import argparse
import json
from importlib import import_module

import numpy as np
import pandas as pd

from common import DERIVED, LISTS, TABLES, read_jsonl

GRID = import_module("03_code_search").GRID
RULES = ("override", "exfiltration", "remote_exec", "confirmation_bypass", "concealment")
RNG = np.random.default_rng(1122)
TABLES.mkdir(exist_ok=True)


# ------------------------------------------------------------------ signals
def signals(f: pd.DataFrame) -> pd.DataFrame:
    """Binary per-file detector signals (NaN-safe: unfetched files are excluded before this is used)."""
    s = pd.DataFrame(index=f.index)
    s["hidden_unicode"] = f.n_suspicious_unicode.fillna(0) > 0
    s["tag_payload"] = f.has_tag_payload.fillna(False).astype(bool)
    s["decoded_payload"] = f.has_decoded_payload.fillna(False).astype(bool)
    s["bidi_override"] = f.has_bidi_override.fillna(False).astype(bool)
    s["instruction_comment"] = f.n_instruction_comments.fillna(0) > 0
    for r in RULES:
        s[f"rule_{r}"] = f[f"rule_{r}"].fillna(0) > 0
    s["any_rule"] = s[[f"rule_{r}" for r in RULES]].any(axis=1)
    s["any_signal"] = s.hidden_unicode | s.instruction_comment | s.any_rule
    return s


def grid_bin(shard) -> int:
    """Grid bin (cluster) that a leaf shard 'lo..hi' lies in."""
    if not isinstance(shard, str) or ".." not in shard:
        return -1
    lo = int(shard.split("..")[0])
    for i, (a, b) in enumerate(GRID):
        if a <= lo <= b:
            return i
    return -1


# ------------------------------------------------------------------ bootstrap
def boot_ratio(num: np.ndarray, den: np.ndarray, strata: np.ndarray | None, B: int) -> tuple[float, float]:
    """Cluster bootstrap CI for sum(num)/sum(den). num, den: per-cluster sums (num may be 2-D: clusters x stats)."""
    num = num if num.ndim == 2 else num[:, None]
    strata = np.zeros(len(den), int) if strata is None else strata
    est = np.zeros((B, num.shape[1]))
    tot_n, tot_d = np.zeros((B, num.shape[1])), np.zeros(B)
    for s in np.unique(strata):
        idx = np.flatnonzero(strata == s)
        w = RNG.multinomial(len(idx), np.full(len(idx), 1 / len(idx)), size=B)      # B x clusters
        tot_n += w @ num[idx]
        tot_d += w @ den[idx]
    with np.errstate(invalid="ignore", divide="ignore"):
        est = tot_n / tot_d[:, None]
    return np.nanpercentile(est, 2.5, axis=0), np.nanpercentile(est, 97.5, axis=0)


# ------------------------------------------------------------------ Frame 1
def frame1(files: pd.DataFrame, B: int) -> None:
    days = read_jsonl(LISTS / "frame1_days.jsonl")
    design = {d["stratum"]: d for d in days if d["kind"] == "design"}
    sel = pd.DataFrame([d for d in days if d["kind"] == "day"]).drop_duplicates(["stratum", "day"], keep="last")
    repos = pd.DataFrame(read_jsonl(LISTS / "frame1_repos.jsonl"))[["repo", "stratum", "day"]]
    trees = pd.DataFrame(read_jsonl(LISTS / "frame1_trees.jsonl")).drop_duplicates("repo", keep="last")
    repos = repos.merge(trees[["repo", "status", "truncated"]], on="repo", how="left")
    print("Frame 1 tree status:", repos.status.value_counts(dropna=False).to_dict(),
          "| truncated:", int(repos.truncated.fillna(False).sum()))
    repos = repos[repos.status == "ok"].copy()              # repos without a readable tree are dropped (reported)
    repos["w"] = 1 / repos.stratum.map(lambda s: design[s]["p"])

    f1 = files[files.frame == 1]
    types = sorted(f1.type.unique())
    has = f1.groupby(["repo", "type"]).size().unstack(fill_value=0).gt(0)
    sig = pd.concat([f1[["repo"]], signals(f1[f1.fetched.fillna(False)])], axis=1).groupby("repo").any()
    R = repos.set_index("repo")
    R = R.join(has.reindex(R.index, fill_value=False)).join(sig.drop(columns=[], errors="ignore").reindex(R.index, fill_value=False))
    R[types] = R[types].fillna(False).astype(bool)
    # .vscode/settings.json is mostly editor settings, not agent configuration: kept as its own row, not in "any"
    R["any_agent_file"] = R[[t for t in types if t != "vscode_settings"]].any(axis=1)
    sigcols = [c for c in signals(f1.head(0)).columns]
    R[sigcols] = R[sigcols].fillna(False).astype(bool)

    clus = sel[["stratum", "day"]].copy()
    clus["cid"] = np.arange(len(clus))
    R = R.reset_index().merge(clus, on=["stratum", "day"], how="left")
    assert R.cid.notna().all(), "repo from an unselected day"
    strata_codes = clus.stratum.map({s: i for i, s in enumerate(sorted(design))}).to_numpy()

    def estimate(sub: pd.DataFrame, cols: list[str], label: str, strat_arr) -> list[dict]:
        W = sub[cols].astype(float).mul(sub.w, axis=0)
        W["w"], W["cid"] = sub.w, sub.cid.astype(int)
        agg = W.groupby("cid").sum().reindex(sub_cids, fill_value=0.0)      # zero rows for empty days
        num, den = agg[cols].to_numpy(), agg.w.to_numpy()
        lo, hi = boot_ratio(num, den, strat_arr, B)
        out = []
        for j, c in enumerate(cols):
            share = num[:, j].sum() / den.sum()
            out.append({"group": label, "measure": c, "repos_sampled": len(sub), "repos_with": int(sub[c].sum()),
                        "share": share, "share_lo": lo[j], "share_hi": hi[j], "est_repos": num[:, j].sum(),
                        "est_population": den.sum()})
        return out

    prev_cols = ["any_agent_file"] + types
    rows_p, rows_r = [], []
    for label, sub_clus in [("all", clus)] + [(s, clus[clus.stratum == s]) for s in sorted(design)]:
        sub_cids = sub_clus.cid.tolist()
        sub = R[R.cid.isin(sub_cids)]
        strat_arr = sub_clus.stratum.map({s: i for i, s in enumerate(sorted(design))}).to_numpy()
        rows_p += estimate(sub, prev_cols, label, strat_arr)
        # risk signals among repos that have at least one agent file, and among all repos
        rows_r += [dict(r, base="all_repos") for r in estimate(sub, sigcols, label, strat_arr)]
        subA = sub[sub.any_agent_file]
        rows_r += [dict(r, base="repos_with_agent_file") for r in estimate(subA, sigcols, label, strat_arr)]
    pd.DataFrame(rows_p).to_csv(TABLES / "b1_frame1_prevalence.csv", index=False)
    pd.DataFrame(rows_r).to_csv(TABLES / "b2_frame1_risk.csv", index=False)
    p = pd.DataFrame(rows_p)
    print(p[p.group == "all"][["measure", "repos_with", "share", "share_lo", "share_hi", "est_repos"]].round(4).to_string(index=False))


# ------------------------------------------------------------------ Frame 2
def frame2(files: pd.DataFrame, B: int) -> pd.DataFrame:
    f2 = files[files.frame == 2].copy()
    f2["cluster"] = f2.shard.map(grid_bin)
    rows = []
    for t, g in f2.groupby("type"):
        fe = g[g.fetched.fillna(False)]
        s = signals(fe)
        cl = fe.cluster.to_numpy()
        u, inv = np.unique(cl, return_inverse=True)
        num = np.zeros((len(u), s.shape[1]))
        np.add.at(num, inv, s.to_numpy(float))
        den = np.bincount(inv, minlength=len(u)).astype(float)
        lo, hi = boot_ratio(num, den, None, B)
        p = float(g.p_incl.iloc[0])
        for j, c in enumerate(s.columns):
            rows.append({"type": t, "p_incl": p, "census": p >= 1, "files": len(g), "fetched": len(fe),
                         "fetched_share": len(fe) / len(g), "clusters": len(u), "forks": int(g.fork.sum()),
                         "signal": c, "files_with": int(s[c].sum()), "rate": s[c].mean(), "rate_lo": lo[j],
                         "rate_hi": hi[j], "est_files_population": len(g) / p, "est_files_with": s[c].sum() / p})
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b3_frame2_detectors.csv", index=False)
    wide = out.pivot(index="type", columns="signal", values="rate")
    print((wide[["any_signal", "hidden_unicode", "instruction_comment", "any_rule", "rule_remote_exec",
                 "rule_confirmation_bypass"]] * 100).round(2).to_string())
    return f2


# ------------------------------------------------------------------ MCP + autonomy
def mcp_and_autonomy(files: pd.DataFrame, f2: pd.DataFrame) -> None:
    srv = pd.read_parquet(DERIVED / "mcp_servers.parquet")
    if "blob_kind" not in srv:      # scan outputs written before the column rename
        srv = srv.rename(columns={"kind": "launch"}).assign(blob_kind=None)
    else:
        srv = srv.rename(columns={"kind": "launch"})
    cfg = f2[(f2.kind != "md") & f2.fetched.fillna(False)][["type", "kind", "sha", "repo", "path", "cluster"]]
    on = ["sha"] if srv.blob_kind.isna().all() else ["sha", "kind"]
    srv = srv.rename(columns={"blob_kind": "kind"}) if "kind" in on else srv.drop(columns="blob_kind")
    s = cfg.merge(srv.drop_duplicates(), on=on, how="inner")
    s["secret"] = s.secrets.map(lambda x: bool(json.loads(x)) if isinstance(x, str) else False)
    s["pin"] = s.pin.fillna("n/a")

    launch = (s.groupby(["type", "launch", "pin"]).size().rename("entries").reset_index())
    launch["share_of_type"] = launch.entries / launch.groupby("type").entries.transform("sum")
    allt = s.groupby(["launch", "pin"]).size().rename("entries").reset_index().assign(type="all")
    allt["share_of_type"] = allt.entries / allt.entries.sum()
    pd.concat([launch, allt]).to_csv(TABLES / "b4_mcp_launch.csv", index=False)

    s["pinned"] = s.pin.isin(["exact", "digest"])        # exact version (npm/PyPI) or image digest (docker)
    per_type = []
    for t, g in [("all", s)] + list(s.groupby("type")):
        files_with_servers = g[["repo", "path"]].drop_duplicates().shape[0]
        files_with_secret = g[g.secret][["repo", "path"]].drop_duplicates().shape[0]
        rem = g[g.launch == "remote"]
        pk = g[g.eco.notna()]
        per_type.append({"type": t, "server_entries": len(g), "config_files": files_with_servers,
                         "files_with_literal_secret": files_with_secret,
                         "share_files_with_literal_secret": files_with_secret / files_with_servers if files_with_servers else np.nan,
                         "entries_with_literal_secret": int(g.secret.sum()),
                         "remote_entries": len(rem), "remote_http_nonlocal": int(((rem.remote_scheme == "http") & ~rem.remote_local.fillna(False).astype(bool)).sum()),
                         "package_entries": len(pk), "package_unpinned": int((~pk.pinned).sum()),
                         "share_package_unpinned": (~pk.pinned).mean() if len(pk) else np.nan,
                         **{f"share_unpinned_{e}": (~pk[pk.eco == e].pinned).mean() if (pk.eco == e).any() else np.nan
                            for e in ("npm", "pypi", "docker")},
                         "entries_always_allow": int((g.always_allow > 0).sum())})
    pd.DataFrame(per_type).to_csv(TABLES / "b5_mcp_remote_secrets.csv", index=False)
    print(pd.DataFrame(per_type).round(3).to_string(index=False))

    pk = s[s.eco.notna() & s.package.notna()]
    top = (pk.groupby(["eco", "package"]).agg(files=("path", "size"), repos=("repo", "nunique"),
                                               unpinned_share=("pinned", lambda x: 1 - x.mean()))
           .reset_index().sort_values("repos", ascending=False))
    top.to_parquet(DERIVED / "mcp_packages.parquet", index=False)
    top[top.repos >= 25].head(100).to_csv(TABLES / "b7_top_mcp_packages.csv", index=False)
    print("distinct MCP packages:", top.groupby("eco").size().to_dict())

    # autonomy grants (file level, Frame 2; Frame 1 counts alongside)
    rows = []
    for fr in (1, 2):
        cs = files[(files.frame == fr) & (files.type == "claude_settings") & files.fetched.fillna(False)]
        if len(cs):
            dang = cs.cs_dangerous.fillna("[]").map(json.loads)
            sec = cs.cs_secrets.fillna("[]").map(json.loads)
            n = len(cs)
            items = {"bypass_permissions_mode": dang.map(lambda d: "bypass_permissions_mode" in d),
                     "default_mode_acceptEdits": cs.cs_default_mode.eq("acceptEdits"),
                     "allow_bash_any": dang.map(lambda d: "bash_any" in d),
                     "allow_bash_risky_cmd": dang.map(lambda d: "bash_risky_cmd" in d),
                     "allow_webfetch_any": dang.map(lambda d: "webfetch_any" in d),
                     "allow_write_any": dang.map(lambda d: "write_any" in d),
                     "allow_mcp_tool": dang.map(lambda d: "mcp_tool" in d),
                     "enable_all_project_mcp": dang.map(lambda d: "enable_all_project_mcp" in d),
                     "any_dangerous_grant": dang.map(bool),
                     "has_hooks": cs.cs_hooks_n.fillna(0) > 0,
                     "has_deny_rules": cs.cs_deny_n.fillna(0) > 0,
                     "literal_secret_in_env": sec.map(bool)}
            rows += [{"frame": fr, "type": "claude_settings", "item": k, "files": n, "files_with": int(v.sum()),
                      "share": v.mean()} for k, v in items.items()]
        vs = files[(files.frame == fr) & (files.type == "vscode_settings") & files.fetched.fillna(False)]
        if len(vs):
            items = {"chat_tools_auto_approve": vs.vs_auto_approve.fillna(False).astype(bool),
                     "terminal_auto_approve_rules": vs.vs_terminal_auto_approve_rules.fillna(0) > 0,
                     "terminal_auto_approve_any": vs.vs_terminal_auto_approve_any.fillna(False).astype(bool)}
            rows += [{"frame": fr, "type": "vscode_settings", "item": k, "files": len(vs), "files_with": int(v.sum()),
                      "share": v.mean()} for k, v in items.items()]
    a = pd.DataFrame(rows)
    a.to_csv(TABLES / "b6_autonomy.csv", index=False)
    print(a.round(4).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    files = pd.read_parquet(DERIVED / "files.parquet")
    frame1(files, a.boot)
    f2 = frame2(files, a.boot)
    mcp_and_autonomy(files, f2)


if __name__ == "__main__":
    main()
