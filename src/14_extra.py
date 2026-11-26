"""Analyses added for transparency and depth (all outputs are aggregates in tables/; macros in b14_macros.csv).

  design         Frame-1 sampling design per stratum: frame days, inclusion probability, selected days, repositories
  hooks          what committed Claude Code hooks run: event x command class (network, package runner, repo script, ...)
  cooccur        co-occurrence of risk conditions in the same settings file and in the same repository
  concentration  how concentrated risky configuration is in a few copy families; distribution of family sizes
  sensitivity    headline rates under alternative definitions (demo/test files excluded, stricter/looser grants and
                 pinning, cross-owner copying only)
  popularity     differences between star strata (Frame 1) with approximate 95% intervals
  mal_resolution for launches of packages with OSV malicious records: would the launch resolve to a malicious version?
Usage: python src/14_extra.py
"""
from __future__ import annotations

import datetime as dt
import json
import re

import numpy as np
import pandas as pd
from statsmodels.stats.proportion import confint_proportions_2indep, proportion_confint

from common import DERIVED, LISTS, RAW, TABLES, read_jsonl

PAPER_A = TABLES.parents[1] / "slopsquat-study"
M: list[dict] = []          # macros: key, value, fmt (pct | num | pp | tt | raw)
MD = {"agents_md", "claude_md", "gemini_md", "copilot_instr", "cursor_rules_mdc", "cursorrules", "windsurfrules",
      "clinerules"}
MCP = {"mcp_json", "cursor_mcp", "vscode_mcp"}
DEMO = re.compile(r"(?:^|[/_.-])(?:tests?|fixtures?|examples?|demos?|samples?|attacks?|payloads?|poc|ctf|benchmarks?|"
                  r"evals?|red-?team|vulnerable|malicious|injection|scanner|honeypot|security-?(?:test|lab))(?:[/_.-]|$)", re.I)


def m(key: str, value, fmt: str = "raw") -> None:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return
    M.append({"key": key, "value": value, "fmt": fmt})


def loads(x):
    if isinstance(x, str):
        try:
            return json.loads(x)
        except ValueError:
            return []
    return list(x) if x is not None and not (isinstance(x, float) and np.isnan(x)) else []


# ---------------------------------------------------------------------------------------------- design
def design() -> None:
    days = pd.DataFrame(read_jsonl(LISTS / "frame1_days.jsonl"))
    des = days[days.kind == "design"].set_index("stratum")
    sel = days[days.kind == "day"]
    b1 = pd.read_csv(TABLES / "b1_frame1_prevalence.csv")
    frame_days = (dt.date(2026, 11, 23) - dt.date(2008, 1, 1)).days + 1
    rows = []
    for s in ("s1", "s2", "s3"):
        r = b1[(b1.group == s) & (b1.measure == "any_agent_file")].iloc[0]
        g = sel[sel.stratum == s]
        rows.append({"stratum": s, "stars_lo": int(des.loc[s, "lo"]), "stars_hi": int(des.loc[s, "hi"]),
                     "search_total_at_design": int(des.loc[s, "population"]), "p": float(des.loc[s, "p"]),
                     "frame_days": frame_days, "days_selected": len(g), "days_with_repos": int((g.repos > 0).sum()),
                     "repos_sampled": int(r.repos_sampled), "est_population": float(r.est_population)})
        k = {"s1": "SOne", "s2": "STwo", "s3": "SThree"}[s]
        m(f"Des{k}P", f"{des.loc[s, 'p']:.4f}"); m(f"Des{k}Days", len(g), "num")
        m(f"Des{k}Repos", int(r.repos_sampled), "num"); m(f"Des{k}SearchTotal", int(des.loc[s, "population"]), "num")
        m(f"Des{k}EstPop", round(r.est_population, -2), "num")
    m("DesFrameDays", frame_days, "num")
    tot = sum(r["search_total_at_design"] for r in rows)
    est = sum(r["est_population"] for r in rows)
    m("DesSearchTotalAll", tot, "num"); m("DesEstPopAll", round(est, -2), "num")
    m("DesEstOverSearch", abs(est / tot - 1), "pct"); m("DesDaysAll", sum(r["days_selected"] for r in rows), "num")
    pd.DataFrame(rows).to_csv(TABLES / "b14_design.csv", index=False)
    print(pd.DataFrame(rows).to_string(index=False))


# ---------------------------------------------------------------------------------------------- hooks
HOOK_CLASSES = [   # first match wins, ordered from most to least security-relevant
    ("remote_exec", re.compile(r"(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex)\b", re.I)),
    ("network", re.compile(r"\b(curl|wget|iwr|invoke-webrequest|invoke-restmethod|nc|ncat|scp|rsync)\b|https?://", re.I)),
    ("package_runner", re.compile(r"\b(npx|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run)\b", re.I)),
    # a script in the user's home directory is the user's own code, not the repository's
    ("user_script", re.compile(r"(~/|\$HOME\b|\$\{HOME\}|%USERPROFILE%|/Users/[^/\s]+/|/home/[^/\s]+/)", re.I)),
    ("repo_script", re.compile(r"(\$CLAUDE_PROJECT_DIR|\.claude/hooks/|\./|scripts?/)[^\s]*\.(sh|py|js|mjs|ts|ps1|rb)\b"
                               r"|\b(bash|sh|python3?|node|bun|deno|pwsh|powershell)\s+[^\s]+\.(sh|py|js|mjs|ts|ps1)\b", re.I)),
    ("format_lint_test", re.compile(r"\b(prettier|eslint|biome|black|ruff|isort|gofmt|goimports|rustfmt|cargo\s+(fmt|clippy|test)|"
                                    r"mypy|tsc|pytest|jest|vitest|npm\s+(run\s+)?(test|lint|format)|make\s+\w+)\b", re.I)),
    ("notify", re.compile(r"\b(osascript|notify-send|terminal-notifier|afplay|paplay|say|toast|ntfy|BurntToast)\b", re.I)),
    ("git", re.compile(r"\bgit\s+\w+", re.I)),
]


def hook_class(cmd: str) -> str:
    for k, rx in HOOK_CLASSES:
        if rx.search(cmd):
            return k
    return "other"


def hooks(files: pd.DataFrame) -> None:
    cs = files[(files.frame == 2) & (files.type == "claude_settings") & files.fetched.fillna(False)]
    cs = cs[cs.cs_hooks_n.fillna(0) > 0].drop_duplicates("sha")
    n_files = int(((files.frame == 2) & (files.type == "claude_settings") & files.fetched.fillna(False)).sum())
    per_file, rows = [], []
    for sha in cs.sha:
        try:
            obj = json.loads((RAW / sha[:2] / sha).read_bytes().decode("utf-8", "replace"))
        except ValueError:
            continue
        hk = obj.get("hooks") if isinstance(obj, dict) else None
        if not isinstance(hk, dict):
            continue
        classes = set()
        for ev, lst in hk.items():
            for grp in lst if isinstance(lst, list) else []:
                for h in (grp.get("hooks") or []) if isinstance(grp, dict) else []:
                    cmd = h.get("command") if isinstance(h, dict) else None
                    if isinstance(cmd, str):
                        c = hook_class(cmd)
                        rows.append({"event": ev, "class": c})
                        classes.add((ev, c))
        per_file.append({"sha": sha, "classes": classes})
    # file-level shares over all settings files with hooks (blob level: identical files counted once)
    hf = pd.DataFrame(per_file)
    out = []
    for c in [k for k, _ in HOOK_CLASSES] + ["other"]:
        any_ev = hf.classes.map(lambda s: any(x[1] == c for x in s))
        ss = hf.classes.map(lambda s: ("SessionStart", c) in s)
        out.append({"class": c, "files_with_hooks": len(hf), "share_any_event": float(any_ev.mean()),
                    "share_session_start": float(ss.mean())})
        m(f"Hook{camel(c)}Share", float(any_ev.mean()), "pct"); m(f"Hook{camel(c)}SessionShare", float(ss.mean()), "pct")
    ev = pd.DataFrame(rows)
    tot = ev.event.value_counts()
    ev["event"] = ev.event.where(ev.event.map(tot) >= 5, "(event names used by fewer than 5 commands)")  # free text
    ev = ev.groupby(["event", "class"]).size().rename("commands").reset_index()
    ev.to_csv(TABLES / "b14_hook_events.csv", index=False)
    pd.DataFrame(out).to_csv(TABLES / "b14_hooks.csv", index=False)
    m("HookFiles", len(hf), "num"); m("HookCommands", len(rows), "num")
    net_ss = hf.classes.map(lambda s: any(x[0] == "SessionStart" and x[1] in ("remote_exec", "network", "package_runner")
                                          for x in s))
    m("HookSessionNetOrRunnerN", int(net_ss.sum()), "num"); m("HookSessionNetOrRunnerShare", float(net_ss.mean()), "pct")
    m("HookSettingsFiles", n_files, "num")
    print(pd.DataFrame(out).round(3).to_string(index=False))


def camel(s: str) -> str:
    return "".join(w[:1].upper() + w[1:] for w in re.split(r"[^A-Za-z0-9]+", s) if w)


# ---------------------------------------------------------------------------------------------- co-occurrence
def cooccur(files: pd.DataFrame, srv: pd.DataFrame) -> None:
    f = files[(files.frame == 2) & files.fetched.fillna(False)].copy()
    rule_cols = [c for c in f.columns if c.startswith("rule_") and not c.endswith("_negated")]
    f["any_rule"] = f[rule_cols].fillna(0).sum(axis=1) > 0
    dang = f.cs_dangerous.map(loads)
    f["grant"] = dang.map(lambda d: any(x != "mcp_tool" for x in d))
    f["critical"] = dang.map(lambda d: bool({"bypass_permissions_mode", "bash_any"} & set(d)))
    f["enable_all"] = dang.map(lambda d: "enable_all_project_mcp" in d)
    f["hooks"] = f.cs_hooks_n.fillna(0) > 0
    unp = set(srv[srv.eco.notna() & ~srv.pin.isin(["exact", "digest"])].sha)
    f["unpinned"] = f.sha.isin(unp) & f.type.isin(MCP)
    rows = []

    def cond(name, base_mask, a_mask, b_mask, unit):
        """P(B | A) vs P(B | not A) within the base population, with a Newcombe interval for the difference."""
        A, B = a_mask[base_mask], b_mask[base_mask]
        ka, na, kb, nb = int((A & B).sum()), int(A.sum()), int((~A & B).sum()), int((~A).sum())
        if not na or not nb:
            return
        lo, hi = confint_proportions_2indep(ka, na, kb, nb, method="newcomb")
        rows.append({"comparison": name, "unit": unit, "n_A": na, "p_B_given_A": ka / na, "n_notA": nb,
                     "p_B_given_notA": kb / nb, "diff": ka / na - kb / nb, "diff_lo": lo, "diff_hi": hi,
                     "ratio": (ka / na) / (kb / nb) if kb else np.nan})
        k = camel(name)
        m(f"Co{k}GivenA", ka / na, "pct"); m(f"Co{k}GivenNotA", kb / nb, "pct"); m(f"Co{k}NA", na, "num")
        m(f"Co{k}Ratio", f"{(ka / na) / (kb / nb):.1f}" if kb else None)
        m(f"Co{k}Diff", ka / na - kb / nb, "pp"); m(f"Co{k}DiffLo", float(lo), "pp"); m(f"Co{k}DiffHi", float(hi), "pp")

    # file level, inside one settings file
    cs = f[f.type == "claude_settings"]
    cond("critical_then_hooks", pd.Series(True, index=cs.index), cs.critical, cs.hooks, "settings file")
    # repository level (census types: settings and MCP configurations are enumerated completely)
    by = f.groupby("repo").agg(grant=("grant", "any"), critical=("critical", "any"), enable_all=("enable_all", "any"),
                               unpinned=("unpinned", "any"),
                               has_settings=("type", lambda t: (t == "claude_settings").any()),
                               has_mcp=("type", lambda t: t.isin(MCP).any()),
                               has_claude_md=("type", lambda t: (t == "claude_md").any()))
    rule_cm = f[f.type == "claude_md"].groupby("repo").any_rule.any()
    by["rule_claude_md"] = rule_cm.reindex(by.index).fillna(False).astype(bool)
    both = by.has_settings & by.has_mcp
    cond("enable_all_then_unpinned", both, by.enable_all, by.unpinned, "repository with settings and MCP config")
    cond("grant_then_unpinned", both, by.grant, by.unpinned, "repository with settings and MCP config")
    sc = by.has_settings & by.has_claude_md          # CLAUDE.md is sampled with probability p, independently of grants
    cond("grant_then_rule", sc, by.grant, by.rule_claude_md, "repository with settings and sampled CLAUDE.md")
    # the concrete chain: every project MCP server auto-starts AND one of them floats to the registry's latest
    chain = int((by.enable_all & by.unpinned).sum())
    m("CoAutoStartFloatingRepos", chain, "num")
    m("CoAutoStartFloatingShareOfEnableAll", chain / max(int((by.enable_all & both).sum()), 1), "pct")
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b14_cooccur.csv", index=False)
    print(out.round(4).to_string(index=False))


# ---------------------------------------------------------------------------------------------- concentration
def concentration(files: pd.DataFrame, srv: pd.DataFrame) -> None:
    f = files[(files.frame == 2) & files.fetched.fillna(False) & (files.chars.fillna(0) >= 200)
              & (files.json_status.fillna("") != "symlink")].copy()
    f["owner"] = f.repo.str.split("/").str[0].str.lower()
    fam = f.groupby("sha").agg(repos=("repo", "nunique"), owners=("owner", "nunique"))
    fam = fam[fam.repos >= 2].sort_values("repos", ascending=False)
    bins = [(2, 2), (3, 5), (6, 20), (21, 100), (101, 10 ** 9)]
    sizes = [{"family_repos": (str(lo) if lo == hi else f"{lo}-{hi}") if hi < 10 ** 9 else f">{lo - 1}", "families": int(((fam.repos >= lo) & (fam.repos <= hi)).sum()),
              "files": int(fam[(fam.repos >= lo) & (fam.repos <= hi)].repos.sum())} for lo, hi in bins]
    pd.DataFrame(sizes).to_csv(TABLES / "b14_family_sizes.csv", index=False)
    for key, s in zip(("FamTwo", "FamThreeFive", "FamSixTwenty", "FamTwentyOneHundred", "FamOverHundred"), sizes):
        m(f"{key}Families", s["families"], "num"); m(f"{key}Files", s["files"], "num")
    m("ConFamilies", len(fam), "num"); m("ConFamiliesTwo", int((fam.repos == 2).sum()), "num")
    m("ConFamiliesOverHundred", int((fam.repos > 100).sum()), "num")
    m("ConCrossOwnerFamilies", int((fam.owners >= 2).sum()), "num")
    m("ConCrossOwnerShare", float((fam.owners >= 2).mean()), "pct")
    rule_cols = [c for c in f.columns if c.startswith("rule_") and not c.endswith("_negated")]
    dang = f.cs_dangerous.map(loads)
    unp = set(srv[srv.eco.notna() & ~srv.pin.isin(["exact", "digest"])].sha)
    sig = {"dangerous_grant": dang.map(lambda d: any(x != "mcp_tool" for x in d)),
           "unpinned_mcp": f.sha.isin(unp) & f.type.isin(MCP),
           "any_rule": f[rule_cols].fillna(0).sum(axis=1) > 0}
    rows = []
    for name, v in sig.items():
        risky = f[v.values]
        n_risky = len(risky)
        in_fam = risky.sha.isin(fam.index)
        r = {"signal": name, "risky_files": n_risky, "share_in_families": float(in_fam.mean()) if n_risky else np.nan}
        risky_fams = fam[fam.index.isin(set(risky.sha))]
        for q in (0.01, 0.05, 0.10):
            k = max(1, int(np.ceil(q * len(risky_fams))))
            top = set(risky_fams.head(k).index)
            r[f"top{int(q * 100)}pct_families_share_of_risky_files"] = float(risky.sha.isin(top).mean()) if n_risky else np.nan
        r["risky_families"] = len(risky_fams)
        r["top10_families_share"] = float(risky.sha.isin(set(risky_fams.head(10).index)).mean()) if n_risky else np.nan
        rows.append(r)
        k = camel(name)
        m(f"Con{k}InFamilies", r["share_in_families"], "pct"); m(f"Con{k}TopOnePct", r["top1pct_families_share_of_risky_files"], "pct")
        m(f"Con{k}TopFivePct", r["top5pct_families_share_of_risky_files"], "pct")
        m(f"Con{k}TopTenPct", r["top10pct_families_share_of_risky_files"], "pct")
        m(f"Con{k}TopTenFamilies", r["top10_families_share"], "pct"); m(f"Con{k}Families", len(risky_fams), "num")
        # cross-owner copies only (excludes an account copying its own configuration)
        cross = set(fam[fam.owners >= 2].index)
        m(f"Con{k}CrossOwner", float(risky.sha.isin(cross).mean()) if n_risky else None, "pct")
    pd.DataFrame(rows).to_csv(TABLES / "b14_concentration.csv", index=False)
    print(pd.DataFrame(rows).round(3).to_string(index=False))


# ---------------------------------------------------------------------------------------------- sensitivity
def sensitivity(files: pd.DataFrame, srv: pd.DataFrame) -> None:
    f = files[(files.frame == 2) & files.fetched.fillna(False)].copy()
    demo = f.repo.str.contains(DEMO) | f.path.str.contains(DEMO)
    rule_cols = [c for c in f.columns if c.startswith("rule_") and not c.endswith("_negated")]
    md = f.type.isin(MD)
    rows = []

    def add(name, val, base, fmt="pct"):
        rows.append({"analysis": name, "value": val, "base_files": int(base)})
        m(f"Sens{camel(name)}", val, fmt)

    any_rule = f[rule_cols].fillna(0).sum(axis=1) > 0
    uni = f.n_suspicious_unicode.fillna(0) > 0
    com = f.n_instruction_comments.fillna(0) > 0
    for nm, v in (("rule", any_rule), ("unicode", uni), ("comment", com)):
        add(f"{nm}_all", float(v[md].mean()), md.sum())
        add(f"{nm}_no_demo", float(v[md & ~demo].mean()), (md & ~demo).sum())
    add("demo_share_md", float(demo[md].mean()), md.sum())
    cs = f.type == "claude_settings"
    dang = f.cs_dangerous.map(loads)
    add("grant_critical_only", float(dang[cs].map(lambda d: bool({"bypass_permissions_mode", "bash_any"} & set(d))).mean()), cs.sum())
    add("grant_main", float(dang[cs].map(lambda d: any(x != "mcp_tool" for x in d)).mean()), cs.sum())
    add("grant_incl_mcp_tool", float(dang[cs].map(bool).mean()), cs.sum())
    add("grant_main_no_demo", float(dang[cs & ~demo].map(lambda d: any(x != "mcp_tool" for x in d)).mean()), (cs & ~demo).sum())
    # pinning: strict (main: not exact/digest) vs lenient (only launches with no version at all)
    # same units as the main MCP results (06_stats.py): server entries of every file that defines servers (each
    # file counted, not each distinct content), and files with at least one package launch
    cfg = f[(f.kind != "md")][["kind", "sha", "repo", "path"]]
    s2 = srv.drop_duplicates().rename(columns={"kind": "launch"}).rename(columns={"blob_kind": "kind"})
    pk = cfg.merge(s2, on=["sha", "kind"], how="inner")
    pk = pk[pk.eco.notna()]
    pk["strict"] = ~pk.pin.isin(["exact", "digest"])
    pk["lenient"] = pk.pin == "unpinned"
    per_file = pk.groupby(["repo", "path"])[["strict", "lenient"]].any()
    add("unpinned_files_strict", float(per_file.strict.mean()), len(per_file))
    add("unpinned_files_lenient", float(per_file.lenient.mean()), len(per_file))
    add("unpinned_entries_strict", float(pk.strict.mean()), len(pk))
    add("unpinned_entries_lenient", float(pk.lenient.mean()), len(pk))
    pd.DataFrame(rows).to_csv(TABLES / "b14_sensitivity.csv", index=False)
    print(pd.DataFrame(rows).round(4).to_string(index=False))


# ---------------------------------------------------------------------------------------------- popularity
def popularity() -> None:
    b1 = pd.read_csv(TABLES / "b1_frame1_prevalence.csv")
    b2 = pd.read_csv(TABLES / "b2_frame1_risk.csv")
    rows = []
    for tab, measures, base in ((b1, ["any_agent_file", "agents_or_claude_md", "mcp_json", "claude_settings"], None),
                                (b2, ["any_rule", "instruction_comment", "any_signal"], "with_agent_files")):
        for meas in measures:
            g = tab[tab.measure == meas]
            if base is not None and "base" in g:
                g = g[g.base != "all_repos"]
            if not {"s1", "s3"} <= set(g.group):
                continue
            a, c = g[g.group == "s1"].iloc[0], g[g.group == "s3"].iloc[0]
            se = lambda r: (r.share_hi - r.share_lo) / 3.92                 # from the cluster-bootstrap interval
            d = c.share - a.share
            s = np.sqrt(se(a) ** 2 + se(c) ** 2)                            # strata are sampled independently
            rows.append({"measure": meas, "s1": a.share, "s3": c.share, "diff": d, "lo": d - 1.96 * s, "hi": d + 1.96 * s})
            k = camel(meas)
            m(f"Pop{k}Diff", d, "pp"); m(f"Pop{k}DiffLo", d - 1.96 * s, "pp"); m(f"Pop{k}DiffHi", d + 1.96 * s, "pp")
    pd.DataFrame(rows).to_csv(TABLES / "b14_popularity.csv", index=False)
    print(pd.DataFrame(rows).round(4).to_string(index=False))


# ---------------------------------------------------------------------------------------------- MAL resolution
def mal_resolution(srv: pd.DataFrame) -> None:
    """For each launch of a package that has an OSV MAL record: unpinned (resolves at run time: exposed whenever a
    malicious version is the one served), pinned to a version listed as affected, or pinned to an unaffected one."""
    risk = pd.read_parquet(DERIVED / "mcp_package_risk.parquet")
    mal = pd.read_parquet(PAPER_A / "data" / "registry" / "osv_mal.parquet")
    mal = mal[mal.withdrawn.isna()]
    mal["eco"] = mal.ecosystem.map({"PyPI": "pypi", "npm": "npm"})
    norm = lambda e, n: re.sub(r"[-_.]+", "-", n.lower()) if e == "pypi" else n.lower()
    # the OSV snapshot records whether a MAL entry covers all versions (all_versions); version lists are not kept,
    # so a pinned launch of a package whose record covers only some versions cannot be checked
    allv: dict = {}
    for e, n, a in zip(mal.eco, mal.name, mal.all_versions):
        if e is not None:
            allv[(e, norm(e, n))] = allv.get((e, norm(e, n)), False) or bool(a)
    malk = {(e, norm(e, n)) for e, n in zip(risk.eco[risk.mal_record], risk.name[risk.mal_record])}
    pk = srv[srv.eco.isin(["npm", "pypi"]) & srv.package.notna()].copy()
    pk["k"] = [(e, norm(e, re.sub(r"\[.*\]$", "", p))) for e, p in zip(pk.eco, pk.package)]
    pk = pk[pk.k.isin(malk)]

    def cls(r):
        if r.pin not in ("exact", "digest"):
            return "unpinned"
        return "pinned_all_versions_malicious" if allv.get(r.k) else "pinned_version_not_checkable"
    pk["res"] = pk.apply(cls, axis=1)
    out = pk.groupby("res").agg(entries=("sha", "size"), files=("sha", "nunique")).reset_index()
    out.to_csv(TABLES / "b14_mal_resolution.csv", index=False)
    for _, r in out.iterrows():
        m(f"MalRes{camel(r.res)}Entries", int(r.entries), "num"); m(f"MalRes{camel(r.res)}Files", int(r.files), "num")
    m("MalResEntries", len(pk), "num")
    print(out.to_string(index=False))


def coverage_adjusted(files: pd.DataFrame, srv: pd.DataFrame) -> None:
    """Code search under-indexes small files. Estimate index coverage by size class from Frame 1 (census types: every
    Frame-1 file is eligible) and reweight Frame-2 files by 1 / coverage(size class) of their type."""
    unp = set(srv[srv.eco.notna() & ~srv.pin.isin(["exact", "digest"])].sha)
    rows = []
    for t, label, sig in (("claude_settings", "grant",
                           lambda g: g.cs_dangerous.map(loads).map(lambda d: any(x != "mcp_tool" for x in d))),
                          ("mcp_json", "unpinned", lambda g: g.sha.isin(unp))):
        cs = {(d["repo"].lower(), d["path"]) for d in read_jsonl(LISTS / "code_search" / f"{t}.jsonl")}
        f1 = files[(files.frame == 1) & (files.type == t) & files.fetched.fillna(False)].copy()
        f1["found"] = [(r.lower(), p) in cs for r, p in zip(f1.repo, f1.path)]
        edges = np.unique(np.quantile(f1.chars.fillna(0), [0, .25, .5, .75, 1]))
        edges[0], edges[-1] = -1, np.inf
        f1["cls"] = pd.cut(f1.chars.fillna(0), edges, labels=False)
        cov = f1.groupby("cls").found.mean()
        f2 = files[(files.frame == 2) & (files.type == t) & files.fetched.fillna(False)].copy()
        f2["cls"] = pd.cut(f2.chars.fillna(0), edges, labels=False)
        w = 1 / f2.cls.map(cov).clip(lower=0.05)
        y = sig(f2).astype(float)
        raw, adj = float(y.mean()), float((w * y).sum() / w.sum())
        y1 = sig(f1).astype(float)
        w1 = f1.weight.fillna(1.0)
        fr1 = float((w1 * y1).sum() / w1.sum())
        rows.append({"type": t, "signal": label, "frame2_raw": raw, "frame2_coverage_adjusted": adj, "frame1": fr1,
                     "coverage_by_size_class": "; ".join(f"{c:.2f}" for c in cov)})
        k = camel(label)
        m(f"CovAdj{k}Raw", raw, "pct"); m(f"CovAdj{k}Adj", adj, "pct"); m(f"CovAdj{k}FrameOne", fr1, "pct")
        m(f"CovAdj{k}SmallCov", float(cov.iloc[0]), "pct"); m(f"CovAdj{k}LargeCov", float(cov.iloc[-1]), "pct")
        m(f"CovAdj{k}MissedMedianChars", float(f1[~f1.found].chars.median()), "num")
        m(f"CovAdj{k}FoundMedianChars", float(f1[f1.found].chars.median()), "num")
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b14_coverage_adjusted.csv", index=False)
    print(out.round(4).to_string(index=False))
    # mechanisms for instruction files: are missed files copies of files in other repositories? does the comment gap
    # persist within .cursor/rules/*.mdc, the type with the lowest coverage?
    md_types = sorted(MD)
    nrep = files.groupby("sha").repo.nunique()
    cs = set()
    bins = {}
    for t in md_types:
        cs |= {(t, d["repo"].lower(), d["path"]) for d in read_jsonl(LISTS / "code_search" / f"{t}.jsonl")}
        bins[t] = [tuple(map(int, d["shard"].split(".."))) for d in read_jsonl(LISTS / "code_search" / f"{t}_shards.jsonl")
                   if d.get("status") in ("done", "split", "error") and ".." in str(d.get("shard"))]
    sizes = pd.DataFrame(read_jsonl(LISTS / "frame1_files.jsonl"))[["type", "repo", "path", "size"]]
    f1 = files[(files.frame == 1) & files.type.isin(MD) & files.fetched.fillna(False)].merge(
        sizes, on=["type", "repo", "path"], how="left")
    f1 = f1[[any(a <= s <= b for a, b in bins.get(t, [])) for t, s in zip(f1.type, f1["size"])]]
    f1["found"] = [(t, r.lower(), p) in cs for t, r, p in zip(f1.type, f1.repo, f1.path)]
    f1["dup"] = f1.sha.map(nrep).fillna(1) >= 2
    m("CovMechDupFound", float(f1[f1.found].dup.mean()), "pct"); m("CovMechDupMissed", float(f1[~f1.found].dup.mean()), "pct")
    mdc = f1[f1.type == "cursor_rules_mdc"]
    com = mdc.n_instruction_comments.fillna(0) > 0
    m("CovMechMdcFoundK", int(com[mdc.found].sum()), "num"); m("CovMechMdcFoundN", int(mdc.found.sum()), "num")
    m("CovMechMdcMissedK", int(com[~mdc.found].sum()), "num"); m("CovMechMdcMissedN", int((~mdc.found).sum()), "num")


def repo_cluster(files: pd.DataFrame, srv: pd.DataFrame, B: int = 500) -> None:
    """Files of one repository are not independent. For the main Frame-2 rates, compare a naive interval (files
    independent) with a Poisson bootstrap over repositories (files weighted by 1/p); report the design effect."""
    rng = np.random.default_rng(7)
    f = files[(files.frame == 2) & files.fetched.fillna(False)].copy()
    rule_cols = [c for c in f.columns if c.startswith("rule_") and not c.endswith("_negated")]
    md = f.type.isin(MD)
    dang = f.cs_dangerous.map(loads).map(lambda d: any(x != "mcp_tool" for x in d))
    cfg = f[f.kind != "md"][["kind", "sha", "repo", "path"]]
    pk = cfg.merge(srv.drop_duplicates().rename(columns={"kind": "launch"}).rename(columns={"blob_kind": "kind"}),
                   on=["sha", "kind"], how="inner")
    pk = pk[pk.eco.notna()]
    unp_files = pk.assign(u=~pk.pin.isin(["exact", "digest"])).groupby(["repo", "path"]).u.any()
    measures = {
        "rule_md": (f[md], (f[rule_cols].fillna(0).sum(axis=1) > 0)[md]),
        "comment_md": (f[md], (f.n_instruction_comments.fillna(0) > 0)[md]),
        "grant_settings": (f[f.type == "claude_settings"], dang[f.type == "claude_settings"]),
    }
    uf = unp_files.reset_index()
    measures["unpinned_mcp_files"] = (uf.assign(weight=1.0), uf.u)
    rows = []
    for name, (g, y) in measures.items():
        w = g.weight.fillna(1.0).to_numpy() if "weight" in g else np.ones(len(g))
        y = y.astype(float).to_numpy()
        est = float((w * y).sum() / w.sum())
        n = len(y)
        n_eff = w.sum() ** 2 / (w ** 2).sum()
        se_naive = np.sqrt(est * (1 - est) / n_eff)
        agg = pd.DataFrame({"r": g.repo.to_numpy(), "wy": w * y, "w": w}).groupby("r").sum()
        num, den = agg.wy.to_numpy(), agg.w.to_numpy()
        reps = []
        for _ in range(B // 50):
            k = rng.poisson(1.0, size=(50, len(num)))
            reps += list((k @ num) / (k @ den))
        se_boot = float(np.std(reps, ddof=1))
        deff = (se_boot / se_naive) ** 2 if se_naive > 0 else np.nan
        lo, hi = np.percentile(reps, [2.5, 97.5])
        rows.append({"measure": name, "files": n, "repos": len(num), "rate": est, "naive_lo": est - 1.96 * se_naive,
                     "naive_hi": est + 1.96 * se_naive, "repo_boot_lo": lo, "repo_boot_hi": hi, "design_effect": deff})
        k_ = camel(name)
        m(f"Clu{k_}Rate", est, "pct"); m(f"Clu{k_}Lo", float(lo), "pct"); m(f"Clu{k_}Hi", float(hi), "pct")
        m(f"Clu{k_}Deff", f"{deff:.1f}")
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b14_repo_cluster.csv", index=False)
    m("CluDeffMax", f"{out.design_effect.max():.1f}")
    print(out.round(4).to_string(index=False))


def main() -> None:
    files = pd.read_parquet(DERIVED / "files.parquet")
    srv = pd.read_parquet(DERIVED / "mcp_servers.parquet")
    repo_cluster(files, srv)
    coverage_adjusted(files, srv)
    for fn in (design, popularity):
        fn()
    hooks(files)
    cooccur(files, srv)
    concentration(files, srv)
    sensitivity(files, srv)
    mal_resolution(srv)
    pd.DataFrame(M).to_csv(TABLES / "b14_macros.csv", index=False)
    print(f"{len(M)} macros")


if __name__ == "__main__":
    main()
