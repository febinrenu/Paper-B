"""Every number in the manuscript, as LaTeX macros generated from tables/ (paper/numbers.tex).

The manuscript prints values only through \\R{Name}; a value missing here renders as a red ?? so nothing is typed by hand.
Usage: python src/10_numbers.py
"""
from __future__ import annotations

import math
import re
from pathlib import Path

import pandas as pd

from common import TABLES

PAPER = Path(__file__).resolve().parents[1] / "paper"
M: dict[str, str] = {}


def camel(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", " ", str(s))
    words = {"md": "Md", "mcp": "Mcp", "mdc": "Mdc", "instr": "Instr"}
    out = "".join(words.get(w.lower(), w[:1].upper() + w[1:]) for w in s.split())
    digits = {"0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four", "5": "Five", "6": "Six", "7": "Seven",
              "8": "Eight", "9": "Nine"}
    return "".join(digits.get(c, c) for c in out)


def num(x, d=0) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return None
    return f"{x:,.{d}f}".replace(",", "{,}")


def pct(x) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return None
    p = 100 * x
    d = 1 if p >= 1 or p == 0 else (2 if p >= 0.1 else 3)
    return f"{p:.{d}f}\\%"


def approx(x) -> str:
    """Population estimates: three significant figures."""
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return None
    if x == 0:
        return "0"
    mag = 10 ** max(0, int(math.floor(math.log10(abs(x)))) - 2)
    return num(round(x / mag) * mag)


def tex(s: str) -> str:
    return "\\texttt{" + str(s).replace("\\", "/").replace("_", "\\_").replace("&", "\\&").replace("#", "\\#") \
        .replace("%", "\\%").replace("~", "\\textasciitilde{}") + "}"


def put(name: str, val) -> None:
    if val is not None:
        M[name] = val


def read(name: str) -> pd.DataFrame | None:
    p = TABLES / name
    return pd.read_csv(p) if p.exists() else None


def frame1() -> None:
    b1 = read("b1_frame1_prevalence.csv")
    if b1 is not None:
        for _, r in b1.iterrows():
            g = "" if r.group == "all" else camel(r.group)
            k = f"FOne{g}{camel(r.measure)}"
            put(k + "Share", pct(r.share)); put(k + "Lo", pct(r.share_lo)); put(k + "Hi", pct(r.share_hi))
            put(k + "N", num(r.repos_with)); put(k + "Est", approx(r.est_repos))
            if r.measure == "any_agent_file":
                put(f"FOne{g}Sampled", num(r.repos_sampled)); put(f"FOne{g}Pop", approx(r.est_population))
                put(f"FOne{g}RuleOfThree", pct(3 / r.repos_with))    # 95% upper bound when 0 of n repos show a signal
                put(f"FOne{g}AnyAgentFileOneIn", num(round(1 / r.share)) if r.share else None)
    b2 = read("b2_frame1_risk.csv")
    if b2 is not None:
        for _, r in b2.iterrows():
            g = "" if r.group == "all" else camel(r.group)
            base = "Pop" if r.base == "all_repos" else ""
            k = f"FOneRisk{base}{g}{camel(r.measure)}"
            put(k + "Share", pct(r.share)); put(k + "Lo", pct(r.share_lo)); put(k + "Hi", pct(r.share_hi))
            put(k + "N", num(r.repos_with)); put(k + "Est", approx(r.est_repos))


def frame2() -> None:
    b3 = read("b3_frame2_detectors.csv")
    if b3 is None:
        return
    for t, g in b3.groupby("type"):
        r0 = g.iloc[0]
        k = f"FTwo{camel(t)}"
        put(k + "Files", num(r0.files)); put(k + "Fetched", pct(r0.fetched_share)); put(k + "P", f"{r0.p_incl:.3f}")
        put(k + "Pop", approx(r0.est_files_population)); put(k + "Census", "census" if r0.census else "sample")
        for _, r in g.iterrows():
            s = k + camel(r.signal)
            put(s + "Rate", pct(r.rate)); put(s + "Lo", pct(r.rate_lo)); put(s + "Hi", pct(r.rate_hi))
            put(s + "N", num(r.files_with)); put(s + "Est", approx(r.est_files_with))
    one = b3.drop_duplicates("type")
    put("FTwoTypes", num(len(one))); put("FTwoCensusTypes", num(int(one.census.sum())))
    put("FTwoFiles", num(one.files.sum())); put("FTwoPop", approx(one.est_files_population.sum()))
    md = b3[~b3.type.isin(["mcp_json", "cursor_mcp", "vscode_mcp", "claude_settings"])]
    for sig, g in md.groupby("signal"):
        put(f"FTwoMd{camel(sig)}N", num(g.files_with.sum()))
        put(f"FTwoMd{camel(sig)}Rate", pct(g.est_files_with.sum() / g.est_files_population.sum()))
        put(f"FTwoMd{camel(sig)}Est", approx(g.est_files_with.sum()))
    put("FTwoMdFiles", num(md.drop_duplicates("type").files.sum()))
    put("FTwoMdPop", approx(md.drop_duplicates("type").est_files_population.sum()))


def mcp() -> None:
    b5 = read("b5_mcp_remote_secrets.csv")
    if b5 is not None:
        for _, r in b5.iterrows():
            k = "Mcp" + ("" if r.type == "all" else camel(r.type))
            put(k + "Entries", num(r.server_entries)); put(k + "ConfigFiles", num(r.config_files))
            put(k + "SecretFiles", num(r.files_with_literal_secret)); put(k + "SecretShare", pct(r.share_files_with_literal_secret))
            put(k + "SecretEntries", num(r.entries_with_literal_secret))
            put(k + "RemoteEntries", num(r.remote_entries)); put(k + "RemoteHttp", num(r.remote_http_nonlocal))
            put(k + "RemoteHttpShare", pct(r.remote_http_nonlocal / r.remote_entries if r.remote_entries else float("nan")))
            put(k + "PkgEntries", num(r.package_entries)); put(k + "Unpinned", num(r.package_unpinned))
            put(k + "UnpinnedShare", pct(r.share_package_unpinned))
            put(k + "UnpinnedNpm", pct(r.share_unpinned_npm)); put(k + "UnpinnedPypi", pct(r.share_unpinned_pypi))
            put(k + "UnpinnedDocker", pct(r.share_unpinned_docker)); put(k + "AlwaysAllow", num(r.entries_always_allow))
            if "files_with_unpinned" in r:
                put(k + "FilesUnpinned", num(r.files_with_unpinned))
                put(k + "FilesUnpinnedShare", pct(r.share_files_with_unpinned))
                put(k + "PkgFiles", num(r.get("files_with_package_launch")))
                put(k + "PkgFilesUnpinnedShare", pct(r.get("share_pkgfiles_with_unpinned")))
    b4 = read("b4_mcp_launch.csv")
    if b4 is not None:
        b4 = b4[b4.type == "all"] if (b4.type == "all").any() else b4     # per-type rows would double-count
        tot = b4.entries.sum()
        for launch, g in b4.groupby("launch"):
            put(f"McpLaunch{camel(launch)}Share", pct(g.entries.sum() / tot)); put(f"McpLaunch{camel(launch)}N", num(g.entries.sum()))
        pk = b4[b4.launch.isin(["npx", "uvx", "docker"])]
        for pin, g in pk.groupby("pin"):
            put(f"McpPin{camel(pin)}Share", pct(g.entries.sum() / pk.entries.sum()))
        put("McpLaunchTotal", num(tot))
    b7 = read("b7_top_mcp_packages.csv")
    if b7 is not None:
        b7 = b7.sort_values("repos", ascending=False).reset_index(drop=True)
        for i, r in b7.head(10).iterrows():
            k = f"TopPkg{camel(str(i + 1))}"
            put(k + "Name", tex(r.package)); put(k + "Repos", num(r.repos)); put(k + "Files", num(r.files))
            put(k + "Unpinned", pct(r.unpinned_share))
    b8 = read("b8_mcp_package_risk.csv")
    if b8 is not None:
        for _, r in b8.iterrows():
            k = f"Link{'' if r.eco == 'all' else camel(r.eco)}"
            put(k + "Packages", num(r.packages_total)); put(k + "PkgFiles", num(r.files_total))
            c = k + camel(r.category)
            put(c + "N", num(r.packages)); put(c + "Share", pct(r.share_packages)); put(c + "Files", num(r.files))
            put(c + "Repos", num(r.repos_upper_bound)); put(c + "Unpinned", pct(r.unpinned_share_of_files))


def autonomy() -> None:
    b6 = read("b6_autonomy.csv")
    if b6 is None:
        return
    for _, r in b6.iterrows():
        k = f"Auto{'FOne' if r.frame == 1 else 'FTwo'}{camel(r.type)}{camel(r['item'])}"
        put(k + "Share", pct(r.share)); put(k + "N", num(r.files_with))
        put(f"Auto{'FOne' if r.frame == 1 else 'FTwo'}{camel(r.type)}Files", num(r.files))


def inheritance() -> None:
    b9 = read("b9_inheritance.csv")
    if b9 is None:
        return
    for _, r in b9[b9.frame == 2].iterrows():
        k = f"Inh{'' if r.type == 'all_types' else camel(r.type)}{camel(r.subset)}"
        put(k + "Share", pct(r.share_shared)); put(k + "N", num(r.shared)); put(k + "Files", num(r.files))
        put(k + "Largest", num(r.largest_family_repos))
    sz = read("b9_inheritance_sizes.csv")
    if sz is not None:
        a = sz[(sz.frame == 2) & (sz.type == "all_types")]
        for _, r in a.iterrows():
            put(f"InhFamily{camel(str(r.family_repos))}Blobs", num(r.blobs)); put(f"InhFamily{camel(str(r.family_repos))}Files", num(r.files))


def copilot_template() -> None:
    """Instruction-like HTML comments in copilot-instructions.md that come from VS Code's workspace scaffolding."""
    import json
    files_p = TABLES.parent / "data" / "derived" / "files.parquet"
    det_p = TABLES.parent / "data" / "derived" / "details.jsonl"
    if not (files_p.exists() and det_p.exists()):
        return
    f = pd.read_parquet(files_p, columns=["frame", "type", "sha", "n_instruction_comments"])
    f = f[(f.frame == 2) & (f.type == "copilot_instr")]
    hit = f[f.n_instruction_comments > 0]
    shas, tmpl = set(hit.sha), {}
    pats = ("Use this file to provide workspace-specific custom instructions to Copilot",
            "copilot-instructions.md file in the .github directory")
    with open(det_p, encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            if d["sha"] in shas:
                tmpl[d["sha"]] = any(p in c.get("snippet", "") for c in d.get("comments", []) for p in pats)
    t = int(hit.sha.map(tmpl).fillna(False).sum())
    put("CopilotTmplN", num(t)); put("CopilotTmplShare", pct(t / len(hit)) if len(hit) else None)
    put("CopilotNonTmplRate", pct((len(hit) - t) / len(f)) if len(f) else None)


def validation() -> None:
    for fn, pre in (("b10_validation.csv", "Val"), ("b10_validation_holdout.csv", "Hold")):
        b10 = read(fn)
        if b10 is None:
            continue
        for _, r in b10.iterrows():
            k = f"{pre}{camel(r.detector)}"
            put(k + "N", num(r.n)); put(k + "Agree", pct(r.get("agree_share")))
            if str(r.detector).startswith("agreement"):
                put(k + "Kappa", f"{r.kappa:.2f}"); put(k + "KappaError", f"{r.kappa_error:.2f}")
                put(k + "KappaUnsafe", f"{r.kappa_unsafe:.2f}")
                continue
            for c in ("precision_l1", "precision_l2", "precision_both", "precision_either", "unsafe_both_share",
                      "precision_fixed_both", "precision_fixed_either"):
                put(k + camel(c), pct(r.get(c)))
            for c in ("malicious_l1", "malicious_l2", "malicious_both", "n_still_flagged"):
                put(k + camel(c), num(r.get(c)))


def frame_checks() -> None:
    fc = read("b12_frame_checks.csv")
    if fc is not None:
        for _, r in fc.iterrows():
            put("Chk" + camel(r.check), num(r.value))
    en = read("b12_enumeration.csv")
    if en is not None:
        put("ChkListedOverReportedMin", f"{en.listed_over_reported.min():.3f}")
        put("ChkListedOverReportedMax", f"{en.listed_over_reported.max():.3f}")
        put("ChkShards", num(en.shards.sum())); put("ChkShardsTruncated", num(en.truncated.sum()))
        put("ChkShardsError", num(en.error_last.sum()))
    cv = read("b12_coverage.csv")
    if cv is not None:
        for _, r in cv.iterrows():
            k = "Cov" + camel(r.type)
            put(k + "Share", pct(r.coverage)); put(k + "Lo", pct(r.lo)); put(k + "Hi", pct(r.hi))
            put(k + "N", num(r.in_selected_bins)); put(k + "MissShare", pct(1 - r.coverage))
    cb = read("b12_coverage_bias.csv")
    if cb is not None:
        for _, r in cb.iterrows():
            k = "CovBias" + camel(str(r.measure).split(" (")[0])
            put(k + "Found", pct(r.found_rate)); put(k + "Missed", pct(r.missed_rate))
            put(k + "FoundN", num(r.found_n)); put(k + "MissedN", num(r.missed_n))
            put(k + "P", f"{r.fisher_p:.2f}" if r.fisher_p >= 0.01 else f"{r.fisher_p:.1e}")
        put("CovBiasMinP", f"{cb.fisher_p.min():.2f}")
    lo = read("b12_location.csv")
    if lo is not None:
        for _, r in lo.iterrows():
            k = "Loc" + camel(r.type) + camel(r.location)
            put(k + "Files", num(r.files)); put(k + "Repos", num(r.repos))
            for c in ("any_dangerous_grant", "bypass_mode", "literal_secret", "unpinned_launch"):
                if c in r and pd.notna(r[c]):
                    put(k + camel(c), pct(r[c]))
        for t, g in lo.groupby("type"):
            put("Loc" + camel(t) + "RootShare", pct(g[g.location == "root"].files.sum() / g.files.sum()))
    pr = read("b12_per_repo.csv")
    if pr is not None:
        for _, r in pr.iterrows():
            k = "PerRepo" + camel(r.signal)
            put(k + "FileRate", pct(r.files_rate)); put(k + "RepoRate", pct(r.repo_rate)); put(k + "Repos", num(r.repos))
    se = read("b12_secrets.csv")
    if se is not None and len(se):
        put("SecretTypes", num(len(se))); put("SecretTopType", tex(se.iloc[0].secret_type))
        put("SecretTopShare", pct(se.iloc[0].occurrences / se.occurrences.sum()))
    ow = read("b12_owners.csv")
    if ow is not None and len(ow):
        r = ow.iloc[0]
        put("OwnFamilies", num(r.families)); put("OwnSingleOwnerShare", pct(r.share_single_owner))
        put("OwnMaxOwners", num(r.max_owners))


def dangling() -> None:
    d = read("b13_dangling.csv")
    if d is None:
        return
    d = d[d["class"] != "distinct_scopes_checked"]
    un = d[d.scoped.astype(str) == "False"]
    sc = d[d.scoped.astype(str) == "True"]
    for (eco, cls), g in un.groupby(["eco", "class"]):
        put(f"Dang{camel(eco)}{camel(cls)}N", num(g.names.sum())); put(f"Dang{camel(eco)}{camel(cls)}Files", num(g.files.sum()))
    for cls, g in un.groupby("class"):
        put(f"DangUnscoped{camel(cls)}N", num(g.names.sum())); put(f"DangUnscoped{camel(cls)}Files", num(g.files.sum()))
    put("DangUnscopedN", num(un.names.sum()))
    reg = un[~un["class"].isin(["placeholder", "refused"])]
    put("DangUnscopedRegistrableN", num(reg.names.sum())); put("DangUnscopedRegistrableFiles", num(reg.files.sum()))
    put("DangUnscopedRegistrableRepos", num(reg.repos_upper_bound.sum()))
    names = sc[sc["class"] != "scope_has_no_packages"]
    put("DangScopedN", num(names.names.sum()))
    put("DangScopedNearMissN", num(names[names["class"] == "near_miss"].names.sum()))
    free = sc[sc["class"] == "scope_has_no_packages"]
    put("DangScopedFreeScopeN", num(free.names.sum())); put("DangScopedFreeScopeFiles", num(free.files.sum()))


def main() -> None:
    for f in (frame1, frame2, mcp, autonomy, inheritance, copilot_template, validation, frame_checks, dangling):
        f()
    PAPER.mkdir(exist_ok=True)
    lines = ["% generated by src/10_numbers.py from tables/ -- do not edit"]
    lines += [f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(M.items())]
    (PAPER / "numbers.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(M)} macros to {PAPER / 'numbers.tex'}")


if __name__ == "__main__":
    main()
