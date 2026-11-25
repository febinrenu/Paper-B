"""Link MCP launch packages to registry state, OSV malicious-package records and Paper A's hallucinated names.

Input: data/derived/mcp_packages.parquet (from 06_stats.py): eco, package, files, repos, unpinned_share.
npm and PyPI only (docker images are out of scope here).

For every distinct package name:
  * registry lookup with Paper A's code (slopsquat-study/src/05_enrich.py), cache in
    data/derived/mcp_registry_cache.jsonl. Lookups that fail on the network are retried until resolved
    (run_until_clean) and are never read as "does not exist"; if any stay unresolved this script exits 1.
  * OSV MAL join (slopsquat-study/data/registry/osv_mal.parquet)
  * membership in Paper A's hallucinated name set (absent from the early-2024 snapshot, emitted by >= 1 model)
Categories (not exclusive):
  dangling          no such package on the registry (and no npm tombstone)
    dangling_unscoped   ... and unscoped: anyone can register the name
    dangling_scoped     ... npm @scope/name: only the scope's owner can publish it (claimable only if the scope is free)
  mal_record        an OSV MAL record exists for the name
    malicious_at_birth  first MAL record within 30 days of the package's creation (or creation unknown)
    compromised         first MAL record > 30 days after creation: malicious versions of an existing package
  removed         npm tombstone (unpublished), all PyPI files yanked, or npm security-holding package
  hallucinated    in Paper A's hallucinated set
Outputs: tables/b8_mcp_package_risk.csv (aggregates); data/derived/mcp_package_risk.parquet (private, name level).
Usage: python src/07_link.py
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys

import numpy as np
import pandas as pd

from common import DERIVED, PAPER_A, TABLES

NOT_A_NAME = re.compile(r"(\s|\$|\{|\}|^\.|^[<>=~^!]|^git\+|^github:|^https?:|^file:|^npm:|://|\\|^[\d.]+$)")
COMPROMISE_DAYS = 30     # first MAL record > 30 days after creation: compromise of an existing package


def load_paper_a_enrich():
    """Import Paper A's 05_enrich in isolation: it does `from common import ...`, and this project has its own
    `common` module, so Paper A's src is put first and the module cache is restored afterwards."""
    src = str(PAPER_A / "src")
    saved = sys.modules.pop("common", None)
    sys.path.insert(0, src)
    try:
        spec = importlib.util.spec_from_file_location("paper_a_enrich", PAPER_A / "src" / "05_enrich.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(src)
        sys.modules.pop("common", None)
        if saved is not None:
            sys.modules["common"] = saved
    return mod


def clean(eco: str, pkg: str) -> str | None:
    if not isinstance(pkg, str) or not pkg or NOT_A_NAME.search(pkg):
        return None
    if eco == "pypi":
        pkg = re.sub(r"\[.*\]$", "", pkg)                       # extras
        return pkg if re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", pkg) else None
    if pkg.count("/") != (1 if pkg.startswith("@") else 0):      # paths, or a scope without a name
        return None
    return pkg


def key(eco: str, n: str) -> str:
    n = n.lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n    # PEP 503 for PyPI


def truthy(v) -> bool:
    return v is True or (isinstance(v, (bool, np.bool_)) and bool(v))


def main() -> None:
    pk = pd.read_parquet(DERIVED / "mcp_packages.parquet")
    pk = pk[pk.eco.isin(["npm", "pypi"])].copy()
    pk["name"] = [clean(e, p) for e, p in zip(pk.eco, pk.package)]
    skipped = pk[pk.name.isna()]
    pk = pk[pk.name.notna()]
    # several raw strings can map to one name (extras, case): aggregate (files / repos summed: upper bound for repos)
    pk["unpinned_files"] = pk.files * pk.unpinned_share
    pk = (pk.groupby(["eco", "name"]).agg(files=("files", "sum"), repos=("repos", "sum"),
                                          unpinned_files=("unpinned_files", "sum")).reset_index())
    print("packages:", pk.groupby("eco").size().to_dict(), "| skipped non-name strings:", skipped.groupby("eco").size().to_dict())

    enrich = load_paper_a_enrich()
    enrich.CACHE = DERIVED / "mcp_registry_cache.jsonl"
    cands = list(zip(pk.eco, pk.name))
    left = enrich.run_until_clean(cands)
    recs = {}
    for line in enrich.CACHE.read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        recs[(d["eco"], d["name"])] = d
    if left:
        raise SystemExit(f"{left} registry lookups unresolved (network); nothing written")

    r = [recs.get(c, {}) for c in cands]
    pk["exists"] = [truthy(d.get("exists")) for d in r]
    pk["tombstone"] = [truthy(d.get("tombstone")) for d in r]
    pk["yanked_all"] = [truthy(d.get("yanked_all")) for d in r]
    pk["security_holding"] = [truthy(d.get("security_holding")) for d in r]
    pk["created"] = [d.get("created") for d in r]
    pk["latest_version"] = [d.get("latest_version") for d in r]

    mal = pd.read_parquet(PAPER_A / "data" / "registry" / "osv_mal.parquet")
    mal["eco"] = mal.ecosystem.map({"PyPI": "pypi", "npm": "npm"})
    mal = mal[mal.eco.notna()]
    mal["k"] = [key(e, n) for e, n in zip(mal.eco, mal.name)]
    malfirst = mal.groupby(["eco", "k"]).published.min().to_dict()
    malk = set(malfirst)
    names = pd.read_parquet(PAPER_A / "data" / "derived" / "names.parquet")
    nm_cols = [c for c in names.columns if c.startswith("n_models")]
    hal = names[(~names.in_2024.astype(bool)) & (names[nm_cols].sum(axis=1) > 0)]
    halk = {(e, key(e, n)) for e, n in zip(hal.eco, hal.name)}

    k = [(e, key(e, n)) for e, n in zip(pk.eco, pk.name)]
    pk["mal_record"] = [x in malk for x in k]
    pk["mal_first_published"] = pd.to_datetime(pd.Series([malfirst.get(x) for x in k], index=pk.index), utc=True, errors="coerce")
    created = pd.to_datetime(pk.created, utc=True, errors="coerce")
    late = ((pk.mal_first_published - created).dt.days > COMPROMISE_DAYS).fillna(False)
    pk["compromised"] = pk.mal_record & late
    pk["malicious_at_birth"] = pk.mal_record & ~pk.compromised
    pk["hallucinated"] = [x in halk for x in k]
    pk["removed"] = pk.tombstone | pk.yanked_all | pk.security_holding
    pk["dangling"] = ~pk.exists & ~pk.tombstone
    scoped = pk.name.str.startswith("@")
    pk["dangling_scoped"] = pk.dangling & scoped
    pk["dangling_unscoped"] = pk.dangling & ~scoped
    pk.to_parquet(DERIVED / "mcp_package_risk.parquet", index=False)

    rows = []
    for eco, g in [("all", pk)] + list(pk.groupby("eco")):
        base = {"eco": eco, "packages_total": len(g), "files_total": int(g.files.sum()),
                "skipped_non_name_strings": int(len(skipped) if eco == "all" else (skipped.eco == eco).sum())}
        for cat in ("dangling", "dangling_unscoped", "dangling_scoped", "mal_record", "malicious_at_birth",
                    "compromised", "removed", "hallucinated"):
            s = g[g[cat]]
            rows.append({**base, "category": cat, "packages": len(s), "share_packages": len(s) / len(g) if len(g) else np.nan,
                         "files": int(s.files.sum()), "repos_upper_bound": int(s.repos.sum()),
                         "unpinned_share_of_files": s.unpinned_files.sum() / s.files.sum() if s.files.sum() else np.nan})
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b8_mcp_package_risk.csv", index=False)
    print(out.round(4).to_string(index=False))
    both = pk[pk.hallucinated & pk.dangling]
    print("hallucinated and still dangling:", both.groupby("eco").size().to_dict(),
          "| hallucinated with MAL record:", pk[pk.hallucinated & pk.mal_record].groupby("eco").size().to_dict())


if __name__ == "__main__":
    main()
