"""RQ4 inheritance: how often is agent configuration, including risky configuration, copied verbatim across repositories?

A file is "shared" when the same git blob (byte-identical content) appears in at least two distinct repositories of the
same frame. Only substantive files (>= 200 characters, not a git symlink) are analysed. This is a lower bound on copying (any edit breaks identity). Frame 2 types with p < 1 are a sample of size
bins, but byte-identical files have the same size and therefore fall in the same bin: within a selected bin, every copy of
a blob is enumerated, so the shared share is unbiased for sampled types too. Forks are reported separately because code
search indexes forks only when they are starred above their parent.

Outputs (aggregates only, no names):
  tables/b9_inheritance.csv        per frame x type x subset (all / with signal / with dangerous grant / with secret / with
                                   unpinned MCP launch): files, shared files, share shared, largest copy family (repos)
  tables/b9_inheritance_sizes.csv  distribution of copy-family sizes (2, 3-9, 10-99, 100+ repos) per type
Usage: python src/08_inherit.py
"""
from __future__ import annotations

import json
from importlib import import_module

import numpy as np
import pandas as pd

from common import DERIVED, TABLES

signals = import_module("06_stats").signals
MIN_CHARS = 200


def subsets(f: pd.DataFrame, srv: pd.DataFrame) -> dict[str, pd.Series]:
    s = signals(f)
    dangerous = f.cs_dangerous.fillna("[]").map(json.loads).map(bool)          # stored as JSON strings
    secret = (f.n_server_secrets.fillna(0) > 0) | f.cs_secrets.fillna("[]").map(json.loads).map(bool)
    unpinned = f.sha.isin(srv[srv.pin == "unpinned"].sha)
    return {"all": pd.Series(True, index=f.index), "any_signal": s.any_signal, "any_rule": s.any_rule,
            "instruction_comment": s.instruction_comment, "dangerous_grant": dangerous, "literal_secret": secret,
            "unpinned_mcp": unpinned}


def main() -> None:
    files = pd.read_parquet(DERIVED / "files.parquet")
    files = files[files.fetched.fillna(False).astype(bool) & files.sha.notna()].copy()
    # Trivial files (git symlinks such as "AGENTS.md", "@AGENTS.md" imports, empty templates such as {"mcpServers": {}})
    # are identical by construction and would dominate the copy families: only substantive files are analysed.
    files = files[(files.chars.fillna(0) >= MIN_CHARS) & (files.json_status.fillna("") != "symlink")]
    srv = pd.read_parquet(DERIVED / "mcp_servers.parquet")
    rows, sizes = [], []
    for frame in (1, 2):
        f = files[files.frame == frame].drop_duplicates(["repo", "path"])
        fam = f.groupby("sha").repo.nunique()                      # copy-family size, in repositories
        f = f.assign(family=f.sha.map(fam), shared=lambda d: d.sha.map(fam) >= 2)
        for t, g in [("all_types", f)] + list(f.groupby("type")):
            for name, mask in subsets(g, srv).items():
                h = g[mask]
                if not len(h):
                    continue
                nf = h[~h.fork]
                rows.append({"frame": frame, "type": t, "subset": name, "files": len(h), "shared": int(h.shared.sum()),
                             "share_shared": h.shared.mean(), "files_nonfork": len(nf),
                             "share_shared_nonfork": nf.shared.mean() if len(nf) else np.nan,
                             "distinct_blobs": h.sha.nunique(), "largest_family_repos": int(h.family.max())})
            u = g.drop_duplicates("sha")
            bins = pd.cut(u.family, [0, 1, 2, 9, 99, np.inf], labels=["1", "2", "3-9", "10-99", "100+"])
            for b, n in bins.value_counts().sort_index().items():
                sizes.append({"frame": frame, "type": t, "family_repos": b, "blobs": int(n),
                              "files": int(g.sha.isin(u.sha[bins == b]).sum())})
    pd.DataFrame(rows).to_csv(TABLES / "b9_inheritance.csv", index=False)
    pd.DataFrame(sizes).to_csv(TABLES / "b9_inheritance_sizes.csv", index=False)
    out = pd.DataFrame(rows)
    print(out[out.type == "all_types"].to_string(index=False))


if __name__ == "__main__":
    main()
