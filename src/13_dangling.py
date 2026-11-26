"""What are the dangling package names that MCP configurations launch, and could an attacker register them?

Each dangling (non-existent, never-published) name is classified, in this order:
  placeholder     template text: some-/example-/my-/your-/test- prefixes, __X__, <x>, {x}
  refused         the registry would not accept it as a new name: npm names with upper-case letters or invalid
                  characters, names equal to an existing npm name once punctuation is removed (checked against the
                  early-2024 npm snapshot), PyPI names of standard-library modules
  near_miss       its tokens, ignoring "mcp"/"server(s)" and order, equal those of a package that exists in the same
                  configurations: a misremembered name of a real package
  other           none of the above
Scoped npm names (@scope/name) can only be published by the scope's owner; for each distinct scope we ask the npm
search API whether any package exists under it. A scope with no packages may be unclaimed.
Outputs: tables/b13_dangling.csv (aggregates only).
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import httpx
import pandas as pd

from common import DERIVED, TABLES, USER_AGENT

PAPER_A = Path(__file__).resolve().parents[2] / "slopsquat-study"
CACHE = DERIVED / "npm_scope_cache.jsonl"
PLACEHOLDER = re.compile(r"^(some|example|examples|my|your|test|sample|demo|placeholder|foo|bar|dummy|template)[-_.]|"
                         r"__\w+__|[<>{}]|^(copy|example|test|todo|package|name)$", re.I)
STOP = {"mcp", "server", "servers", "model", "context", "protocol", "modelcontextprotocol"}


def tokens(name: str) -> frozenset:
    n = name.split("/")[-1].lower()
    return frozenset(t for t in re.split(r"[-_.]+", n) if t and t not in STOP)


def scope_has_packages(scope: str, cache: dict, client: httpx.Client) -> bool | None:
    if scope in cache:
        return cache[scope]
    for attempt in range(5):
        try:
            r = client.get("https://registry.npmjs.org/-/v1/search", params={"text": f"scope:{scope}", "size": 1})
            if r.status_code == 200:
                v = r.json().get("total", 0) > 0
                cache[scope] = v
                with open(CACHE, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"scope": scope, "has": v}) + "\n")
                time.sleep(0.4)
                return v
        except httpx.HTTPError:
            pass
        time.sleep(5 * (attempt + 1))
    return None


def main() -> None:
    pk = pd.read_parquet(DERIVED / "mcp_package_risk.parquet")
    exist_tokens = {}
    for e, n in zip(pk.eco[pk.exists], pk.name[pk.exists]):
        exist_tokens.setdefault(tokens(n), []).append((e, n))
    npm_snap = set((PAPER_A / "data" / "registry" / "npm_2024.txt").read_text(encoding="utf-8").split("\n"))
    strip = lambda n: re.sub(r"[._-]", "", n.lower())
    npm_stripped = {strip(n) for n in npm_snap if n and not n.startswith("@")}
    stdlib = set(sys.stdlib_module_names)

    d = pk[pk.dangling].copy()

    def classify(e, n):
        if PLACEHOLDER.search(n):
            return "placeholder"
        if e == "npm" and not n.startswith("@"):
            if n != n.lower() or not re.fullmatch(r"[a-z0-9][a-z0-9._~-]*", n.lower()) or strip(n) in npm_stripped:
                return "refused"
        if e == "pypi" and n.lower() in stdlib:
            return "refused"
        tk = tokens(n)
        if tk and tk in exist_tokens:
            return "near_miss"
        return "other"
    d["class"] = [classify(e, n) for e, n in zip(d.eco, d.name)]

    cache = {}
    if CACHE.exists():
        for line in CACHE.read_text(encoding="utf-8").splitlines():
            x = json.loads(line)
            cache[x["scope"]] = x["has"]
    client = httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=30)
    scoped = d[d.name.str.startswith("@")]
    scopes = sorted({n.split("/")[0][1:] for n in scoped.name})
    for s in scopes:
        scope_has_packages(s, cache, client)
    d["scope_free"] = [(not cache.get(n.split("/")[0][1:], True)) if n.startswith("@") else None for n in d.name]

    rows = []
    for (e, sc), g in d.groupby([d.eco, d.name.str.startswith("@")]):
        for cls, h in g.groupby("class"):
            rows.append({"eco": e, "scoped": bool(sc), "class": cls, "names": len(h), "files": int(h.files.sum()),
                         "repos_upper_bound": int(h.repos.sum())})
        if sc:
            rows.append({"eco": e, "scoped": True, "class": "scope_has_no_packages",
                         "names": int(g.scope_free.fillna(False).astype(bool).sum()),
                         "files": int(g[g.scope_free.fillna(False).astype(bool)].files.sum()),
                         "repos_upper_bound": int(g[g.scope_free.fillna(False).astype(bool)].repos.sum())})
    rows.append({"eco": "all", "scoped": None, "class": "distinct_scopes_checked", "names": len(scopes)})
    out = pd.DataFrame(rows)
    out.to_csv(TABLES / "b13_dangling.csv", index=False)
    print(out.to_string(index=False))
    # registrable-by-anyone = unscoped, not placeholder, not refused; or scoped under a scope with no packages
    reg = d[(~d.name.str.startswith("@") & ~d["class"].isin(["placeholder", "refused"])) |
            (d.name.str.startswith("@") & d.scope_free.fillna(False).astype(bool) & (d["class"] != "placeholder"))]
    print("registrable (unscoped valid + scoped under free scopes):", reg.groupby("eco").size().to_dict(),
          "files", int(reg.files.sum()))


if __name__ == "__main__":
    main()
