"""Shared paths, GitHub client (read-only, rate-limit aware, pauses while offline) and helpers."""
from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
LISTS = DATA / "lists"        # repo / file lists (identify repos: not published)
RAW = DATA / "raw"            # fetched file contents (not published)
DERIVED = DATA / "derived"    # per-file findings (not published)
TABLES = ROOT / "tables"      # aggregates only (published)
FIGURES = ROOT / "figures"
MANIFEST = DATA / "MANIFEST.json"
PAPER_A = ROOT.parent / "slopsquat-study"
for _p in (LISTS, RAW, DERIVED, TABLES, FIGURES):
    _p.mkdir(parents=True, exist_ok=True)

USER_AGENT = "agent-config-census/0.1 (academic measurement; read-only)"
API = "https://api.github.com"

# File types under study: label -> (code-search query, path test)
FILE_TYPES = {
    "agents_md":        ("filename:AGENTS.md",                           lambda p: p.split("/")[-1] == "AGENTS.md"),
    "claude_md":        ("filename:CLAUDE.md",                           lambda p: p.split("/")[-1] == "CLAUDE.md"),
    "gemini_md":        ("filename:GEMINI.md",                           lambda p: p.split("/")[-1] == "GEMINI.md"),
    "cursorrules":      ("filename:.cursorrules",                        lambda p: p.split("/")[-1] == ".cursorrules"),
    "cursor_rules_mdc": ("path:.cursor/rules extension:mdc",             lambda p: "/.cursor/rules/" in "/" + p and p.endswith(".mdc")),
    "copilot_instr":    ("path:.github filename:copilot-instructions.md", lambda p: p.endswith(".github/copilot-instructions.md")),
    "windsurfrules":    ("filename:.windsurfrules",                      lambda p: p.split("/")[-1] == ".windsurfrules"),
    "clinerules":       ("filename:.clinerules",                         lambda p: p.split("/")[-1] == ".clinerules"),
    "mcp_json":         ("filename:.mcp.json",                           lambda p: p.split("/")[-1] == ".mcp.json"),
    "cursor_mcp":       ("path:.cursor filename:mcp.json",               lambda p: p.endswith(".cursor/mcp.json")),
    "vscode_mcp":       ("path:.vscode filename:mcp.json",               lambda p: p.endswith(".vscode/mcp.json")),
    "claude_settings":  ("path:.claude filename:settings.json",          lambda p: p.endswith(".claude/settings.json")),
    "vscode_settings":  (None,                                           lambda p: p.endswith(".vscode/settings.json")),  # Frame 1 only
}
MARKDOWN_TYPES = {"agents_md", "claude_md", "gemini_md", "cursorrules", "cursor_rules_mdc", "copilot_instr",
                  "windsurfrules", "clinerules"}


def file_type(path: str) -> str | None:
    for k, (_, test) in FILE_TYPES.items():
        if test(path):
            return k
    return None


def gh_token() -> str:
    """Token of the logged-in gh CLI, read at runtime and never written to disk."""
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def wait_online(host: str = "https://api.github.com", every: int = 60) -> None:
    t0, logged = time.time(), False
    while True:
        try:
            httpx.get(host, timeout=20)
            if logged:
                print(time.strftime("%H:%M"), f"connection back after {(time.time()-t0)/60:.0f} min", flush=True)
            return
        except httpx.HTTPError:
            if not logged:
                print(time.strftime("%H:%M"), "offline; pausing until the connection returns", flush=True)
                logged = True
            time.sleep(every)


class GitHub:
    """Read-only REST client. Honours primary limits (X-RateLimit-*) and secondary limits (Retry-After)."""

    def __init__(self, min_interval: float = 0.0):
        self.c = httpx.Client(headers={"Authorization": f"Bearer {gh_token()}", "User-Agent": USER_AGENT,
                                       "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
                              timeout=60, follow_redirects=True)
        self.min_interval = min_interval     # e.g. 6.5 s for code search (10/min)
        self._last = 0.0
        self._lock = threading.Lock()        # spacing is shared across worker threads

    def _space(self) -> None:
        with self._lock:
            wait = self._last + self.min_interval - time.time()
            self._last = max(time.time(), self._last + self.min_interval)
        if wait > 0:
            time.sleep(wait)

    def get(self, url: str, params: dict | None = None, ok404: bool = True) -> httpx.Response | None:
        url = url if url.startswith("http") else API + url
        attempt = 0
        while True:
            self._space()
            try:
                r = self.c.get(url, params=params)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                wait_online()
                continue
            except httpx.HTTPError as ex:
                attempt += 1
                if attempt > 6:
                    print("giving up:", url, type(ex).__name__, flush=True)
                    return None
                time.sleep(min(10 * attempt, 120))
                continue
            rem = r.headers.get("x-ratelimit-remaining")
            if r.status_code in (403, 429) and ("rate limit" in r.text.lower() or rem == "0"):
                ra = r.headers.get("retry-after")
                reset = int(r.headers.get("x-ratelimit-reset", time.time() + 60))
                wait = int(ra) if ra else max(5, reset - int(time.time()) + 3)
                print(time.strftime("%H:%M"), f"rate limited, sleeping {wait}s", flush=True)
                time.sleep(min(wait, 3700))
                continue
            if r.status_code in (500, 502, 503, 504):
                attempt += 1
                if attempt > 6:
                    return None
                time.sleep(min(10 * attempt, 120))
                continue
            if r.status_code == 404 and ok404:
                return None
            if r.status_code in (409, 451):      # empty repo / legal block
                return None
            limit = int(r.headers.get("x-ratelimit-limit", 5000))
            # stay polite near the primary limit; the margin scales with the bucket (core 5000/h vs search 10-30/min)
            if rem is not None and int(rem) <= max(0, limit // 250):
                reset = int(r.headers.get("x-ratelimit-reset", time.time() + 60))
                time.sleep(max(1, reset - int(time.time()) + 2))
            return r


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def update_manifest(entries: dict) -> None:
    m = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    m.update(entries)
    MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True))


def append_jsonl(path: Path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
