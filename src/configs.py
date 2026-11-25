"""RQ2/RQ3 parsers: MCP server configs and agent permission settings. Pure functions, no I/O.

Formats handled
  {"mcpServers": {...}}  Claude Code .mcp.json, Cursor .cursor/mcp.json, Cline/Roo, Windsurf
  {"servers": {...}}     VS Code .vscode/mcp.json (also "mcp": {"servers": ...} in .vscode/settings.json)
  .claude/settings.json  permissions.allow/deny/ask, defaultMode, hooks, enableAllProjectMcpServers
  .vscode/settings.json  chat.tools.autoApprove and terminal auto-approve rules
JSON with comments / trailing commas is accepted (json5). A git symlink (blob containing a path) is
reported as such. Secret VALUES are never returned: only the detector type that matched.
"""
from __future__ import annotations

import json
import re

try:
    import json5
except ImportError:          # pragma: no cover
    json5 = None


def load_json(text: str):
    """Returns (obj, status) with status in ok | jsonc | symlink | empty | invalid."""
    s = text.strip().lstrip("﻿")
    if not s:
        return None, "empty"
    if "\n" not in s and len(s) < 300 and not s.startswith(("{", "[")) and ("/" in s or s.endswith(".json")):
        return None, "symlink"
    try:
        return json.loads(s), "ok"
    except ValueError:
        pass
    if json5 is not None:
        try:
            return json5.loads(s), "jsonc"
        except Exception:  # noqa: BLE001
            pass
    return None, "invalid"


# ---------------------------------------------------------------- secrets (type only)
SECRET_PATTERNS = {
    "github_token": r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b",
    "openai_key": r"\bsk-(proj-)?[A-Za-z0-9_-]{30,}\b",
    "anthropic_key": r"\bsk-ant-[A-Za-z0-9_-]{30,}\b",
    "aws_access_key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "slack_token": r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b",
    "stripe_key": r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}
_SECRET_C = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}
_SECRETY_KEY = re.compile(r"(api[_-]?key|token|secret|password|passwd|auth|bearer|credential)", re.I)
_PLACEHOLDER = re.compile(r"^\s*$|\$\{|\$[A-Z_]|<[^>]+>|your[_-]|xxx|\*\*\*|changeme|example|placeholder|dummy|test|\.\.\.|TODO|^env:|^input:", re.I)


def secret_types(key: str, value) -> list[str]:
    if not isinstance(value, str):
        return []
    hits = [k for k, p in _SECRET_C.items() if p.search(value)]
    if not hits and _SECRETY_KEY.search(key or "") and not _PLACEHOLDER.search(value) and len(value) >= 16 \
            and re.fullmatch(r"[A-Za-z0-9_\-\.=+/:]{16,}", value):
        hits = ["generic_high_entropy"]
    return hits


# ---------------------------------------------------------------- launch specs
NPX_RUNNERS = {"npx", "npx.cmd", "bunx", "pnpx"}
PY_RUNNERS = {"uvx", "pipx"}
_VALUE_FLAGS_UV = {"--python", "-p", "--with", "-w", "--with-editable", "--with-requirements", "--index", "--index-url",
                   "--extra-index-url", "--default-index", "--find-links", "-f", "--directory", "--project", "--env-file",
                   "--python-preference", "--cache-dir", "--config-file", "--constraints", "-c", "--overrides",
                   "--index-strategy", "--keyring-provider", "--refresh-package", "--reinstall-package", "--upgrade-package",
                   "-P"}
_VALUE_FLAGS_DOCKER = {"-e", "--env", "-v", "--volume", "--name", "--network", "-p", "--publish", "-w", "--workdir",
                       "--env-file", "--mount", "-u", "--user", "--entrypoint", "--platform", "-l", "--label", "--add-host"}


def _npm_spec(args: list[str]) -> str | None:
    it = iter(range(len(args)))
    for i in it:
        a = args[i]
        if a in ("-p", "--package") and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("--package="):
            return a.split("=", 1)[1]
        if a.startswith("-"):
            continue
        return a
    return None


def split_npm(spec: str) -> tuple[str, str | None]:
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3'); 'pkg' -> ('pkg', None)."""
    if spec.startswith("@"):
        at = spec.find("@", 1)
    else:
        at = spec.find("@")
    return (spec, None) if at <= 0 else (spec[:at], spec[at + 1:])


def split_py(spec: str) -> tuple[str, str | None]:
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:(==|@|>=|~=|<=|>|<)\s*(.+))?$", spec)
    if not m:
        return spec, None
    return m.group(1), (None if not m.group(2) else (m.group(3) if m.group(2) in ("==", "@") else m.group(2) + m.group(3)))


def pin_state(version: str | None, eco: str) -> str:
    if version is None or version in ("latest", "*", ""):
        return "unpinned"
    if eco == "npm" and re.fullmatch(r"\d+\.\d+\.\d+([-+][\w.\-]+)?", version):
        return "exact"
    if eco == "pypi" and re.fullmatch(r"\d+(\.\d+)*([abrc.\-+]\w*)?", version):
        return "exact"
    return "range_or_tag"


def classify_server(name: str, s: dict) -> dict:
    out = {"server": name[:80], "kind": "unknown", "eco": None, "package": None, "version": None, "pin": None,
           "remote_scheme": None, "remote_local": None, "secrets": [], "disabled": bool(s.get("disabled")),
           "always_allow": len(s.get("alwaysAllow") or s.get("autoApprove") or []) if isinstance(s.get("alwaysAllow") or s.get("autoApprove") or [], list) else 0}
    for k, v in (s.get("env") or {}).items() if isinstance(s.get("env"), dict) else []:
        out["secrets"] += secret_types(k, v)
    for k, v in (s.get("headers") or {}).items() if isinstance(s.get("headers"), dict) else []:
        out["secrets"] += secret_types(k, v)
    url = s.get("url") or s.get("serverUrl")
    if isinstance(url, str) and url:
        out["kind"] = "remote"
        out["remote_scheme"] = url.split(":", 1)[0].lower()
        out["remote_local"] = bool(re.match(r"^\w+://(localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal)", url))
        out["secrets"] += secret_types("url", url)
        return out
    cmd = s.get("command")
    args = s.get("args") if isinstance(s.get("args"), list) else []
    args = [str(a) for a in args]
    if not isinstance(cmd, str) or not cmd:
        return out
    parts = cmd.split()
    base = parts[0].replace("\\", "/").split("/")[-1].lower()
    args = parts[1:] + args
    for a in args:
        out["secrets"] += secret_types("arg", a)
    if base in ("cmd", "cmd.exe") and "/c" in [a.lower() for a in args]:          # Windows wrapper: cmd /c npx ...
        i = [a.lower() for a in args].index("/c")
        if i + 1 < len(args):
            return {**classify_server(name, {**s, "command": args[i + 1], "args": args[i + 2:]}), "secrets": out["secrets"]}
    if base in NPX_RUNNERS or (base in ("pnpm", "yarn") and args[:1] == ["dlx"]):
        spec = _npm_spec(args[1:] if base in ("pnpm", "yarn") else args)
        if spec:
            pkg, ver = split_npm(spec)
            out.update(kind="npx", eco="npm", package=pkg, version=ver, pin=pin_state(ver, "npm"))
        return out
    if base in PY_RUNNERS or (base == "uv" and args[:2] == ["tool", "run"]):
        a2 = args[2:] if base == "uv" else (args[1:] if base == "pipx" and args[:1] == ["run"] else args)
        spec, skip = None, False
        for i, a in enumerate(a2):
            if skip:                        # value of the previous flag (e.g. --python 3.12), not the package
                skip = False
                continue
            if a == "--from" and i + 1 < len(a2):
                spec = a2[i + 1]
                break
            if a in _VALUE_FLAGS_UV:
                skip = True
                continue
            if not a.startswith("-"):
                spec = a
                break
        if spec:
            if spec.startswith(("git+", "http")):
                out.update(kind="uvx", eco="pypi", package=spec[:120], pin="vcs_or_url")
            else:
                pkg, ver = split_py(spec)
                out.update(kind="uvx", eco="pypi", package=pkg, version=ver, pin=pin_state(ver, "pypi"))
        return out
    if base in ("docker", "podman") and args[:1] == ["run"]:
        i, image = 1, None
        while i < len(args):
            a = args[i]
            if a in _VALUE_FLAGS_DOCKER:
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            image = a
            break
        if image:
            pin = "digest" if "@sha256:" in image else ("unpinned" if ":" not in image.split("/")[-1] or image.endswith(":latest") else "tag")
            out.update(kind="docker", eco="docker", package=image.split("@")[0][:120], pin=pin)
        return out
    out["kind"] = "local" if base in ("node", "python", "python3", "deno", "bun", "java", "dotnet", "go", "ruby", "php") \
        or "/" in parts[0] or parts[0].startswith(".") else "other_binary"
    return out


def parse_mcp(obj) -> list[dict]:
    if not isinstance(obj, dict):
        return []
    mcp = obj.get("mcp")
    servers = obj.get("mcpServers") or obj.get("servers") or (mcp.get("servers") if isinstance(mcp, dict) else None) or {}
    if not isinstance(servers, dict):
        return []
    return [classify_server(str(k), v) for k, v in servers.items() if isinstance(v, dict)]


# ---------------------------------------------------------------- autonomy grants
_DANGEROUS_ALLOW = [
    (r"^Bash(\(\s*\*?\s*\)|\(\s*\*\s*:\s*\*\s*\))?$", "bash_any"),
    (r"^Bash\((curl|wget|bash|sh|python3?|node|npx|eval|rm)[ :]", "bash_risky_cmd"),
    (r"^WebFetch(\(\*?\))?$", "webfetch_any"),
    (r"^(Write|Edit|MultiEdit)(\(\*\*?\))?$", "write_any"),
    (r"^mcp__", "mcp_tool"),
]


def parse_claude_settings(obj) -> dict:
    out = {"allow_n": 0, "deny_n": 0, "ask_n": 0, "default_mode": None, "hooks_n": 0, "hook_events": [],
           "enable_all_project_mcp": False, "dangerous": [], "secrets": []}
    if not isinstance(obj, dict):
        return out
    perm = obj.get("permissions") or {}
    if isinstance(perm, dict):
        allow = [a for a in perm.get("allow") or [] if isinstance(a, str)]
        out["allow_n"], out["deny_n"], out["ask_n"] = len(allow), len(perm.get("deny") or []), len(perm.get("ask") or [])
        out["default_mode"] = perm.get("defaultMode")
        for a in allow:
            for pat, lab in _DANGEROUS_ALLOW:
                if re.search(pat, a.strip()):
                    out["dangerous"].append(lab)
                    break
    if out["default_mode"] == "bypassPermissions":
        out["dangerous"].append("bypass_permissions_mode")
    hooks = obj.get("hooks") or {}
    if isinstance(hooks, dict):
        out["hook_events"] = sorted(hooks)
        out["hooks_n"] = sum(len(h.get("hooks", [])) if isinstance(h, dict) else 1
                             for v in hooks.values() if isinstance(v, list) for h in v)
    out["enable_all_project_mcp"] = obj.get("enableAllProjectMcpServers") is True
    if out["enable_all_project_mcp"]:
        out["dangerous"].append("enable_all_project_mcp")
    for k, v in (obj.get("env") or {}).items() if isinstance(obj.get("env"), dict) else []:
        out["secrets"] += secret_types(k, v)
    if isinstance(obj.get("apiKeyHelper"), str):
        out["secrets"] += secret_types("apiKeyHelper", obj["apiKeyHelper"])
    return out


def parse_vscode_settings(obj) -> dict:
    out = {"auto_approve": False, "terminal_auto_approve_rules": 0, "terminal_auto_approve_any": False, "mcp_servers": []}
    if not isinstance(obj, dict):
        return out
    out["auto_approve"] = obj.get("chat.tools.autoApprove") is True or obj.get("chat.tools.global.autoApprove") is True
    rules = obj.get("chat.tools.terminal.autoApprove") or obj.get("chat.agent.terminal.autoApprove") or {}
    if isinstance(rules, dict):
        on = [k for k, v in rules.items() if v is True or (isinstance(v, dict) and v.get("approve") is True)]
        out["terminal_auto_approve_rules"] = len(on)
        out["terminal_auto_approve_any"] = any(k.strip() in ("*", "/.*/", "/.*/s") for k in on)
    out["mcp_servers"] = parse_mcp(obj)
    return out
