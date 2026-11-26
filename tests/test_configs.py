import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from configs import (load_json, parse_claude_settings, parse_mcp, parse_vscode_settings,  # noqa: E402
                     secret_types, split_npm)


def test_load_variants():
    assert load_json('{"a": 1}')[1] == "ok"
    assert load_json('{\n // comment\n "a": 1,\n}')[1] == "jsonc"
    assert load_json("mcp/memory/.mcp.json")[1] == "symlink"
    assert load_json("   ")[1] == "empty"
    assert load_json("{oops")[1] == "invalid"


def test_npx_specs():
    cfg = {"mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
        "pinned": {"command": "npx", "args": ["-y", "some-mcp@1.2.3"]},
        "latest": {"command": "npx", "args": ["mcp-remote@latest", "https://x"]},
        "pkgflag": {"command": "npx", "args": ["-y", "--package=@scope/tool@^2.0.0", "tool"]},
        "win": {"command": "cmd", "args": ["/c", "npx", "-y", "@upstash/context7-mcp"]},
    }}
    s = {x["server"]: x for x in parse_mcp(cfg)}
    assert s["fs"]["package"] == "@modelcontextprotocol/server-filesystem" and s["fs"]["pin"] == "unpinned"
    assert s["pinned"]["pin"] == "exact" and s["pinned"]["package"] == "some-mcp"
    assert s["latest"]["pin"] == "unpinned"
    assert s["pkgflag"]["package"] == "@scope/tool" and s["pkgflag"]["pin"] == "range_or_tag"
    assert s["win"]["kind"] == "npx" and s["win"]["package"] == "@upstash/context7-mcp"


def test_uvx_docker_remote_local():
    cfg = {"servers": {
        "git": {"type": "stdio", "command": "uvx", "args": ["mcp-server-git==0.6.2", "--repository", "."]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "gh": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"]},
        "dig": {"command": "docker", "args": ["run", "img/x@sha256:abc"]},
        "web": {"type": "http", "url": "http://mcp.example.com/sse"},
        "loc": {"url": "http://localhost:3000/mcp"},
        "mine": {"command": "node", "args": ["./build/index.js"]},
    }}
    s = {x["server"]: x for x in parse_mcp(cfg)}
    assert s["git"]["pin"] == "exact" and s["git"]["package"] == "mcp-server-git"
    assert s["fetch"]["pin"] == "unpinned"
    assert s["gh"]["kind"] == "docker" and s["gh"]["pin"] == "unpinned"
    assert s["dig"]["pin"] == "digest"
    assert s["web"]["remote_scheme"] == "http" and not s["web"]["remote_local"]
    assert s["loc"]["remote_local"]
    assert s["mine"]["kind"] == "local"


def test_secrets_type_only():
    fake = "ghp_" + "A" * 36
    cfg = {"mcpServers": {"gh": {"command": "npx", "args": ["x"], "env": {"GITHUB_TOKEN": fake, "OTHER": "${env:TOKEN}"}}}}
    s = parse_mcp(cfg)[0]
    assert s["secrets"] == ["github_token"]
    assert fake not in str(s)                       # value never returned
    assert secret_types("API_KEY", "<your-api-key>") == []
    assert secret_types("API_KEY", "your_api_key_here_123456") == []


def test_claude_settings():
    st = parse_claude_settings({"permissions": {"allow": ["Bash", "Bash(curl:*)", "Read", "WebFetch", "Bash(npm test)"],
                                                "defaultMode": "bypassPermissions"},
                                "hooks": {"PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "x"}]}]},
                                "enableAllProjectMcpServers": True})
    assert st["allow_n"] == 5 and set(st["dangerous"]) == {"bash_any", "bash_runner_wildcard", "webfetch_any",
                                                          "bypass_permissions_mode", "enable_all_project_mcp"}
    assert st["hooks_n"] == 1 and st["hook_events"] == ["PostToolUse"]


def test_vscode_settings():
    v = parse_vscode_settings({"chat.tools.autoApprove": True, "chat.tools.terminal.autoApprove": {"npm test": True, "/.*/": True},
                               "mcp": {"servers": {"a": {"command": "npx", "args": ["b"]}}}})
    assert v["auto_approve"] and v["terminal_auto_approve_any"] and v["terminal_auto_approve_rules"] == 2
    assert v["mcp_servers"][0]["package"] == "b"


def test_split_npm():
    assert split_npm("@a/b@1.0.0") == ("@a/b", "1.0.0") and split_npm("@a/b") == ("@a/b", None) and split_npm("x@latest") == ("x", "latest")


def test_parse_mcp_odd_shapes():
    assert parse_mcp({"mcp": ["a", "b"]}) == []
    assert parse_mcp({"mcp": {"servers": {"x": {"command": "npx", "args": ["-y", "pkg"]}}}})[0]["package"] == "pkg"
    assert parse_mcp([1, 2]) == []


def test_uvx_value_flags_are_not_packages():
    from configs import parse_mcp
    obj = {"mcpServers": {
        "a": {"command": "uvx", "args": ["--python", "3.12", "mcp-server-time"]},
        "b": {"command": "uvx", "args": ["--with", "numpy", "--from", "pkg-x==1.0", "pkg-x"]},
        "c": {"command": "uv", "args": ["tool", "run", "-p", "3.11", "serena"]}}}
    got = {s["server"]: (s["package"], s["pin"]) for s in parse_mcp(obj)}
    assert got["a"] == ("mcp-server-time", "unpinned")
    assert got["b"][0] == "pkg-x" and got["b"][1] == "exact"
    assert got["c"][0] == "serena"
