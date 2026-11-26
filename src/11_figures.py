"""Paper figures, built only from the aggregate CSVs in tables/ (PDF + PNG in figures/, PDF copy in paper/).

Palette and mark conventions follow the companion study (single axis per chart, thin marks, recessive grid,
direct labels where few series).
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from common import TABLES  # noqa: E402

FIG = TABLES.parent / "figures"
PAPER = TABLES.parent / "paper"
FIG.mkdir(exist_ok=True)
BLUE, ORANGE, GREEN, AMBER, PINK, DKGREEN = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"
INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#ffffff"
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
    "xtick.color": MUTED, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "figure.facecolor": SURF, "axes.facecolor": SURF, "pdf.fonttype": 42,
})
LABEL = {"any_agent_file": "Any agent configuration", "agents_md": "AGENTS.md", "claude_md": "CLAUDE.md",
         "gemini_md": "GEMINI.md", "copilot_instr": "Copilot instructions", "cursor_rules_mdc": "Cursor rules (.mdc)",
         "cursorrules": ".cursorrules", "windsurfrules": ".windsurfrules", "clinerules": ".clinerules",
         "mcp_json": ".mcp.json", "cursor_mcp": "Cursor MCP config", "vscode_mcp": "VS Code MCP config",
         "claude_settings": "Claude Code settings", "vscode_settings": "VS Code settings"}


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(FIG / f"{name}.png", dpi=200, bbox_inches="tight")
    fig.savefig(PAPER / f"{name}.pdf", bbox_inches="tight")
    plt.close(fig)
    print("ok", name)


def fig_adoption():
    b1 = pd.read_csv(TABLES / "b1_frame1_prevalence.csv")
    measures = ["any_agent_file", "agents_md", "claude_md", "copilot_instr", "cursor_rules_mdc", "cursorrules",
                "gemini_md", "mcp_json", "claude_settings", "cursor_mcp", "vscode_mcp"]
    strata = [("s1", "10–99 stars", AMBER), ("s2", "100–999 stars", ORANGE), ("s3", "≥1,000 stars", BLUE)]
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    ax.grid(axis="y", visible=False)
    for i, m in enumerate(measures):
        y = -i
        for j, (g, lab, col) in enumerate(strata):
            r = b1[(b1.group == g) & (b1.measure == m)]
            if not len(r):
                continue
            r = r.iloc[0]
            off = (j - 1) * 0.22
            ax.plot([100 * r.share_lo, 100 * r.share_hi], [y + off, y + off], color=col, lw=1.8)
            ax.scatter([100 * r.share], [y + off], s=16, color=col, zorder=3, edgecolor=SURF, linewidth=0.8,
                       label=lab if i == 0 else None)
    ax.set_yticks([-i for i in range(len(measures))])
    ax.set_yticklabels([LABEL[m] for m in measures])
    ax.set_xlabel("Share of active repositories (%), 95% CI")
    ax.legend(loc="lower right", fontsize=7.5)
    save(fig, "fig_adoption")


def fig_mcp():
    b4 = pd.read_csv(TABLES / "b4_mcp_launch.csv")
    a = b4[b4.type == "all"] if (b4.type == "all").any() else b4.groupby(["launch", "pin"], dropna=False).entries.sum().reset_index()
    tot = a.entries.sum()
    order = ["npx", "uvx", "docker", "remote", "local", "other_binary", "unknown"]
    names = {"npx": "npx (npm)", "uvx": "uvx (PyPI)", "docker": "docker", "remote": "remote URL", "local": "local command",
             "other_binary": "other binary", "unknown": "unknown"}
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.5), gridspec_kw={"width_ratios": [1.1, 1], "wspace": 0.75})
    ax = axes[0]
    ax.grid(axis="y", visible=False)
    vals = [a[a.launch == l].entries.sum() / tot * 100 for l in order]
    ax.barh(range(len(order))[::-1], vals, color=BLUE, height=0.6)
    ax.set_xlim(0, max(vals) * 1.25)
    for i, v in enumerate(vals):
        ax.text(v + 0.8, len(order) - 1 - i, f"{v:.1f}%", va="center", fontsize=7, color=INK2)
    ax.set_yticks(range(len(order))[::-1]); ax.set_yticklabels([names[l] for l in order])
    ax.set_xlabel("Share of MCP server entries (%)")
    ax.set_title("How servers are started", loc="left", fontsize=8.5, color=INK)
    ax = axes[1]
    ax.grid(axis="y", visible=False)
    pins = [("unpinned", "no version / latest", ORANGE), ("range_or_tag", "range or tag", AMBER),
            ("tag", "image tag", AMBER), ("exact", "exact version", GREEN), ("digest", "image digest", DKGREEN),
            ("vcs_or_url", "VCS or URL", MUTED)]
    launchers = ["npx", "uvx", "docker"]
    for i, l in enumerate(launchers):
        g = a[a.launch == l]
        n = g.entries.sum()
        left = 0
        for pin, lab, col in pins:
            v = g[g.pin == pin].entries.sum() / n * 100 if n else 0
            if v <= 0:
                continue
            ax.barh(len(launchers) - 1 - i, v, left=left, color=col, height=0.6, edgecolor=SURF, linewidth=1)
            left += v
    ax.set_yticks(range(len(launchers))[::-1]); ax.set_yticklabels([names[l] for l in launchers])
    ax.set_xlim(0, 100); ax.set_xlabel("Share of package launches (%)")
    ax.set_title("How package launches are pinned", loc="left", fontsize=8.5, color=INK)
    from matplotlib.patches import Patch
    seen, handles = set(), []
    for pin, lab, col in pins:
        if (pin, lab) not in seen and (a.pin == pin).any():
            handles.append(Patch(color=col, label=lab)); seen.add((pin, lab))
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.35), ncol=3, fontsize=7)
    save(fig, "fig_mcp")


def fig_signals():
    b3 = pd.read_csv(TABLES / "b3_frame2_detectors.csv")
    types = ["agents_md", "claude_md", "gemini_md", "copilot_instr", "cursor_rules_mdc", "cursorrules",
             "windsurfrules", "clinerules"]
    sigs = [("instruction_comment", "Instruction-like hidden comment", BLUE), ("any_rule", "Injection-style rule", ORANGE),
            ("hidden_unicode", "Suspicious invisible Unicode", GREEN)]
    fig, ax = plt.subplots(figsize=(5.6, 3.0))
    ax.grid(axis="y", visible=False)
    for i, t in enumerate(types):
        for j, (s, lab, col) in enumerate(sigs):
            r = b3[(b3.type == t) & (b3.signal == s)]
            if not len(r):
                continue
            r = r.iloc[0]
            y = -i + (j - 1) * 0.22
            lo, hi, v = max(r.rate_lo, 1e-5) * 100, max(r.rate_hi, 1e-5) * 100, max(r.rate, 1e-5) * 100
            ax.plot([lo, hi], [y, y], color=col, lw=1.6)
            ax.scatter([v], [y], s=14, color=col, zorder=3, edgecolor=SURF, linewidth=0.8, label=lab if i == 0 else None)
    ax.set_xscale("log")
    ax.set_xlim(1e-3, 20)
    ax.set_xticks([0.001, 0.01, 0.1, 1, 10]); ax.set_xticklabels(["0.001", "0.01", "0.1", "1", "10"])
    ax.set_yticks([-i for i in range(len(types))]); ax.set_yticklabels([LABEL[t] for t in types])
    ax.set_xlabel("Share of files (%), log scale, 95% CI")
    ax.legend(loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=3, fontsize=7)
    save(fig, "fig_signals")


def fig_autonomy():
    b6 = pd.read_csv(TABLES / "b6_autonomy.csv")
    d = b6[(b6.frame == 2) & (b6.type == "claude_settings")]
    d1 = b6[(b6.frame == 1) & (b6.type == "claude_settings")]
    items = [("any_dangerous_grant", "Any dangerous pre-approval"),
             ("allow_bash_runner_wildcard", "Interpreter/runner wildcard"),
             ("allow_write_any", "Unrestricted file writes"), ("allow_bash_any", "Unrestricted shell"),
             ("allow_bash_rm_wildcard", "Recursive rm wildcard"), ("allow_webfetch_any", "Unrestricted web fetch"),
             ("bypass_permissions_mode", "Permission checks bypassed"),
             ("enable_all_project_mcp", "All project MCP servers enabled"),
             ("allow_mcp_tool", "MCP tool pre-approved*"), ("has_hooks", "Hooks defined*"),
             ("session_start_hook", "Session-start hook*"), ("has_deny_rules", "Deny rules present*")]
    fig, ax = plt.subplots(figsize=(5.4, 3.4))
    ax.grid(axis="y", visible=False)
    vals, v1, lo1, hi1 = [], [], [], []
    for k, lab in items:
        r = d[d["item"] == k]
        vals.append(float(r.share.iloc[0]) * 100 if len(r) else np.nan)
        r1 = d1[d1["item"] == k]
        v1.append(float(r1.share.iloc[0]) * 100 if len(r1) else np.nan)
        lo1.append(float(r1.share_lo.iloc[0]) * 100 if len(r1) and "share_lo" in r1 else np.nan)
        hi1.append(float(r1.share_hi.iloc[0]) * 100 if len(r1) and "share_hi" in r1 else np.nan)
    y = np.arange(len(items))[::-1]
    cols = [ORANGE if not lab.endswith("*") else MUTED for _, lab in items]
    ax.barh(y, vals, color=cols, height=0.62, label="Frame 2 (census of indexed files)")
    v1, lo1, hi1 = map(np.array, (v1, lo1, hi1))
    ax.errorbar(v1, y, xerr=[v1 - lo1, hi1 - v1], fmt="o", ms=3.2, color=INK, ecolor=INK2, elinewidth=0.9,
                capsize=1.8, label="Frame 1 (repository sample, 95% CI)")
    for i, v in enumerate(vals):
        ax.text(max(v, np.nan_to_num(hi1[i])) + 0.8, y[i], f"{v:.1f}%", va="center", fontsize=7, color=INK2)
    ax.set_yticks(y); ax.set_yticklabels([lab for _, lab in items])
    ax.set_xlabel("Share of committed Claude Code settings files (%)\n* not counted as dangerous")
    ax.legend(loc="lower right", fontsize=6.5, frameon=False)
    save(fig, "fig_autonomy")


def fig_copying():
    b9 = pd.read_csv(TABLES / "b9_inheritance.csv")
    d = b9[(b9.frame == 2) & (b9.type == "all_types")]
    subsets = [("all", "All substantive files"), ("any_signal", "Any content signal"), ("any_rule", "Injection-style rule"),
               ("instruction_comment", "Instruction-like comment"), ("dangerous_grant", "Dangerous pre-approval"),
               ("literal_secret", "Literal secret"), ("unpinned_mcp", "Unpinned MCP launch")]
    fig, ax = plt.subplots(figsize=(5.0, 2.5))
    ax.grid(axis="y", visible=False)
    vals = [float(d[d.subset == k].share_shared.iloc[0]) * 100 if (d.subset == k).any() else np.nan for k, _ in subsets]
    ax.barh(range(len(subsets))[::-1], vals, color=[MUTED] + [BLUE] * (len(subsets) - 1), height=0.62)
    for i, v in enumerate(vals):
        ax.text(v + 0.4, len(subsets) - 1 - i, f"{v:.1f}%", va="center", fontsize=7, color=INK2)
    ax.set_yticks(range(len(subsets))[::-1]); ax.set_yticklabels([lab for _, lab in subsets])
    ax.set_xlabel("Files that are byte-identical copies in another repository (%)")
    save(fig, "fig_copying")


if __name__ == "__main__":
    for f in (fig_adoption, fig_mcp, fig_signals, fig_autonomy, fig_copying):
        f()
