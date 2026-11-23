# Agent configuration census

A measurement study of the security surface of AI coding-agent configuration files in public
GitHub repositories: AGENTS.md, CLAUDE.md, GEMINI.md, Cursor/Windsurf/Cline rules, Copilot
instructions, MCP server configs and agent permission settings.

## Research questions

| RQ | Topic | What is measured |
|---|---|---|
| RQ1 | Hidden content | Content the agent reads but a reviewer does not see: invisible Unicode (decoded), HTML comments, injection-style text. |
| RQ2 | Autonomy grants | Project settings that pre-approve dangerous actions for anyone who clones the repository. |
| RQ3 | MCP supply chain | Unpinned launches, plain-HTTP remotes, hard-coded secrets (type only), and packages that are missing, removed or flagged as malicious. |
| RQ4 | Inheritance | How configuration, including risky content, is copied across repositories. |

## Pipeline

| Step | Script | Output |
|---|---|---|
| Frame 1 | `src/01_repo_sample.py` | stratified random sample of active repositories |
| Frame 1 | `src/02_trees.py` | which agent files each sampled repository contains |
| Frame 2 | `src/03_code_search.py` | code-search discovery, equal-probability size-bin cluster sample |
| Content | `src/04_fetch.py` | file contents, pinned to the indexed commit and deduplicated by blob SHA |
| Detectors | `src/hidden.py`, `src/configs.py` | pure functions, tested in `tests/` |

To run the tests: `python -m pytest tests`.

## Ethics

- Public data only, read-only API use within documented rate limits.
- Secret values are never stored; only the type of detector that matched.
- Raw content and per-repository lists stay local and are never published.
- Findings are disclosed to repository owners before any identifying publication.
- Only aggregates and code are released.
