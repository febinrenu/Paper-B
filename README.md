# What the agent reads: security risks in AI coding-agent configuration on GitHub

Code and aggregate data for a measurement study of the security surface of AI coding-agent configuration files in
public GitHub repositories: AGENTS.md, CLAUDE.md, GEMINI.md, Cursor/Windsurf/Cline rules, Copilot instructions, MCP
server configurations and Claude Code permission settings.

The study uses two probability samples:

- **Frame 1** is a stratified cluster sample of 38,623 active public repositories with at least ten stars, which
  gives design-weighted population estimates.
- **Frame 2** is a size-stratified sample of files enumerated through GitHub code search, which gives the scale
  needed for rare content.

On top of the samples it adds an audit of search-index coverage, detectors validated by two blind labellers and a
hold-out sample, and linkage of every launched npm/PyPI package to registry state and OSV malicious-package records.

## Research questions

| RQ | Topic | What is measured |
|---|---|---|
| RQ0 | Adoption | Share of active repositories that ship agent configuration, by type and popularity. |
| RQ1 | Hidden content | Content the agent reads but a reviewer does not see: invisible Unicode (decoded), instruction-like HTML comments, injection-style text. |
| RQ2 | Autonomy grants | Committed settings that pre-approve dangerous actions, by severity; what committed hooks run. |
| RQ3 | MCP supply chain | Pinning of launched packages, plain-HTTP remotes, literal secrets (type only), and launched packages that are unregistered, removed or have malicious-package records. |
| RQ4 | Inheritance | Byte-identical configuration across repositories, copy-family sizes and concentration of risk. |

## Pipeline

| Step | Script | Output |
|---|---|---|
| Frame 1 | `src/01_repo_sample.py` | stratified cluster sample of repositories by creation day |
| Frame 1 | `src/02_trees.py` | agent files in each sampled repository |
| Frame 2 | `src/03_code_search.py` | code-search enumeration, equal-probability size-bin cluster sample |
| Content | `src/04_fetch.py` | file contents at the indexed commit, deduplicated by blob SHA |
| Scan | `src/05_scan.py` | detector flags per file (resumable checkpoints; exact-file-name scope) |
| Estimates | `src/06_stats.py` | Frame 1 and Frame 2 estimates (`tables/b1`–`b7`) |
| Linkage | `src/07_link.py` | registry state and OSV MAL records of launched packages (`b8`) |
| Inheritance | `src/08_inherit.py` | byte-identical copies (`b9`) |
| Validation | `src/09_validation_sheet.py` | labelling sheets and two-labeller scoring (`b10`) |
| Frame checks | `src/12_frame_checks.py` | sample integrity, enumeration completeness, index coverage and coverage bias (`b12`) |
| Dangling names | `src/13_dangling.py` | placeholder / refused / near-miss / other classes (`b13`) |
| Extra analyses | `src/14_extra.py` | design table, hooks, co-occurrence, concentration, sensitivity, popularity, coverage adjustment (`b14`) |
| Figures | `src/11_figures.py` | `figures/` |
| Numbers | `src/10_numbers.py` | every number in the manuscript as a LaTeX macro |

Detectors are pure functions in `src/hidden.py` and `src/configs.py` and are tested in `tests/`
(`python -m pytest tests`). No repository content is ever executed.

## Data

`tables/` holds the aggregate results (CSV) and `figures/` the figures. Raw file contents, per-repository lists and
name-level package data are not published. They identify repositories with unfixed security issues and package names
that an attacker could register. Researchers can obtain them from the corresponding author for verification. The
public table of most-referenced packages withholds names that are unregistered, removed or have malicious-package
records.

## Ethics

- Public data only, read-only API use within documented rate limits.
- Secret values are never stored; only the type of detector that matched.
- Raw content and per-repository lists stay local and are never published.
- Lists of unregistered package names were sent to the npm and PyPI security teams before publication.
- Only aggregates and code are released.

## Authors

Febin K. Renu (corresponding, febink@karunya.edu.in) and Johann Shoni George, Division of Computer Science and
Engineering, Karunya Institute of Technology and Sciences, Coimbatore, India.
