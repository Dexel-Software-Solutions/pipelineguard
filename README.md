# 🛡️ PipelineGuard

> Security auditor for **CI/CD pipelines**. Most scanners look at your code, PipelineGuard
> looks at the pipeline that builds, tests and ships it, the #1 target of modern supply-chain attacks.

Zero dependencies · Python 3.11+ · CLI + Tkinter GUI · SARIF for GitHub Code Scanning ·
Auto-fix · Reusable GitHub Action

## Features

- **13 rules** for GitHub Actions, Dockerfiles and committed secrets (table below)
- **Also scans** composite `action.yml` files, `docker-compose` files and (with a smaller rule set:
  remote-script execution, unpinned images and secrets) GitLab CI, Jenkinsfile, Azure Pipelines,
  CircleCI and Bitbucket Pipelines
- **Auto-fix** (`pipelineguard fix`): adds `permissions`, job timeouts, `persist-credentials: false`
  and can pin actions to commit SHAs (GitHub API, falling back to `git ls-remote`). Dry-run diff by
  default. Fixes that could break a workflow (e.g. credentials in a job that pushes) are skipped
  and listed as notes.
- **Reports:** text, JSON, SARIF 2.1.0, interactive HTML (filter + dark mode), Markdown, SVG badge
- **Config file** `.pipelineguard.toml`: ignore rules, exclude paths, set thresholds
- **CI quality gate:** non-zero exit code by severity
- **Desktop GUI:** filter, search, sort, auto-fix preview, dark mode, export
- **Reusable GitHub Action** and **pre-commit hook**
- Secrets are **redacted** in every output format (text, JSON, SARIF, HTML, Markdown, GUI)
- **Score & grade:** a critical finding always means grade F, a high finding can never score better
  than C, and `--min-severity` never improves the score

## Rules

| ID | Severity | Issue |
|----|----------|-------|
| PG001 | low-high | Actions not pinned to a commit SHA (mutable `@main` = high) |
| PG002 | high/critical | `pull_request_target` (critical when it checks out PR head code) |
| PG003 | high | Script injection through untrusted `${{ ... }}` (issue/PR/commit/discussion fields, `head_ref`, ...) in `run:` and `github-script` |
| PG004 | medium/high | Missing `permissions:` (top-level or per-job) or `write-all` |
| PG005 | high | `curl \| bash` style remote script execution (sudo, `bash <(curl)`, `$(curl)`, python, PowerShell `iex`, ...) |
| PG006 | medium/critical | Hardcoded secrets and credentials (AWS, GitHub, GitLab, PyPI, Slack, Stripe, npm, DB URLs, `password=`/`.env` values ...) |
| PG007 | medium | Self-hosted runners |
| PG008 | high | `ACTIONS_ALLOW_UNSECURE_COMMANDS` |
| PG009 | low | Job without `timeout-minutes` |
| PG010 | low | `actions/checkout` without `persist-credentials: false` |
| PG011 | medium | `secrets: inherit` |
| PG012 | medium | Container image `latest` or untagged (Dockerfile, compose, workflow `container:`/`services:`, `docker://`) |
| PG013 | low | Dockerfile runs as root |

Suppress one line with a `# pipelineguard:ignore` comment.

## Install & use

```bash
pip install -e .
pipelineguard scan .                                          # text report
pipelineguard scan . -f html -o report.html                   # interactive report
pipelineguard scan . -f sarif -o pg.sarif --fail-on high      # CI gate
pipelineguard scan . --ignore PG009 --exclude "tests/*"
pipelineguard fix .                                           # preview fixes (dry-run)
pipelineguard fix . --write --pin                             # apply + pin SHAs (internet)
pipelineguard scan . -f badge -o badge.svg                    # README badge
pipelineguard rules | about | gui
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` bad input, invalid config or an internal error.
Config example: [`.pipelineguard.toml.example`](.pipelineguard.toml.example). The config file is found in the
scanned folder or any parent up to the repository root and is validated strictly (typos are errors,
not silently ignored). The GUI uses the same config as the CLI.

### Use it in your own pipeline

```yaml
- uses: actions/checkout@v4
- uses: dexel-software-solutions/pipelineguard@v1.2.0
  with:
    fail-on: high
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/dexel-software-solutions/pipelineguard
    rev: v1.2.0
    hooks: [{ id: pipelineguard }]
```

## This repo's own pipeline (dogfooded)

```
push / PR ──► CI ─┬─ ruff + pytest (Linux & Windows, py3.11-3.13)
                  ├─ Bandit · pip-audit · PipelineGuard on itself ─► SARIF ─► Code Scanning
                  └─ reusable action self-test
weekly ───────► CodeQL
tag vX.Y.Z ──► Release ─ PyInstaller (3 OS) ─► SHA256 ─► SBOM ─► SLSA attestation ─► GitHub Release
```
> Every `uses:` in this repo is pinned to a commit SHA (Dependabot keeps them current).

## Limitations

Rules are line/regex based (no full YAML parser), so exotic formatting can be missed and
PG002 inspects the whole file rather than a single job. Secret detection uses known token
formats plus an assignment heuristic (no entropy analysis); unquoted `key=value` secrets are only
reported in config-like files (`.env`, `.yml`, `.ini`, ...). GitLab/Jenkins/Azure/CircleCI/Bitbucket
files get only the generic checks (PG005, PG006, PG012). Treat findings as strong hints and review
auto-fix diffs before committing.

## 💬 Support

Need help, found a false positive, or want a custom feature or integration?

**Dexel Software Solutions**

- 📧 Email: [dexelsoftwaresolutions@gmail.com](mailto:dexelsoftwaresolutions@gmail.com)
- 🐙 GitHub: [github.com/dexel-software-solutions](https://github.com/dexel-software-solutions)
- 🐞 Bugs and feature requests: [open an issue](https://github.com/dexel-software-solutions/pipelineguard/issues)
- 🔒 Security reports: see [SECURITY.md](SECURITY.md)

Inside the app: **Help → Support / Contact**, or run `pipelineguard about`.
If PipelineGuard helps you, a ⭐ on GitHub is the best way to say thanks.

## Development

```bash
pip install -e ".[dev]" && ruff check . && pytest -q
```
See [CONTRIBUTING.md](CONTRIBUTING.md). License: MIT © Dexel Software Solutions.
