# Changelog

## 1.2.0 - audit fixes
**Bug fixes**
- An empty / comment-only workflow no longer crashes the scan (CLI exit 1 and a frozen GUI);
  a failure in one file is now reported as a warning and the scan continues
- Unexpected errors exit with code 2 instead of 1 (which looked like "findings found");
  clean errors for `-o` to a missing folder, missing Tkinter, bad config, unknown `--ignore` rule
- Secrets are now redacted in *every* finding and for *every* secret on a line
- Score/grade: critical => F, high => at most C, medium => at most B; `--min-severity` no longer inflates it
- GUI honours `.pipelineguard.toml`; worker-thread errors can no longer leave the GUI stuck on "Scanning..."
- Scanning `.github` or `.github/workflows` directly now finds the workflows
- `.pipelineguard.toml` is validated strictly (types, severities, rule ids, unknown keys) and is
  also searched in parent folders; `fail_on`/`min_severity` are case-insensitive
- PG009 looks at job-level `timeout-minutes` only (a step timeout no longer hides it)
- PG002: `head_ref` in `concurrency` is no longer critical; `refs/pull/*/merge` and
  `format('refs/pull/...')` checkouts are now critical
- Auto-fix is safe: it no longer removes credentials from jobs that push/fetch, no longer forces
  read-only `permissions` on workflows that need a token, handles flow-style `with: {}` and
  commented `with:`, and any `runs-on` form; skipped fixes are reported as notes
- PG010 no longer flags jobs that legitimately push

**Detection**
- PG003: many more untrusted contexts (commits, head_commit, discussion, workflow_run, labels,
  `||`/function wrappers, bracket syntax) and `actions/github-script` scripts
- PG005: sudo/env/`/bin/bash`, `bash <(curl)`, `$(curl)`, python/perl/node, tee chains, PowerShell,
  backslash-continued lines, Dockerfile `RUN` continuations; fewer false positives (`|| bash`, `| jq`)
- PG006: `password=`, JSON and unquoted `.env`/YAML secrets, `$` in passwords, GitLab/PyPI/GitHub
  fine-grained tokens, AWS secret keys, DB/URL credentials, Slack webhooks; far fewer false positives
  (vault names, `process.env`, path references, "Latest..." passwords)
- New coverage: composite `action.yml`, `docker-compose`, workflow `container:`/`services:`/`docker://`
  images, `runs-on` list form for self-hosted runners, `USER root:root` / `0:0`

**Other**
- SARIF: `security-severity`, rule levels and help URIs for GitHub Code Scanning
- `fix --pin` falls back to `git ls-remote` when the GitHub API is rate-limited
- Version has a single source (`pipelineguard.__version__`); release checks tag == version
- Release SBOM now describes the checked-out source; pre-commit hook runs on every commit;
  CI skips SARIF upload on fork PRs; every action in this repo is pinned to a commit SHA
- 110+ new regression tests

## 1.1.0
- New: `pipelineguard fix` (dry-run diff, `--write`, optional `--pin` to resolve SHAs)
- New rules PG009 (timeouts), PG010 (persist-credentials), PG011 (secrets: inherit),
  PG012 (unpinned images), PG013 (root containers); generic-credential and more secret patterns
- Dockerfile, GitLab CI, Jenkins, Azure, CircleCI and Bitbucket scanning
- `.pipelineguard.toml` config, `--ignore`, `--exclude`, `--min-severity`
- Markdown report, SVG badge, interactive HTML report with dark mode
- Reusable GitHub Action (`action.yml`) and pre-commit hook
- GUI: filter/search, sortable columns, auto-fix preview, dark mode, Support dialog
- Job-level `permissions` no longer triggers PG004

## 1.0.0
- Initial release
