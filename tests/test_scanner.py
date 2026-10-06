import json

import pytest

from pipelineguard.cli import main
from pipelineguard.fixer import fix_paths, fix_text
from pipelineguard.report import to_badge, to_html, to_markdown, to_sarif
from pipelineguard.scanner import scan

BAD = """name: bad
on:
  pull_request_target:
jobs:
  x:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@main
      - run: echo "${{ github.event.pull_request.title }}"
      - run: curl -s https://example.com/x.sh | bash
"""

GOOD = """name: good
on: [push]
permissions:
  contents: read
jobs:
  x:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          persist-credentials: false
      - run: echo ok
"""

PLAIN = """name: plain
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: always()
        with:
          fetch-depth: 0
"""


def make(tmp_path, content, secret=None, files=None):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(content)
    if secret:
        (tmp_path / "config.py").write_text(secret)
    for name, body in (files or {}).items():
        (tmp_path / name).write_text(body)
    return str(tmp_path)


def ids(res):
    return {f.rule_id for f in res.findings}


def test_detects_all_workflow_rules(tmp_path):
    res = scan(make(tmp_path, BAD))
    assert {"PG001", "PG002", "PG003", "PG004", "PG005", "PG007", "PG009", "PG010"} <= ids(res)
    assert res.worst() == 4 and res.grade == "F"


def test_clean_workflow_scores_perfect(tmp_path):
    res = scan(make(tmp_path, GOOD))
    assert res.findings == [] and res.score == 100


def test_job_level_permissions_are_not_flagged(tmp_path):
    wf = GOOD.replace("permissions:\n  contents: read\n", "").replace(
        "    timeout-minutes: 10\n", "    timeout-minutes: 10\n    permissions:\n"
                                     "      contents: read\n")
    assert "PG004" not in ids(scan(make(tmp_path, wf)))


def test_secrets_found_and_redacted(tmp_path):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    res = scan(make(tmp_path, GOOD, f'KEY = "{key}"\n'))
    f = next(x for x in res.findings if x.rule_id == "PG006")
    assert key not in f.snippet and "REDACTED" in f.snippet


def test_generic_credential_and_placeholder(tmp_path):
    real = "pass" + 'word = "Zk9fQ2pLm1xR"\n'
    fake = "pass" + 'word = "changeme-please"\n'
    assert "PG006" in ids(scan(make(tmp_path, GOOD, real)))
    other = tmp_path / "b"
    other.mkdir()
    assert "PG006" not in ids(scan(make(other, GOOD, fake)))


def test_ignore_marker(tmp_path):
    res = scan(make(tmp_path, GOOD.replace("echo ok", "echo ok # pipelineguard:ignore")))
    assert res.findings == []


def test_docker_and_gitlab_rules(tmp_path):
    docker = "FROM python:latest AS b\nFROM b\nRUN curl -s x.sh | sh\n"
    gitlab = "image: node\nscript:\n  - curl -s x.sh | bash\n"
    res = scan(make(tmp_path, GOOD, files={"Dockerfile": docker, ".gitlab-ci.yml": gitlab}))
    assert {"PG012", "PG013", "PG005"} <= ids(res)
    assert res.dockerfiles == 1 and res.other_ci == 1


def test_secrets_inherit(tmp_path):
    wf = GOOD + "  call:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n"
    assert "PG011" in ids(scan(make(tmp_path, wf)))


def test_config_ignore_exclude_and_min_severity(tmp_path):
    p = make(tmp_path, BAD)
    assert "PG007" not in ids(scan(p, ignore_rules=["PG007"]))
    assert scan(p, exclude=[".github/*"]).findings == []
    high_up = {f.severity for f in scan(p, min_severity="high").findings}
    assert high_up <= {"high", "critical"}
    cfg = 'ignore_rules = ["PG007"]\nfail_on = "critical"\n'
    (tmp_path / ".pipelineguard.toml").write_text(cfg)
    assert main(["scan", p]) == 1                      # critical still present
    assert main(["scan", p, "--no-config", "--fail-on", "critical"]) == 1


def test_fix_makes_workflow_clean(tmp_path):
    p = make(tmp_path, PLAIN)
    before = ids(scan(p))
    assert {"PG004", "PG009", "PG010"} <= before
    changes = fix_paths(p, write=True)
    assert changes
    after = scan(p)
    assert not ({"PG004", "PG009", "PG010"} & ids(after))
    assert fix_paths(p) == []                          # idempotent
    text = (tmp_path / ".github/workflows/ci.yml").read_text()
    assert text.count("persist-credentials: false") == 2 and "fetch-depth: 0" in text


def test_fix_pin_with_fake_resolver():
    out = fix_text("jobs:\n  a:\n    steps:\n      - uses: some/action@v2\n", {"pin"},
                   resolver=lambda repo, ref: "a" * 40)
    assert f"some/action@{'a' * 40}  # v2" in out


def test_fix_dry_run_does_not_write(tmp_path, capsys):
    p = make(tmp_path, PLAIN)
    f = tmp_path / ".github/workflows/ci.yml"
    assert main(["fix", p]) == 0
    assert f.read_text() == PLAIN and "dry-run" in capsys.readouterr().out
    assert main(["fix", p, "--write"]) == 0 and f.read_text() != PLAIN
    assert main(["fix", p, "--only", "bogus"]) == 2


def test_reports(tmp_path):
    xss = BAD.replace("echo ok", "x") + "      - run: echo '<script>alert(1)</script>'\n"
    res = scan(make(tmp_path, xss))
    page = to_html(res)
    assert "<script>alert(1)" not in page and "dexelsoftwaresolutions@gmail.com" in page
    assert json.loads(to_sarif(res))["version"] == "2.1.0"
    assert "| Severity |" in to_markdown(res)
    assert to_badge(res).startswith("<svg") and "F " in to_badge(res)


@pytest.mark.parametrize("cmd", [["about"], ["rules"]])
def test_info_commands(cmd, capsys):
    assert main(cmd) == 0
    out = capsys.readouterr().out
    assert "dexelsoftwaresolutions@gmail.com" in out or "PG013" in out


def test_cli_exit_codes(tmp_path):
    p = make(tmp_path, BAD)
    assert main(["scan", p, "--fail-on", "high"]) == 1
    assert main(["scan", str(tmp_path / "nope")]) == 2
