"""Regression tests for every bug found in the v1.1.0 audit."""
import json
import os
import subprocess
import sys

import pytest

from pipelineguard.cli import main
from pipelineguard.config import load_config
from pipelineguard.fixer import fix_paths, fix_text
from pipelineguard.report import to_json, to_sarif, to_text
from pipelineguard.rules import (
    check_dockerfile,
    check_secrets,
    check_workflow,
    has_untrusted_context,
    is_remote_exec,
    redact,
)
from pipelineguard.scanner import ScanResult, scan, scan_project

HDR = ("name: t\non: [push]\npermissions:\n  contents: read\njobs:\n  a:\n"
       "    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n")
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GHP = "ghp_" + "A1b2C3d4E5" * 4


def put(root, files):
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return str(root)


def ids(findings):
    return {f.rule_id for f in findings}


# ------------------------------------------------------------------ B1 crashes
@pytest.mark.parametrize("body", ["", "\n\n", "# only a comment\n"])
def test_empty_workflow_does_not_crash(tmp_path, body):
    root = put(tmp_path, {".github/workflows/x.yml": body})
    res = scan(root)
    assert res.errors == [] and res.findings == []
    assert main(["scan", root, "--fail-on", "critical"]) == 0


def test_one_broken_file_does_not_abort_scan(tmp_path, monkeypatch):
    import pipelineguard.scanner as sc

    def boom(rel, text):
        raise RuntimeError("boom")

    monkeypatch.setattr(sc, "check_workflow", boom)
    root = put(tmp_path, {".github/workflows/x.yml": HDR + "      - run: echo\n",
                          "cfg.py": f'K = "{AWS}"\n'})
    res = scan(root)
    assert res.errors and "boom" in res.errors[0]
    assert "PG006" in ids(res.findings)                # the other file was still scanned
    assert "could not analyse" in to_text(res)
    assert json.loads(to_json(res))["errors"]


def test_internal_error_exits_2_not_1(tmp_path, monkeypatch):
    import pipelineguard.cli as cli

    def boom(*a, **k):
        raise RuntimeError("kaput")

    monkeypatch.setattr(cli, "scan_project", boom)
    assert main(["scan", str(tmp_path)]) == 2


# ----------------------------------------------------------------- B2 fixer safety
PUSH_WF = ("name: bump\non: [workflow_dispatch]\njobs:\n  bump:\n    runs-on: ubuntu-latest\n"
           "    steps:\n      - uses: actions/checkout@v4\n"
           "      - run: |\n          git commit -am bump\n          git push origin HEAD\n")


def test_fixer_keeps_credentials_for_pushing_jobs():
    notes = []
    out = fix_text(PUSH_WF, {"permissions", "timeouts", "persist"}, notes=notes)
    assert "persist-credentials" not in out
    assert "permissions:" not in out                       # needs write -> not forced read-only
    assert "timeout-minutes: 15" in out                    # the safe fix is still applied
    assert any("git push" in n for n in notes) and any("permissions" in n for n in notes)


def test_fixer_skips_permissions_for_token_users():
    wf = ("name: c\non: [pull_request]\njobs:\n  c:\n    runs-on: ubuntu-latest\n"
          "    steps:\n      - run: gh pr comment 1 --body hi\n        env:\n"
          "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n")
    assert "permissions:" not in fix_text(wf, {"permissions"})


def test_pushing_job_not_flagged_for_persist_credentials():
    assert "PG010" not in ids(check_workflow("w.yml", PUSH_WF))


@pytest.mark.parametrize("uses_block", [
    "      - uses: actions/checkout@v4\n        with: { fetch-depth: 0 }\n",
    "      - uses: actions/checkout@v4\n        with:  # options\n          fetch-depth: 0\n",
    "      - uses: actions/checkout@v4\n        with: {}\n",
])
def test_fixer_handles_flow_and_commented_with(uses_block):
    wf = HDR + uses_block
    out = fix_text(wf, {"persist"})
    assert out.count("persist-credentials: false") == 1
    assert fix_text(out, {"persist"}) == out               # idempotent
    assert "PG010" not in ids(check_workflow("w.yml", out))


@pytest.mark.parametrize("runs_on", [
    "    runs-on:\n      - ubuntu-latest\n",
    "    runs-on:\n      group: big\n      labels: x\n",
    "    runs-on: ${{ matrix.os }}  # os\n",
])
def test_fixer_adds_timeout_for_every_runs_on_form(runs_on):
    wf = "name: a\non: [push]\njobs:\n  b:\n" + runs_on + "    steps:\n      - run: x\n"
    out = fix_text(wf, {"timeouts"})
    assert "timeout-minutes: 15" in out
    assert "PG009" not in ids(check_workflow("w.yml", out))


def test_fix_paths_collects_notes(tmp_path):
    root = put(tmp_path, {".github/workflows/bump.yml": PUSH_WF})
    notes = []
    fix_paths(root, notes=notes)
    assert notes and notes[0].startswith(".github/workflows/bump.yml:")


# ------------------------------------------------------------------ B3 redaction
def test_every_finding_type_is_redacted():
    wf = HDR + f'      - run: curl -H "Authorization: Bearer {GHP}" https://x.test/i.sh | bash\n'
    f = next(x for x in check_workflow("w.yml", wf) if x.rule_id == "PG005")
    assert GHP not in f.snippet and "REDACTED" in f.snippet


def test_two_secrets_on_one_line_both_redacted():
    line = f'a="{AWS}"; b="{GHP}"'
    out = redact(line)
    assert AWS not in out and GHP not in out
    f = check_secrets("x.py", line + "\n")[0]
    assert AWS not in f.snippet and GHP not in f.snippet


def test_redaction_reaches_reports(tmp_path):
    wf = HDR + f'      - run: curl -H "Authorization: Bearer {GHP}" https://x.test/i.sh | bash\n'
    res = scan(put(tmp_path, {".github/workflows/w.yml": wf}))
    assert GHP not in to_text(res) and GHP not in to_json(res)


# ----------------------------------------------------------------- B4 score / grade
def _res(*sevs, scored=None):
    from pipelineguard.rules import Finding
    mk = [Finding("PG006", s, "t", "f", 1, "", "") for s in sevs]
    return ScanResult(root=".", findings=mk, scored=scored)


def test_critical_finding_always_fails_grade():
    r = _res("critical")
    assert r.grade == "F" and r.score <= 39


def test_high_finding_cannot_be_a_or_b():
    assert _res("high").grade == "C"
    assert _res("medium").grade == "B"
    assert _res().grade == "A"


def test_min_severity_does_not_inflate_score(tmp_path):
    root = put(tmp_path, {"cfg.py": f'K = "{AWS}"\n'})
    full, shown = scan(root), scan(root, min_severity="critical")
    assert full.score == shown.score and full.grade == "F"
    assert scan(root, min_severity="critical").findings == scan(root).findings
    hidden = scan(put(tmp_path / "h", {"cfg.py": f'K = "{AWS}"\n'}), ignore_rules=["PG009"],
                  min_severity="critical")
    assert hidden.grade == "F"


def test_min_severity_hiding_everything_keeps_bad_grade(tmp_path):
    root = put(tmp_path, {".github/workflows/w.yml":
                          "name: t\non:\n  pull_request_target:\njobs:\n  a:\n"
                          "    runs-on: self-hosted\n    steps:\n      - run: curl x | bash\n"})
    res = scan(root, min_severity="critical")
    assert res.grade != "A" and res.score == scan(root).score


# --------------------------------------------------- B5 config / GUI shares scan_project
def test_scan_project_honours_config(tmp_path):
    root = put(tmp_path, {".github/workflows/w.yml": "name: t\non: [push]\njobs:\n  a:\n"
                          "    runs-on: self-hosted\n    steps:\n      - run: x\n",
                          ".pipelineguard.toml": 'ignore_rules = ["PG004","PG007","PG009"]\n'})
    res, cfg = scan_project(root)
    assert res.findings == [] and cfg["ignore_rules"] == ["PG004", "PG007", "PG009"]
    assert scan_project(root, use_config=False)[0].findings


def test_config_found_in_parent_folder(tmp_path):
    (tmp_path / ".git").mkdir()
    put(tmp_path, {".pipelineguard.toml": 'fail_on = "critical"\n'})
    sub = tmp_path / "svc"
    sub.mkdir()
    assert load_config(str(sub)) == {"fail_on": "critical"}


# --------------------------------------------------------- B6 scan path variants
@pytest.mark.parametrize("sub", [".", ".github", ".github/workflows"])
def test_workflows_found_whatever_folder_is_scanned(tmp_path, sub):
    put(tmp_path, {".github/workflows/w.yml": "name: t\non: [push]\njobs:\n  a:\n"
                   "    runs-on: self-hosted\n    steps:\n      - uses: some/a@main\n"})
    res = scan(str(tmp_path / sub))
    assert res.workflows == 1 and {"PG001", "PG007"} <= ids(res.findings)


# ------------------------------------------------------------- B7 config validation
@pytest.mark.parametrize("cfg", [
    'fail_on = "hgih"\n', 'min_severity = 3\n', 'ignore_rules = "PG009"\n',
    'exclude = "tests/*"\n', 'ignore_rules = ["PG999"]\n', 'fail_one = "high"\n',
    "this is not toml\n",
])
def test_invalid_config_is_rejected_loudly(tmp_path, cfg):
    put(tmp_path, {".pipelineguard.toml": cfg})
    with pytest.raises(ValueError, match=r"\.pipelineguard\.toml"):
        load_config(str(tmp_path))
    assert main(["scan", str(tmp_path)]) == 2


def test_config_values_are_normalised(tmp_path):
    put(tmp_path, {".pipelineguard.toml": 'fail_on = "HIGH"\nignore_rules = ["pg009"]\n'})
    assert load_config(str(tmp_path)) == {"fail_on": "high", "ignore_rules": ["PG009"]}


def test_unknown_cli_ignore_rule_is_rejected(tmp_path):
    assert main(["scan", str(tmp_path), "--ignore", "PG999"]) == 2


# ------------------------------------------------------- B8 / B9 rule precision
def test_step_level_timeout_does_not_hide_missing_job_timeout():
    wf = ("name: t\non: [push]\npermissions:\n  contents: read\njobs:\n  a:\n"
          "    runs-on: ubuntu-latest\n    steps:\n      - run: sleep 1\n"
          "        timeout-minutes: 1\n")
    assert "PG009" in ids(check_workflow("w.yml", wf))


def test_pg002_head_ref_in_concurrency_is_not_critical():
    wf = ("name: t\non:\n  pull_request_target:\nconcurrency:\n  group: ci-${{ github.head_ref }}\n"
          "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    f = next(x for x in check_workflow("w.yml", wf) if x.rule_id == "PG002")
    assert f.severity == "high"


@pytest.mark.parametrize("ref", [
    "${{ github.event.pull_request.head.sha }}",
    "refs/pull/${{ github.event.pull_request.number }}/merge",
    "${{ format('refs/pull/{0}/head', github.event.number) }}",
])
def test_pg002_critical_for_all_pr_checkout_forms(ref):
    wf = ("name: t\non:\n  pull_request_target:\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
          f"    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: {ref}\n")
    f = next(x for x in check_workflow("w.yml", wf) if x.rule_id == "PG002")
    assert f.severity == "critical"


# ----------------------------------------------------------------- B10 CLI polish
def test_output_to_missing_directory_is_a_clean_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "-o", str(tmp_path / "no" / "dir" / "r.json")]) == 2
    assert "Cannot write" in capsys.readouterr().err


def test_fix_prints_notes_for_skipped_fixes(tmp_path, capsys):
    root = put(tmp_path, {".github/workflows/bump.yml": PUSH_WF})
    assert main(["fix", root]) == 0
    assert "NOTE:" in capsys.readouterr().err


def test_gui_command_without_tkinter(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "pipelineguard.gui", None)    # makes the import fail
    assert main(["gui"]) == 2
    assert "Tkinter" in capsys.readouterr().err


def test_python_m_pipelineguard_runs(tmp_path):
    r = subprocess.run([sys.executable, "-m", "pipelineguard", "scan", str(tmp_path)],
                       capture_output=True, text=True, check=False,
                       env={**os.environ, "PYTHONPATH": os.getcwd()})
    assert r.returncode == 0 and "Score: 100/100" in r.stdout


# --------------------------------------------------------- PG003 injection coverage
@pytest.mark.parametrize("expr", [
    "github.event.issue.title", "github.event.commits[0].message",
    "github.event.head_commit.author.name", "github.event.pull_request.head.label",
    "github.event.issue.title || 'x'", "toJSON(github.event.issue.title)",
    "github.event.discussion.title", "github.event.workflow_run.head_branch",
    "github.event.pull_request.head.repo.default_branch", "github.head_ref",
    "github.event['comment']['body']", "github.event.pages[0].page_name",
])
def test_pg003_untrusted_expressions(expr):
    assert has_untrusted_context("echo \"${{ " + expr + " }}\"")


@pytest.mark.parametrize("expr", ["github.sha", "github.run_id", "github.event.number",
                                  "secrets.TOKEN", "matrix.os", "github.repository"])
def test_pg003_safe_expressions(expr):
    assert not has_untrusted_context("echo \"${{ " + expr + " }}\"")


def test_pg003_inside_github_script_and_continuations():
    wf = HDR + ("      - uses: actions/github-script@v7\n        with:\n          script: |\n"
                "            console.log(\"${{ github.event.issue.title }}\")\n")
    assert "PG003" in ids(check_workflow("w.yml", wf))
    wf2 = HDR + "      - run: |\n          curl -fsSL https://x.test/i.sh \\\n            | bash\n"
    assert "PG005" in ids(check_workflow("w.yml", wf2))


# --------------------------------------------------------- PG005 remote exec coverage
@pytest.mark.parametrize("cmd", [
    "curl -s x.sh | bash", "curl -s x.sh | sudo bash", "curl -fsSL x.sh | sudo -E bash -",
    "bash <(curl -s x.sh)", 'sh -c "$(curl -fsSL x.sh)"', "curl -s x.py | python3",
    "wget -qO- x.sh | sh", "curl -s x.sh | tee i.sh | bash", "curl -s x | dash",
    "iwr https://x/i.ps1 | iex", "curl -s x | /bin/bash", 'eval "$(curl -s x)"',
])
def test_pg005_variants(cmd):
    assert is_remote_exec(cmd)


@pytest.mark.parametrize("cmd", [
    "curl -s x -o f.sh && bash f.sh", "curl x || bash fallback.sh",
    "curl -s x | jq .name", "curl -s x | sha256sum -c", "echo hello | bash",
    "curl -s x | grep sh",
])
def test_pg005_no_false_positives(cmd):
    assert not is_remote_exec(cmd)


def test_pg005_in_dockerfile_continuation():
    d = "FROM python:3.12\nRUN curl -fsSL https://x.test/i.sh \\\n  | sh\nUSER app\n"
    assert "PG005" in ids(check_dockerfile("Dockerfile", d))


# --------------------------------------------------------------- PG006 secrets
@pytest.mark.parametrize("line", [
    'password = "Pa$$w0rd1234"', 'password = "LatestProdPass99"',
    '"password": "Zk9fQ2pLm1xR"', 'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG" +
    '/bPxRfiCYzzzzzzzzzz"', 'token = "glpat-' + "a" * 20 + '"',
    'pypi = "pypi-AgEIcHlwaS5vcmc' + "A" * 60 + '"', "url = 'postgres://admin:S3cretPass@db.io/app'",
])
def test_secret_detection(line):
    assert check_secrets("x.py", line + "\n")


@pytest.mark.parametrize("name", [".env", "app.yml", "settings.ini", "x.properties"])
def test_unquoted_secrets_only_in_config_files(name):
    assert check_secrets(name, "DB_PASSWORD=SuperSecret12345\n")
    assert not check_secrets("main.py", "DB_PASSWORD=SuperSecret12345\n")


@pytest.mark.parametrize("line", [
    'secret: "my-secret-name-in-vault"', 'api_key = "process.env.API_KEY_VALUE"',
    'password = "changeme-please"', "password = get_password(user)",
    'secret_name = "prod-database-credentials"', "secrets: inherit",
    'password: "${DB_PASSWORD}"', "url = 'postgres://user:password@localhost/db'",
    'secret = "/run/secrets/db_password"', "password: !Ref DatabasePassword1",
])
def test_secret_false_positives(line):
    assert check_secrets("app.yml", line + "\n") == []


# ----------------------------------------------------- coverage of other file types
def test_composite_action_is_scanned(tmp_path):
    action = ("name: x\nruns:\n  using: composite\n  steps:\n"
              "    - run: echo \"${{ github.event.issue.title }}\"\n      shell: bash\n"
              "    - uses: foo/bar@main\n")
    res = scan(put(tmp_path, {"action.yml": action, "other/action.yml": "name: js\nruns:\n"
                              "  using: node20\n  main: index.js\n"}))
    assert {"PG001", "PG003"} <= ids(res.findings) and res.other_ci == 2


def test_workflow_container_services_and_compose_images(tmp_path):
    wf = HDR.replace("    steps:\n", "    container:\n      image: node:latest\n"
                     "    services:\n      db:\n        image: postgres\n    steps:\n") \
        + "      - run: echo\n"
    res = scan(put(tmp_path, {".github/workflows/w.yml": wf,
                              "docker-compose.yml": "services:\n  db:\n    image: redis:latest\n"}))
    assert sum(f.rule_id == "PG012" for f in res.findings) == 3


def test_docker_uses_reference_unpinned():
    assert "PG012" in ids(check_workflow("w.yml",
                                         HDR + "      - uses: docker://alpine:latest\n"))


def test_self_hosted_list_form_and_root_user_variants():
    wf = "name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    timeout-minutes: 1\n" \
         "    runs-on:\n      - self-hosted\n      - linux\n    steps:\n      - run: x\n"
    assert "PG007" in ids(check_workflow("w.yml", wf))
    for user in ("root", "0", "root:root", "0:0"):
        assert "PG013" in ids(check_dockerfile("Dockerfile", f"FROM python:3.12\nUSER {user}\n"))
    assert "PG013" not in ids(check_dockerfile("Dockerfile", "FROM python:3.12\nUSER app:app\n"))


# --------------------------------------------------------------- reports / pinning
def test_sarif_has_security_severity():
    r = _res("critical", "low")
    doc = json.loads(to_sarif(r))
    rules = {x["id"]: x for x in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["PG006"]["properties"]["security-severity"] == "9.5"
    assert rules["PG006"]["defaultConfiguration"]["level"] == "error"
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] == 1


def test_sarif_files_are_not_rescanned(tmp_path):
    root = put(tmp_path, {"cfg.py": f'K = "{AWS}"\n'})
    first = scan(root)
    (tmp_path / "pipelineguard.sarif").write_text(to_sarif(first))
    assert scan(root).files_scanned == first.files_scanned


def test_resolve_sha_uses_git_fallback(monkeypatch):
    import pipelineguard.fixer as fx
    monkeypatch.setattr(fx, "_CACHE", {})
    monkeypatch.setattr(fx, "_api_sha", lambda repo, ref: None)
    monkeypatch.setattr(fx, "_git_sha", lambda repo, ref: "b" * 40)
    assert fx.resolve_sha("actions/checkout", "v4") == "b" * 40
    assert fx.resolve_sha("bad repo", "v4") is None


def test_git_sha_prefers_peeled_tag(monkeypatch):
    import pipelineguard.fixer as fx

    class R:
        stdout = ("1" * 40 + "\trefs/tags/v1\n" + "2" * 40 + "\trefs/tags/v1^{}\n")

    monkeypatch.setattr(fx.shutil, "which", lambda _: "/usr/bin/git")
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: R())
    assert fx._git_sha("o/r", "v1") == "2" * 40


def test_utf8_bom_workflow_is_scanned(tmp_path):
    p = tmp_path / ".github" / "workflows"
    p.mkdir(parents=True)
    (p / "w.yml").write_bytes(b"\xef\xbb\xbf" + b"name: t\non: [push]\njobs:\n  a:\n"
                              b"    runs-on: self-hosted\n    steps:\n      - run: x\n")
    assert "PG007" in ids(scan(str(tmp_path)).findings)


# --------------------------------------------------------------------------- GUI
def test_gui_survives_worker_exceptions_and_uses_config(tmp_path):
    tk = pytest.importorskip("tkinter")
    try:
        from pipelineguard.gui import App
        app = App()
    except tk.TclError:
        pytest.skip("no display available")
    import time
    try:
        got = []
        app._bg(lambda: (_ for _ in ()).throw(RuntimeError("worker died")), got.append)
        end = time.time() + 3
        while not got and time.time() < end:
            app.update()
            time.sleep(0.02)
        assert isinstance(got[0], RuntimeError)

        root = put(tmp_path, {".github/workflows/w.yml": "name: t\non: [push]\njobs:\n  a:\n"
                              "    runs-on: self-hosted\n    steps:\n      - run: x\n",
                              ".pipelineguard.toml": 'ignore_rules = ["PG004","PG007","PG009"]\n'})
        app.path.set(root)
        app._scan()
        end = time.time() + 3
        while app.result is None and time.time() < end:
            app.update()
            time.sleep(0.02)
        assert app.result is not None and app.result.findings == []
        assert "disabled" not in app.scan_btn.state()
    finally:
        app.destroy()
