"""Auto-fixers for GitHub Actions workflows. Default mode is a dry-run (diff only).

The fixers are deliberately conservative: when a change could break a workflow (for
example removing credentials from a job that pushes) the fix is skipped and a note is
reported instead of silently rewriting the file.
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess  # nosec B404
import urllib.request
from pathlib import Path

from .rules import (
    GIT_WRITE_HINT,
    SHA_RE,
    USES_RE,
    WRITE_PERM_HINT,
    job_key_line,
    job_lines_for,
    jobs_of,
    needs_toplevel_permissions,
    step_range,
)

DEFAULT_ONLY = ("permissions", "timeouts", "persist")
ALL_FIXES = (*DEFAULT_ONLY, "pin")
_CACHE: dict[tuple[str, str], str | None] = {}
FAILED: list[str] = []   # actions that could not be resolved (offline / rate-limited)


def _api_sha(repo: str, ref: str) -> str | None:
    headers = {"Accept": "application/vnd.github.sha", "User-Agent": "pipelineguard"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    # fixed https host; repo/ref are validated by resolve_sha()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/commits/{ref}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            sha = resp.read().decode().strip()
    except (OSError, ValueError):
        return None
    return sha if SHA_RE.match(sha) else None


def _git_sha(repo: str, ref: str) -> str | None:
    """Fallback that needs no API quota: `git ls-remote` against github.com."""
    git = shutil.which("git")
    if not git:
        return None
    cmd = [git, "ls-remote", f"https://github.com/{repo}.git",
           f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"]
    try:
        # fixed binary, validated arguments, no shell
        out = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=25, check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    found = {}
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if SHA_RE.match(sha):
            found[name] = sha
    for name in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"):
        if name in found:      # peeled tag first: annotated tags point at a tag object
            return found[name]
    return None


def resolve_sha(repo: str, ref: str) -> str | None:
    """Resolve owner/repo@ref to a commit SHA (GitHub API, then `git ls-remote`)."""
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or not re.fullmatch(r"[\w./-]+", ref):
        return None
    if (repo, ref) in _CACHE:
        return _CACHE[(repo, ref)]
    sha = _api_sha(repo, ref) or _git_sha(repo, ref)
    _CACHE[(repo, ref)] = sha
    if sha is None:
        FAILED.append(f"{repo}@{ref}")
    return sha


def fix_pin(lines, resolver):
    out = []
    for line in lines:
        m = None if line.lstrip().startswith("#") else USES_RE.match(line)
        if m and not m.group(1).startswith((".", "docker://")) and not SHA_RE.match(m.group(2)):
            name, ref = m.groups()
            sha = resolver("/".join(name.split("/")[:2]), ref)
            if sha:
                line = line.replace(f"@{ref}", f"@{sha}", 1)
                if "#" not in line:
                    line = f"{line}  # {ref}"
        out.append(line)
    return out


def fix_timeouts(lines, minutes: int = 15) -> None:
    inserts = []
    for _, s, e in jobs_of(lines):
        if job_key_line(lines, s, e, "timeout-minutes") is not None:
            continue
        k = job_key_line(lines, s, e, "runs-on")
        if k is not None:     # insert *before* runs-on: works for scalar, list and map forms
            ln = lines[k]
            inserts.append((k, " " * (len(ln) - len(ln.lstrip())) + f"timeout-minutes: {minutes}"))
    for pos, text in sorted(inserts, reverse=True):
        lines.insert(pos, text)


def fix_persist(lines, notes: list[str] | None = None) -> None:
    notes = notes if notes is not None else []
    inserts = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(-\s*)?uses:\s*['\"]?actions/checkout@", line)
        if not m:
            continue
        key_col = len(m.group(1)) + len(m.group(2) or "")
        a, b = step_range(lines, i)
        if any("persist-credentials" in ln for ln in lines[a:b]):
            continue
        if GIT_WRITE_HINT.search("\n".join(job_lines_for(lines, i))):
            notes.append(f"line {i + 1}: left checkout alone (the job uses git push/fetch/commit "
                         "and needs the credentials)")
            continue
        flow = next((j for j in range(a, b)
                     if len(lines[j]) - len(lines[j].lstrip()) == key_col
                     and re.match(r"^\s*with:\s*\{.*\}\s*(#.*)?$", lines[j])), None)
        if flow is not None:
            fm = re.match(r"^(\s*)with:\s*\{(.*)\}\s*(#.*)?$", lines[flow])
            inner = fm.group(2).strip()
            new_inner = (inner + ", " if inner else "") + "persist-credentials: false"
            comment = f"  {fm.group(3)}" if fm.group(3) else ""
            lines[flow] = f"{fm.group(1)}with: {{ {new_inner} }}{comment}"
            continue
        w = next((j for j in range(a, b)
                  if len(lines[j]) - len(lines[j].lstrip()) == key_col
                  and re.match(r"^\s*with:\s*(#.*)?$", lines[j])), None)
        if w is None:
            if any(ln.strip().startswith("with:") for ln in lines[a:b]):
                notes.append(f"line {i + 1}: `with:` has an unusual form; add "
                             "persist-credentials: false by hand")
                continue
            pad = " " * key_col
            inserts.append((i + 1, [f"{pad}with:", f"{pad}  persist-credentials: false"]))
        else:
            nxt = next((ln for ln in lines[w + 1:b] if ln.strip()), "")
            child = len(nxt) - len(nxt.lstrip())
            child = child if child > key_col else key_col + 2
            inserts.append((w + 1, [" " * child + "persist-credentials: false"]))
    for pos, new in sorted(inserts, reverse=True):
        lines[pos:pos] = new


def fix_permissions(lines, notes: list[str] | None = None) -> None:
    notes = notes if notes is not None else []
    if not needs_toplevel_permissions(lines):
        return
    if WRITE_PERM_HINT.search("\n".join(lines)):
        notes.append("no top-level `permissions:` added: the workflow pushes, uses a token, "
                     "calls other workflows or publishes - choose the minimal scopes by hand")
        return
    idx = next((i for i, ln in enumerate(lines) if re.match(r"^jobs:", ln)), None)
    if idx is not None:
        lines[idx:idx] = ["permissions:", "  contents: read", ""]


def fix_text(text: str, only, resolver=None, notes: list[str] | None = None) -> str:
    notes = notes if notes is not None else []
    nl = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    if "pin" in only and resolver:
        lines = fix_pin(lines, resolver)
    if "persist" in only:
        fix_persist(lines, notes)
    if "timeouts" in only:
        fix_timeouts(lines)
    if "permissions" in only:
        fix_permissions(lines, notes)
    out = nl.join(lines)
    return out + nl if text.endswith("\n") else out


def fix_paths(root: str, only=DEFAULT_ONLY, pin: bool = False, write: bool = False,
              resolver=resolve_sha, notes: list[str] | None = None) -> list[tuple[str, str]]:
    """Return [(relative_path, unified_diff)] for files that change; write if asked.

    Human-readable reasons for skipped fixes are appended to `notes` when given.
    """
    wanted = set(only) | ({"pin"} if pin else set())
    base = Path(root).resolve()
    wf_dir = base / ".github" / "workflows"
    results: list[tuple[str, str]] = []
    if not wf_dir.is_dir():
        return results
    for path in sorted([*wf_dir.glob("*.yml"), *wf_dir.glob("*.yaml")]):
        rel = path.relative_to(base).as_posix()
        try:
            old = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            if notes is not None:
                notes.append(f"{rel}: skipped ({type(exc).__name__})")
            continue
        file_notes: list[str] = []
        new = fix_text(old, wanted, resolver, file_notes)
        if notes is not None:
            notes += [f"{rel}: {n}" for n in dict.fromkeys(file_notes)]
        if new == old:
            continue
        diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                            f"a/{rel}", f"b/{rel}"))
        results.append((rel, diff))
        if write:
            path.write_bytes(new.encode("utf-8"))
    return results
