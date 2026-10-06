"""Repository scanner: walks a project and applies the rules."""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from .config import load_config
from .rules import (
    RULE_TITLES,
    SEVERITY_ORDER,
    Finding,
    check_action,
    check_dockerfile,
    check_generic_ci,
    check_secrets,
    check_workflow,
)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox",
             ".pytest_cache", ".ruff_cache", ".mypy_cache"}
SKIP_EXT = (".lock", ".min.js", ".svg", ".map", ".sarif")
CI_NAMES = {".gitlab-ci.yml", ".gitlab-ci.yaml", "bitbucket-pipelines.yml",
            "bitbucket-pipelines.yaml", ".drone.yml"}
MAX_BYTES = 1_000_000
WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
# A repo can never score better than this while it has a finding of that severity.
SCORE_CAP = {"critical": 39, "high": 74, "medium": 89}


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    workflows: int = 0
    other_ci: int = 0
    dockerfiles: int = 0
    errors: list[str] = field(default_factory=list)
    # every finding that is not explicitly ignored (before `min_severity` hides some);
    # the score is computed from this list so that hiding findings cannot inflate it.
    scored: list[Finding] | None = None

    @property
    def score(self) -> int:
        pool = self.findings if self.scored is None else self.scored
        score = max(0, 100 - sum(WEIGHTS[f.severity] for f in pool))
        worst = max((SEVERITY_ORDER[f.severity] for f in pool), default=-1)
        for sev, cap in SCORE_CAP.items():
            if worst >= SEVERITY_ORDER[sev]:
                score = min(score, cap)
        return score

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

    def counts(self) -> dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def worst(self) -> int:
        return max((SEVERITY_ORDER[f.severity] for f in self.findings), default=-1)


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return None if b"\0" in data else data.decode("utf-8-sig", errors="ignore")


def _classify(path: Path, low: str) -> str | None:
    posix = path.as_posix()
    yaml = low.endswith((".yml", ".yaml"))
    if "/.github/workflows/" in posix and yaml:
        return "workflow"
    if low in ("action.yml", "action.yaml"):
        return "action"
    if low.startswith("dockerfile") or low.endswith(".dockerfile"):
        return "docker"
    if (low in CI_NAMES or low.startswith(("jenkinsfile", "azure-pipelines"))
            or (yaml and low.startswith(("docker-compose", "compose.")))
            or posix.lower().endswith("/.circleci/config.yml")):
        return "ci"
    return None


def scan(root: str, ignore_rules=(), exclude=(), min_severity: str = "info") -> ScanResult:
    base = Path(root).resolve()
    if not base.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")
    if min_severity not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {min_severity}")
    ignored = {r.upper() for r in ignore_rules}
    unknown = sorted(ignored - set(RULE_TITLES))
    if unknown:
        raise ValueError(f"Unknown rule id(s): {', '.join(unknown)}")
    res = ScanResult(root=str(base))
    for dirpath, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs
                         if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for name in sorted(files):
            path = Path(dirpath) / name
            rel = path.relative_to(base).as_posix()
            if name.lower().endswith(SKIP_EXT) or any(fnmatch.fnmatch(rel, p) for p in exclude):
                continue
            text = _read(path)
            if text is None:
                continue
            res.files_scanned += 1
            kind = _classify(path, name.lower())
            try:
                if kind == "workflow":
                    res.workflows += 1
                    res.findings += check_workflow(rel, text)
                elif kind == "action":
                    res.other_ci += 1
                    res.findings += check_action(rel, text)
                elif kind == "docker":
                    res.dockerfiles += 1
                    res.findings += check_dockerfile(rel, text)
                elif kind == "ci":
                    res.other_ci += 1
                    res.findings += check_generic_ci(rel, text)
                res.findings += check_secrets(rel, text)
            except Exception as exc:  # one bad file must never abort the whole scan
                res.errors.append(f"{rel}: {type(exc).__name__}: {exc}")
    kept = [f for f in res.findings if f.rule_id not in ignored]
    floor = SEVERITY_ORDER[min_severity]
    res.scored = kept
    res.findings = [f for f in kept if SEVERITY_ORDER[f.severity] >= floor]
    res.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return res


def scan_project(root: str, ignore_rules=(), exclude=(), min_severity: str | None = None,
                 use_config: bool = True) -> tuple[ScanResult, dict]:
    """Scan `root` honouring `.pipelineguard.toml`. Returns (result, config)."""
    cfg = load_config(root) if use_config else {}
    result = scan(root,
                  ignore_rules=[*cfg.get("ignore_rules", []), *ignore_rules],
                  exclude=[*cfg.get("exclude", []), *exclude],
                  min_severity=min_severity or cfg.get("min_severity", "info"))
    return result, cfg
