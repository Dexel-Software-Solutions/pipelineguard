"""Optional `.pipelineguard.toml` project configuration (strictly validated)."""
from __future__ import annotations

import tomllib
from pathlib import Path

from .rules import RULE_TITLES, SEVERITY_ORDER

CONFIG_NAME = ".pipelineguard.toml"
VALID_KEYS = ("ignore_rules", "exclude", "fail_on", "min_severity")


def find_config(root: str) -> Path | None:
    """Look for the config in `root`, then in parent folders up to the repository root."""
    base = Path(root).resolve()
    for folder in (base, *base.parents):
        cand = folder / CONFIG_NAME
        if cand.is_file():
            return cand
        if (folder / ".git").exists():
            break
    return None


def load_config(root: str) -> dict:
    """Return {ignore_rules, exclude, fail_on, min_severity}; raise ValueError if invalid."""
    path = find_config(root)
    if path is None:
        return {}
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Invalid {CONFIG_NAME} ({path}): {exc}") from exc

    def bad(msg: str) -> ValueError:
        return ValueError(f"Invalid {CONFIG_NAME} ({path}): {msg}")

    unknown = sorted(set(raw) - set(VALID_KEYS))
    if unknown:
        raise bad(f"unknown key(s) {', '.join(unknown)}; valid keys: {', '.join(VALID_KEYS)}")
    cfg: dict = {}
    for key in ("ignore_rules", "exclude"):
        if key in raw:
            val = raw[key]
            if not (isinstance(val, list) and all(isinstance(v, str) for v in val)):
                raise bad(f"`{key}` must be a list of strings, e.g. {key} = [\"...\"]")
            cfg[key] = val
    if "ignore_rules" in cfg:
        cfg["ignore_rules"] = [r.upper() for r in cfg["ignore_rules"]]
        unknown_rules = [r for r in cfg["ignore_rules"] if r not in RULE_TITLES]
        if unknown_rules:
            raise bad(f"unknown rule id(s) in ignore_rules: {', '.join(unknown_rules)}")
    for key in ("fail_on", "min_severity"):
        if key in raw:
            val = raw[key]
            if not (isinstance(val, str) and val.lower() in SEVERITY_ORDER):
                raise bad(f"`{key}` must be one of {', '.join(SEVERITY_ORDER)} (got {val!r})")
            cfg[key] = val.lower()
    return cfg
