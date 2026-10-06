"""Detection rules for CI/CD pipelines, Dockerfiles and committed secrets."""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
IGNORE_MARK = "pipelineguard:ignore"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str
    fix: str

    def to_dict(self) -> dict:
        return asdict(self)


RULE_TITLES = {
    "PG001": "Action not pinned to a commit SHA",
    "PG002": "Dangerous pull_request_target usage",
    "PG003": "Script injection via untrusted context",
    "PG004": "Missing or overly broad workflow permissions",
    "PG005": "Remote script piped into a shell",
    "PG006": "Hardcoded secret",
    "PG007": "Self-hosted runner",
    "PG008": "Unsecure workflow commands enabled",
    "PG009": "Job has no timeout-minutes",
    "PG010": "checkout persists credentials",
    "PG011": "secrets: inherit passes every secret",
    "PG012": "Unpinned container image (latest / untagged)",
    "PG013": "Container runs as root",
}

# Highest severity each rule can report (used for SARIF `security-severity`).
RULE_SEVERITY = {
    "PG001": "high", "PG002": "critical", "PG003": "high", "PG004": "high",
    "PG005": "high", "PG006": "critical", "PG007": "medium", "PG008": "high",
    "PG009": "low", "PG010": "low", "PG011": "medium", "PG012": "medium",
    "PG013": "low",
}

USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MUTABLE_REFS = {"main", "master", "latest", "develop", "dev", "head"}
TRUSTED_OWNERS = {"actions", "github"}

# ---------------------------------------------------------------- injection (PG003)
_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}")
_PEOPLE = r"(?:author|committer)\.(?:name|email)"
_UNTRUSTED_PATH = re.compile(
    r"\bgithub\.(?:head_ref\b"
    r"|event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))"
    r"|(?:comment|review|review_comment)\.body"
    r"|discussion\.(?:title|body)"
    r"|release\.(?:name|body)"
    r"|pages\.page_name"
    r"|(?:commits|head_commit)\.(?:message|" + _PEOPLE + r")"
    r"|workflow_run\.(?:head_branch|display_title"
    r"|head_commit\.(?:message|" + _PEOPLE + r")|pull_requests\.head\.ref)"
    r"))"
)


def has_untrusted_context(line: str) -> bool:
    """True when a `${{ ... }}` expression on the line reads attacker-controlled data."""
    for m in _EXPR_RE.finditer(line):
        expr = re.sub(r"\[\s*['\"](\w+)['\"]\s*\]", r".\1", m.group(1))   # ['issue'] -> .issue
        expr = re.sub(r"\[[^\]]*\]", "", expr)                           # commits[0] -> commits
        if _UNTRUSTED_PATH.search(expr):
            return True
    return False


# ------------------------------------------------------------ remote exec (PG005)
_SH = r"(?:ba|z|da|k|a)?sh"
_FETCH = r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)"
_INTERP = rf"(?:{_SH}|python[\d.]*|perl|ruby|node|iex|Invoke-Expression)"
REMOTE_EXEC = [
    # curl ... | [sudo -E] [/bin/]bash   (also through tee / extra pipes)
    re.compile(rf"\b{_FETCH}\b[^\n;]*?(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\S+\s+)*)?"
               rf"(?:env\s+(?:\S+=\S+\s+)*)?(?:/\S+/)?{_INTERP}\b", re.I),
    # bash <(curl ...)
    re.compile(rf"\b{_SH}\s+(?:-\S+\s+)*<\(\s*{_FETCH}\b", re.I),
    # eval "$(curl ...)" / source <(curl ...)
    re.compile(rf"\b(?:eval|source)\s+[\"']?(?:<\(|\$\()\s*{_FETCH}\b", re.I),
    # sh -c "$(curl ...)"
    re.compile(rf"\b{_SH}\s+(?:-\S+\s+)*[\"']?\$\(\s*{_FETCH}\b", re.I),
    # . <(curl ...)
    re.compile(rf"(?:^|\s)\.\s+<\(\s*{_FETCH}\b", re.I),
    # iex (iwr ...)
    re.compile(r"\b(?:iex|Invoke-Expression)\b[^\n]*"
               r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b", re.I),
]


def is_remote_exec(line: str) -> bool:
    return any(rx.search(line) for rx in REMOTE_EXEC)


# ---------------------------------------------------------------- pull_request_target
_REF_LINE = re.compile(r"^\s*(?:-\s*)?(?:ref|repository)\s*:\s*(.*)$")
_HEAD_VALUE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.head_ref|refs/pull/"
    r"|github\.event\.(?:pull_request\.)?number|github\.event\.workflow_run\.head_")
_GIT_CHECKOUT = re.compile(r"\bgit\s+(?:checkout|fetch|pull|clone|switch)\b|\bgh\s+pr\s+checkout\b")

# Jobs that legitimately need git credentials / write tokens (used by PG010 and the fixer).
GIT_WRITE_HINT = re.compile(
    r"\bgit\s+(?:push|commit|tag|merge|rebase|pull|fetch|submodule|lfs|am|cherry-pick)\b"
    r"|EndBug/add-and-commit|git-auto-commit-action|peter-evans/create-pull-request"
    r"|ad-m/github-push-action|github-pages-deploy-action|peaceiris/actions-gh-pages"
    r"|release-please|semantic-release|changesets/action", re.I)
WRITE_PERM_HINT = re.compile(
    GIT_WRITE_HINT.pattern
    + r"|\bgh\s+\w+|GITHUB_TOKEN|github-script|action-gh-release|actions/create-release"
    r"|actions/deploy-pages|actions/labeler|actions/stale|attest-build-provenance"
    r"|id-token|upload-sarif|ghcr\.io|docker/login-action|packages:"
    r"|dependabot/fetch-metadata|^\s+uses:\s*\./\.github/workflows/", re.I | re.M)

# ---------------------------------------------------------------------- secrets
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{50,}"), "critical"),
    ("GitLab token", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "critical"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "critical"),
    ("Slack webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
     "high"),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY"
                r"(?: BLOCK)?-----"), "critical"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "critical"),
    ("Stripe live key", re.compile(r"[sr]k_live_[0-9a-zA-Z]{20,}"), "critical"),
    ("SendGrid key", re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), "critical"),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}"), "critical"),
    ("PyPI token", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"), "critical"),
]
AWS_SECRET = re.compile(
    r"(?i)aws_?secret_?(?:access_?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"
    r"(?![A-Za-z0-9/+=])")
DB_URL = re.compile(
    r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@'\"<>${}]+:([^\s@'\"/<>${}]{3,})@[^\s'\"]+", re.I)
BEARER = re.compile(r"(?i)\b(?:bearer|token|basic)\s+([A-Za-z0-9._~+/=\-]{20,})")

_KEY_WORDS = (r"(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token"
              r"|auth[_-]?token|private[_-]?key|client[_-]?secret)")
GENERIC_SECRET = re.compile(
    r"""(?i)(?:^|[\s"'{,(])([\w.-]{0,40}""" + _KEY_WORDS + r"""[\w.-]{0,40})["']?\s*[:=]\s*"""
    r"""(?:"([^"\s]{8,200})"|'([^'\s]{8,200})'|([^\s"'#,;)]{10,200}))""")
KEY_EXCLUDE = re.compile(
    r"(?i)(?:name|id|arn|path|file|ref|version|length|policy|manager|store|type|field"
    r"|label|prompt|hint|env)$")
PLACEHOLDER = re.compile(
    r"(?i)(?<![a-z])(?:example|changeme|placeholder|dummy|sample|test|xxx+)(?![a-z])"
    r"|your[_-]|\*{3,}|^<.*>$|^(?:pass(?:word|wd)?|secret|token)$")
REFERENCE = re.compile(
    r"(?i)^\$|^\{\{|^%|^<.*>$|process\.env|os\.environ|getenv|\bsecrets\.|\bvars\.|\bvault\b"
    r"|\bkms\b|\.\.\.|^(?:\.{0,2}/|~/)[\w./-]+$")
_UNQUOTED_EXT = {".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml",
                 ".sh", ".bash", ".tfvars", ".txt", ""}
MAX_GENERIC_LINE = 1000

FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
IMAGE_RE = re.compile(r"^\s*-?\s*image:\s*['\"]?([^\s'\"$]+)")
CONTAINER_RE = re.compile(r"^\s*container:\s*['\"]?([^\s'\"{$]+)")


_SELF_HOSTED_FIX = "Use ephemeral runners and never expose them to fork PRs."


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _unquoted_allowed(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if name == ".env" or name.startswith(".env."):
        return True
    dot = name.rfind(".")
    return (name[dot:] if dot > 0 else "") in _UNQUOTED_EXT


def _generic_spans(line: str, unquoted_ok: bool, strict: bool = True) -> Iterator[tuple[int, int]]:
    """Yield (start, end) of values that look like hardcoded credentials."""
    if len(line) > MAX_GENERIC_LINE:
        return
    for m in GENERIC_SECRET.finditer(line):
        if KEY_EXCLUDE.search(m.group(1)):
            continue
        idx = next(i for i in (2, 3, 4) if m.group(i) is not None)
        value = m.group(idx)
        if idx == 4:                                    # unquoted
            bad = (not unquoted_ok or not re.search(r"[A-Za-z]", value)
                   or not re.search(r"\d", value) or re.search(r"[()\[\]<>{}!@&*]", value[:1])
                   or re.search(r"[()\[\]<>{}]", value))
            if bad:
                continue
        if strict and (REFERENCE.search(value) or PLACEHOLDER.search(value)):
            continue
        yield m.start(idx), m.end(idx)


def redact(line: str) -> str:
    """Mask every credential-looking token on the line (known formats and heuristics)."""
    spans: list[tuple[int, int, int]] = []
    for _, rx, _ in SECRET_PATTERNS:
        spans += [(m.start(), m.end(), 4) for m in rx.finditer(line)]
    for rx in (AWS_SECRET, DB_URL, BEARER):
        spans += [(m.start(1), m.end(1), 0) for m in rx.finditer(line)]
    spans += [(s, e, 0) for s, e in _generic_spans(line, True, strict=False)]
    if not spans:
        return line
    spans.sort()
    out, pos = [], 0
    for s, e, keep in spans:
        if s < pos:
            continue
        out.append(line[pos:s])
        out.append((line[s:s + keep] if e - s > 8 else "") + "…[REDACTED]")
        pos = e
    out.append(line[pos:])
    return "".join(out)


def _make_add(rel, lines, out):
    def add(rid, sev, n, fix, title=None):
        text = lines[n - 1] if 0 < n <= len(lines) else ""
        if IGNORE_MARK in text:
            return
        out.append(Finding(rid, sev, title or RULE_TITLES[rid], rel, n,
                           redact(text).strip()[:160], fix))
    return add


def _block_lines(lines, keys=("run",)) -> Iterator[tuple[int, str, str]]:
    """Yield (lineno, text, key) for every line that belongs to a `run:`/`script:` value."""
    key_rx = re.compile(r"^\s*(?:-\s*)?(" + "|".join(keys) + r"):\s*(.*)$")
    block_col, block_key = None, ""
    for i, line in enumerate(lines, 1):
        if block_col is not None:
            if not line.strip() or _indent(line) > block_col:
                yield i, line, block_key
                continue
            block_col = None
        m = key_rx.match(line)
        if not m:
            continue
        rest = m.group(2).strip()
        if rest[:1] in ("|", ">"):
            block_col, block_key = line.index(m.group(1) + ":"), m.group(1)
        elif rest:
            yield i, line, m.group(1)


def _join_continuations(items):
    """Merge shell lines ending in a backslash into one logical line (keeps first lineno)."""
    buf, start, key = "", 0, ""
    for i, text, k in items:
        if not buf:
            start, key = i, k
        buf += text.rstrip()[:-1] + " " if text.rstrip().endswith("\\") else text
        if not text.rstrip().endswith("\\"):
            yield start, buf, key
            buf = ""
    if buf:
        yield start, buf, key


def jobs_of(lines):
    """Return [(name, first_line, last_line)] (1-indexed) for each job."""
    idx = next((i for i, ln in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", ln)), None)
    if idx is None:
        return []
    starts, child, stop = [], None, len(lines)
    for i in range(idx + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        ind = _indent(line)
        if ind == 0:
            stop = i
            break
        child = ind if child is None else child
        m = re.match(r"^\s+([\w.-]+):\s*(?:#.*)?$", line)
        if ind == child and m:
            starts.append((m.group(1), i + 1))
    return [(name, s, starts[n + 1][1] - 1 if n + 1 < len(starts) else stop)
            for n, (name, s) in enumerate(starts)]


def job_key_line(lines, s, e, key):
    """0-based index of the job-level `key:` line of the job spanning (s, e), else None."""
    body = lines[s:e]
    child = next((_indent(ln) for ln in body
                  if ln.strip() and not ln.lstrip().startswith("#")), None)
    if child is None:
        return None
    rx = re.compile(rf"^\s*{re.escape(key)}\s*:")
    for k, ln in enumerate(body):
        if _indent(ln) == child and rx.match(ln):
            return s + k
    return None


def job_lines_for(lines, idx):
    """Lines of the job containing 0-based line idx (whole file when no job matches)."""
    for _, s, e in jobs_of(lines):
        if s - 1 <= idx < e:
            return lines[s - 1:e]
    return lines


def step_range(lines, i):
    """Slice bounds (start, end) of the lines that belong to the step at index i."""
    base = _indent(lines[i])
    j = i + 1
    while j < len(lines):
        ln = lines[j]
        if ln.strip():
            ind = _indent(ln)
            if ind < base or (ind <= base and re.match(r"^\s*-\s", ln)):
                break
        j += 1
    return i + 1, j


def needs_toplevel_permissions(lines) -> bool:
    if any(re.match(r"^permissions\s*:", ln) for ln in lines):
        return False
    jobs = jobs_of(lines)
    if not jobs:
        return False
    return not all(job_key_line(lines, s, e, "permissions") is not None for _, s, e in jobs)


def _unpinned_image(img: str, stages=()) -> bool:
    tail = img.split("/")[-1]
    if img.lower() == "scratch" or img.startswith("$") or "@sha256:" in img \
            or img.lower() in stages:
        return False
    return ":" not in tail or tail.endswith(":latest")


def _check_uses(lines, add) -> None:
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        d = re.match(r"^\s*-?\s*uses:\s*['\"]?docker://(\S+?)['\"]?\s*(?:#.*)?$", line)
        if d:                                                            # PG012 (docker://)
            if _unpinned_image(d.group(1)):
                add("PG012", "medium", i, "Pin the image to a version tag or @sha256 digest.")
            continue
        m = USES_RE.match(line)
        if not m:
            continue
        name, ref = m.groups()
        if name.startswith("./") or SHA_RE.match(ref):
            continue
        owner = name.split("/")[0].lower()
        sev = ("high" if ref.lower() in MUTABLE_REFS
               else "low" if owner in TRUSTED_OWNERS else "medium")
        add("PG001", sev, i,
            f"Pin {name} to a full 40-char commit SHA (keep the tag as a comment).")


def _check_scripts(lines, add) -> None:
    for i, line, key in _join_continuations(_block_lines(lines, ("run", "script"))):
        if has_untrusted_context(line):                                  # PG003
            add("PG003", "high", i, "Pass the value through an env: variable and "
                "reference it as \"$VAR\" in the script.")
        if key == "run" and is_remote_exec(line):                        # PG005
            add("PG005", "high", i, "Download, verify a checksum/signature, then execute.")


def _prt_checks_out_head(lines) -> bool:
    run_lines = {i for i, _, _ in _block_lines(lines)}
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        m = _REF_LINE.match(line)
        if m and _HEAD_VALUE.search(m.group(1)):
            return True
        if i in run_lines and _GIT_CHECKOUT.search(line) and _HEAD_VALUE.search(line):
            return True
    return False


def check_workflow(rel: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    add = _make_add(rel, lines, out)

    _check_uses(lines, add)                                              # PG001
    _check_scripts(lines, add)                                           # PG003 / PG005

    prt = next((i for i, ln in enumerate(lines, 1)                       # PG002
                if "pull_request_target" in ln and not ln.lstrip().startswith("#")), None)
    if prt:
        head = _prt_checks_out_head(lines)
        add("PG002", "critical" if head else "high", prt,
            "Never check out PR head code in pull_request_target; use pull_request "
            "or a two-stage workflow_run pattern.",
            "pull_request_target checks out untrusted PR code" if head else None)

    if needs_toplevel_permissions(lines):                                # PG004
        add("PG004", "medium", 1, "Add a top-level `permissions: contents: read` "
            "and grant more per job only when needed.",
            "No top-level permissions block (defaults may be too broad)")

    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        if re.match(r"^\s*permissions:\s*write-all", line):              # PG004
            add("PG004", "high", i, "Replace write-all with the minimal scopes required.")
        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*['\"]?true", line):   # PG008
            add("PG008", "high", i, "Remove it; migrate to $GITHUB_ENV / $GITHUB_PATH files.")
        if re.match(r"^\s+secrets:\s*inherit\b", line):                  # PG011
            add("PG011", "medium", i, "Pass only the specific secrets the called workflow needs.")
        c = CONTAINER_RE.match(line) or IMAGE_RE.match(line)             # PG012
        if c and _unpinned_image(c.group(1)):
            add("PG012", "medium", i, "Pin the image to a version tag or @sha256 digest.")
        r = re.match(r"^(\s*)runs-on:\s*(.*)$", line)                    # PG007
        if r:
            val = r.group(2).split("#")[0]
            if "self-hosted" in val:
                add("PG007", "medium", i, _SELF_HOSTED_FIX)
            elif not val.strip():                                        # block / list form
                j = i
                while j < len(lines) and (not lines[j].strip()
                                          or _indent(lines[j]) > len(r.group(1))):
                    if "self-hosted" in lines[j].split("#")[0]:
                        add("PG007", "medium", i, _SELF_HOSTED_FIX)
                        break
                    j += 1

    for name, s, e in jobs_of(lines):                                    # PG009
        if job_key_line(lines, s, e, "runs-on") is not None \
                and job_key_line(lines, s, e, "timeout-minutes") is None:
            add("PG009", "low", s,
                f"Add `timeout-minutes` to job '{name}' to stop runaway builds.")

    for i, line in enumerate(lines):                                     # PG010
        if re.match(r"^\s*(?:-\s*)?uses:\s*['\"]?actions/checkout@", line):
            a, b = step_range(lines, i)
            if any("persist-credentials" in ln for ln in lines[a:b]):
                continue
            if GIT_WRITE_HINT.search("\n".join(job_lines_for(lines, i))):
                continue                      # the job pushes/fetches: credentials are needed
            add("PG010", "low", i + 1,
                "Add `with: persist-credentials: false` unless the job must push.")
    return out


def check_action(rel: str, text: str) -> list[Finding]:
    """Composite action definitions (action.yml): unpinned uses + script injection."""
    lines = text.splitlines()
    out: list[Finding] = []
    if not any(re.match(r"^\s*using:\s*['\"]?composite", ln) for ln in lines):
        return out
    add = _make_add(rel, lines, out)
    _check_uses(lines, add)
    _check_scripts(lines, add)
    return out


def _logical_lines(lines):
    """Join Dockerfile continuation lines; yield (first_lineno, text)."""
    buf, start = "", 0
    for i, ln in enumerate(lines, 1):
        if not buf:
            start = i
        stripped = ln.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        yield start, buf + ln
        buf = ""
    if buf:
        yield start, buf


def check_dockerfile(rel: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    add = _make_add(rel, lines, out)
    stages, last_from = set(), None
    for i, line in _logical_lines(lines):
        m = FROM_RE.match(line)
        if m:
            img, alias = m.group(1), m.group(2)
            last_from = i
            if _unpinned_image(img, stages):
                add("PG012", "medium", i, "Pin the base image to a version tag or @sha256 digest.")
            if alias:
                stages.add(alias.lower())
        elif re.match(r"^\s*RUN\b", line) and is_remote_exec(line):
            add("PG005", "high", i, "Download, verify a checksum/signature, then execute.")
    if last_from:
        users = [m.group(1).split(":")[0].lower()
                 for _, ln in _logical_lines(lines[last_from:])
                 if (m := re.match(r"^\s*USER\s+(\S+)", ln, re.I))]
        if not users or users[-1] in ("root", "0"):
            add("PG013", "low", last_from, "Add a non-root `USER` before the final CMD/ENTRYPOINT.")
    return out


def check_generic_ci(rel: str, text: str) -> list[Finding]:
    """GitLab CI, Jenkins, Azure Pipelines, CircleCI, Bitbucket, compose: basic checks."""
    lines = text.splitlines()
    out: list[Finding] = []
    add = _make_add(rel, lines, out)
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        if is_remote_exec(line):
            add("PG005", "high", i, "Download, verify a checksum/signature, then execute.")
        m = IMAGE_RE.match(line)
        if m and _unpinned_image(m.group(1)):
            add("PG012", "medium", i, "Pin the image to a version tag or @sha256 digest.")
    return out


def check_secrets(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    unquoted_ok = _unquoted_allowed(rel)
    for i, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line:
            continue
        hit = None
        for name, rx, sev in SECRET_PATTERNS:
            if rx.search(line):
                hit = (name, sev)
                break
        if not hit and AWS_SECRET.search(line):
            hit = ("AWS secret access key", "critical")
        if not hit:
            d = DB_URL.search(line)
            if d and not PLACEHOLDER.search(d.group(1)) and not REFERENCE.search(d.group(1)):
                hit = ("Credentials embedded in URL", "high")
        if not hit and next(_generic_spans(line, unquoted_ok), None):
            hit = ("Hardcoded credential", "medium")
        if hit:
            name, sev = hit
            out.append(Finding("PG006", sev, f"{name} committed to repository", rel, i,
                               redact(line).strip()[:160],
                               "Revoke the credential now, rotate it, and move it to "
                               "GitHub encrypted secrets / a vault."))
    return out
