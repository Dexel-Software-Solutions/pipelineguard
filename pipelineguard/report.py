"""Report renderers: text, JSON, SARIF 2.1.0, HTML, Markdown and an SVG badge."""
from __future__ import annotations

import html
import json
import re

from . import SUPPORT, __version__
from .rules import RULE_SEVERITY, RULE_TITLES, SEVERITY_ORDER
from .scanner import ScanResult

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}
SECURITY_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
GRADE_COLOR = {"A": "#2ea44f", "B": "#97ca00", "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44"}


def to_text(r: ScanResult) -> str:
    out = [f"PipelineGuard {__version__} - {r.root}",
           (f"Score: {r.score}/100 (grade {r.grade}) | files: {r.files_scanned} | "
            f"workflows: {r.workflows} | dockerfiles: {r.dockerfiles} | "
            f"other CI: {r.other_ci} | findings: {len(r.findings)}"), ""]
    for f in r.findings:
        out.append(f"[{f.severity.upper():8}] {f.rule_id} {f.file}:{f.line}  {f.title}")
        out.append(f"           > {f.snippet}")
        out.append(f"           fix: {f.fix}")
    if r.errors:
        out.append("")
        out += [f"WARNING: could not analyse {e}" for e in r.errors]
    out.append(f"\nSupport: {SUPPORT['email']} | {SUPPORT['github']}")
    return "\n".join(out)


def to_json(r: ScanResult) -> str:
    return json.dumps({"tool": "PipelineGuard", "version": __version__, "root": r.root,
                       "score": r.score, "grade": r.grade, "counts": r.counts(),
                       "files_scanned": r.files_scanned, "errors": r.errors,
                       "findings": [f.to_dict() for f in r.findings]}, indent=2)


def to_sarif(r: ScanResult) -> str:
    worst: dict[str, str] = {}
    for f in r.findings:
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER.get(worst.get(f.rule_id, "info"), -1):
            worst[f.rule_id] = f.severity
    rules = []
    for rid, title in RULE_TITLES.items():
        sev = worst.get(rid, RULE_SEVERITY[rid])
        rules.append({
            "id": rid, "name": rid, "shortDescription": {"text": title},
            "fullDescription": {"text": title},
            "helpUri": f"{SUPPORT['github']}/pipelineguard#rules",
            "defaultConfiguration": {"level": SARIF_LEVEL[sev]},
            "properties": {"security-severity": SECURITY_SCORE[sev],
                           "tags": ["security", "ci-cd"]}})
    results = [{
        "ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title}. Fix: {f.fix}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file},
            "region": {"startLine": max(1, f.line)}}}],
    } for f in r.findings]
    driver = {"name": "PipelineGuard", "version": __version__,
              "informationUri": SUPPORT["github"], "rules": rules}
    return json.dumps({"version": "2.1.0",
                       "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": driver}, "results": results}]}, indent=2)


def to_markdown(r: ScanResult) -> str:
    def cell(s: str) -> str:
        return s.replace("|", "\\|").replace("\n", " ")
    c = r.counts()
    out = ["# PipelineGuard report", "",
           f"**Score:** {r.score}/100 (grade **{r.grade}**) · critical {c['critical']} · "
           f"high {c['high']} · medium {c['medium']} · low {c['low']}", ""]
    if r.findings:
        out += ["| Severity | Rule | Location | Issue | Fix |", "|---|---|---|---|---|"]
        out += [f"| {f.severity} | {f.rule_id} | `{cell(f.file)}:{f.line}` | "
                f"{cell(f.title)} | {cell(f.fix)} |" for f in r.findings]
    else:
        out.append("No findings. ✅")
    if r.errors:
        out += ["", "**Could not analyse:**", *[f"- `{e}`" for e in r.errors]]
    out += ["", f"_Support: {SUPPORT['name']} - {SUPPORT['email']}_"]
    return "\n".join(out)


def to_badge(r: ScanResult) -> str:
    label, value = "pipeline security", f"{r.grade} {r.score}/100"
    lw, vw = 7 * len(label) + 12, 7 * len(value) + 12
    w = lw + vw
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" '
            f'aria-label="{label}: {value}"><rect width="{lw}" height="20" fill="#555"/>'
            f'<rect x="{lw}" width="{vw}" height="20" fill="{GRADE_COLOR[r.grade]}"/>'
            f'<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" '
            f'text-anchor="middle"><text x="{lw / 2}" y="14">{label}</text>'
            f'<text x="{lw + vw / 2}" y="14">{value}</text></g></svg>')


_CSS = """:root{--bg:#fff;--fg:#1f2328;--card:#f6f8fa;--bd:#d0d7de}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--bd:#30363d}}
body{font:14px system-ui,sans-serif;margin:0;background:var(--bg);color:var(--fg)}
main{max-width:1200px;margin:0 auto;padding:24px}[hidden]{display:none!important}
.card{display:flex;gap:20px;align-items:center;background:var(--card);border:1px solid var(--bd);
border-radius:12px;padding:16px 20px;margin:16px 0;flex-wrap:wrap}
.grade{font-size:48px;font-weight:700;width:80px;height:80px;border-radius:50%;display:flex;
align-items:center;justify-content:center;color:#fff}
.g-A{background:#2ea44f}.g-B{background:#97ca00}.g-C{background:#dfb317}.g-D{background:#fe7d37}
.g-F{background:#e05d44}
.b{padding:2px 10px;border-radius:12px;font-weight:600;margin-right:6px;color:#111}
.critical{--c:#f8b4b4}.high{--c:#fcd5b0}.medium{--c:#fdf0b0}.low{--c:#d7ecd0}.b{background:var(--c)}
table{border-collapse:collapse;width:100%}td,th{border:1px solid var(--bd);padding:6px 8px;
text-align:left;vertical-align:top}tbody tr td:first-child{background:var(--c);color:#111;
font-weight:600}code{font-size:12px;word-break:break-all}
.bar{display:flex;gap:8px;margin:12px 0}.bar input,.bar select{padding:6px;background:var(--card);
color:var(--fg);border:1px solid var(--bd);border-radius:6px}.bar input{flex:1}
footer{margin-top:28px;color:gray;font-size:12px}a{color:#0969da}"""

_JS = """const q=document.getElementById('q'),s=document.getElementById('s');
function f(){const t=q.value.toLowerCase(),v=s.value;
document.querySelectorAll('tbody tr').forEach(r=>{
r.hidden=!((!v||r.dataset.sev===v)&&r.textContent.toLowerCase().includes(t))})}
q.oninput=f;s.onchange=f;"""

_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PipelineGuard report</title><style>__CSS__</style>
<main><h1>PipelineGuard report</h1><div>__ROOT__</div>
<div class="card"><div class="grade g-__GRADE__">__GRADE__</div>
<div><h2 style="margin:0">Score __SCORE__/100</h2><p>__META__</p><div>__BADGES__</div></div></div>
<div class="bar"><input id="q" placeholder="Filter findings..."><select id="s">
<option value="">All severities</option><option>critical</option><option>high</option>
<option>medium</option><option>low</option></select></div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Issue</th><th>Code</th>
<th>Fix</th></tr></thead><tbody>__ROWS__</tbody></table>
<footer>Generated by PipelineGuard __VERSION__ · Support: __SUPNAME__ ·
<a href="mailto:__EMAIL__">__EMAIL__</a> · <a href="__GITHUB__">GitHub</a></footer></main>
<script>__JS__</script></html>"""


def to_html(r: ScanResult) -> str:
    e = html.escape
    c = r.counts()
    rows = "".join(
        f"<tr class='{f.severity}' data-sev='{f.severity}'><td>{f.severity}</td>"
        f"<td>{f.rule_id}</td><td>{e(f.file)}:{f.line}</td><td>{e(f.title)}</td>"
        f"<td><code>{e(f.snippet)}</code></td><td>{e(f.fix)}</td></tr>" for f in r.findings)
    badges = "".join(f"<span class='b {k}'>{k} {c[k]}</span>"
                     for k in ("critical", "high", "medium", "low"))
    meta = (f"{r.files_scanned} files · {r.workflows} workflows · {r.dockerfiles} Dockerfiles · "
            f"{r.other_ci} other CI files")
    mapping = {"CSS": _CSS, "JS": _JS, "ROOT": e(r.root), "GRADE": r.grade,
               "SCORE": str(r.score), "META": meta, "BADGES": badges, "ROWS": rows,
               "VERSION": __version__, "SUPNAME": e(SUPPORT["name"]),
               "EMAIL": e(SUPPORT["email"]), "GITHUB": e(SUPPORT["github"])}
    return re.sub(r"__([A-Z]+)__", lambda m: mapping.get(m.group(1), m.group(0)), _PAGE)


RENDERERS = {"text": to_text, "json": to_json, "sarif": to_sarif, "html": to_html,
             "markdown": to_markdown, "badge": to_badge}
