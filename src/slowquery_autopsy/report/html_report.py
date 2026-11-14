"""Static HTML report generation with fully local templates and assets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import AnalysisResult

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
CSS = """
:root { --bg:#f5f2ea; --panel:#fffdf7; --ink:#20241f; --muted:#6c7068;
  --line:#d8d2c4; --accent:#245c4f; --warn:#8a4b1f; --high:#a02f2f; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 "Segoe UI", "Microsoft YaHei", system-ui, sans-serif; }
header, main, footer { max-width:1120px; margin:0 auto; padding:0 24px; }
header { padding-top:36px; padding-bottom:18px; border-bottom:2px solid var(--ink); }
footer { margin-top:36px; padding-top:16px; padding-bottom:32px;
  border-top:1px solid var(--line); color:var(--muted); font-size:12px; }
h1 { font-size:30px; line-height:1.2; margin:6px 0 10px; letter-spacing:-.02em; }
h2 { margin:30px 0 12px; font-size:20px; border-left:4px solid var(--accent); padding-left:10px; }
h3 { margin:20px 0 8px; font-size:16px; }
a { color:var(--accent); text-decoration-thickness:1px; text-underline-offset:2px; }
code { background:#ede8dc; border-radius:3px; padding:1px 4px; font-size:.9em; }
pre { background:#1f2622; color:#f3efe4; padding:16px; overflow:auto;
  border-radius:6px; font-size:13px; line-height:1.5; }
table { width:100%; border-collapse:collapse; background:var(--panel);
  border:1px solid var(--line); margin:10px 0; font-size:13px; }
th, td { border-bottom:1px solid var(--line); padding:8px 10px; text-align:left; vertical-align:top; }
th { background:#e9e3d5; font-weight:600; }
tr:last-child td { border-bottom:0; }
.eyebrow { color:var(--muted); text-transform:uppercase; letter-spacing:.12em;
  font-size:11px; margin:0; }
.muted { color:var(--muted); }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; }
.metric { background:var(--panel); border:1px solid var(--line); padding:14px; border-radius:5px; }
.metric strong { display:block; font-size:24px; color:var(--accent); }
.metric span { color:var(--muted); font-size:12px; }
.sev { font-weight:700; text-transform:uppercase; font-size:11px; }
.sev-critical, .sev-high { color:var(--high); }
.sev-medium { color:var(--warn); }
section { margin-bottom:8px; }
""".strip()


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "htm", "xml", "j2"]),
        keep_trailing_newline=True,
    )


def render_index(result: AnalysisResult) -> str:
    template = _environment().get_template("index.html.j2")
    return template.render(
        css=CSS,
        batch_id=result.batch_id,
        config_hash=result.config_hash,
        input_hash=result.input_hash,
        summary=result.summary,
        clusters=result.clusters,
        findings=result.findings,
        unparsed=result.unparsed,
    )


def render_cluster(result: AnalysisResult, cluster: Any) -> str:
    template = _environment().get_template("cluster.html.j2")
    queries = [query for query in result.queries if query.cluster_id == cluster.fingerprint]
    findings = [
        finding for finding in result.findings
        if finding.cluster_id == cluster.fingerprint
    ]
    return template.render(
        css=CSS,
        batch_id=result.batch_id,
        cluster=cluster,
        queries=queries,
        findings=findings,
    )


def render_detail(result: AnalysisResult, query: Any) -> str:
    template = _environment().get_template("detail.html.j2")
    findings = [finding for finding in result.findings if finding.cluster_id == query.cluster_id]
    plans = [
        plan for plan in result.plans
        if query.cluster_id and plan.linked_cluster_id == query.cluster_id
    ]
    return template.render(
        css=CSS,
        batch_id=result.batch_id,
        query=query,
        findings=findings,
        plans=plans,
    )


def write_html_reports(result: AnalysisResult, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    index_path = output_dir / "index.html"
    index_path.write_text(render_index(result), encoding="utf-8", newline="\n")
    written.append(index_path)
    for cluster in result.clusters:
        path = output_dir / f"cluster-{cluster.fingerprint}.html"
        path.write_text(render_cluster(result, cluster), encoding="utf-8", newline="\n")
        written.append(path)
    for query in result.queries:
        path = output_dir / f"query-{query.query_id}.html"
        path.write_text(render_detail(result, query), encoding="utf-8", newline="\n")
        written.append(path)
    return written
