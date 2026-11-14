"""Local read-only HTTP report service (loopback only, no write routes)."""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

from .. import __version__
from ..report.html_report import CSS
from ..store.ledger import open_readonly

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _page(title: str, body: str, nav: str = "") -> str:
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · 慢查解剖台</title><style>{CSS}</style></head>
<body><header><p class="eyebrow">SLOWQUERY AUTOPSY · LOCAL READ-ONLY SERVICE</p>
<h1>{html.escape(title)}</h1>{nav}</header><main>{body}</main>
<footer>只读本地台账 · 仅监听 127.0.0.1 · 不连接数据库 · 不执行 SQL · 不发起网络请求</footer>
</body></html>"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _batch_nav(batch_id: str) -> str:
    b = quote(batch_id, safe="")
    return (
        f'<p class="muted"><a href="/batch/{b}">批次概览</a> · '
        f'<a href="/batch/{b}/clusters">簇列表</a> · '
        f'<a href="/batch/{b}/findings">发现列表</a></p>'
    )


def _index(ledger: Any) -> str:
    batches = ledger.list_batches()
    rows = "".join(
        f'<tr><td><a href="/batch/{quote(batch["batch_id"], safe="")}"><code>{_esc(batch["batch_id"])}</code></a></td>'
        f'<td>{_esc(batch["summary"].get("counts", {}).get("queries", 0))}</td>'
        f'<td>{_esc(batch["summary"].get("counts", {}).get("clusters", 0))}</td>'
        f'<td>{_esc(batch["summary"].get("counts", {}).get("findings", 0))}</td>'
        f'<td>{_esc(batch["created_at"])}</td></tr>'
        for batch in batches
    ) or '<tr><td colspan="5">台账中还没有批次。</td></tr>'
    return _page("批次列表", f"""<section><h2>批次</h2>
<table><thead><tr><th>批次</th><th>慢查</th><th>簇</th><th>发现</th><th>台账写入时间</th></tr></thead>
<tbody>{rows}</tbody></table>
<p class="muted">服务以 SQLite <code>mode=ro</code> 只读打开台账；不提供上传、执行或写接口。</p>
</section>""")


def _batch(ledger: Any, batch_id: str) -> tuple[int, str]:
    batch = ledger.get_batch(batch_id)
    if not batch:
        return 404, _page("批次不存在", "<p>未找到该批次。</p>")
    summary = batch["summary"]
    counts = summary.get("counts", {})
    severity = summary.get("severity_counts", {})
    return 200, _page(f"批次 {batch_id}", f"""{_batch_nav(batch_id)}
<section><h2>概览</h2><div class="metrics">
<div class="metric"><strong>{_esc(counts.get('queries', 0))}</strong><span>慢查</span></div>
<div class="metric"><strong>{_esc(counts.get('clusters', 0))}</strong><span>指纹簇</span></div>
<div class="metric"><strong>{_esc(counts.get('findings', 0))}</strong><span>发现</span></div>
<div class="metric"><strong>{_esc(counts.get('high_findings', 0))}</strong><span>高危及以上</span></div>
<div class="metric"><strong>{_esc(counts.get('unparsed_lines', 0))}</strong><span>未解析行</span></div>
</div>
<p class="muted">严重级别：{_esc(severity)}</p>
<p>输入哈希 <code>{_esc(batch['input_hash'][:16])}</code> · 配置哈希 <code>{_esc(batch['config_hash'][:16])}</code></p>
</section>
<section><h2>未解析与未关联</h2>
<p>未解析行 {_esc(counts.get('unparsed_lines', 0))} 条；未关联计划 {_esc(counts.get('unassociated_plans', 0))} 个。</p>
</section>""")


def _clusters(ledger: Any, batch_id: str) -> tuple[int, str]:
    if not ledger.get_batch(batch_id):
        return 404, _page("批次不存在", "<p>未找到该批次。</p>")
    clusters = ledger.list_clusters(batch_id)
    rows = "".join(
        f'<tr><td><a href="/cluster/{quote(batch_id, safe="")}/{quote(c["cluster_id"], safe="")}"><code>{_esc(c["cluster_id"])}</code></a></td>'
        f'<td>{_esc(c["query_count"])}</td><td>{c["total_duration_ms"]:.3f}</td>'
        f'<td>{c["p95_duration_ms"]:.3f}</td><td>{c["amplification"]:.2f}x</td>'
        f'<td><code>{_esc(c["sample_sql"][:120])}</code></td></tr>'
        for c in clusters
    ) or '<tr><td colspan="6">无簇。</td></tr>'
    body = _batch_nav(batch_id) + f"""<section><h2>指纹簇</h2>
<table><thead><tr><th>簇</th><th>次数</th><th>总耗时 ms</th><th>P95 ms</th><th>放大</th><th>样本</th></tr></thead>
<tbody>{rows}</tbody></table></section>"""
    return 200, _page(f"簇列表 · {batch_id}", body)


def _cluster(ledger: Any, batch_id: str, cluster_id: str) -> tuple[int, str]:
    cluster = ledger.get_cluster(batch_id, cluster_id)
    if not cluster:
        return 404, _page("簇不存在", "<p>未找到该簇。</p>")
    queries = ledger.list_queries(batch_id, cluster_id)
    findings = [f for f in ledger.list_findings(batch_id) if f["cluster_id"] == cluster_id]
    query_rows = "".join(
        f'<tr><td><a href="/query/{quote(batch_id, safe="")}/{quote(q["query_id"], safe="")}"><code>{_esc(q["query_id"])}</code></a></td>'
        f'<td>{_esc(q["source_file"])}:{_esc(q["line_no"])}</td><td>{q["duration_ms"]:.3f}</td>'
        f'<td>{_esc(q["rows_examined"])} / {_esc(q["rows_sent"])}</td></tr>'
        for q in queries
    )
    finding_rows = "".join(
        f'<tr><td>{_esc(f["severity"])}</td><td><code>{_esc(f["rule_id"])}</code></td>'
        f'<td><a href="/finding/{quote(batch_id, safe="")}/{quote(f["finding_id"], safe="")}"><code>{_esc(f["finding_id"])}</code></a></td>'
        f'<td>{_esc(f["description"])}</td></tr>'
        for f in findings
    ) or '<tr><td colspan="4">无关联发现。</td></tr>'
    body = _batch_nav(batch_id) + f"""<section><h2>统计</h2>
<p>出现 {_esc(cluster['query_count'])} 次 · 平均 {cluster['avg_duration_ms']:.3f} ms ·
P50 {cluster['p50_duration_ms']:.3f} ms · P95 {cluster['p95_duration_ms']:.3f} ms ·
扫描放大 {cluster['amplification']:.2f}x · 锁等待占比 {cluster['lock_ratio']:.2%}</p>
<h2>样本 SQL</h2><pre>{_esc(cluster['sample_sql'])}</pre>
<h3>归一化</h3><pre>{_esc(cluster['normalized_sql'])}</pre></section>
<section><h2>关联发现</h2><table><thead><tr><th>级别</th><th>规则</th><th>finding_id</th><th>说明</th></tr></thead>
<tbody>{finding_rows}</tbody></table></section>
<section><h2>单体慢查</h2><table><thead><tr><th>query_id</th><th>来源</th><th>耗时 ms</th><th>扫描/返回</th></tr></thead>
<tbody>{query_rows}</tbody></table></section>"""
    return 200, _page(f"簇 {cluster_id}", body)


def _findings(ledger: Any, batch_id: str) -> tuple[int, str]:
    if not ledger.get_batch(batch_id):
        return 404, _page("批次不存在", "<p>未找到该批次。</p>")
    findings = ledger.list_findings(batch_id)
    rows = "".join(
        f'<tr><td>{_esc(f["severity"])}</td><td><code>{_esc(f["rule_id"])}</code></td>'
        f'<td><a href="/finding/{quote(batch_id, safe="")}/{quote(f["finding_id"], safe="")}"><code>{_esc(f["finding_id"])}</code></a></td>'
        f'<td>{_esc(f["category"])}</td><td><code>{_esc(f["cluster_id"] or f["plan_file"])}</code></td>'
        f'<td>{_esc(f["description"])}</td></tr>'
        for f in findings
    ) or '<tr><td colspan="6">无发现。</td></tr>'
    body = _batch_nav(batch_id) + f"""<section><h2>诊断发现</h2>
<table><thead><tr><th>级别</th><th>规则</th><th>finding_id</th><th>类别</th><th>目标</th><th>说明</th></tr></thead>
<tbody>{rows}</tbody></table></section>"""
    return 200, _page(f"发现列表 · {batch_id}", body)


def _finding(ledger: Any, batch_id: str, finding_id: str) -> tuple[int, str]:
    finding = ledger.get_finding(batch_id, finding_id)
    if not finding:
        return 404, _page("发现不存在", "<p>未找到该发现。</p>")
    evidence = json.dumps(finding["evidence"], ensure_ascii=False, sort_keys=True, indent=2)
    body = _batch_nav(batch_id) + f"""<section><h2>{_esc(finding['title'])}</h2>
<table><tbody>
<tr><th>finding_id</th><td><code>{_esc(finding['finding_id'])}</code></td></tr>
<tr><th>规则</th><td><code>{_esc(finding['rule_id'])}</code></td></tr>
<tr><th>级别 / 类别</th><td>{_esc(finding['severity'])} / {_esc(finding['category'])}</td></tr>
<tr><th>簇</th><td><code>{_esc(finding['cluster_id'] or '—')}</code></td></tr>
<tr><th>计划 / 节点</th><td>{_esc(finding['plan_file'] or '—')} / {_esc(finding['node_path'] or '—')}</td></tr>
</tbody></table>
<p>{_esc(finding['description'])}</p><h3>证据</h3><pre>{_esc(evidence)}</pre>
<h3>建议</h3><p>{_esc(finding['recommendation'])}</p></section>"""
    return 200, _page("发现详情", body)


def _query(ledger: Any, batch_id: str, query_id: str) -> tuple[int, str]:
    query = ledger.get_query(batch_id, query_id)
    if not query:
        return 404, _page("慢查不存在", "<p>未找到该慢查。</p>")
    cost = json.dumps(query["cost"], ensure_ascii=False, sort_keys=True, indent=2)
    body = _batch_nav(batch_id) + f"""<section><h2>单体慢查</h2>
<p>{_esc(query['source_file'])}:{_esc(query['line_no'])} · {_esc(query['timestamp'])}</p>
<p>耗时 {query['duration_ms']:.3f} ms · 锁等待 {query['lock_time_ms']:.3f} ms ·
扫描 {_esc(query['rows_examined'])} · 返回 {_esc(query['rows_sent'])} · 用户 {_esc(query['user_name'])}</p>
<h3>SQL</h3><pre>{_esc(query['sql_text'])}</pre>
<h3>归一化</h3><pre>{_esc(query['normalized_sql'])}</pre>
<h3>成本向量</h3><pre>{_esc(cost)}</pre></section>"""
    return 200, _page("慢查详情", body)


def make_handler(ledger_path: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SlowQueryAutopsy/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8",
                  head_only: bool = False) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            if not head_only:
                self.wfile.write(payload)

        def _dispatch(self, head_only: bool = False) -> None:
            parsed = urlparse(self.path)
            parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
            try:
                with open_readonly(ledger_path) as ledger:
                    if not parts:
                        status, body = 200, _index(ledger)
                    elif parts == ["healthz"]:
                        payload = {"status": "ok", "readonly": True, "version": __version__,
                                   "batches": len(ledger.list_batches())}
                        status, body = 200, json.dumps(payload, sort_keys=True)
                        self._send(status, body, "application/json; charset=utf-8", head_only)
                        return
                    elif parts[0] == "batch" and len(parts) == 2:
                        status, body = _batch(ledger, parts[1])
                    elif parts[0] == "batch" and len(parts) == 3 and parts[2] == "clusters":
                        status, body = _clusters(ledger, parts[1])
                    elif parts[0] == "batch" and len(parts) == 3 and parts[2] == "findings":
                        status, body = _findings(ledger, parts[1])
                    elif parts[0] == "cluster" and len(parts) == 3:
                        status, body = _cluster(ledger, parts[1], parts[2])
                    elif parts[0] == "finding" and len(parts) == 3:
                        status, body = _finding(ledger, parts[1], parts[2])
                    elif parts[0] == "query" and len(parts) == 3:
                        status, body = _query(ledger, parts[1], parts[2])
                    else:
                        status, body = 404, _page("页面不存在", "<p>未知路径。</p>")
            except FileNotFoundError:
                status, body = 503, _page("台账不可用", "<p>本地台账文件不存在。</p>")
            self._send(status, body, head_only=head_only)

        def do_GET(self) -> None:
            self._dispatch(False)

        def do_HEAD(self) -> None:
            self._dispatch(True)

        def _reject(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = 0
            if 0 < length <= 65536:
                self.rfile.read(length)
            self._send(405, "read-only service: only GET and HEAD are allowed",
                       "text/plain; charset=utf-8")

        do_POST = _reject
        do_PUT = _reject
        do_DELETE = _reject
        do_PATCH = _reject

    return Handler


def build_server(ledger_path: Path | str, host: str = "127.0.0.1", port: int = 5000) -> ThreadingHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("server must bind to 127.0.0.1 only")
    path = Path(ledger_path).resolve()
    with open_readonly(path) as ledger:
        if "batches" not in ledger.table_names():
            raise ValueError("ledger schema is missing")
    server = ThreadingHTTPServer((host, port), make_handler(path))
    server.daemon_threads = True
    return server
