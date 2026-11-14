from __future__ import annotations

import json
import re
from slowquery_autopsy.report import write_reports
from slowquery_autopsy.report.html_report import render_index
from slowquery_autopsy.report.json_report import build_json_report
from slowquery_autopsy.report.markdown_report import render_markdown

EXTERNAL = re.compile(r"https?://|//cdn|@import|url\(", re.I)


def _generate(config, result):
    written = write_reports(config, result)
    base = config.reports_dir / result.batch_id
    return written, base


def test_markdown_report_sections(temp_config, result):
    written, base = _generate(temp_config, result)
    assert written["markdown"].endswith("report.md")
    text = (base / "report.md").read_text(encoding="utf-8")
    for heading in ["概览", "TOP 指纹簇", "计划审计发现", "未解析日志",
                    "未关联计划", "排除的元数据语句", "口径与边界"]:
        assert heading in text
    assert "fixtures/logs/malformed_lines.log" in text
    assert "nearest-rank" in text
    assert result.clusters[0].fingerprint in text
    assert "COST-AMP-001" in text


def test_json_report_fields_and_determinism(temp_config, result):
    written, base = _generate(temp_config, result)
    assert written["json"].endswith("report.json")
    payload = json.loads((base / "report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["metadata"]["batch_id"] == result.batch_id
    assert len(payload["clusters"]) == 4
    assert len(payload["queries"]) == 20
    assert len(payload["findings"]) == len(result.findings)
    assert "evidence" in payload["findings"][0]
    assert payload["unparsed"][0]["line_no"] >= 1
    first = (base / "report.json").read_bytes()
    _generate(temp_config, result)
    assert (base / "report.json").read_bytes() == first
    assert build_json_report(result) == build_json_report(result)


def test_html_reports_are_local_and_complete(temp_config, result):
    written, base = _generate(temp_config, result)
    html_dir = base / "html"
    assert written["html_index"].endswith("index.html")
    index = (html_dir / "index.html").read_text(encoding="utf-8")
    assert result.batch_id in index
    assert "cluster-" in index
    assert EXTERNAL.search(index) is None
    files = sorted(html_dir.glob("*.html"))
    assert len(files) == 1 + len(result.clusters) + len(result.queries)
    for path in files:
        assert EXTERNAL.search(path.read_text(encoding="utf-8")) is None
    cluster_file = html_dir / f"cluster-{result.clusters[0].fingerprint}.html"
    assert "样本 SQL" in cluster_file.read_text(encoding="utf-8")
    query_file = html_dir / f"query-{result.queries[0].query_id}.html"
    detail = query_file.read_text(encoding="utf-8")
    assert result.queries[0].query_id in detail and "成本向量" in detail


def test_markdown_and_index_render_deterministically(result):
    first = render_markdown(result)
    second = render_markdown(result)
    assert first == second
    assert render_index(result) == render_index(result)
    assert first.startswith("# 慢查解剖台")


def test_unparsed_and_excluded_are_explicit(temp_config, result):
    _, base = _generate(temp_config, result)
    text = (base / "report.md").read_text(encoding="utf-8")
    assert "总计 3 条" in text
    assert "SET" in text and "SHOW" in text
    assert "bad_index.json" in text
    assert "deadbeefdeadbeef" in text
