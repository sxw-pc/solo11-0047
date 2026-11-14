"""Deterministic Markdown audit report."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import AnalysisResult
from ..util.hashing import canonical_json


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _code(value: str) -> str:
    return f"`{value.replace('`', '\\`')}`" if value else "—"


def _severity_counts(result: AnalysisResult) -> str:
    counts = result.finding_counts()
    return " · ".join(f"{level}={counts.get(level, 0)}" for level in counts)


def _effective_severity_counts(result: AnalysisResult) -> str:
    counts = result.effective_finding_counts()
    return " · ".join(f"{level}={counts.get(level, 0)}" for level in counts)


def _overview(result: AnalysisResult) -> list[str]:
    counts = result.summary["counts"]
    durations = result.summary["durations"]
    baseline = result.summary.get("finding_baselines", {})
    suppressed = counts.get("suppressed_findings", 0)
    lines = [
        "## 1. 概览", "",
        f"- 批次 ID：`{result.batch_id}`",
        f"- 配置哈希：`{result.config_hash[:16]}`",
        f"- 输入哈希：`{result.input_hash[:16]}`",
        f"- 输入文件：{counts['input_files']}；解析慢查：{counts['queries']}；参与聚类：{counts['analyzed_queries']}；排除：{counts['excluded_queries']}",
        f"- 指纹簇：{counts['clusters']}；计划：{counts['plans']}；未关联计划：{counts['unassociated_plans']}",
        f"- 发现：{counts['findings']}；生效高危及以上：{counts['high_findings']}；基线抑制：{suppressed}；未解析行：{counts['unparsed_lines']}",
        f"- 原始严重级别分布：{_severity_counts(result)}",
        f"- 生效严重级别分布：{_effective_severity_counts(result)}（被抑制发现按 info 计）",
        f"- 基线规则：{baseline.get('count', 0)} 条",
        f"- 全部慢查总耗时：{durations['all_queries_total_ms']:.3f} ms；参与分析总耗时：{durations['analyzed_total_ms']:.3f} ms",
        "- 分位数口径：nearest-rank（`ceil(q*n)`）；放大倍数 = 扫描行总数 / max(返回行总数, 1)",
        "",
    ]
    return lines


def _clusters(result: AnalysisResult, limit: int) -> list[str]:
    lines = ["## 2. TOP 指纹簇", "", "按总耗时降序，总耗时相同按指纹升序。", "",
             "| # | 簇 ID | 次数 | 总耗时 ms | 平均 ms | P50 ms | P95 ms | 扫描/返回 | 总扫描行 | 耗时占比 |",
             "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for index, cluster in enumerate(result.clusters[:limit], start=1):
        lines.append(
            f"| {index} | `{cluster.fingerprint}` | {cluster.query_count} | "
            f"{cluster.total_duration_ms:.3f} | {cluster.avg_duration_ms:.3f} | "
            f"{cluster.p50_duration_ms:.3f} | {cluster.p95_duration_ms:.3f} | "
            f"{cluster.amplification:.2f}x | {cluster.total_rows_examined} | "
            f"{cluster.duration_share:.2%} |"
        )
    if not result.clusters:
        lines.append("| — | 无 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0% |")
    lines.extend(["", "### 高扫描放大清单（>100x）", ""])
    amplified = [cluster for cluster in result.clusters if cluster.amplification > 100]
    if amplified:
        lines.extend(["| 簇 ID | 次数 | 放大倍数 | 样本 SQL |", "|---|---:|---:|---|"])
        for cluster in amplified:
            lines.append(
                f"| `{cluster.fingerprint}` | {cluster.query_count} | "
                f"{cluster.amplification:.2f}x | {_cell(cluster.sample_sql[:160])} |"
            )
    else:
        lines.append("无超过 100x 的簇。")
    lines.append("")
    return lines


def _severity_label(finding) -> str:
    if finding.suppressed:
        return f"info（原始 {finding.original_severity}，已抑制）"
    return finding.original_severity


def _plan_and_findings(result: AnalysisResult) -> list[str]:
    lines = ["## 3. 计划审计发现", "",
             "| 生效级别 | 原始级别 | 规则 | 计划 | 节点 | 表 | 描述 |",
             "|---|---|---|---|---|---|---|"]
    plan_findings = [finding for finding in result.findings if finding.category == "plan"]
    for finding in plan_findings:
        evidence = finding.evidence
        lines.append(
            f"| {finding.effective_severity} | {_severity_label(finding)} | `{finding.rule_id}` | "
            f"{_cell(finding.plan_file)} | `{finding.node_path}` | "
            f"{_cell(evidence.get('table', '—'))} | {_cell(finding.description)} |"
        )
    if not plan_findings:
        lines.append("| — | — | 无 | — | — | — | — |")
    lines.extend(["", "## 4. 诊断发现明细", ""])
    if not result.findings:
        lines.extend(["未触发任何规则。", ""])
    for finding in result.findings:
        lines.append(
            f"### [{finding.effective_severity.upper()}] `{finding.finding_id}` — {finding.title}"
        )
        lines.append("")
        lines.append(f"- 类别：{finding.category}；规则：`{finding.rule_id}`；簇：{_code(finding.cluster_id)}")
        lines.append(f"- 计划/节点：{_code(finding.plan_file)} / {_code(finding.node_path)}")
        if finding.suppressed:
            lines.append(
                f"- 基线抑制：原始级别 {finding.original_severity}；生效级别 info；"
                f"基线 `{finding.baseline_id}`（{finding.suppression_reason}）"
            )
        else:
            lines.append(f"- 严重级别：{finding.original_severity}（未抑制）")
        lines.append(f"- 说明：{finding.description}")
        lines.append(f"- 证据：`{canonical_json(finding.evidence)}`")
        lines.append(f"- 建议：{finding.recommendation}")
        lines.append("")
    lines.extend(["### 规则触发表", "",
                  "| finding_id | 规则 | 原始级别 | 生效级别 | 抑制 | 类别 | 簇 |",
                  "|---|---|---|---|---|---|---|"])
    for finding in result.findings:
        lines.append(
            f"| `{finding.finding_id}` | `{finding.rule_id}` | {finding.original_severity} | "
            f"{finding.effective_severity} | {'是' if finding.suppressed else '否'} | "
            f"{finding.category} | {_code(finding.cluster_id)} |"
        )
    if not result.findings:
        lines.append("| — | — | — | — | — | — | — |")
    lines.append("")
    return lines


def _baseline_section(result: AnalysisResult) -> list[str]:
    baseline = result.summary.get("finding_baselines", {})
    items = baseline.get("items", [])
    lines = ["## 5. 发现基线豁免", "",
             f"共登记 {len(items)} 条基线；本批次命中 {baseline.get('suppressed_findings', 0)} 条发现。",
             "",
             "基线只按规则 ID / SQL 指纹匹配，不记录计划节点行号或路径等易变证据。", ""]
    if items:
        lines.extend(["| 基线 ID | 规则 | 指纹 | 来源 | 备注 |",
                      "|---|---|---|---|---|"])
        for item in items:
            lines.append(
                f"| `{item['baseline_id']}` | {_code(item.get('rule_id', ''))} | "
                f"{_code(item.get('fingerprint', ''))} | {item.get('origin', '—')} | "
                f"{_cell(item.get('note', '') or '—')} |"
            )
    else:
        lines.append("未登记任何基线。")
    lines.append("")
    return lines


def _exceptions(result: AnalysisResult, preview: int) -> list[str]:
    lines = ["## 6. 未解析日志", "",
             f"总计 {len(result.unparsed)} 条；以下最多列出 {preview} 条。", ""]
    if result.unparsed:
        lines.extend(["| 文件 | 行号 | 原因 | 原始片段 |", "|---|---:|---|---|"])
        for item in result.unparsed[:preview]:
            lines.append(
                f"| {_cell(item.file)} | {item.line_no} | {_cell(item.reason)} | {_cell(item.text[:180])} |"
            )
        if len(result.unparsed) > preview:
            lines.append(f"| … | … | 其余 {len(result.unparsed) - preview} 条 | … |")
    else:
        lines.append("无。")
    lines.extend(["", "## 7. 未关联计划", ""])
    if result.summary["unassociated_plans"]:
        lines.extend(["| 计划文件 | 指纹 | 节点数 | 原因 |", "|---|---|---:|---|"])
        for item in result.summary["unassociated_plans"]:
            lines.append(
                f"| {_cell(item['source_file'])} | `{item['fingerprint'] or '—'}` | "
                f"{item['node_count']} | {_cell(item['reason'])} |"
            )
    else:
        lines.append("无。")
    lines.extend(["", "## 8. 排除的元数据语句", "",
                  f"排除前缀：{', '.join(result.summary['excluded_prefixes']) or '无'}",
                  f"共 {len(result.excluded)} 条。", ""])
    if result.excluded:
        lines.extend(["| 前缀 | 次数 | 示例位置 | SQL |", "|---|---:|---|---|"])
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in result.excluded:
            grouped.setdefault(item["prefix"], []).append(item)
        for prefix in sorted(grouped):
            samples = grouped[prefix]
            lines.append(
                f"| {prefix} | {len(samples)} | {samples[0]['source_file']}:{samples[0]['line_no']} | "
                f"{_cell(samples[0]['sql'][:120])} |"
            )
    else:
        lines.append("无。")
    lines.append("")
    return lines


def _appendix(result: AnalysisResult) -> list[str]:
    lines = ["## 9. 输入文件", "",
             "| 文件 | 格式 | 编码 | 行数 | 解析 | 未解析 | 排除 | SHA-256 |",
             "|---|---|---|---:|---:|---:|---:|---|"]
    for stat in result.file_stats:
        lines.append(
            f"| {_cell(stat.path)} | {stat.log_format} | {stat.encoding} | {stat.line_count} | "
            f"{stat.parsed_count} | {stat.unparsed_count} | {stat.excluded_count} | `{stat.sha256[:16]}…` |"
        )
    lines.extend([
        "", "## 10. 口径与边界", "",
        f"- 归一化规则（按顺序）：{', '.join(result.summary['normalization_rules'])}",
        "- 指纹 = SHA-256(归一化文本 + 有序结构 token 序列) 前 16 位十六进制。",
        "- 分位数使用 nearest-rank，不做插值；同一输入与配置产生相同的正文。",
        "- 扫描放大倍数与锁等待占比按簇内总量计算；每千次调用耗时为平均耗时 × 1000。",
        "- 发现基线按规则 ID / SQL 指纹匹配；抑制只改变生效级别（降为 info），原始级别与 finding_id 不变。",
        "- diff 与 fail_on_severity 均按生效级别判断；原始严重度分布始终单独给出。",
        "- 本报告只做静态文本分析，不连接数据库、不执行 SQL、不生成改写版本。",
        "- 误报提示：合成 fixture 与规则阈值仅用于演示；真实结论需结合业务与执行环境复核。",
        "",
    ])
    return lines


def render_markdown(result: AnalysisResult) -> str:
    top = int(result.summary.get("top_clusters", 8))
    preview = int(result.summary.get("unparsed_preview", 10))
    lines = [
        "# 慢查解剖台 · 批次审计报告", "",
        f"> 项目：{result.summary.get('project', 'slowquery-autopsy')} · 批次 `{result.batch_id}`", "",
    ]
    lines.extend(_overview(result))
    lines.extend(_clusters(result, top))
    lines.extend(_plan_and_findings(result))
    lines.extend(_baseline_section(result))
    lines.extend(_exceptions(result, preview))
    lines.extend(_appendix(result))
    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(result: AnalysisResult, path: Path,
                          top_clusters: int | None = None,
                          unparsed_preview: int | None = None) -> Path:
    if top_clusters is not None:
        result.summary["top_clusters"] = top_clusters
    if unparsed_preview is not None:
        result.summary["unparsed_preview"] = unparsed_preview
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(result), encoding="utf-8", newline="\n")
    return path
