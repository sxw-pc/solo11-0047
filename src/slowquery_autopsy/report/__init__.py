"""Report generation entry points."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import AppConfig
from ..models import AnalysisResult
from .html_report import write_html_reports
from .json_report import build_json_report, write_json_report
from .markdown_report import render_markdown, write_markdown_report

__all__ = [
    "build_json_report",
    "render_markdown",
    "write_html_reports",
    "write_json_report",
    "write_markdown_report",
    "write_reports",
]


def write_reports(config: AppConfig, result: AnalysisResult) -> dict[str, str]:
    batch_dir = config.reports_dir / result.batch_id
    formats = list(config.report_options.get("formats", []))
    written: dict[str, str] = {}
    if "markdown" in formats:
        path = write_markdown_report(result, batch_dir / "report.md")
        written["markdown"] = config.display(path)
    if "json" in formats:
        path = write_json_report(result, batch_dir / "report.json")
        written["json"] = config.display(path)
    if "html" in formats:
        html_dir = batch_dir / "html"
        paths = write_html_reports(result, html_dir)
        written["html_index"] = config.display(html_dir / "index.html")
        written["html_files"] = str(len(paths))
    return written


def report_directory(config: AppConfig, result: AnalysisResult) -> Path:
    return config.reports_dir / result.batch_id


def load_report(config: AppConfig, result: AnalysisResult) -> dict[str, Any]:
    return build_json_report(result)
