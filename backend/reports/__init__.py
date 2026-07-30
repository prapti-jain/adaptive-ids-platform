"""Report generation package."""

from backend.reports.html_renderer import render_report_html
from backend.reports.report_generator import ReportGenerator

__all__ = ["ReportGenerator", "render_report_html"]
