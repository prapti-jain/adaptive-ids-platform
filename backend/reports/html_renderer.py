"""Render report dicts as printable HTML."""

from __future__ import annotations

import html
from typing import Any


def render_report_html(report: dict[str, Any]) -> str:
    """Return a clean, printable HTML incident summary for ``report``."""
    summary = report.get("summary") or {}
    by_severity = summary.get("by_severity") or {}
    by_attack = summary.get("by_attack_type") or {}
    top_attackers = report.get("top_attackers") or []
    top_ports = report.get("top_ports") or []
    alerts = report.get("alerts") or []
    notes = report.get("notes") or {}

    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    severity_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in sorted(by_severity.items())
    ) or "<tr><td colspan='2'>None</td></tr>"

    attack_rows = "".join(
        f"<tr><td class='mono'>{esc(k)}</td><td>{esc(v)}</td></tr>"
        for k, v in sorted(by_attack.items())
    ) or "<tr><td colspan='2'>None</td></tr>"

    attacker_rows = "".join(
        f"<tr><td class='mono'>{esc(item.get('source_ip'))}</td>"
        f"<td>{esc(item.get('alert_count'))}</td></tr>"
        for item in top_attackers
    ) or "<tr><td colspan='2'>None</td></tr>"

    port_rows = "".join(
        f"<tr><td class='mono'>{esc(item.get('port'))}</td>"
        f"<td>{esc(item.get('alert_count'))}</td></tr>"
        for item in top_ports
    ) or "<tr><td colspan='2'>None</td></tr>"

    alert_rows = "".join(
        "<tr>"
        f"<td class='mono'>{esc(a.get('id'))}</td>"
        f"<td class='mono'>{esc(a.get('attack_type'))}</td>"
        f"<td>{esc(a.get('severity'))}</td>"
        f"<td class='mono'>{esc(a.get('source_ip'))}</td>"
        f"<td class='mono'>{esc(a.get('target_ip') or '—')}</td>"
        f"<td>{esc(a.get('risk_score'))}</td>"
        f"<td>{esc(a.get('status'))}</td>"
        f"<td>{esc(a.get('detected_at'))}</td>"
        "</tr>"
        for a in alerts
    ) or "<tr><td colspan='8'>No alerts in this period.</td></tr>"

    response_note = esc(
        notes.get("response_module")
        or "Response / recommendation module is not implemented."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>AIDTIP Incident Report — {esc(report.get('id'))}</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      margin: 2rem auto;
      max-width: 960px;
      color: #0f172a;
      line-height: 1.45;
    }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    .meta {{ color: #475569; margin-bottom: 1.5rem; }}
    .mono {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 0.92em; }}
    .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }}
    .card {{
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 0.9rem 1.1rem;
      min-width: 140px;
      background: #f8fafc;
    }}
    .card .label {{ font-size: 0.75rem; text-transform: uppercase; color: #64748b; }}
    .card .value {{ font-size: 1.6rem; font-weight: 600; margin-top: 0.25rem; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 0.75rem 0 1.5rem;
      font-size: 0.92rem;
    }}
    th, td {{
      border: 1px solid #e2e8f0;
      padding: 0.45rem 0.55rem;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: #f1f5f9; }}
    .note {{
      border-left: 4px solid #94a3b8;
      background: #f8fafc;
      padding: 0.75rem 1rem;
      margin: 1rem 0 2rem;
      color: #334155;
    }}
    @media print {{
      body {{ margin: 0.5in; }}
      .card {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <h1>AIDTIP Incident Summary</h1>
  <p class="meta">
    Report ID: <span class="mono">{esc(report.get('id'))}</span><br />
    Period: {esc(report.get('period_start'))} → {esc(report.get('period_end'))}<br />
    Generated: {esc(report.get('generated_at'))}
  </p>

  <div class="note"><strong>Note:</strong> {response_note}
  Recommended-action column omitted for this reason.</div>

  <div class="cards">
    <div class="card">
      <div class="label">Total alerts</div>
      <div class="value">{esc(summary.get('total_alerts', 0))}</div>
    </div>
    <div class="card">
      <div class="label">Attack types</div>
      <div class="value">{esc(len(by_attack))}</div>
    </div>
    <div class="card">
      <div class="label">Critical</div>
      <div class="value">{esc(by_severity.get('CRITICAL', 0))}</div>
    </div>
  </div>

  <h2>By severity</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{severity_rows}</tbody>
  </table>

  <h2>By attack type</h2>
  <table>
    <thead><tr><th>Attack type</th><th>Count</th></tr></thead>
    <tbody>{attack_rows}</tbody>
  </table>

  <h2>Top attackers</h2>
  <table>
    <thead><tr><th>Source IP</th><th>Alerts</th></tr></thead>
    <tbody>{attacker_rows}</tbody>
  </table>

  <h2>Top ports</h2>
  <table>
    <thead><tr><th>Port</th><th>Alerts</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>

  <h2>Alerts in period</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Type</th><th>Severity</th><th>Source</th>
        <th>Target</th><th>Risk</th><th>Status</th><th>Detected</th>
      </tr>
    </thead>
    <tbody>{alert_rows}</tbody>
  </table>
</body>
</html>
"""
