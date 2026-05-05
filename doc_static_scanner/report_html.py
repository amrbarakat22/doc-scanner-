from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .utils import truncate_text, write_text


def generate_html_report(analysis: dict[str, Any], output_path: Path, max_preview_chars: int) -> None:
    risk = analysis["risk"]
    file_info = analysis["file_info"]
    body = [
        "<!doctype html><html><head><meta charset='utf-8'><title>Office Static Scan Report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:32px;color:#1f2933}table{border-collapse:collapse;width:100%;margin:12px 0}td,th{border:1px solid #d0d7de;padding:7px;vertical-align:top}th{background:#f6f8fa;text-align:left}.badge{display:inline-block;padding:8px 12px;border-radius:4px;background:#1f2937;color:white}.warning{background:#fff4ce;border-left:5px solid #b7791f;padding:12px}.raw{white-space:pre-wrap;background:#f6f8fa;padding:10px;border:1px solid #d0d7de;overflow:auto}h1,h2{color:#111827}</style>",
        "</head><body>",
        "<h1>Microsoft Office Static Malware Analysis Report</h1>",
        "<p class='warning'>Safety warning: do not open this document on the host, enable macros, or run it in Office software. This report is produced from local static analysis only.</p>",
        f"<p><span class='badge'>Risk: {e(risk['level'])} ({risk['score']}/100)</span></p>",
        "<h2>Executive Summary</h2>",
        _risk_reasons_table(risk.get("reasons", [])),
        "<h2>File Identity</h2>",
        _dict_table(file_info),
        "<h2>Hashes</h2>",
        _dict_table(analysis["hashes"]),
        "<h2>Metadata</h2>",
        _dict_table(analysis.get("metadata", {}) or {"status": "No metadata found by optional tools"}),
        "<h2>Tool Availability</h2>",
        _tools_table(analysis.get("external_tools", {})),
        "<h2>OLE Structure</h2>",
        _list_table(analysis.get("ole", {}).get("streams", [])[:200]),
        "<h2>OOXML Package</h2>",
        _list_table(analysis.get("ooxml", {}).get("entries", [])[:300]),
        "<h2>IOCs</h2>",
        _ioc_sections(analysis.get("iocs", {})),
        "<h2>Suspicious Patterns</h2>",
        _patterns(analysis.get("suspicious_patterns", {})),
        "<h2>Antivirus and YARA</h2>",
        _av_yara(analysis.get("external_tools", {}), max_preview_chars),
        "<h2>Raw Output Previews</h2>",
        _raw_previews(analysis.get("external_tools", {}), max_preview_chars),
        "<h2>Output Files</h2>",
        _dict_table(analysis.get("artifacts", {})),
        "</body></html>",
    ]
    write_text(output_path, "\n".join(body))


def e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _dict_table(data: dict[str, Any]) -> str:
    rows = ["<table><tbody>"]
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            value = html.escape(str(value))
        rows.append(f"<tr><th>{e(key)}</th><td>{e(value)}</td></tr>")
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _list_table(rows_data: list[dict[str, Any]]) -> str:
    if not rows_data:
        return "<p>None found.</p>"
    keys = sorted({key for row in rows_data for key in row.keys()})
    rows = ["<table><thead><tr>"] + [f"<th>{e(key)}</th>" for key in keys] + ["</tr></thead><tbody>"]
    for row in rows_data:
        rows.append("<tr>" + "".join(f"<td>{e(row.get(key, ''))}</td>" for key in keys) + "</tr>")
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _risk_reasons_table(reasons: list[dict[str, Any]]) -> str:
    if not reasons:
        return "<p>No risk points were added.</p>"
    return _list_table(reasons)


def _tools_table(tools: dict[str, dict[str, Any]]) -> str:
    rows = []
    for name, result in tools.items():
        rows.append(
            {
                "tool": name,
                "installed": result.get("installed"),
                "status": result.get("skipped_reason") or ("Timed out" if result.get("timed_out") else f"exit {result.get('exit_code')}"),
                "output": result.get("output_path"),
            }
        )
    return _list_table(rows)


def _ioc_sections(iocs: dict[str, list[str]]) -> str:
    output = []
    for category, values in iocs.items():
        output.append(f"<h3>{e(category)}</h3>")
        if values:
            output.append("<ul>" + "".join(f"<li>{e(value)}</li>" for value in values[:200]) + "</ul>")
        else:
            output.append("<p>None found.</p>")
    return "\n".join(output)


def _patterns(patterns: dict[str, list[dict[str, str]]]) -> str:
    if not patterns:
        return "<p>None found.</p>"
    output = []
    for category, findings in patterns.items():
        output.append(f"<h3>{e(category)}</h3>")
        output.append(_list_table(findings))
    return "\n".join(output)


def _av_yara(tools: dict[str, dict[str, Any]], max_preview_chars: int) -> str:
    selected = {name: tools.get(name, {}) for name in ("clamscan", "yara")}
    return _raw_previews(selected, max_preview_chars)


def _raw_previews(tools: dict[str, dict[str, Any]], max_preview_chars: int) -> str:
    output = []
    for name, result in tools.items():
        text = (str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))).strip()
        if not text:
            text = str(result.get("skipped_reason") or "No output")
        output.append(f"<h3>{e(name)}</h3><div class='raw'>{e(truncate_text(text, max_preview_chars))}</div>")
    return "\n".join(output)
