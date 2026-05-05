from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .utils import truncate_text


def generate_pdf_report(analysis: dict[str, Any], output_path: Path, max_preview_chars: int) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output_path), pagesize=LETTER, rightMargin=0.55 * inch, leftMargin=0.55 * inch, topMargin=0.55 * inch, bottomMargin=0.55 * inch)
    story: list[Any] = []
    risk = analysis["risk"]

    story.append(Paragraph("Microsoft Office Static Malware Analysis Report", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Safety warning: do not open this document on the host, enable macros, or run it in Office software. This report is produced from local static analysis only.", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(_risk_table(risk))
    story.append(Spacer(1, 12))

    _section(story, styles, "Executive Summary")
    reason_rows = [[r["points"], r["reason"], r.get("evidence", "")] for r in risk.get("reasons", [])]
    if not reason_rows:
        reason_rows = [["0", "No risk points were added", ""]]
    story.append(_table([["Points", "Reason", "Evidence"]] + reason_rows))

    _section(story, styles, "File Identity")
    story.append(_dict_table(analysis["file_info"]))
    _section(story, styles, "Hashes")
    story.append(_dict_table(analysis["hashes"]))
    _section(story, styles, "Metadata")
    story.append(_dict_table(analysis.get("metadata", {}) or {"status": "No metadata found by optional tools"}))
    _section(story, styles, "Timeline")
    timeline = {key: analysis["file_info"].get(key) for key in ("created_or_changed_time_utc", "modified_time_utc", "accessed_time_utc")}
    story.append(_dict_table(timeline))
    _section(story, styles, "Tool Availability")
    story.append(_table([["Tool", "Installed", "Status", "Raw output"]] + _tool_rows(analysis.get("external_tools", {}))))

    story.append(PageBreak())
    _section(story, styles, "Macro Analysis")
    macro_rows = [["Source", "Indicators"]]
    macro_rows.append(["OLE", ", ".join(item.get("name", "") for item in analysis.get("ole", {}).get("macro_related_streams", [])) or "None found"])
    macro_rows.append(["OOXML", ", ".join(item.get("name", "") for item in analysis.get("ooxml", {}).get("vba_projects", [])) or "None found"])
    story.append(_table(macro_rows))

    _section(story, styles, "OLE Structure")
    story.append(_table_from_dicts(analysis.get("ole", {}).get("streams", [])[:120], ["name", "size", "first_bytes", "is_stream"]))
    _section(story, styles, "Embedded Objects")
    embedded = analysis.get("ole", {}).get("embedded_object_indicators", []) + analysis.get("ooxml", {}).get("embeddings", []) + analysis.get("ooxml", {}).get("activex", [])
    story.append(_table_from_dicts(embedded[:100], ["name", "size", "first_bytes"]))
    _section(story, styles, "OOXML Package")
    story.append(_table_from_dicts(analysis.get("ooxml", {}).get("entries", [])[:160], ["name", "size", "compressed_size"]))

    story.append(PageBreak())
    _section(story, styles, "IOCs")
    for category, values in analysis.get("iocs", {}).items():
        story.append(Paragraph(_esc(category), styles["Heading3"]))
        story.append(Paragraph(_esc(", ".join(values[:80]) if values else "None found."), styles["BodyText"]))
        story.append(Spacer(1, 6))

    _section(story, styles, "Suspicious Patterns")
    pattern_rows = [["Category", "Description", "Matches"]]
    for category, findings in analysis.get("suspicious_patterns", {}).items():
        for finding in findings:
            pattern_rows.append([category, finding.get("description", ""), finding.get("matches", "")])
    if len(pattern_rows) == 1:
        pattern_rows.append(["None", "No suspicious patterns matched", ""])
    story.append(_table(pattern_rows))

    _section(story, styles, "Antivirus and YARA")
    story.append(_raw_table({name: analysis.get("external_tools", {}).get(name, {}) for name in ("clamscan", "yara")}, max_preview_chars))

    story.append(PageBreak())
    _section(story, styles, "Raw Output Previews")
    story.append(_raw_table(analysis.get("external_tools", {}), max_preview_chars))
    _section(story, styles, "Appendix: Output Files")
    story.append(_dict_table(analysis.get("artifacts", {})))

    doc.build(story, onFirstPage=_page_number, onLaterPages=_page_number)


def _section(story: list[Any], styles: Any, title: str) -> None:
    from reportlab.platypus import Paragraph, Spacer

    story.append(Spacer(1, 10))
    story.append(Paragraph(_esc(title), styles["Heading2"]))


def _risk_table(risk: dict[str, Any]) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    table = Table([["Risk Level", "Score"], [risk["level"], f"{risk['score']}/100"]], colWidths=[260, 120])
    color = {"Low": colors.HexColor("#2f855a"), "Medium": colors.HexColor("#b7791f"), "High": colors.HexColor("#c53030"), "Critical": colors.HexColor("#742a2a")}.get(risk["level"], colors.grey)
    table.setStyle(TableStyle([("BACKGROUND", (0, 1), (-1, 1), color), ("TEXTCOLOR", (0, 1), (-1, 1), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("PADDING", (0, 0), (-1, -1), 8)]))
    return table


def _dict_table(data: dict[str, Any]) -> Any:
    return _table([["Field", "Value"]] + [[key, value] for key, value in data.items()])


def _table_from_dicts(rows: list[dict[str, Any]], keys: list[str]) -> Any:
    if not rows:
        return _table([["Status"], ["None found"]])
    return _table([keys] + [[row.get(key, "") for key in keys] for row in rows])


def _tool_rows(tools: dict[str, dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for name, result in tools.items():
        status = result.get("skipped_reason") or ("Timed out" if result.get("timed_out") else f"exit {result.get('exit_code')}")
        rows.append([name, result.get("installed"), status, result.get("output_path")])
    return rows


def _raw_table(tools: dict[str, dict[str, Any]], max_preview_chars: int) -> Any:
    rows = [["Tool", "Preview"]]
    for name, result in tools.items():
        text = (str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))).strip()
        if not text:
            text = str(result.get("skipped_reason") or "No output")
        rows.append([name, truncate_text(text, max_preview_chars)])
    return _table(rows, col_widths=[110, 410])


def _table(rows: list[list[Any]], col_widths: list[int] | None = None) -> Any:
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, Table, TableStyle

    styles = getSampleStyleSheet()
    wrapped = [[Paragraph(_esc(cell), styles["BodyText"]) for cell in row] for row in rows]
    table = Table(wrapped, repeatRows=1, colWidths=col_widths)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f6")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d7de")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
    return table


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _page_number(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 0.3 * 72, f"Page {doc.page}")
    canvas.restoreState()
