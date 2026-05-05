from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import DEFAULT_OUTPUT_DIR, ScanConfig
from .external_tools import run_external_tools
from .fileinfo import collect_file_info
from .hashing import calculate_hashes
from .ole_analysis import analyze_ole
from .ooxml_analysis import analyze_ooxml
from .report_html import generate_html_report
from .report_pdf import generate_pdf_report
from .scoring import calculate_risk
from .strings_iocs import extract_iocs, extract_strings, iocs_to_text
from .suspicious_patterns import find_suspicious_patterns
from .utils import ensure_dir, local_timestamp_for_path, write_json, write_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Safely perform local static analysis of suspicious Microsoft Office documents.",
    )
    parser.add_argument("sample", type=Path, help="Path to the suspicious Office document, for example test12.doc")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT_DIR, help="Output root directory (default: scan_reports)")
    parser.add_argument("--yara-rules", type=Path, help="Directory or file of local YARA rules to run recursively")
    parser.add_argument("--no-clamav", action="store_true", help="Skip local clamscan even when installed")
    parser.add_argument("--json", action="store_true", help="Print the final JSON report to stdout")
    parser.add_argument("--max-pdf-output-chars", type=int, default=50000, help="Maximum raw-output preview characters per PDF/HTML section")
    parser.add_argument("--verbose", action="store_true", help="Print progress messages")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = ScanConfig(
        output_root=args.out,
        yara_rules=args.yara_rules,
        use_clamav=not args.no_clamav,
        json_to_stdout=args.json,
        max_pdf_output_chars=args.max_pdf_output_chars,
        verbose=args.verbose,
    )
    try:
        analysis = run_scan(args.sample, config)
    except ScannerError as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("scanner interrupted", file=sys.stderr)
        return 130
    if config.json_to_stdout:
        print(json.dumps(analysis, indent=2, sort_keys=True, default=str))
    else:
        print(f"Report written to: {analysis['artifacts']['output_dir']}")
        print(f"Risk: {analysis['risk']['level']} ({analysis['risk']['score']}/100)")
    return 0


def run_scan(sample: Path, config: ScanConfig) -> dict[str, Any]:
    sample = sample.expanduser().resolve()
    if not sample.exists():
        raise ScannerError(f"sample does not exist: {sample}")
    if not sample.is_file():
        raise ScannerError(f"sample is not a regular file: {sample}")

    timestamp = local_timestamp_for_path()
    output_dir = ensure_dir(config.output_root / f"{sample.name}_{timestamp}")
    raw_dir = ensure_dir(output_dir / "raw")
    extracted_dir = ensure_dir(output_dir / "extracted")

    _log(config, "Collecting file identity and hashes")
    file_info = collect_file_info(sample)
    hashes = calculate_hashes(sample)

    _log(config, "Analyzing Office container structure")
    ole = analyze_ole(sample)
    ooxml = analyze_ooxml(sample)

    _log(config, "Extracting strings and IOCs")
    strings = extract_strings(sample, max_bytes=config.max_strings_file_bytes)
    iocs = extract_iocs(strings)
    strings_path = extracted_dir / "strings.txt"
    iocs_path = extracted_dir / "iocs.txt"
    write_text(strings_path, "\n".join(strings))
    write_text(iocs_path, iocs_to_text(iocs))

    _log(config, "Running optional local tools")
    external_tools = run_external_tools(sample, raw_dir, config)
    metadata = extract_metadata_from_tools(external_tools)

    pattern_sources = list(strings)
    pattern_sources.extend(_tool_texts(external_tools))
    pattern_sources.extend(_relationship_texts(ooxml))
    suspicious_patterns = find_suspicious_patterns(pattern_sources)

    analysis: dict[str, Any] = {
        "scanner": {
            "name": "doc-static-scanner",
            "static_only": True,
            "safety": "Document was not opened, executed, detonated, uploaded, or processed with Office software.",
        },
        "file_info": file_info,
        "hashes": hashes,
        "ole": ole,
        "ooxml": ooxml,
        "metadata": metadata,
        "strings": {
            "count": len(strings),
            "saved_to": str(strings_path),
            "preview": strings[:250],
            "truncated_in_json": len(strings) > 250,
        },
        "iocs": iocs,
        "suspicious_patterns": suspicious_patterns,
        "external_tools": external_tools,
        "artifacts": {
            "output_dir": str(output_dir),
            "raw_dir": str(raw_dir),
            "extracted_dir": str(extracted_dir),
            "strings": str(strings_path),
            "iocs": str(iocs_path),
            "report_pdf": str(output_dir / "report.pdf"),
            "report_html": str(output_dir / "report.html"),
            "report_json": str(output_dir / "report.json"),
        },
    }
    analysis["risk"] = calculate_risk(analysis)

    _log(config, "Writing JSON, HTML, and PDF reports")
    write_json(output_dir / "report.json", analysis)
    generate_html_report(analysis, output_dir / "report.html", config.max_pdf_output_chars)
    generate_pdf_report(analysis, output_dir / "report.pdf", config.max_pdf_output_chars)
    return analysis


def extract_metadata_from_tools(external_tools: dict[str, dict[str, Any]]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for tool_name in ("olemeta", "exiftool"):
        result = external_tools.get(tool_name, {})
        text = (str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))).strip()
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                continue
            normalized = f"{tool_name}.{key}"
            metadata[normalized] = value
    return metadata


def _tool_texts(external_tools: dict[str, dict[str, Any]]) -> list[str]:
    texts: list[str] = []
    for result in external_tools.values():
        texts.append(str(result.get("stdout", "")))
        texts.append(str(result.get("stderr", "")))
        if result.get("skipped_reason"):
            texts.append(str(result["skipped_reason"]))
    return texts


def _relationship_texts(ooxml: dict[str, Any]) -> list[str]:
    return [str(item.get("target", "")) for item in ooxml.get("external_relationships", [])]


def _log(config: ScanConfig, message: str) -> None:
    if config.verbose:
        print(f"[scanner] {message}", file=sys.stderr)


class ScannerError(Exception):
    pass

