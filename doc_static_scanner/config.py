from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanConfig:
    output_root: Path
    yara_rules: Path | None = None
    use_clamav: bool = True
    json_to_stdout: bool = False
    max_pdf_output_chars: int = 50000
    verbose: bool = False
    tool_timeout: int = 90
    max_strings_file_bytes: int = 64 * 1024 * 1024


DEFAULT_OUTPUT_DIR = Path("scan_reports")

