from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import ScanConfig
from .utils import write_text


@dataclass
class ToolResult:
    name: str
    command: list[str]
    installed: bool
    skipped_reason: str | None
    exit_code: int | None
    timed_out: bool
    output_path: str
    stdout: str
    stderr: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def combined_output(self) -> str:
        return (self.stdout + ("\n" if self.stdout and self.stderr else "") + self.stderr).strip()


OLETOOLS = ("oleid", "olevba", "mraptor", "oleobj", "oledir", "olemap", "olemeta", "oletimes")


def run_external_tools(path: Path, raw_dir: Path, config: ScanConfig) -> dict[str, dict[str, object]]:
    results: dict[str, ToolResult] = {}
    for tool in OLETOOLS:
        results[tool] = _run_or_skip(tool, [tool, str(path)], raw_dir, config.tool_timeout)

    if _looks_like_rtf(path):
        results["rtfobj"] = _run_or_skip("rtfobj", ["rtfobj", str(path)], raw_dir, config.tool_timeout)
    else:
        results["rtfobj"] = _skip("rtfobj", ["rtfobj", str(path)], raw_dir, "File does not appear to be RTF")

    results["exiftool"] = _run_or_skip("exiftool", ["exiftool", str(path)], raw_dir, config.tool_timeout)

    if config.use_clamav:
        results["clamscan"] = _run_or_skip("clamscan", ["clamscan", "--no-summary", str(path)], raw_dir, config.tool_timeout)
    else:
        results["clamscan"] = _skip("clamscan", ["clamscan", "--no-summary", str(path)], raw_dir, "Disabled by --no-clamav")

    if config.yara_rules:
        if config.yara_rules.exists():
            results["yara"] = _run_or_skip("yara", ["yara", "-r", str(config.yara_rules), str(path)], raw_dir, config.tool_timeout)
        else:
            results["yara"] = _skip("yara", ["yara", "-r", str(config.yara_rules), str(path)], raw_dir, "Rules path does not exist")
    else:
        results["yara"] = _skip("yara", ["yara", "-r", "<rules>", str(path)], raw_dir, "No --yara-rules path provided")

    return {name: result.as_dict() for name, result in results.items()}


def _run_or_skip(name: str, command: list[str], raw_dir: Path, timeout: int) -> ToolResult:
    output_path = raw_dir / f"{name}.txt"
    executable = shutil.which(command[0])
    if not executable:
        return _skip(name, command, raw_dir, "Not installed / skipped")
    run_command = [executable, *command[1:]]
    try:
        proc = subprocess.run(
            run_command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        result = ToolResult(name, run_command, True, None, proc.returncode, False, str(output_path), proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        result = ToolResult(name, run_command, True, "Timed out", None, True, str(output_path), stdout, stderr)
    write_text(output_path, result.combined_output or status_text(result))
    return result


def _skip(name: str, command: list[str], raw_dir: Path, reason: str) -> ToolResult:
    output_path = raw_dir / f"{name}.txt"
    result = ToolResult(name, command, False, reason, None, False, str(output_path), "", "")
    write_text(output_path, status_text(result))
    return result


def status_text(result: ToolResult) -> str:
    if result.skipped_reason:
        return result.skipped_reason
    if result.timed_out:
        return "Timed out"
    return "No output"


def _looks_like_rtf(path: Path) -> bool:
    if path.suffix.lower() == ".rtf":
        return True
    try:
        return path.read_bytes()[:16].lstrip().startswith(b"{\\rtf")
    except OSError:
        return False

