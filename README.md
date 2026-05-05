# doc-static-scanner

`doc-static-scanner` is a defensive, local-only static analysis utility for suspicious Microsoft Office documents, especially legacy OLE files such as `test12.doc`. It produces a polished PDF report, a standalone HTML report, a machine-readable JSON report, raw tool outputs, extracted strings, and IOC lists.

## Safety Warning

Do not open suspicious documents on your host. This scanner does not execute documents, enable macros, automate Word or LibreOffice, use Wine, detonate samples, or upload files to external services. Optional VirusTotal-style functionality is intentionally not included except that future integrations must be hash lookup only and must never upload samples.

## Install

Use a virtual environment. This avoids Ubuntu/Debian PEP 668 `externally-managed-environment` errors.

```bash
cd doc-static-scanner
python3 -m venv ~/.venvs/doc-static-scanner
source ~/.venvs/doc-static-scanner/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Optional local system tools:

```bash
sudo apt update
sudo apt install -y file binutils clamav yara libimage-exiftool-perl
```

Optional oletools:

```bash
source .venv/bin/activate
python -m pip install oletools
```

## Usage

Scan `test12.doc`:

```bash
python scanner.py test12.doc
```

Choose an output root:

```bash
python scanner.py test12.doc --out scan_reports
```

Run local YARA rules:

```bash
python scanner.py test12.doc --yara-rules ./rules
```

Skip ClamAV:

```bash
python scanner.py test12.doc --no-clamav
```

Print JSON to stdout:

```bash
python scanner.py test12.doc --json
```

Limit raw-output preview length in PDF and HTML:

```bash
python scanner.py test12.doc --max-pdf-output-chars 50000
```

Verbose progress:

```bash
python scanner.py test12.doc --verbose
```

## Output

Each scan creates:

```text
scan_reports/<sample_name>_<timestamp>/
  report.pdf
  report.html
  report.json
  raw/
    oleid.txt
    olevba.txt
    mraptor.txt
    oleobj.txt
    oledir.txt
    olemap.txt
    olemeta.txt
    oletimes.txt
    rtfobj.txt
    exiftool.txt
    clamscan.txt
    yara.txt
  extracted/
    strings.txt
    iocs.txt
```

Missing tools are recorded as `Not installed / skipped` and do not fail the scan. Suspicious findings also do not make the CLI return nonzero. Nonzero exit codes are reserved for serious scanner errors such as a missing input file.

## What It Analyzes

- File identity, timestamps, MIME/type hints, and whole-file entropy.
- MD5, SHA1, SHA256, and SHA512.
- OLE streams, sizes, first bytes, macro-related streams, and embedded object indicators.
- OOXML ZIP entries, `vbaProject.bin`, external links, embeddings, ActiveX, `customXml`, and external relationships.
- Optional local tools: `oleid`, `olevba`, `mraptor`, `oleobj`, `oledir`, `olemap`, `olemeta`, `oletimes`, `rtfobj`, `exiftool`, `clamscan`, and `yara`.
- ASCII and UTF-16LE strings, URLs, domains, IPs, emails, Windows paths, registry keys, base64-looking blobs, PowerShell-looking commands, and suspicious executable names.
- Suspicious macro and Office abuse patterns including auto-execution, process execution, network download, obfuscation, file system, registry, DDE, embedded OLE, and external template indicators.

## Risk Scoring

The scanner uses an explainable 0-100 scoring model:

- `0-24`: Low
- `25-49`: Medium
- `50-74`: High
- `75-100`: Critical

The PDF, HTML, and JSON reports list exactly which indicators added points.

## PEP 668 Troubleshooting

If you see an error like `externally-managed-environment`, do not install packages globally with `pip`. Create and activate a virtual environment:

```bash
python3 -m venv ~/.venvs/doc-static-scanner
source ~/.venvs/doc-static-scanner/bin/activate
python -m pip install -r requirements.txt
```

## Development

```bash
python -m compileall .
pytest
python scanner.py --help
```
