# PQShield

## Overview

PQShield is a PQC-aware TLS scanner and component bill of materials (CBOM) generator for evaluating TLS endpoints. It performs an SSL/TLS posture scan using SSLyze, inspects certificate chains, simulates modern client compatibility, and generates a risk-based Excel report.

## Key Features

- Active TLS scanning with support for SSLv2/SSLv3/TLS 1.0-1.3
- Cipher suite parsing and categorization
- Certificate chain extraction and authentication evaluation
- PQC readiness analysis for Kyber, Dilithium, SPHINCS, and Falcon
- Modern browser client simulation for compatibility checks
- Active OpenSSL-based PQC probe when `openssl` is available
- Posture and vulnerability assessment for legacy issues such as:
  - Heartbleed
  - CCS injection
  - ROBOT
  - TLS_FALLBACK_SCSV
  - SWEET32
  - BEAST
  - POODLE
  - DROWN
  - FREAK
  - RC4 flaws
  - TLS compression / CRIME
- Generates JSON CBOM output and Excel risk reports

## Repository Structure

- `cli.py` - Command-line entrypoint for scanning targets and writing output files
- `pqc_scanner/scanner.py` - Main TLS scanning logic, SSLyze orchestration, certificate parsing, active probe, and analysis
- `pqc_scanner/models.py` - Pydantic models for structured scan result serialization
- `pqc_scanner/analyzers.py` - Cipher parsing, PQC readiness evaluation, modern client simulation, and authentication helpers
- `pqc_scanner/risk_engine.py` - Excel report generation with scoring and recommendations

## Installation

1. Create and activate a Python environment.
2. Install required dependencies.

```powershell
python -m pip install -r requirements.txt
```

Required packages:

- `sslyze`
- `cryptography`
- `openpyxl`
- `pydantic`

## Usage

Run the scanner from the repository root with a target host or IP.

```powershell
python cli.py example.com -o cbom_example.json -r audit_example.xlsx
```

CLI options:

- `target` - hostname, IP, or URL to scan
- `-o, --output` - output JSON path (default: `cbom_results.json`)
- `-r, --report` - output Excel report path (default: `TLS_PQC_Risk_Report.xlsx`)
- `--no-report` - skip Excel report generation

## Output

The scanner produces:

- JSON CBOM output with a comprehensive `ScanResults` payload
- Excel risk report summarizing posture, vulnerabilities, certificate checks, and PQC readiness

## Architecture

### `cli.py`

- Parses target strings and normalizes hosts/ports
- Starts the async scanner
- Writes JSON output
- Calls `generate_risk_report()` to build the Excel workbook

### `pqc_scanner/scanner.py`

- Uses SSLyze to query the server for supported cipher suites, certificates, curves, and TLS features
- Parses and normalizes cipher metadata
- Extracts certificate fields and extensions via `cryptography`
- Performs active Python TLS connection checks and optional OpenSSL probes
- Assesses vulnerabilities and builds structured result models

### `pqc_scanner/analyzers.py`

- Simulates modern browser client compatibility based on supported protocols and cipher suites
- Generates PQC readiness reports from cipher inventory, certificate signature algorithms, and probe results
- Parses cipher suite names into key exchange, authentication, bulk encryption, and MAC details

### `pqc_scanner/risk_engine.py`

- Builds an Excel workbook with formatting, colors, and posture scoring
- Converts scan JSON data into a risk report workbook
- Uses scoring tables and recommendation logic for TLS, certificate, and PQC findings

## Notes

- `openssl` is optional but provides enhanced active PQC probe capability.
- The scanner focuses on TLS posture and PQC readiness; it does not perform web application vulnerability scanning.
- The default scanner version string in `ScanMetadata` is `17.0.0-Fallback-Architecture`.

## Example

```powershell
python cli.py https://google.com --output google_cbom.json --report google_risk.xlsx
```

This will scan the target, save the JSON CBOM, and generate an Excel risk report.
