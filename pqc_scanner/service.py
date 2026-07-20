"""
HTTP service wrapping the TLS/PQC scanner. This is what actually gets
deployed (Railway, Fly.io, Render, ...) — the frontend never spawns Python
itself, it just calls this over HTTPS.

Local dev:
    uvicorn pqc_scanner.service:app --reload --port 8000

Endpoint:
    POST /scan  { "target": "example.com" }
    -> 200 { ...ScanReport shaped JSON... }
    -> 4xx/5xx { "error": "..." }
"""
import asyncio
import json
import os
import re
import tempfile
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .scanner import TLSScanner
from .report_builder import build_scan_report
from .risk_engine import generate_risk_report

app = FastAPI(title="PQShield Scanner Service")

# Lock this down to your real frontend origin(s) in production via the
# ALLOWED_ORIGINS env var (comma separated). Defaults to * for local dev.
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins.split(",") if allowed_origins != "*" else ["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

SCAN_TIMEOUT_SECONDS = 90


class ScanRequest(BaseModel):
    target: str


class ExportRequest(BaseModel):
    # The raw CBOM scan JSON (same shape as cbom_results.json / ScanResults.model_dump()),
    # exactly as returned in the `raw` field of POST /scan. This is round-tripped from the
    # frontend rather than re-scanned, so exporting never re-hits the target.
    raw: dict[str, Any]
    filename: str | None = None


def parse_target(target_str: str) -> tuple[str, int]:
    target_str = re.sub(r"^https?://", "", target_str.strip())
    target_str = target_str.split("/")[0]

    if target_str.startswith("["):
        host_end = target_str.find("]")
        host = target_str[1:host_end]
        rest = target_str[host_end + 1:]
        port = int(rest.split(":")[-1]) if ":" in rest else 443
        return host, port

    if ":" in target_str:
        host, port_str = target_str.rsplit(":", 1)
        return host, int(port_str)

    return target_str, 443


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/scan")
async def scan(req: ScanRequest):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="A target hostname is required.")

    host, port = parse_target(target)

    try:
        scanner = TLSScanner(host, port)
        results = await asyncio.wait_for(scanner.run_scan(), timeout=SCAN_TIMEOUT_SECONDS)
        raw = results.model_dump(mode="json")
        report = build_scan_report(raw)
        # `raw` is the same CBOM shape the CLI writes to cbom_results.json and
        # that risk_engine.generate_risk_report() consumes — the frontend
        # stores it alongside `report` so Export JSON / Export Excel never
        # need to re-scan the target.
        return {"report": report, "raw": raw}
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail=f"Scan of {target} timed out.")
    except Exception as e:  # noqa: BLE001 - surface the real failure to the caller
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/export/excel")
async def export_excel(req: ExportRequest):
    """
    Rebuilds the Excel risk report (same generator the CLI uses) from raw
    CBOM JSON already produced by a prior /scan call. Never touches the
    network — pure data-in, file-out.
    """
    with tempfile.TemporaryDirectory() as tmp:
        json_path = os.path.join(tmp, "cbom.json")
        xlsx_path = os.path.join(tmp, "report.xlsx")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(req.raw, f)

        try:
            ok = generate_risk_report(json_path, xlsx_path)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"Could not generate Excel report: {e}")

        if not ok or not os.path.exists(xlsx_path):
            raise HTTPException(status_code=500, detail="Excel report generation failed.")

        filename = req.filename or "TLS_PQC_Risk_Report.xlsx"
        with open(xlsx_path, "rb") as f:
            data = f.read()

    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
