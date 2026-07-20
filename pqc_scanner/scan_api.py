"""
JSON-only scan entrypoint, meant to be spawned as a subprocess from the
Next.js backend (see web-platform/src/app/api/scan/route.ts).

Usage:
    python3 -m pqc_scanner.scan_api <target>

Prints exactly one line of JSON to stdout on success:
    {"ok": true, "report": {...ScanReport shaped JSON...}}
or on failure:
    {"ok": false, "error": "..."}

Nothing else is ever written to stdout — all diagnostics go to stderr — so the
Node side can safely JSON.parse(stdout) without stripping banners.
"""
import asyncio
import json
import re
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass

from .scanner import TLSScanner
from .report_builder import build_scan_report


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


async def run(target: str) -> dict:
    host, port = parse_target(target)
    scanner = TLSScanner(host, port)
    results = await scanner.run_scan()
    report = build_scan_report(results.model_dump())
    return report


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print(json.dumps({"ok": False, "error": "A target hostname is required."}))
        sys.exit(1)

    target = sys.argv[1]

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        report = asyncio.run(asyncio.wait_for(run(target), timeout=90))
        print(json.dumps({"ok": True, "report": report}))
    except asyncio.TimeoutError:
        print(json.dumps({"ok": False, "error": f"Scan of {target} timed out after 90s."}))
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 - surface any scan failure to the caller
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
