import argparse
import asyncio
import traceback
import re
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass

from pqc_scanner.scanner import TLSScanner
from pqc_scanner.risk_engine import generate_risk_report


def parse_target(target_str: str) -> tuple[str, int]:
    """
    Accept any of:
      google.com
      google.com:443
      https://google.com
      https://google.com:8443/path
      [::1]:443   (IPv6)
    """
    target_str = re.sub(r"^https?://", "", target_str)
    target_str = target_str.split("/")[0]  # strip path

    if target_str.startswith("["):
        # IPv6 literal  ->  [::1]:443
        host_end = target_str.find("]")
        host = target_str[1:host_end]
        rest = target_str[host_end + 1:]
        port = int(rest.split(":")[-1]) if ":" in rest else 443
        return host, port

    if ":" in target_str:
        host, port_str = target_str.rsplit(":", 1)
        return host, int(port_str)

    return target_str, 443


async def main():
    parser = argparse.ArgumentParser(
        description="PQC-Aware TLS Scanner & CBOM Generator"
    )
    parser.add_argument(
        "target",
        help="Target hostname / IP with optional port (e.g. google.com:443)",
    )
    parser.add_argument(
        "-o", "--output",
        default="cbom_results.json",
        help="Output JSON file path (default: cbom_results.json)",
    )
    parser.add_argument(
        "-r", "--report",
        default="TLS_PQC_Risk_Report.xlsx",
        help="Output Excel risk report path (default: TLS_PQC_Risk_Report.xlsx)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip generating the Excel risk report",
    )
    args = parser.parse_args()

    host, port = parse_target(args.target)
    print(f"[*] Starting PQC-aware TLS scan -> {host}:{port}")

    scanner = TLSScanner(host, port)
    try:
        results = await scanner.run_scan()

        with open(args.output, "w", encoding="utf-8") as f:
            f.write(results.model_dump_json(indent=4))

        print(f"[+] CBOM JSON written to: {args.output}")

        if not args.no_report:
            print(f"[*] Generating Excel risk report …")
            ok = generate_risk_report(args.output, args.report)
            if ok:
                print(f"[+] Excel report written to: {args.report}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
