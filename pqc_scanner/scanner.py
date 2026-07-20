import asyncio
import time
import socket
import urllib.request
import ssl
import subprocess
import re
import sys
import shutil
import ipaddress
from datetime import datetime, timezone

from sslyze import (
    Scanner, ServerScanRequest, ServerNetworkLocation,
    ScanCommand, ScanCommandAttemptStatusEnum
)
from nassl.ephemeral_key_info import DhEphemeralKeyInfo, EcDhEphemeralKeyInfo
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed448, ed25519
from .models import ScanResults, ScanMetadata, ProtocolSupport, CipherCategory
from .analyzers import (
    generate_pqc_report, simulate_modern_clients,
    parse_cipher_details, evaluate_cert_authentication,
)


class TLSScanner:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.ip_address = ""
        self.start_time = 0.0

    # ------------------------------------------------------------------
    # PQC Active Probe via OpenSSL CLI
    # ------------------------------------------------------------------

    def _probe_pqc_openssl_cli(self) -> dict:
        """
        Try to negotiate a PQC key-exchange group by calling `openssl s_client`
        with each known ML-KEM / Kyber group name.

        downgrade_detected is set to True only when:
          - We successfully connected but the server refused ALL PQC groups
            and fell back to a classical group.
        It remains False when the server has no legacy protocols at all
        (i.e. pure TLS 1.3 with strong ciphers and no downgrade surface).
        """
        groups_to_try = [
            "X25519MLKEM768",
            "X25519Kyber768Draft00",
            "x25519_mlkem768",
            "MLKEM768",
            "X448MLKEM1024",
            "SecP256r1MLKEM768",
        ]

        probe_result = {
            "status": "Attempted",
            "pqc_negotiated": False,
            "negotiated_group": None,
            "error_or_output": None,
            "negotiation_telemetry": {
                "client_supported_pqc_groups_sent": groups_to_try,
                "server_supported_pqc_groups_accepted": [],
                # Start as None — we set it properly after probing
                "downgrade_detected": None,
            },
        }

        openssl_exe = shutil.which("openssl")
        if not openssl_exe:
            probe_result["status"] = "Skipped — openssl not found in PATH"
            probe_result["negotiation_telemetry"]["downgrade_detected"] = False
            return probe_result

        classical_fallback_observed = False

        for pqc_group in groups_to_try:
            cmd = [
                openssl_exe, "s_client",
                "-connect", f"{self.host}:{self.port}",
                "-groups", pqc_group,
                "-no_ticket", "-brief",
            ]

            try:
                res = subprocess.run(
                    cmd, input=b"Q\n", capture_output=True, timeout=8
                )
                output = (
                    res.stdout.decode("utf-8", errors="ignore")
                    + res.stderr.decode("utf-8", errors="ignore")
                )

                # If -groups flag not recognised, retry with -curves
                if (
                    "Call to SSL_CONF_cmd" in output
                    or "unrecognized command" in output.lower()
                ):
                    cmd_fallback = [
                        openssl_exe, "s_client",
                        "-connect", f"{self.host}:{self.port}",
                        "-curves", pqc_group,
                        "-no_ticket", "-brief",
                    ]
                    res = subprocess.run(
                        cmd_fallback, input=b"Q\n", capture_output=True, timeout=8
                    )
                    output = (
                        res.stdout.decode("utf-8", errors="ignore")
                        + res.stderr.decode("utf-8", errors="ignore")
                    )
                    if (
                        "Call to SSL_CONF_cmd" in output
                        or "unrecognized command" in output.lower()
                    ):
                        # This OpenSSL build doesn't know this group at all
                        continue

                match = re.search(
                    r"(?:Negotiated TLS1\.3 group|Server Temp Key):\s*([a-zA-Z0-9_]+)",
                    output,
                )

                if match:
                    group = match.group(1)
                    probe_result["negotiated_group"] = group

                    if "KYBER" in group.upper() or "MLKEM" in group.upper():
                        # PQC negotiated successfully
                        probe_result["pqc_negotiated"] = True
                        probe_result["status"] = "Success"
                        probe_result["negotiation_telemetry"][
                            "server_supported_pqc_groups_accepted"
                        ] = [group]
                        probe_result["negotiation_telemetry"][
                            "downgrade_detected"
                        ] = False
                        return probe_result
                    else:
                        # Connected but server chose a classical group
                        classical_fallback_observed = True
                        probe_result["status"] = (
                            f"Classical fallback — server chose {group}"
                        )
                else:
                    probe_result["status"] = "Connected but group not parsed"

            except FileNotFoundError:
                probe_result["status"] = "Skipped — openssl binary not executable"
                probe_result["negotiation_telemetry"]["downgrade_detected"] = False
                return probe_result
            except subprocess.TimeoutExpired:
                pass

        # After all groups tried — determine downgrade_detected correctly:
        # A downgrade is only meaningful if the server actually accepted a
        # classical connection when we offered PQC.  If the server refused
        # to connect at all (e.g. TLS 1.3 only, no legacy support), that is
        # NOT a downgrade — it is a strong configuration.
        if probe_result["negotiation_telemetry"]["downgrade_detected"] is None:
            probe_result["negotiation_telemetry"]["downgrade_detected"] = (
                classical_fallback_observed
            )

        if probe_result["status"] == "Attempted":
            probe_result["status"] = "Failed — no PQC group accepted"

        return probe_result

    # ------------------------------------------------------------------
    # Active TLS Negotiation (Python ssl module)
    # ------------------------------------------------------------------

    def _fetch_active_negotiation(self) -> dict:
        data = {
            "ALPN": "None",
            "Negotiated Protocol": "Unknown",
            "Negotiated Cipher": "Unknown",
            "Compression": False,
        }
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        try:
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    data["ALPN"] = ssock.selected_alpn_protocol() or "None"
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        data["Negotiated Cipher"] = cipher_info[0]
                        data["Negotiated Protocol"] = cipher_info[1]
                    try:
                        data["Compression"] = ssock.compression() is not None
                    except Exception:
                        data["Compression"] = False
        except Exception:
            pass
        return data

    # ------------------------------------------------------------------
    # HTTP Headers
    # ------------------------------------------------------------------

    def _fetch_http_data(self) -> dict:
        http_data = {
            "HTTP Status Code": "Unknown",
            "HSTS": "not offered",
            "Server Banner": "No banner found",
            "Cookie Count": 0,
            "Secure Cookie": "No",
            "HTTP-only Cookie": "No",
        }
        if self.port not in (443, 8443):
            return http_data

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"https://{self.host}:{self.port}/",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                http_data["HTTP Status Code"] = f"{response.getcode()} OK"
                headers = response.info()
                if "Strict-Transport-Security" in headers:
                    http_data["HSTS"] = headers["Strict-Transport-Security"]
                if "Server" in headers:
                    http_data["Server Banner"] = headers["Server"]
                cookies = headers.get_all("Set-Cookie")
                if cookies:
                    http_data["Cookie Count"] = len(cookies)
                    http_data["Secure Cookie"] = (
                        "All Secure"
                        if all("Secure" in c for c in cookies)
                        else "Not all Secure"
                    )
                    http_data["HTTP-only Cookie"] = (
                        "All HttpOnly"
                        if all("HttpOnly" in c for c in cookies)
                        else "Not all HttpOnly"
                    )
        except urllib.error.HTTPError as e:
            http_data["HTTP Status Code"] = f"{e.code} Error"
        except Exception:
            http_data["HTTP Status Code"] = "Connection Failed"
        return http_data

    # ------------------------------------------------------------------
    # External CLI Scanner (stub — extend as needed)
    # ------------------------------------------------------------------

    def _run_external_cli_scanner(self) -> dict:
        return {}

    # ------------------------------------------------------------------
    # Certificate Extension Extractor
    # ------------------------------------------------------------------

    @staticmethod
    def _hostname_matches_identity(host: str, identity: str) -> bool:
        """Match a hostname against a certificate CN/SAN entry, honoring
        leftmost wildcards (e.g. '*.google.com' matches 'gemini.google.com')."""
        if not host or not identity:
            return False
        host = host.strip(".").lower()
        identity = identity.strip(".").lower()
        if identity.startswith("*."):
            suffix = identity[1:]  # keep leading dot, e.g. ".google.com"
            return host.endswith(suffix) and host.count(".") >= suffix.count(".")
        return host == identity

    def _is_sni_capable_hostname(self) -> bool:
        """SNI (RFC 6066) is sent by the client whenever it connects using a
        hostname rather than a raw IP literal, since server_hostname is
        always passed to wrap_socket in this scanner's handshakes."""
        try:
            ipaddress.ip_address(self.host)
            return False
        except ValueError:
            return True

    def _extract_extensions(self, cert) -> dict:
        data = {
            "SANs": [],
            "Key Usage": [],
            "Extended Key Usage": [],
            "OCSP URLs": [],
            "CA Issuers": [],
            "Certificate Transparency": "No",
        }
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            data["SANs"] = [name.value for name in ext.value]
        except Exception:
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            if ext.value.digital_signature:
                data["Key Usage"].append("Digital Signature")
            if ext.value.key_encipherment:
                data["Key Usage"].append("Key Encipherment")
            try:
                if ext.value.content_commitment:
                    data["Key Usage"].append("Non-Repudiation")
            except Exception:
                pass
        except Exception:
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            data["Extended Key Usage"] = [u._name for u in ext.value]
        except Exception:
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for desc in ext.value:
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    data["OCSP URLs"].append(desc.access_location.value)
                elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    data["CA Issuers"].append(desc.access_location.value)
        except Exception:
            pass
        try:
            CT_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            cert.extensions.get_extension_for_oid(CT_OID)
            data["Certificate Transparency"] = "Yes (SCT present)"
        except Exception:
            pass
        return data

    # ------------------------------------------------------------------
    # Cipher Categorisation
    # ------------------------------------------------------------------

    def _categorize_ciphers(self, ciphers: list) -> list:
        cats = {
            "NULL Ciphers": False,
            "Anonymous NULL Ciphers": False,
            "Export Ciphers": False,
            "LOW Ciphers (64-bit)": False,
            "RC4": False,
            "3DES / IDEA": False,
            "Obsolete CBC Ciphers": False,
            "Strong Encryption (AEAD)": False,
        }
        for c in ciphers:
            name = c.get("cipher_name", "").upper()
            if "NULL" in name and "WITH_NULL" in name:
                cats["NULL Ciphers"] = True
            if "ANON" in name or "ADH" in name or "AECDH" in name:
                cats["Anonymous NULL Ciphers"] = True
            if "EXPORT" in name or "_EXP" in name:
                cats["Export Ciphers"] = True
            if "DES" in name and "3DES" not in name:
                cats["LOW Ciphers (64-bit)"] = True
            if "RC4" in name:
                cats["RC4"] = True
            if "3DES" in name or "IDEA" in name:
                cats["3DES / IDEA"] = True
            # Only flag CBC as "Obsolete" when paired with a weak protocol
            # (TLS 1.0/1.1/SSLv3) — TLS 1.2 CBC with SHA-256+ is acceptable
            if "CBC" in name and c.get("protocol", "") in (
                "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"
            ):
                cats["Obsolete CBC Ciphers"] = True
            if "GCM" in name or "CHACHA20" in name or "POLY1305" in name:
                cats["Strong Encryption (AEAD)"] = True

        return [CipherCategory(category=k, supported=v) for k, v in cats.items()]

    # ------------------------------------------------------------------
    # EMS Check
    # ------------------------------------------------------------------

    def _check_ems_support(self) -> bool:
        openssl_exe = shutil.which("openssl")
        if not openssl_exe:
            return False
        cmd = [
            openssl_exe, "s_client",
            "-connect", f"{self.host}:{self.port}",
            "-tls1_2", "-no_ticket",
        ]
        try:
            res = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=5)
            output = (
                res.stdout.decode("utf-8", errors="ignore")
                + res.stderr.decode("utf-8", errors="ignore")
            )
            return "Extended master secret: yes" in output
        except Exception:
            return False

    # ------------------------------------------------------------------
    # DEFLATE / TLS Compression Check (CRIME vector)
    # RFC 3749, CVE-2012-4929
    # Strategy 1: Python ssl module (most reliable)
    # Strategy 2: openssl s_client -comp fallback
    # ------------------------------------------------------------------

    def _check_deflate_compression(self) -> dict:
        """
        Detect whether the server negotiates TLS-level DEFLATE compression.
        Returns a dict with keys: deflate_supported, method, evidence.
        RFC 3749 defines DEFLATE compression for TLS; it enables CRIME (CVE-2012-4929).
        """
        result = {
            "deflate_supported": False,
            "method": "none",
            "evidence": "No TLS compression detected.",
        }

        # ── Strategy 1: Python ssl module ──────────────────────────────
        # ssl.SSLSocket.compression() returns the compression method string
        # (e.g. "zlib") if negotiated, or None if not.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Enable compression in the SSL context (Python disables it by default)
        try:
            # OP_NO_COMPRESSION is the flag to DISABLE it; we want to ALLOW it
            # to probe whether the server will agree.
            ctx.options &= ~ssl.OP_NO_COMPRESSION
        except AttributeError:
            pass  # older Python — just try anyway

        try:
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    comp = ssock.compression()
                    if comp is not None:
                        result["deflate_supported"] = True
                        result["method"] = "python-ssl"
                        result["evidence"] = (
                            f"TLS compression negotiated via Python ssl module: {comp}. "
                            f"CRIME attack (CVE-2012-4929) is exploitable."
                        )
                        return result
        except Exception:
            pass

        # ── Strategy 2: openssl s_client -comp ─────────────────────────
        openssl_exe = shutil.which("openssl")
        if openssl_exe:
            cmd = [
                openssl_exe, "s_client",
                "-connect", f"{self.host}:{self.port}",
                "-comp",           # explicitly request compression
                "-no_ticket",
            ]
            try:
                res = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=8)
                output = (
                    res.stdout.decode("utf-8", errors="ignore")
                    + res.stderr.decode("utf-8", errors="ignore")
                )
                # openssl prints "Compression: zlib compression" when negotiated
                # and "Compression: NONE" when not
                if re.search(r"Compression:\s*(?!NONE)\S+", output, re.IGNORECASE):
                    comp_match = re.search(r"Compression:\s*(\S.*)", output, re.IGNORECASE)
                    comp_name = comp_match.group(1).strip() if comp_match else "DEFLATE/zlib"
                    result["deflate_supported"] = True
                    result["method"] = "openssl-cli"
                    result["evidence"] = (
                        f"TLS compression negotiated via openssl s_client -comp: {comp_name}. "
                        f"CRIME attack (CVE-2012-4929) is exploitable."
                    )
                else:
                    result["evidence"] = (
                        "openssl s_client -comp confirmed: server rejected TLS compression. "
                        "CRIME not exploitable."
                    )
                    result["method"] = "openssl-cli"
            except Exception:
                pass

        return result

    # ------------------------------------------------------------------
    # Vulnerability Assessment  ← CORE FIX IS HERE
    # ------------------------------------------------------------------

    def _assess_vulnerabilities_strict(
        self, result, ciphers, active_data, protocols, categories
    ) -> dict:
        """
        Assess vulnerabilities with correct logic:

        KEY FIX — SWEET32 / BEAST / POODLE / downgrade:
          If the server does NOT support any legacy protocol (TLS 1.0 / 1.1 /
          SSLv3 / SSLv2), and does NOT offer 3DES/RC4/CBC in any actively
          negotiable context, these vulnerabilities are FALSE regardless of
          whether TLS_FALLBACK_SCSV is present.

          A downgrade attack requires BOTH:
            (a) a legacy protocol endpoint that can be targeted, AND
            (b) absence of TLS_FALLBACK_SCSV protection.

          If there is no (a), there is nothing to downgrade to — so
          downgrade_open = False and all downgrade-dependent vulns = False.
        """
        vulns: dict = {}
        ext_vulns = self._run_external_cli_scanner()

        container = getattr(
            result, "scan_result",
            getattr(result, "scan_commands_results", None),
        )
        if not container:
            return {"error": "SSLyze result container missing"}

        # ---- Heartbleed ----
        if "Heartbleed" in ext_vulns:
            vulns["Heartbleed"] = ext_vulns["Heartbleed"]
        else:
            hb = getattr(container, ScanCommand.HEARTBLEED.value, None)
            if (
                hb
                and getattr(hb, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
                and hasattr(hb, "result")
            ):
                vulns["Heartbleed"] = {
                    "is_vulnerable": getattr(hb.result, "is_vulnerable_to_heartbleed", False),
                    "source": "native",
                }
            else:
                vulns["Heartbleed"] = {"error": "Check failed", "source": "native"}

        # ---- CCS Injection ----
        ccs = getattr(container, ScanCommand.OPENSSL_CCS_INJECTION.value, None)
        if (
            ccs
            and getattr(ccs, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
            and hasattr(ccs, "result")
        ):
            vulns["CCS_Injection"] = {
                "is_vulnerable": getattr(ccs.result, "is_vulnerable_to_ccs_injection", False),
                "source": "native",
            }
        else:
            vulns["CCS_Injection"] = {"error": "Check failed", "source": "native"}

        # ---- ROBOT ----
        if "ROBOT" in ext_vulns:
            vulns["ROBOT"] = ext_vulns["ROBOT"]
        else:
            robot = getattr(container, ScanCommand.ROBOT.value, None)
            if (
                robot
                and getattr(robot, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
                and hasattr(robot, "result")
            ):
                robot_res = getattr(robot.result, "robot_result", None)
                if robot_res:
                    enum_val = getattr(robot_res, "name", "UNKNOWN")
                    is_vuln = enum_val in (
                        "VULNERABLE_STRONG_KEY", "VULNERABLE_WEAK_KEY"
                    )
                    vulns["ROBOT"] = {
                        "is_vulnerable": is_vuln,
                        "enum_state": enum_val,
                        "source": "native",
                    }
                else:
                    vulns["ROBOT"] = {
                        "is_vulnerable": False,
                        "enum_state": "SKIPPED",
                        "source": "native",
                    }
            else:
                vulns["ROBOT"] = {"error": "Check failed", "source": "native"}

        # ---- Secure Renegotiation ----
        renego = getattr(container, ScanCommand.SESSION_RENEGOTIATION.value, None)
        if (
            renego
            and getattr(renego, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
            and hasattr(renego, "result")
        ):
            vulns["Secure_Renegotiation"] = {
                "is_supported": getattr(renego.result, "supports_secure_renegotiation", False),
                "source": "native",
            }
        else:
            vulns["Secure_Renegotiation"] = {"error": "Check failed", "source": "native"}

        # ---- Protocol flags ----
        sslv2_active  = any(p.protocol == "SSLv2"   and p.supported for p in protocols)
        sslv3_active  = any(p.protocol == "SSLv3"   and p.supported for p in protocols)
        tls10_active  = any(p.protocol == "TLS 1.0" and p.supported for p in protocols)
        tls11_active  = any(p.protocol == "TLS 1.1" and p.supported for p in protocols)
        tls12_active  = any(p.protocol == "TLS 1.2" and p.supported for p in protocols)
        tls13_active  = any(p.protocol == "TLS 1.3" and p.supported for p in protocols)

        # ---- TLS_FALLBACK_SCSV ----
        fallback_supported = False
        fallback_cmd = getattr(container, ScanCommand.TLS_FALLBACK_SCSV.value, None)
        if (
            fallback_cmd
            and getattr(fallback_cmd, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
            and hasattr(fallback_cmd, "result")
        ):
            fallback_supported = getattr(
                fallback_cmd.result, "supports_fallback_scsv", False
            )

        # ---- Active negotiation snapshot ----
        default_proto  = active_data.get("Negotiated Protocol", "Unknown")
        default_cipher = active_data.get("Negotiated Cipher", "Unknown")

        # ---- Per-protocol cipher sets ----
        tls10_ciphers = [c for c in ciphers if c.get("protocol") == "TLS 1.0"]
        sslv3_ciphers = [c for c in ciphers if c.get("protocol") == "SSLv3"]

        tls10_has_cbc = any("CBC" in c.get("cipher_name", "") for c in tls10_ciphers)
        sslv3_has_cbc = any("CBC" in c.get("cipher_name", "") for c in sslv3_ciphers)

        has_3des_idea = categories.get("3DES / IDEA", False)
        has_rc4       = categories.get("RC4", False)
        has_export    = categories.get("Export Ciphers", False)
        has_null      = categories.get("NULL Ciphers", False)

        # ─────────────────────────────────────────────────────────────────
        # CORE FIX: legacy_exists and downgrade_open
        #
        # legacy_exists = True only if at least one weak protocol is supported.
        # server_negotiates_modern = True if the live handshake negotiated
        #   TLS 1.2 or TLS 1.3 (checked via active_data "Negotiated Protocol").
        #
        # downgrade_open = True only when ALL THREE conditions hold:
        #   (a) a legacy protocol endpoint exists (something to downgrade TO)
        #   (b) TLS_FALLBACK_SCSV is absent (no protection mechanism)
        #   (c) the server is NOT already negotiating a modern protocol
        #       — if the server always picks TLS 1.3, a passive observer
        #         cannot force a downgrade without active MITM + FALLBACK_SCSV absent
        #
        # If legacy_exists is False OR server already negotiates TLS 1.2/1.3:
        #   downgrade_open MUST be False.
        # ─────────────────────────────────────────────────────────────────
        legacy_exists  = bool(sslv2_active or sslv3_active or tls10_active or tls11_active)

        # Check what the server actually negotiated in the live handshake
        _neg_proto = default_proto.upper()
        server_negotiates_modern = bool(
            "TLS 1.3" in _neg_proto
            or "TLSV1.3" in _neg_proto
            or "TLS 1.2" in _neg_proto
            or "TLSV1.2" in _neg_proto
        )

        # Downgrade is only a real risk when:
        # legacy exists AND no FALLBACK_SCSV AND the server is NOT already
        # always choosing a modern protocol in live negotiation.
        downgrade_open = bool(
            legacy_exists
            and not fallback_supported
            and not server_negotiates_modern
        )

        vulns["Fallback_SCSV"] = {
            "is_supported": fallback_supported,
            # Only mark this as a vulnerability if there IS a legacy protocol
            # that a downgrade could target.
            "is_vulnerable": downgrade_open,
            "legacy_protocol_present": legacy_exists,
            "source": "strict",
            "note": (
                "TLS_FALLBACK_SCSV absent but no legacy protocols enabled — "
                "downgrade attack surface does not exist."
                if not legacy_exists
                else (
                    "TLS_FALLBACK_SCSV absent but server negotiates TLS 1.2/1.3 — "
                    "passive downgrade not exploitable; MITM active attack theoretically possible."
                    if not fallback_supported and server_negotiates_modern
                    else (
                        "Protected — FALLBACK_SCSV present."
                        if fallback_supported
                        else "UNPROTECTED — legacy protocols present, no FALLBACK_SCSV, server may negotiate legacy."
                    )
                )
            ),
        }

        # ─────────────────────────────────────────────────────────────────
        # SWEET32 — 3DES birthday attack
        # Exploitable when:
        #   (a) 3DES is actively negotiated in the default handshake, OR
        #   (b) 3DES exists in supported ciphers AND a downgrade path is open.
        # If neither condition is true -> False.
        # ─────────────────────────────────────────────────────────────────
        sweet32_actively_negotiated = bool(
            "3DES" in default_cipher.upper() or "IDEA" in default_cipher.upper()
        )
        sweet32_via_downgrade = bool(has_3des_idea and downgrade_open)
        sweet32_exploitable = sweet32_actively_negotiated or sweet32_via_downgrade

        vulns["SWEET32"] = {
            "is_vulnerable": sweet32_exploitable,
            "actively_negotiated": sweet32_actively_negotiated,
            "downgrade_vector_open": downgrade_open,
            "3des_in_cipher_list": has_3des_idea,
            "source": "strict",
            "note": (
                "3DES is actively negotiated — SWEET32 is exploitable."
                if sweet32_actively_negotiated
                else (
                    "3DES reachable via downgrade — mitigate by disabling legacy protocols."
                    if sweet32_via_downgrade
                    else "3DES not reachable — SWEET32 not exploitable."
                )
            ),
        }

        # ─────────────────────────────────────────────────────────────────
        # BEAST — TLS 1.0 + CBC chosen-plaintext
        # Exploitable when TLS 1.0 is negotiated WITH a CBC cipher,
        # either directly or via downgrade.
        # ─────────────────────────────────────────────────────────────────
        beast_actively_negotiated = bool(
            default_proto == "TLSv1" and "CBC" in default_cipher.upper()
        )
        beast_via_downgrade = bool(tls10_active and tls10_has_cbc and downgrade_open)
        beast_exploitable = beast_actively_negotiated or beast_via_downgrade

        vulns["BEAST"] = {
            "is_vulnerable": beast_exploitable,
            "actively_negotiated": beast_actively_negotiated,
            "downgrade_vector_open": downgrade_open,
            "tls10_cbc_present": tls10_has_cbc,
            "source": "strict",
            "note": (
                "TLS 1.0 + CBC actively negotiated — BEAST is exploitable."
                if beast_actively_negotiated
                else (
                    "TLS 1.0 + CBC reachable via downgrade."
                    if beast_via_downgrade
                    else "TLS 1.0 + CBC not reachable — BEAST not exploitable."
                )
            ),
        }

        # ─────────────────────────────────────────────────────────────────
        # POODLE (SSL) — SSLv3 + CBC padding oracle
        # ─────────────────────────────────────────────────────────────────
        poodle_actively_negotiated = bool(
            default_proto == "SSLv3" and "CBC" in default_cipher.upper()
        )
        poodle_via_downgrade = bool(sslv3_active and sslv3_has_cbc and downgrade_open)
        poodle_exploitable = poodle_actively_negotiated or poodle_via_downgrade

        vulns["POODLE_SSL"] = {
            "is_vulnerable": poodle_exploitable,
            "actively_negotiated": poodle_actively_negotiated,
            "downgrade_vector_open": downgrade_open,
            "sslv3_cbc_present": sslv3_has_cbc,
            "source": "strict",
            "note": (
                "SSLv3 + CBC actively negotiated — POODLE is exploitable."
                if poodle_actively_negotiated
                else (
                    "SSLv3 + CBC reachable via downgrade."
                    if poodle_via_downgrade
                    else "SSLv3 + CBC not reachable — POODLE not exploitable."
                )
            ),
        }

        # ---- DROWN — SSLv2 decryption oracle ----
        vulns["DROWN"] = {
            "is_vulnerable": bool(sslv2_active),
            "source": "strict",
            "note": (
                "SSLv2 is enabled — DROWN attack is possible."
                if sslv2_active
                else "SSLv2 disabled — DROWN not exploitable."
            ),
        }

        # ---- FREAK — export-grade RSA downgrade ----
        vulns["FREAK"] = {
            "is_vulnerable": bool(has_export),
            "source": "strict",
            "note": (
                "Export-grade ciphers present — FREAK is exploitable."
                if has_export
                else "No export-grade ciphers — FREAK not exploitable."
            ),
        }

        # ---- RC4 Flaws ----
        vulns["RC4_Flaw"] = {
            "is_vulnerable": bool(has_rc4),
            "source": "strict",
            "note": (
                "RC4 cipher suites present — RC4 bias attacks possible."
                if has_rc4
                else "No RC4 ciphers — RC4 attacks not exploitable."
            ),
        }

        # ---- DEFLATE / TLS Compression — CRIME (CVE-2012-4929 / RFC 3749) ----
        # We call the dedicated method which tries Python ssl then openssl -comp.
        deflate_result = self._check_deflate_compression()
        compression_on = deflate_result["deflate_supported"]
        vulns["CRIME_TLS"] = {
            "is_vulnerable": compression_on,
            "deflate_negotiated": compression_on,
            "detection_method": deflate_result.get("method", "unknown"),
            "source": "deflate-probe",
            "note": deflate_result["evidence"],
        }

        # ---- NULL cipher check ----
        vulns["NULL_Cipher"] = {
            "is_vulnerable": bool(has_null),
            "source": "strict",
            "note": (
                "NULL ciphers present — traffic is unencrypted."
                if has_null
                else "No NULL ciphers — encryption enforced."
            ),
        }

        return vulns

    # ------------------------------------------------------------------
    # Main Scan Entry Point
    # ------------------------------------------------------------------

    async def run_scan(self) -> ScanResults:
        self.start_time = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()

        try:
            self.ip_address = socket.gethostbyname(self.host)
        except Exception:
            self.ip_address = "Resolution Failed"

        pqc_probe_results = self._probe_pqc_openssl_cli()

        server_location = ServerNetworkLocation(hostname=self.host, port=self.port)
        scanner = Scanner()

        commands = [
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.ELLIPTIC_CURVES,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.SESSION_RESUMPTION,
            ScanCommand.HEARTBLEED,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.ROBOT,
            ScanCommand.SESSION_RENEGOTIATION,
        ]

        scan_req = ServerScanRequest(
            server_location=server_location, scan_commands=commands
        )
        scanner.queue_scans([scan_req])

        result = None
        for r in scanner.get_results():
            result = r

        if not result:
            raise RuntimeError("SSLyze returned empty results.")

        return self._parse_results(result, start_iso, pqc_probe_results)

    # ------------------------------------------------------------------
    # Result Parser
    # ------------------------------------------------------------------

    def _parse_results(self, result, start_iso: str, pqc_probe: dict) -> ScanResults:
        duration = time.time() - self.start_time
        protocols, ciphers, pfs_ciphers, curves, cipher_order_prefs = [], [], [], [], {}

        cipher_commands = {
            "SSLv2":   ScanCommand.SSL_2_0_CIPHER_SUITES,
            "SSLv3":   ScanCommand.SSL_3_0_CIPHER_SUITES,
            "TLS 1.0": ScanCommand.TLS_1_0_CIPHER_SUITES,
            "TLS 1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
            "TLS 1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
            "TLS 1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
        }

        results_container = getattr(
            result, "scan_result",
            getattr(result, "scan_commands_results", None),
        )

        for proto_name, cmd in cipher_commands.items():
            attempt = getattr(results_container, cmd.value, None)
            is_supported = False
            if (
                attempt
                and getattr(attempt, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
                and hasattr(attempt, "result")
                and getattr(attempt.result, "accepted_cipher_suites", None)
            ):
                is_supported = True
                preferred = getattr(
                    attempt.result, "cipher_suite_preferred_by_server", None
                )
                if preferred and hasattr(preferred, "cipher_suite"):
                    cipher_order_prefs[proto_name] = preferred.cipher_suite.name

                for suite in attempt.result.accepted_cipher_suites:
                    c_name = getattr(
                        getattr(suite, "cipher_suite", None), "name", "Unknown"
                    )
                    cs_enum = getattr(suite, "cipher_suite", None)
                    raw_id = getattr(cs_enum, "value", getattr(cs_enum, "id", None))
                    iana_hex = (
                        f"0x{raw_id:04X}" if isinstance(raw_id, int) else "Unknown"
                    )

                    parsed = parse_cipher_details(c_name, iana_hex)
                    actual_mac = parsed.get("mac", "Unknown")
                    c_upper = c_name.upper()
                    if "SHA384" in c_upper:
                        actual_mac = "SHA384"
                    elif "SHA256" in c_upper:
                        actual_mac = "SHA256"
                    elif "SHA512" in c_upper or "SHA3" in c_upper:
                        actual_mac = "SHA512 or SHA3"
                    elif c_upper.endswith("_SHA") or "SHA1" in c_upper:
                        actual_mac = "SHA1"
                    elif "MD5" in c_upper:
                        actual_mac = "MD5"
                    if parsed["key_exchange"] in ("ECDHE", "DHE"):
                        pfs_ciphers.append(c_name)

                    key_exchange_label = parsed["key_exchange"]
                    dh_prime_bits = None
                    dh_generator = None
                    ecdhe_curve = None
                    ephemeral_key = getattr(suite, "ephemeral_key", None)
                    if isinstance(ephemeral_key, EcDhEphemeralKeyInfo):
                        ecdhe_curve = ephemeral_key.curve_name
                        key_exchange_label = f"ECDHE ({ecdhe_curve})"
                    elif isinstance(ephemeral_key, DhEphemeralKeyInfo):
                        if isinstance(ephemeral_key.prime, (bytes, bytearray)):
                            dh_prime_bits = len(ephemeral_key.prime) * 8
                        if isinstance(ephemeral_key.generator, (bytes, bytearray)):
                            dh_generator = int.from_bytes(ephemeral_key.generator, "big")
                        if dh_prime_bits and dh_generator == 2 and dh_prime_bits in (2048, 3072, 4096):
                            key_exchange_label = f"DHE (ffdhe{dh_prime_bits})"
                        elif dh_prime_bits:
                            key_exchange_label = f"DHE ({dh_prime_bits}-bit)"
                        else:
                            key_exchange_label = "DHE"

                    ciphers.append(
                        {
                            "cipher_name": c_name,
                            "IANA_ID": parsed["IANA_ID"],
                            "protocol": proto_name,
                            "key_exchange": key_exchange_label,
                            "authentication": parsed["authentication"],
                            "bulk_encryption": parsed["bulk_encryption"],
                            "mac": actual_mac,
                            "aead": parsed["aead"],
                            "forward_secrecy": parsed["forward_secrecy"],
                            "security_bits": getattr(
                                getattr(suite, "cipher_suite", None), "key_size", 0
                            ),
                            "dh_prime_bits": dh_prime_bits,
                            "dh_generator": dh_generator,
                            "ecdh_curve": ecdhe_curve,
                        }
                    )
            protocols.append(ProtocolSupport(protocol=proto_name, supported=is_supported))

        # Elliptic curves
        curve_attempt = getattr(results_container, ScanCommand.ELLIPTIC_CURVES.value, None)
        if (
            curve_attempt
            and getattr(curve_attempt, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
            and hasattr(curve_attempt, "result")
            and getattr(curve_attempt.result, "supported_curves", None)
        ):
            curves = [c.name for c in curve_attempt.result.supported_curves]

        if curves:
            curve_label = f"ECDHE ({', '.join(curves)})"
            for cipher in ciphers:
                if cipher.get("key_exchange") == "ECDHE":
                    cipher["key_exchange"] = curve_label

        # Certificates
        certs_data = []
        trust_stores_data = {}
        cert_attempt = getattr(results_container, ScanCommand.CERTIFICATE_INFO.value, None)
        if (
            cert_attempt
            and getattr(cert_attempt, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
            and hasattr(cert_attempt, "result")
            and getattr(cert_attempt.result, "certificate_deployments", None)
        ):
            for dep in cert_attempt.result.certificate_deployments:
                if hasattr(dep, "path_validation_results"):
                    for validation in dep.path_validation_results:
                        store_name = getattr(
                            getattr(validation, "trust_store", None), "name", "Unknown"
                        )
                        val_error = getattr(validation, "validation_error", None)
                        is_trusted = val_error is None
                        if store_name not in trust_stores_data or is_trusted:
                            trust_stores_data[store_name] = {
                                "is_trusted": is_trusted,
                                "validation_error": (
                                    "None" if val_error is None else str(val_error)
                                ),
                                "version": getattr(
                                    getattr(validation, "trust_store", None),
                                    "version", "Unknown",
                                ),
                            }

                if hasattr(dep, "received_certificate_chain"):
                    for cert in dep.received_certificate_chain:
                        parsed_cert = cert.public_key()
                        ext_data = self._extract_extensions(cert)
                        sig_alg_name = getattr(
                            getattr(cert, "signature_algorithm_oid", None),
                            "_name", "Unknown",
                        )
                        pk_size = getattr(parsed_cert, "key_size", None)

                        pk_algo = "Unknown"
                        if isinstance(parsed_cert, rsa.RSAPublicKey):
                            pk_algo = "RSA"
                        elif isinstance(parsed_cert, ec.EllipticCurvePublicKey):
                            pk_algo = "ECDSA"
                        elif isinstance(parsed_cert, dsa.DSAPublicKey):
                            pk_algo = "DSA"
                        elif isinstance(parsed_cert, ed25519.Ed25519PublicKey):
                            pk_algo = "Ed25519"
                        elif isinstance(parsed_cert, ed448.Ed448PublicKey):
                            pk_algo = "Ed448"

                        ext_data = self._extract_extensions(cert)
                        sig_alg_name = getattr(getattr(cert, "signature_algorithm_oid", None), "_name", "Unknown")

                        cert_dict = {
                            "Common Name (CN)": cert.subject.rfc4514_string(),
                            "Serial Number": str(cert.serial_number),
                            "Valid Not Before": cert.not_valid_before_utc.isoformat(),
                            "Valid Not After": cert.not_valid_after_utc.isoformat(),
                            "Expiration Status": "EXPIRED" if datetime.now(timezone.utc) > cert.not_valid_after_utc else "VALID",
                            "Signature Algorithm": sig_alg_name,
                            "Public Key Algorithm": pk_algo,
                            "Public Key Size": pk_size,
                            **ext_data,
                        }
                        cert_dict["cbom_authentication_layer"] = evaluate_cert_authentication(
                            sig_alg_name, pk_size
                        )
                        certs_data.append(cert_dict)

        # Session resumption
        server_defaults: dict = {}
        session_attempt = getattr(
            results_container, ScanCommand.SESSION_RESUMPTION.value, None
        )
        if (
            session_attempt
            and getattr(session_attempt, "status", None) == ScanCommandAttemptStatusEnum.COMPLETED
            and hasattr(session_attempt, "result")
        ):
            server_defaults["Session Resumption Ticket"] = getattr(
                session_attempt.result, "is_ticket_resumption_supported", False
            )
            server_defaults["Session Resumption ID"] = getattr(
                session_attempt.result, "is_session_id_resumption_supported", False
            )

        active_negotiation = self._fetch_active_negotiation()

        server_prefs = {
            "preferred_ciphers_by_protocol": cipher_order_prefs,
            "ALPN Negotiated": active_negotiation["ALPN"],
            "Default Negotiated Protocol": active_negotiation["Negotiated Protocol"],
            "Default Negotiated Cipher": active_negotiation["Negotiated Cipher"],
        }

        # Active transport layer / KEX info
        kex_algo = "Classical (ECDHE/RSA)"
        is_pqc_kex = False
        is_hybrid = False
        nist_kex_ref = "N/A"
        kex_length = 256

        if pqc_probe.get("pqc_negotiated"):
            neg_group = pqc_probe.get("negotiated_group", "")
            kex_algo = neg_group
            is_pqc_kex = True
            nist_kex_ref = "FIPS 203"
            if any(
                prefix in neg_group.upper()
                for prefix in ("X25519", "X448", "SECP")
            ):
                is_hybrid = True
                kex_length = 1024
            else:
                kex_length = 768

        active_transport_layer = {
            "tls_version": active_negotiation.get("Negotiated Protocol", "Unknown"),
            "cipher_suite": active_negotiation.get("Negotiated Cipher", "Unknown"),
            "key_exchange": {
                "algorithm_name": kex_algo,
                "is_pqc": is_pqc_kex,
                "is_hybrid": is_hybrid,
                "nist_standard_reference": nist_kex_ref,
                "key_length_bits": kex_length,
            },
        }

        http_data = self._fetch_http_data()
        cat_list = self._categorize_ciphers(ciphers)
        cat_dict = {c.category: c.supported for c in cat_list}

        vuln_data = self._assess_vulnerabilities_strict(
            result, ciphers, active_negotiation, protocols, cat_dict
        )

        crypto_algs = list(
            {
                a
                for c in ciphers
                for a in (
                    c.get("key_exchange", ""),
                    c.get("authentication", ""),
                    c.get("bulk_encryption", ""),
                )
                if a and a != "Unknown"
            }
        )

        pqc_readiness, pqc_report = generate_pqc_report(
            {"algorithms": crypto_algs}, ciphers, certs_data, pqc_probe
        )

        pfs = {
            "pfs_supported": len(pfs_ciphers) > 0,
            "pfs_ciphers": sorted(set(pfs_ciphers)),
            "ecdhe_curves": curves,
        }

        # TLS extensions heuristic list
        tls_ext = ["renegotiation info/#65281"]
        sni_matched_cert = any(
            any(self._hostname_matches_identity(self.host, san) for san in cert.get("SANs", []))
            or self._hostname_matches_identity(self.host, cert.get("Common Name (CN)", "").split("CN=", 1)[-1])
            for cert in certs_data
        )
        # SNI is a client-sent extension: since every handshake in this
        # scanner is done with server_hostname=self.host, SNI was sent
        # whenever the target is a hostname (not a raw IP literal). A
        # matching SAN/CN additionally confirms the server honored it.
        if sni_matched_cert or self._is_sni_capable_hostname():
            tls_ext.append("server name indication/#0")
        if curves:
            tls_ext.append("EC point formats/#11")
        if server_defaults.get("Session Resumption Ticket"):
            tls_ext.append("session ticket/#35")
        if self._check_ems_support():
            tls_ext.append("extended master secret/#23")
        if any(p.supported for p in protocols if "1.3" in p.protocol):
            tls_ext.extend(["key share/#51", "supported versions/#43"])
        alpn = active_negotiation.get("ALPN")
        if alpn and alpn != "None":
            tls_ext.append("application layer protocol negotiation/#16")

        return ScanResults(
            target={"hostname": self.host, "port": self.port},
            scan_metadata=ScanMetadata(
                target=self.host,
                ip=self.ip_address,
                port=self.port,
                scan_start=start_iso,
                scan_end=datetime.now(timezone.utc).isoformat(),
                scan_duration_seconds=round(duration, 2),
            ),
            protocols=protocols,
            cipher_categories=cat_list,
            cipher_suites=ciphers,
            tls_extensions=tls_ext,
            server_preferences=server_prefs,
            active_transport_layer=active_transport_layer,
            server_defaults=server_defaults,
            certificates=certs_data,
            trust_stores=trust_stores_data,
            pfs=pfs,
            capability_space={"total_ciphers": len(ciphers)},
            vulnerabilities=vuln_data,
            http_response=http_data,
            crypto_inventory={"algorithms": crypto_algs},
            client_simulations=simulate_modern_clients(ciphers, protocols),
            pqc_active_probe=pqc_probe,
            pqc_analysis=pqc_readiness,
            pqc_migration_report=pqc_report,
        )