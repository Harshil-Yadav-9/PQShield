from typing import List, Dict, Any, Tuple


# ---------------------------------------------------------------------------
# Client Simulation
# ---------------------------------------------------------------------------

def simulate_modern_clients(
    server_ciphers: List[Dict],
    server_protocols: List[Any],
) -> Dict[str, str]:
    """
    Simulate what cipher + protocol a modern browser would negotiate.
    Returns a dict of client_name -> negotiated string (or failure message).
    """
    clients = {
        "Chrome (Modern)": {
            "protocols": ["TLS 1.3", "TLS 1.2"],
            "ciphers": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ],
        },
        "Firefox (Modern)": {
            "protocols": ["TLS 1.3", "TLS 1.2"],
            "ciphers": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ],
        },
        "Safari (iOS/macOS)": {
            "protocols": ["TLS 1.3", "TLS 1.2"],
            "ciphers": [
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
        },
        "Edge (Windows 10/11)": {
            "protocols": ["TLS 1.3", "TLS 1.2"],
            "ciphers": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
        },
        "Android (Modern)": {
            "protocols": ["TLS 1.3", "TLS 1.2"],
            "ciphers": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            ],
        },
    }

    supported_cipher_names = {c["cipher_name"] for c in server_ciphers}
    supported_protos = {p.protocol for p in server_protocols if p.supported}

    simulation_results: Dict[str, str] = {}
    for client_name, profile in clients.items():
        connection_made = False
        for proto in profile["protocols"]:
            if proto not in supported_protos:
                continue
            for preferred_cipher in profile["ciphers"]:
                if preferred_cipher in supported_cipher_names:
                    simulation_results[client_name] = f"{proto} / {preferred_cipher}"
                    connection_made = True
                    break
            if connection_made:
                break
        if not connection_made:
            simulation_results[client_name] = "No Compatible Connection Found"

    return simulation_results


# ---------------------------------------------------------------------------
# PQC Report Generator
# ---------------------------------------------------------------------------

def generate_pqc_report(
    crypto_inventory: Dict,
    ciphers: List[Dict],
    certs: List[Dict] = None,
    pqc_probe: Dict = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Analyse PQC readiness from cipher suites, certificates, and the live probe.
    Returns (readiness_list, migration_report).
    """
    has_ml_kem = False
    has_ml_dsa = False
    has_slh_dsa = False
    has_fn_dsa = False
    ml_kem_evidence = "Active ML-KEM negotiation not detected via standard SSLyze."

    # ---- Check cipher suites for hybrid KEM ----
    for c in ciphers:
        name_upper = c.get("cipher_name", "").upper()
        if "MLKEM" in name_upper or "KYBER" in name_upper:
            has_ml_kem = True
            ml_kem_evidence = (
                "ML-KEM hybrid cipher suite detected in standard TLS handshake."
            )
            break

    # ---- Override with active OpenSSL probe result (highest confidence) ----
    if pqc_probe and pqc_probe.get("pqc_negotiated"):
        has_ml_kem = True
        group = pqc_probe.get("negotiated_group", "Unknown")
        ml_kem_evidence = (
            f"Active Key Encapsulation successful via OpenSSL probe! "
            f"Server accepted group: {group}"
        )

    # ---- Inspect certificate chain for PQC signature algorithms ----
    if certs:
        for cert in certs:
            sig_alg = cert.get("Signature Algorithm", "").upper()
            if "MLDSA" in sig_alg or "DILITHIUM" in sig_alg:
                has_ml_dsa = True
            if "SLHDSA" in sig_alg or "SPHINCS" in sig_alg:
                has_slh_dsa = True
            if "FALCON" in sig_alg or "FNDSA" in sig_alg:
                has_fn_dsa = True

    readiness: List[Dict[str, Any]] = [
        {
            "algorithm": "ML-KEM (Kyber) — Key Encapsulation",
            "nist_standard": "FIPS 203",
            "supported": has_ml_kem,
            "evidence": ml_kem_evidence,
        },
        {
            "algorithm": "ML-DSA (Dilithium) — Digital Signatures",
            "nist_standard": "FIPS 204",
            "supported": has_ml_dsa,
            "evidence": (
                "ML-DSA certificate detected in chain."
                if has_ml_dsa
                else "No ML-DSA certificates detected in chain."
            ),
        },
        {
            "algorithm": "SLH-DSA (SPHINCS+) — Stateless Hash Signatures",
            "nist_standard": "FIPS 205",
            "supported": has_slh_dsa,
            "evidence": (
                "SLH-DSA certificate detected in chain."
                if has_slh_dsa
                else "No SLH-DSA certificates detected in chain."
            ),
        },
        {
            "algorithm": "FN-DSA (Falcon) — Lattice-Based Signatures",
            "nist_standard": "FIPS 206",
            "supported": has_fn_dsa,
            "evidence": (
                "FN-DSA certificate detected in chain."
                if has_fn_dsa
                else "No FN-DSA certificates detected in chain."
            ),
        },
    ]

    # ---- Migration report ----
    legacy_deps: set = set()
    replacements: List[str] = []
    for c in ciphers:
        kex = c.get("key_exchange", "")
        if kex in ("ECDHE", "RSA", "DHE"):
            legacy_deps.add(kex)

    for dep in sorted(legacy_deps):
        replacements.append(f"{dep} -> ML-KEM / Hybrid X25519-ML-KEM (FIPS 203)")

    report: Dict[str, Any] = {
        "overall_pqc_ready": has_ml_kem and has_ml_dsa,
        "recommended_migration_path": [
            "1. Upgrade TLS stack to support FIPS 203 (ML-KEM / Kyber).",
            "2. Deploy Hybrid Key Exchange (X25519-ML-KEM768) as interim step.",
            "3. Replace RSA/ECDSA certificates with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
            "4. Audit all CA infrastructure for PQC signing capability.",
            "5. Disable TLS 1.0 / 1.1 / SSLv3 to close downgrade attack surface.",
        ],
        "legacy_dependencies": sorted(legacy_deps),
        "algorithms_requiring_replacement": replacements,
    }

    return readiness, report


# ---------------------------------------------------------------------------
# Cipher Detail Parser
# ---------------------------------------------------------------------------

# Canonical IANA hex codes for common cipher suites
_CIPHER_IANA_MAP: Dict[str, str] = {
    "TLS_AES_128_GCM_SHA256":                          "0x1301",
    "TLS_AES_256_GCM_SHA384":                          "0x1302",
    "TLS_CHACHA20_POLY1305_SHA256":                    "0x1303",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":           "0xC02F",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":           "0xC030",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":         "0xC02B",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":         "0xC02C",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":     "0xCCA8",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":   "0xCCA9",
    "TLS_RSA_WITH_AES_128_GCM_SHA256":                 "0x009C",
    "TLS_RSA_WITH_AES_256_GCM_SHA384":                 "0x009D",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":              "0xC013",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":              "0xC014",
    "TLS_RSA_WITH_AES_128_CBC_SHA":                    "0x002F",
    "TLS_RSA_WITH_AES_256_CBC_SHA":                    "0x0035",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA":                   "0x000A",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":             "0xC012",
    "TLS_RSA_WITH_RC4_128_SHA":                        "0x0005",
    "TLS_RSA_WITH_RC4_128_MD5":                        "0x0004",
    "TLS_NULL_WITH_NULL_NULL":                         "0x0000",
    "TLS_RSA_WITH_NULL_SHA":                           "0x0002",
    "SSL_CK_DES_192_EDE3_CBC_WITH_MD5":                "0xFF-0x1F",
}


def parse_cipher_details(c_name: str, iana_id: str) -> dict:
    """
    Parse a cipher suite name into its cryptographic components.
    Returns a dict with key_exchange, authentication, bulk_encryption,
    mac, aead, forward_secrecy, and IANA_ID.
    """
    name = c_name.upper()
    kex, auth, bulk, mac, aead = "Unknown", "Unknown", "Unknown", "Unknown", False

    # TLS 1.3 AEAD-only suites
    if name in (
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ):
        kex = "ECDHE/DHE"
        auth = "Certificate"
        mac = "AEAD"
        aead = True
        if "AES_128_GCM" in name:
            bulk = "AES-128-GCM"
        elif "AES_256_GCM" in name:
            bulk = "AES-256-GCM"
        elif "CHACHA20" in name:
            bulk = "CHACHA20-POLY1305"

    else:
        parts = name.split("_WITH_")
        if len(parts) == 2:
            left, right = parts[0], parts[1]

            # Key exchange + authentication
            if "ECDHE_ECDSA" in left:
                kex, auth = "ECDHE", "ECDSA"
            elif "ECDHE_RSA" in left:
                kex, auth = "ECDHE", "RSA"
            elif "DHE_RSA" in left:
                kex, auth = "DHE", "RSA"
            elif "DHE_DSS" in left:
                kex, auth = "DHE", "DSS"
            elif "ADH" in left or "AECDH" in left:
                kex, auth = "ECDHE", "Anonymous"
            elif left in ("TLS_RSA", "SSL_RSA"):
                kex, auth = "RSA", "RSA"

            # Bulk encryption + MAC
            if "AES_128_GCM" in right:
                bulk, mac, aead = "AES-128-GCM", "AEAD", True
            elif "AES_256_GCM" in right:
                bulk, mac, aead = "AES-256-GCM", "AEAD", True
            elif "CHACHA20_POLY1305" in right:
                bulk, mac, aead = "CHACHA20-POLY1305", "AEAD", True
            elif "AES_128_CBC" in right:
                bulk, mac = "AES-128-CBC", "SHA"
            elif "AES_256_CBC" in right:
                bulk, mac = "AES-256-CBC", "SHA"
            elif "3DES_EDE_CBC" in right:
                bulk, mac = "3DES-EDE-CBC", "SHA"
            elif "RC4_128" in right:
                if "MD5" in right:
                    bulk, mac = "RC4-128", "MD5"
                else:
                    bulk, mac = "RC4-128", "SHA"
            elif "NULL" in right:
                bulk, mac = "NULL", "NULL"

    return {
        "IANA_ID": _CIPHER_IANA_MAP.get(c_name.upper(), iana_id),
        "key_exchange": kex,
        "authentication": auth,
        "bulk_encryption": bulk,
        "mac": mac,
        "aead": aead,
        "forward_secrecy": kex in ("ECDHE", "DHE", "ECDHE/DHE"),
    }


# ---------------------------------------------------------------------------
# Certificate Authentication Evaluator
# ---------------------------------------------------------------------------

def evaluate_cert_authentication(sig_alg: str, key_size: int) -> dict:
    """
    Map a certificate's signature algorithm to its CBOM classification,
    PQC status, and relevant NIST standard.
    """
    sig_upper = (sig_alg or "UNKNOWN").upper()
    ks = key_size or 0

    if "MLDSA" in sig_upper or "ML-DSA" in sig_upper or "DILITHIUM" in sig_upper:
        return {
            "algorithm_name": sig_alg,
            "is_pqc": True,
            "nist_compliance": "FIPS 204",
            "quantum_safe": True,
            "recommendation": "Compliant — no action required.",
        }
    if "SLHDSA" in sig_upper or "SLH-DSA" in sig_upper or "SPHINCS" in sig_upper:
        return {
            "algorithm_name": sig_alg,
            "is_pqc": True,
            "nist_compliance": "FIPS 205",
            "quantum_safe": True,
            "recommendation": "Compliant — no action required.",
        }
    if "FALCON" in sig_upper or "FNDSA" in sig_upper or "FN-DSA" in sig_upper:
        return {
            "algorithm_name": sig_alg,
            "is_pqc": True,
            "nist_compliance": "FIPS 206",
            "quantum_safe": True,
            "recommendation": "Compliant — no action required.",
        }
    if "ECDSA" in sig_upper or ("EC" in sig_upper and "RSA" not in sig_upper):
        return {
            "algorithm_name": f"ECDSA-{ks}",
            "is_pqc": False,
            "nist_compliance": "NIST SP 800-186 (deprecated post-quantum)",
            "quantum_safe": False,
            "recommendation": "Plan migration to ML-DSA (FIPS 204) before 2030.",
        }
    if "RSA" in sig_upper:
        strength = "Acceptable" if ks >= 2048 else "Weak — below 2048-bit minimum"
        return {
            "algorithm_name": f"RSA-{ks}",
            "is_pqc": False,
            "nist_compliance": f"NIST SP 800-131A ({strength})",
            "quantum_safe": False,
            "recommendation": (
                "Migrate to ML-DSA (FIPS 204). RSA is vulnerable to Shor's algorithm."
            ),
        }
    return {
        "algorithm_name": sig_alg,
        "is_pqc": False,
        "nist_compliance": "Unknown",
        "quantum_safe": False,
        "recommendation": "Manual review required — algorithm not recognised.",
    }
