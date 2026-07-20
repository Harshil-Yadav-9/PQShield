"""
Bridges the raw scan JSON (the same shape written to cbom_results.json / consumed
by risk_engine.generate_risk_report) into the JSON shape the Next.js frontend
expects (web-platform/src/lib/types.ts -> ScanReport).

This intentionally reuses every scoring / severity helper already defined in
risk_engine.py so the web report and the Excel report always agree on numbers.
It does not touch openpyxl at all — pure data in, dict out.
"""
import re
import uuid
from datetime import datetime, timezone

from .risk_engine import (
    Section,
    _rec,
    _p_sev,
    _p_std,
    _hsts,
    _exp,
    _sign_severity,
    _cert_key_type,
    _cert_key_severity,
    _cert_key_recommendation,
    _cert_size_label,
    _cert_size_severity,
    _cert_size_recommendation,
    _cert_algo_display,
    _signature_label,
    _signature_recommendation,
    _normalize_cert_key_size,
    _j,
    _collect_negotiated_groups,
    _negotiated_group_info,
)

SECTION_ID_BY_NAME = {
    "Protocol (Capability space)": "protocol",
    "Certificate": "certificate",
    "Extensions": "extensions",
    "HTTP Security": "http",
    "Vulnerabilities": "vulnerabilities",
    "Cipher Categories": "cipher-categories",
    "Cipher Suites": "cipher-suites",
    "PQC": "pqc",
}


def _finding_from_row(row: dict) -> dict:
    observed = row["finding"]
    if not isinstance(observed, str):
        observed = _j(observed) if isinstance(observed, list) else str(observed)
    contribution = round(row["score"] * row["wt"] / 10.0, 2)
    return {
        "parameter": row["param"],
        "observed": observed,
        "standard": row["std"],
        "severity": row["sev"],
        "contribution": contribution,
        "recommendation": row["rec"],
    }


def _section_summary(findings: list) -> str:
    bad = [f for f in findings if f["severity"] in ("Critical", "High")]
    if not bad:
        return f"No high-severity issues found across {len(findings)} checks."
    names = ", ".join(f["parameter"] for f in bad[:2])
    extra = f" (+{len(bad) - 2} more)" if len(bad) > 2 else ""
    return f"{len(bad)} finding(s) need attention, including {names}{extra}."


def _finalize_section(section: Section) -> dict:
    raw, lo, hi, normalized = section.process()
    findings = [_finding_from_row(r) for r in section.rows]
    return {
        "id": SECTION_ID_BY_NAME.get(section.name, re.sub(r"[^a-z0-9]+", "-", section.name.lower()).strip("-")),
        "name": section.name,
        "weight": section.weight,
        "normalized": normalized,
        "summary": _section_summary(findings),
        "findings": findings,
    }


def _risk_band(score: float) -> str:
    if score < 30:
        return "Critical"
    if score < 50:
        return "At risk"
    if score < 75:
        return "Moderate"
    if score < 90:
        return "Strong"
    return "PQC ready"


def _slugify(hostname: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", hostname.lower()).strip("-") or "target"
    return f"{slug}-{uuid.uuid4().hex[:6]}"


def build_scan_report(data: dict) -> dict:
    """
    data: the dict produced by ScanResults.model_dump() (same shape as
    cbom_results.json). Returns a dict matching web-platform's ScanReport type.
    """
    sm = data.get("scan_metadata") or {}
    t = data.get("target") or {}
    hostname = sm.get("target") or t.get("hostname") or "Unknown"
    ip = sm.get("ip") or t.get("ip") or ""
    port = sm.get("port") or t.get("port") or 443

    sections: list[dict] = []

    # ---------------- Protocol ----------------
    s = Section("Protocol (Capability space)", 23)
    for p in data.get("protocols", []):
        if not isinstance(p, dict):
            continue
        pr, sup = p.get("protocol", ""), p.get("supported", False)
        sv = _p_sev(pr, sup)
        if pr in ("SSLv2", "SSLv3", "TLS 1.0"):
            b = (-10, 10)
        elif pr == "TLS 1.1":
            b = (-6, 10)
        elif pr == "TLS 1.2":
            b = (-2, 5)
        elif pr == "TLS 1.3":
            b = (-10, 10)
        else:
            b = (-10, 10)
        act = f"disable {pr} immediately." if sup and pr in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1") else f"enable {pr}."
        s.add(f"Protocol - {pr} (Capability space)", "Enabled" if sup else "Disabled", _p_std(pr), sv, _rec(sv, act), *b)

    vu = data.get("vulnerabilities")
    vu = vu if isinstance(vu, dict) else {}
    fb = vu.get("Fallback_SCSV")
    fb = fb if isinstance(fb, dict) else {}
    fb_sv = "Acceptable" if fb.get("is_supported") else ("High" if fb.get("legacy_protocol_present") else "Acceptable")
    s.add(
        "Downgrade Protection (TLS_FALLBACK_SCSV)",
        "Supported" if fb.get("is_supported") else "Not Supported",
        "RFC 7507",
        fb_sv,
        _rec(fb_sv, "enable TLS_FALLBACK_SCSV to prevent protocol downgrade attacks."),
        -2,
        5,
    )
    sections.append(_finalize_section(s))

    # ---------------- Certificate ----------------
    s = Section("Certificate", 13)
    certs = [c for c in data.get("certificates", []) if isinstance(c, dict)]
    if not certs:
        certs = [{}]
    for idx, cert in enumerate(certs, 1):
        sig = cert.get("Signature Algorithm", "")
        raw_ksz = cert.get("Public Key Size", 0) or 0
        pk_algo = cert.get("Public Key Algorithm", "")
        cb_algo = ""
        if isinstance(cert.get("cbom_authentication_layer"), dict):
            cb_algo = cert["cbom_authentication_layer"].get("algorithm_name", "") or ""
        cert_algo_ref = pk_algo if pk_algo else (cb_algo if cb_algo else sig)
        ksz = _normalize_cert_key_size(cert_algo_ref, raw_ksz)
        algo_display = _cert_algo_display(sig, cert_algo_ref, ksz)
        key_type = _cert_key_type(sig, cert_algo_ref)
        size_label = _cert_size_label(cert_algo_ref, ksz)
        signature_label = _signature_label(sig)

        s.add(f"Certificate {idx} - Public Key Cert", algo_display, "FIPS 204 / NIST SP 800-131A rev 2", _cert_key_severity(key_type), _cert_key_recommendation(key_type), -10, 10)
        s.add(f"Certificate {idx} - Public Keysize Cert", size_label, "NIST SP 800-131A rev 2", _cert_size_severity(size_label), _cert_size_recommendation(size_label), -10, 10)
        s.add(f"Certificate {idx} - Signature", signature_label, "NIST SP 800-131A rev 2", _sign_severity(signature_label), _signature_recommendation(signature_label), -10, 10)

        eku_raw = cert.get("Extended Key Usage", [])
        eku = [k.lower() for k in eku_raw] if isinstance(eku_raw, list) else []
        eku_sv = "Low" if any("server" in k for k in eku) else "High"
        s.add(f"Certificate {idx} - Extended Key Usage", _j(eku) or "None", "RFC 5280", eku_sv, _rec(eku_sv, "ensure serverAuth is present in EKU extensions."), -6, 10)

        es, n_a = cert.get("Expiration Status", ""), cert.get("Valid Not After", "")
        x_sev, _sc = _exp(es, n_a)
        valid_label = "Valid" if isinstance(es, str) and "VALID" in es.upper() else "Invalid"
        date_display = ""
        if n_a:
            try:
                dt = datetime.fromisoformat(str(n_a).replace("Z", "+00:00"))
                date_display = dt.strftime("%d-%b-%Y")
            except Exception:
                date_display = str(n_a)[:10]
        rec_text = "renew certificate immediately to avoid service outage."
        if x_sev == "Medium":
            rec_text = "Please renew certificate soon as it expires within 30 days."
        s.add(f"Certificate {idx} - Validity / Expiry", f"{valid_label} ({date_display})", "CAB Forum Baseline Requirements", x_sev, _rec(x_sev, rec_text), -10, 10)

        ocsp_urls = cert.get("OCSP URLs") if isinstance(cert.get("OCSP URLs"), list) else []
        ocsp_finding = "Supported and Valid" if ocsp_urls else "Not Supported"
        ocsp_sv = "Acceptable" if ocsp_urls else "High"
        s.add(f"Certificate {idx} - OCSP Staple", ocsp_finding, "NIST SP 800-52r2", ocsp_sv, _rec(ocsp_sv, "have OCSP Stapling validated from trusted authorities."), -6, 5)

        ct = cert.get("Certificate Transparency", "")
        ct_lower = str(ct).lower()
        if "3" in ct_lower or "sct present" in ct_lower:
            ct_label = "3 SCT & more"
        elif "2" in ct_lower:
            ct_label = "2 SCT"
        elif "1" in ct_lower:
            ct_label = "1 SCT"
        else:
            ct_label = "Absent"
        ct_sv = "Acceptable" if ct_label == "3 SCT & more" else "Medium" if ct_label == "2 SCT" else "High"
        s.add(f"Certificate {idx} - Certificate Transparency", ct_label, "Google Policy", ct_sv, _rec(ct_sv, "enable Certificate Transparency logging."), -6, 5)

    tr = data.get("trust_stores")
    tr = tr if isinstance(tr, dict) else {}
    trusted = any(v.get("is_trusted") for v in tr.values() if isinstance(v, dict))
    chain_label = "Trusted chain" if trusted else ("Self-Signed" if len(certs) == 1 else "Chain integrity lost")
    chain_sv = "Low" if trusted else "High"
    s.add("Certificate Chain / Trust Store", chain_label, "PKI BMP, RFC 5280", chain_sv, _rec(chain_sv, "fix incomplete certificate chain or untrusted root CA."), -6, 10)
    sections.append(_finalize_section(s))

    # ---------------- Extensions ----------------
    s = Section("Extensions", 3)
    tx = data.get("tls_extensions")
    tx = tx if isinstance(tx, list) else []
    ext_data = [
        ("SNI", "server name", "NIST SP 800-52 Rev.2/RFC 6066", "implement SNI for multi-tenant hosting to ensure correct certificate routing."),
        ("ALPN", "application layer", "NIST SP 800-52 Rev.2/RFC 7301", "enable ALPN to negotiate application protocols securely."),
        ("Extended Master Secret", "extended master", "NIST SP 800-52 Rev.2/RFC 7627", "enable EMS to prevent MITM session hash vulnerabilities."),
        ("Session Ticket", "session ticket", "RFC 5077", "ensure keys rotate frequently if session tickets are enabled."),
        ("Renegotiation Info", "renegotiation", "CVE-2009-3555/ RFC 5746", "enable secure renegotiation (RFC 5746) to prevent injection attacks."),
        ("EC Point Formats", "EC point", "RFC 4492", "support standard ECC point formats for client compatibility."),
        ("Supported Versions", "supported version", "RFC 8446", "ensure TLS 1.3 supported versions match intended protocols."),
    ]
    for en, kw, std, act in ext_data:
        pr = any(isinstance(e, str) and kw.lower() in e.lower() for e in tx)
        sv = "Acceptable" if pr else "Medium"
        s.add(en, "Supported" if pr else "Not Supported", std, sv, _rec(sv, act), -2, 5)
    sections.append(_finalize_section(s))

    # ---------------- HTTP Security ----------------
    s = Section("HTTP Security", 2)
    ht = data.get("http_response")
    ht = ht if isinstance(ht, dict) else {}
    hs = ht.get("HSTS", "not offered")
    hs_sv = _hsts(str(hs) if hs else "")
    s.add("HSTS", hs, "RFC 6797", hs_sv, _rec(hs_sv, "enforce HSTS header with max-age >= 31536000."), -6, 5)

    sc, hc = ht.get("Secure Cookie", ""), ht.get("HTTP-only Cookie", "")
    sc_str = str(sc).lower() if sc else ""
    if "all" in sc_str:
        cookie_sv, cookie_act = "Acceptable", "N.A."
    else:
        cookie_sv = "High"
        cookie_act = _rec(cookie_sv, "set Secure and HttpOnly flags on application cookies.")
    s.add("Cookie Security", f"Secure: {sc} | HttpOnly: {hc}", "RFC 6265", cookie_sv, cookie_act, -6, 5)

    bn = ht.get("Server Banner", "")
    bn_vuln = bool(re.search(r"[\d.]+", str(bn))) if bn else False
    bn_sv = "Medium" if bn_vuln else "Acceptable"
    s.add("Server Banner", bn or "None", "NIST SP 800-44 / OWASP", bn_sv, _rec(bn_sv, "suppress verbose server version details in headers."), -2, 5)
    sections.append(_finalize_section(s))

    # ---------------- Vulnerabilities ----------------
    s = Section("Vulnerabilities", 18)
    vuln_meta = {
        "Heartbleed": ("Critical", "CVE-2014-0160", "Upgrade OpenSSL immediately, Revoke and reissue certificates, Rotate private keys, Invalidate active sessions, Force password resets if compromise is suspected.", (-10, 10)),
        "ROBOT": ("Critical", "CVE-2017-13099", "Disable RSA Key Exchange cipher suites, Use ECDHE/X25519 key exchange.", (-10, 10)),
        "CCS_Injection": ("Critical", "CVE-2014-0224", "Update OpenSSL/TLS libraries immediately, Patch vulnerable systems.", (-10, 10)),
        "POODLE_SSL": ("Critical", "CVE-2014-3566", "Disable SSL 3.0 completely, Enable TLS 1.2 and TLS 1.3 only, Remove legacy CBC-only configurations.", (-10, 10)),
        "SWEET32": ("High", "CVE-2016-2183", "Disable all 64-bit block cipher, remove 3DES, use AES-GCM, prefer ChaCha20-Poly1305, enable TLS 1.3.", (-6, 10)),
        "BEAST": ("High", "CVE-2011-3389", "Disable TLS 1.0, SSL 3.0, legacy CBC ciphers, prefer TLS 1.2, 1.3 and Use ChaCha20-Poly1305 or AES-GCM.", (-6, 10)),
        "CRIME_TLS": ("High", "CVE-2012-4929", "disable TLS level compression to prevent information leakage.", (-6, 10)),
        "DROWN": ("Critical", "CVE-2016-0800", "disable SSLv2 immediately to secure RSA keys.", (-10, 10)),
        "FREAK": ("High", "CVE-2015-0204", "disable EXPORT grade RSA ciphers.", (-6, 10)),
        "RC4_Flaw": ("High", "CVE-2013-2566", "disable all RC4 cipher suites completely.", (-6, 10)),
        "NULL_Cipher": ("Critical", "CVE-2002-20001", "disable NULL cipher suites that provide no encryption.", (-10, 10)),
        "Secure_Renegotiation": ("High", "RFC 5746 / CVE-2009-3555", "enable RFC 5746 secure renegotiation to prevent MiTM injection.", (-6, 10)),
    }
    for vn, (sv, std, act, lb) in vuln_meta.items():
        if vn not in vu:
            continue
        vd = vu[vn]
        if not isinstance(vd, dict):
            continue
        v_s = "Low" if vn == "Secure_Renegotiation" and vd.get("is_supported") else "High" if vn == "Secure_Renegotiation" else (sv if vd.get("is_vulnerable") else "Low")
        s.add(vn.replace("_", " "), "Vulnerable" if vd.get("is_vulnerable") else "Safe", std, v_s, _rec(v_s, act), *lb)
    sections.append(_finalize_section(s))

    # ---------------- Cipher Categories ----------------
    s = Section("Cipher Categories", 2)
    cc_list = data.get("cipher_categories", [])
    cm = {c.get("category", ""): c.get("supported", False) for c in cc_list if isinstance(c, dict)}
    c_meta = {
        "NULL Ciphers": ("Critical", "RFC 8996", "remove all NULL ciphers as they offer zero encryption.", (-10, 10)),
        "Anonymous NULL Ciphers": ("Critical", "RFC 8996", "remove unauthenticated ciphers to prevent MITM attacks.", (-10, 10)),
        "Export Ciphers": ("Critical", "CVE-2015-0204", "remove legacy EXPORT ciphers to prevent FREAK attacks.", (-10, 10)),
        "LOW Ciphers (64-bit)": ("Critical", "RFC 4346", "remove weak 64-bit encryption ciphers.", (-10, 10)),
        "RC4": ("Critical", "RFC 7465", "disable RC4 algorithms entirely due to statistical biases.", (-10, 10)),
        "3DES / IDEA": ("High", "NIST SP 800-131A", "migrate away from obsolete block ciphers to AES or ChaCha20.", (-6, 10)),
        "Obsolete CBC Ciphers": ("Medium", "NIST SP 800-52r2", "phase out CBC suites in favor of AEAD (GCM/Poly1305).", (-6, 5)),
        "Strong Encryption (AEAD)": ("Low", "RFC 5116", "prioritize AEAD ciphers for maximum integrity and performance.", (-6, 10)),
    }
    for cn, (bs, std, act, bnd) in c_meta.items():
        pr = cm.get(cn, False)
        good_sv = "Low" if bnd[1] == 10 else "Acceptable"
        sv = good_sv if cn == "Strong Encryption (AEAD)" and pr else "High" if cn == "Strong Encryption (AEAD)" else (bs if pr else good_sv)
        s.add(cn, "Present" if pr else "Absent", std, sv, _rec(sv, act), *bnd)
    sections.append(_finalize_section(s))

    # ---------------- Cipher Suites ----------------
    s = Section("Cipher Suites", 23)
    for cs in data.get("cipher_suites", []):
        if not isinstance(cs, dict):
            continue
        nm = cs.get("cipher_name", "").upper()
        if any(x in nm for x in ("NULL", "ANON", "EXPORT", "RC4")):
            sv = "Critical"
        elif any(x in nm for x in ("3DES", "IDEA")):
            sv = "High"
        elif "CBC" in nm and not cs.get("aead"):
            sv = "Medium"
        elif cs.get("aead") and cs.get("forward_secrecy"):
            sv = "Low"
        elif cs.get("aead"):
            sv = "Acceptable"
        elif not cs.get("forward_secrecy"):
            sv = "Medium"
        else:
            sv = "Acceptable"
        s.add(cs.get("cipher_name", ""), "Supported", "RFC 8446 / RFC 5246", sv, "Review the negotiated cipher suite list for legacy fallback removal.", -10, 10)
    sections.append(_finalize_section(s))

    # ---------------- PQC ----------------
    s = Section("PQC", 16)
    pq = data.get("pqc_active_probe")
    pq = pq if isinstance(pq, dict) else {}
    c0 = certs[0] if certs else {}
    cb = c0.get("cbom_authentication_layer")
    cb = cb if isinstance(cb, dict) else {}
    kx = pq.get("pqc_negotiated", False)
    cp = cb.get("is_pqc", False)
    sig_alg = c0.get("Signature Algorithm", "").upper()
    ds_pqc = any(x in sig_alg for x in ("ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS", "FALCON"))
    ds_sv = "Low" if ds_pqc else "Medium"
    kx_sv = "Low" if kx else "Medium"
    neg_group = pq.get("negotiated_group", "") or ""
    neg_group_uc = str(neg_group).upper()
    if kx:
        kx_finding = f"Hybrid PQC supported: {neg_group}" if neg_group_uc else "Hybrid PQC supported"
    else:
        kx_finding = "PQC/Hybrid PQC not supported"
    s.add("PQC Key Encapsulation", kx_finding, "NIST FIPS 203", kx_sv, _rec(kx_sv, "plan infrastructure migration to ML-KEM (FIPS 203)."), -2, 10)

    if ds_pqc:
        if "DILITHIUM" in sig_alg:
            ds_finding = "Pure PQC: DSA(Dilithium) — ML DSA"
        elif "FALCON" in sig_alg or "FN-DSA" in sig_alg or "FNDSA" in sig_alg:
            ds_finding = "Pure PQC: DSA(Falcon) — FL DSA"
        elif "SPHINCS" in sig_alg or "SLH" in sig_alg:
            ds_finding = "Pure PQC: DSA(SPHINCS+) — SH DSA"
        else:
            ds_finding = "Pure PQC: DSA — ML DSA"
    else:
        ds_finding = "Classical"
    s.add("PQC Certificate DSA", ds_finding, "NIST FIPS 204, FIPS 205, FIPS 206", ds_sv, _rec(ds_sv, "plan certificate migration to ML-DSA or SLH-DSA."), -2, 10)

    sink_sv = "Low" if kx and cp else "Medium"
    sink_finding = "Full PQC" if kx and cp else "Classical / Partial"
    s.add("PQC Sinkhole", sink_finding, "NIST SP 800-52", sink_sv, _rec(sink_sv, "enable full PQC authentication chain."), -2, 10)

    tel = pq.get("negotiation_telemetry")
    tel = tel if isinstance(tel, dict) else {}
    is_downgraded = tel.get("downgrade_detected", False)
    pqc_disabled = not kx and not ds_pqc
    if pqc_disabled or is_downgraded:
        dg_sv = "Medium"
        dg_finding = "PQC Disabled / Forced Classical" if pqc_disabled else "Downgrade Detected"
    else:
        dg_sv = "Low"
        dg_finding = "Well Supported"
    s.add("PQC Downgrade", dg_finding, "RFC 8446", dg_sv, _rec(dg_sv, "investigate potential MITM protocol downgrade attack."), -2, 10)

    # Negotiated groups folded in as informational PQC findings (0-weight rows,
    # they still show up in the table but don't skew the section's score much
    # since their lo/hi range is small relative to the rest of the section).
    groups = _collect_negotiated_groups(data)
    if groups:
        for group in groups:
            label, std, sev, rec = _negotiated_group_info(group)
            s.add(f"Negotiated Group - {label}", label, std, sev, rec, -2, 5)
    sections.append(_finalize_section(s))

    posture_score = round(sum(sec["normalized"] * (sec["weight"] / 100) for sec in sections), 1)
    pqc_section = next((sec for sec in sections if sec["id"] == "pqc"), None)
    pqc_readiness = round(pqc_section["normalized"]) if pqc_section else 0

    return {
        "id": _slugify(hostname),
        "scannedAt": sm.get("scan_end") or datetime.now(timezone.utc).isoformat(),
        "target": {
            "hostname": hostname,
            "ip": ip,
            "port": port,
            "scanStart": sm.get("scan_start") or "",
            "scanEnd": sm.get("scan_end") or "",
            "durationSeconds": sm.get("scan_duration_seconds") or 0,
            "scannerVersion": sm.get("scanner_version") or "1.0",
        },
        "postureScore": posture_score,
        "riskBand": _risk_band(posture_score),
        "pqcReadiness": pqc_readiness,
        "sections": sections,
    }
