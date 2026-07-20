import { ScanReport } from "./types";

// This is the single bundled demo report. It's built from fully synthetic
// scan data (public/demo/cbom_demo.json) run through the real PQShield
// scanner engine (pqc_scanner/report_builder.py) — no real organization's
// scan data is used here. The Export JSON / Export Excel buttons on this
// report serve public/demo/cbom_demo.json and public/demo/audit_demo.xlsx
// directly, byte-for-byte, so what you download always matches what's on
// screen.
export const DEMO_REPORT_ID = "pqshield-io-demo";

export const demoReport: ScanReport = {
  "id": "pqshield-io-demo",
  "scannedAt": "2026-07-14T04:15:12.260130+00:00",
  "target": {
    "hostname": "demo.pqshield.io",
    "ip": "203.0.113.42",
    "port": 443,
    "scanStart": "2026-07-14T04:14:44.203772+00:00",
    "scanEnd": "2026-07-14T04:15:12.260130+00:00",
    "durationSeconds": 23.57,
    "scannerVersion": "1.0"
  },
  "postureScore": 72.9,
  "riskBand": "Moderate",
  "pqcReadiness": 72,
  "sections": [
    {
      "id": "protocol",
      "name": "Protocol (Capability space)",
      "weight": 23,
      "normalized": 67.3,
      "summary": "2 finding(s) need attention, including Protocol - TLS 1.0 (Capability space), Protocol - TLS 1.1 (Capability space).",
      "findings": [
        {
          "parameter": "Protocol - SSLv2 (Capability space)",
          "observed": "Disabled",
          "standard": "RFC 6176",
          "severity": "Low",
          "contribution": 4.18,
          "recommendation": "N.A."
        },
        {
          "parameter": "Protocol - SSLv3 (Capability space)",
          "observed": "Disabled",
          "standard": "RFC 7568",
          "severity": "Low",
          "contribution": 4.18,
          "recommendation": "N.A."
        },
        {
          "parameter": "Protocol - TLS 1.0 (Capability space)",
          "observed": "Enabled",
          "standard": "RFC 8996",
          "severity": "Critical",
          "contribution": -4.18,
          "recommendation": "Strongly suggested to disable TLS 1.0 immediately."
        },
        {
          "parameter": "Protocol - TLS 1.1 (Capability space)",
          "observed": "Enabled",
          "standard": "RFC 8996",
          "severity": "High",
          "contribution": -2.01,
          "recommendation": "Recommended to disable TLS 1.1 immediately."
        },
        {
          "parameter": "Protocol - TLS 1.2 (Capability space)",
          "observed": "Enabled",
          "standard": "NIST SP 800-52-r2",
          "severity": "Acceptable",
          "contribution": 0.73,
          "recommendation": "N.A."
        },
        {
          "parameter": "Protocol - TLS 1.3 (Capability space)",
          "observed": "Enabled",
          "standard": "NIST SP 800-52-r2",
          "severity": "Low",
          "contribution": 4.18,
          "recommendation": "N.A."
        },
        {
          "parameter": "Downgrade Protection (TLS_FALLBACK_SCSV)",
          "observed": "Supported",
          "standard": "RFC 7507",
          "severity": "Acceptable",
          "contribution": 0.73,
          "recommendation": "N.A."
        }
      ]
    },
    {
      "id": "certificate",
      "name": "Certificate",
      "weight": 13,
      "normalized": 72.7,
      "summary": "8 finding(s) need attention, including Certificate 2 - OCSP Staple, Certificate 2 - Certificate Transparency (+6 more).",
      "findings": [
        {
          "parameter": "Certificate 1 - Public Key Cert",
          "observed": "ECDSA",
          "standard": "FIPS 204 / NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 1 - Public Keysize Cert",
          "observed": "secp256r1",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 1 - Signature",
          "observed": "RSA + SHA256/384",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 1 - Extended Key Usage",
          "observed": "serverauth",
          "standard": "RFC 5280",
          "severity": "Low",
          "contribution": 0.29,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 1 - Validity / Expiry",
          "observed": "Valid (14-Sep-2026)",
          "standard": "CAB Forum Baseline Requirements",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 1 - OCSP Staple",
          "observed": "Supported and Valid",
          "standard": "NIST SP 800-52r2",
          "severity": "Acceptable",
          "contribution": 0.1,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 1 - Certificate Transparency",
          "observed": "3 SCT & more",
          "standard": "Google Policy",
          "severity": "Acceptable",
          "contribution": 0.1,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 2 - Public Key Cert",
          "observed": "RSA-2048",
          "standard": "FIPS 204 / NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 2 - Public Keysize Cert",
          "observed": "RSA 2048",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended to RSA 3072 or ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 2 - Signature",
          "observed": "RSA + SHA256/384",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 2 - Extended Key Usage",
          "observed": "serverauth | clientauth",
          "standard": "RFC 5280",
          "severity": "Low",
          "contribution": 0.29,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 2 - Validity / Expiry",
          "observed": "Valid (20-Feb-2029)",
          "standard": "CAB Forum Baseline Requirements",
          "severity": "Low",
          "contribution": 0.36,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 2 - OCSP Staple",
          "observed": "Not Supported",
          "standard": "NIST SP 800-52r2",
          "severity": "High",
          "contribution": -0.12,
          "recommendation": "Recommended to have OCSP Stapling validated from trusted authorities."
        },
        {
          "parameter": "Certificate 2 - Certificate Transparency",
          "observed": "Absent",
          "standard": "Google Policy",
          "severity": "High",
          "contribution": -0.12,
          "recommendation": "Recommended to enable Certificate Transparency logging."
        },
        {
          "parameter": "Certificate 3 - Public Key Cert",
          "observed": "RSA-4096",
          "standard": "FIPS 204 / NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 3 - Public Keysize Cert",
          "observed": "RSA 4096 & above",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 3 - Signature",
          "observed": "RSA + SHA256/384",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 3 - Extended Key Usage",
          "observed": "None",
          "standard": "RFC 5280",
          "severity": "High",
          "contribution": -0.17,
          "recommendation": "Recommended to ensure serverAuth is present in EKU extensions."
        },
        {
          "parameter": "Certificate 3 - Validity / Expiry",
          "observed": "Valid (28-Jan-2028)",
          "standard": "CAB Forum Baseline Requirements",
          "severity": "Low",
          "contribution": 0.36,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 3 - OCSP Staple",
          "observed": "Supported and Valid",
          "standard": "NIST SP 800-52r2",
          "severity": "Acceptable",
          "contribution": 0.1,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 3 - Certificate Transparency",
          "observed": "Absent",
          "standard": "Google Policy",
          "severity": "High",
          "contribution": -0.12,
          "recommendation": "Recommended to enable Certificate Transparency logging."
        },
        {
          "parameter": "Certificate 4 - Public Key Cert",
          "observed": "RSA-2048",
          "standard": "FIPS 204 / NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 4 - Public Keysize Cert",
          "observed": "RSA 2048",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended to RSA 3072 or ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 4 - Signature",
          "observed": "RSA + SHA256/384",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 4 - Extended Key Usage",
          "observed": "serverauth",
          "standard": "RFC 5280",
          "severity": "Low",
          "contribution": 0.29,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 4 - Validity / Expiry",
          "observed": "Valid (14-Sep-2026)",
          "standard": "CAB Forum Baseline Requirements",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 4 - OCSP Staple",
          "observed": "Supported and Valid",
          "standard": "NIST SP 800-52r2",
          "severity": "Acceptable",
          "contribution": 0.1,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 4 - Certificate Transparency",
          "observed": "3 SCT & more",
          "standard": "Google Policy",
          "severity": "Acceptable",
          "contribution": 0.1,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 5 - Public Key Cert",
          "observed": "RSA-2048",
          "standard": "FIPS 204 / NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 5 - Public Keysize Cert",
          "observed": "RSA 2048",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended to RSA 3072 or ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 5 - Signature",
          "observed": "RSA + SHA256/384",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 5 - Extended Key Usage",
          "observed": "serverauth | clientauth",
          "standard": "RFC 5280",
          "severity": "Low",
          "contribution": 0.29,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 5 - Validity / Expiry",
          "observed": "Valid (20-Feb-2029)",
          "standard": "CAB Forum Baseline Requirements",
          "severity": "Low",
          "contribution": 0.36,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 5 - OCSP Staple",
          "observed": "Not Supported",
          "standard": "NIST SP 800-52r2",
          "severity": "High",
          "contribution": -0.12,
          "recommendation": "Recommended to have OCSP Stapling validated from trusted authorities."
        },
        {
          "parameter": "Certificate 5 - Certificate Transparency",
          "observed": "Absent",
          "standard": "Google Policy",
          "severity": "High",
          "contribution": -0.12,
          "recommendation": "Recommended to enable Certificate Transparency logging."
        },
        {
          "parameter": "Certificate 6 - Public Key Cert",
          "observed": "RSA-4096",
          "standard": "FIPS 204 / NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 6 - Public Keysize Cert",
          "observed": "RSA 4096 & above",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 6 - Signature",
          "observed": "RSA + SHA256/384",
          "standard": "NIST SP 800-131A rev 2",
          "severity": "Acceptable",
          "contribution": 0.18,
          "recommendation": "Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "Certificate 6 - Extended Key Usage",
          "observed": "None",
          "standard": "RFC 5280",
          "severity": "High",
          "contribution": -0.17,
          "recommendation": "Recommended to ensure serverAuth is present in EKU extensions."
        },
        {
          "parameter": "Certificate 6 - Validity / Expiry",
          "observed": "Valid (28-Jan-2028)",
          "standard": "CAB Forum Baseline Requirements",
          "severity": "Low",
          "contribution": 0.36,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 6 - OCSP Staple",
          "observed": "Supported and Valid",
          "standard": "NIST SP 800-52r2",
          "severity": "Acceptable",
          "contribution": 0.1,
          "recommendation": "N.A."
        },
        {
          "parameter": "Certificate 6 - Certificate Transparency",
          "observed": "Absent",
          "standard": "Google Policy",
          "severity": "High",
          "contribution": -0.12,
          "recommendation": "Recommended to enable Certificate Transparency logging."
        },
        {
          "parameter": "Certificate Chain / Trust Store",
          "observed": "Trusted chain",
          "standard": "PKI BMP, RFC 5280",
          "severity": "Low",
          "contribution": 0.29,
          "recommendation": "N.A."
        }
      ]
    },
    {
      "id": "extensions",
      "name": "Extensions",
      "weight": 3,
      "normalized": 71.4,
      "summary": "No high-severity issues found across 7 checks.",
      "findings": [
        {
          "parameter": "SNI",
          "observed": "Not Supported",
          "standard": "NIST SP 800-52 Rev.2/RFC 6066",
          "severity": "Medium",
          "contribution": -0.09,
          "recommendation": "Enable TLS SNI support and Upgrade legacy TLS stacks that do not support RFC 6066."
        },
        {
          "parameter": "ALPN",
          "observed": "Supported",
          "standard": "NIST SP 800-52 Rev.2/RFC 7301",
          "severity": "Acceptable",
          "contribution": 0.21,
          "recommendation": "N.A."
        },
        {
          "parameter": "Extended Master Secret",
          "observed": "Supported",
          "standard": "NIST SP 800-52 Rev.2/RFC 7627",
          "severity": "Acceptable",
          "contribution": 0.21,
          "recommendation": "N.A."
        },
        {
          "parameter": "Session Ticket",
          "observed": "Not Supported",
          "standard": "RFC 5077",
          "severity": "Medium",
          "contribution": -0.09,
          "recommendation": "It is required for performance optimization."
        },
        {
          "parameter": "Renegotiation Info",
          "observed": "Supported",
          "standard": "CVE-2009-3555/ RFC 5746",
          "severity": "Acceptable",
          "contribution": 0.21,
          "recommendation": "N.A."
        },
        {
          "parameter": "EC Point Formats",
          "observed": "Supported",
          "standard": "RFC 4492",
          "severity": "Acceptable",
          "contribution": 0.21,
          "recommendation": "N.A."
        },
        {
          "parameter": "Supported Versions",
          "observed": "Supported",
          "standard": "RFC 8446",
          "severity": "Acceptable",
          "contribution": 0.21,
          "recommendation": "N.A."
        }
      ]
    },
    {
      "id": "http",
      "name": "HTTP Security",
      "weight": 2,
      "normalized": 62.1,
      "summary": "1 finding(s) need attention, including HSTS.",
      "findings": [
        {
          "parameter": "HSTS",
          "observed": "not offered",
          "standard": "RFC 6797",
          "severity": "High",
          "contribution": -0.46,
          "recommendation": "Recommended to enforce HSTS header with max-age >= 31536000."
        },
        {
          "parameter": "Cookie Security",
          "observed": "Secure: Not all Secure | HttpOnly: All HttpOnly",
          "standard": "RFC 6265",
          "severity": "Acceptable",
          "contribution": 0.38,
          "recommendation": "N.A."
        },
        {
          "parameter": "Server Banner",
          "observed": "ESF",
          "standard": "NIST SP 800-44 / OWASP",
          "severity": "Acceptable",
          "contribution": 0.24,
          "recommendation": "N.A."
        }
      ]
    },
    {
      "id": "vulnerabilities",
      "name": "Vulnerabilities",
      "weight": 18,
      "normalized": 100.0,
      "summary": "No high-severity issues found across 12 checks.",
      "findings": [
        {
          "parameter": "Heartbleed",
          "observed": "Safe",
          "standard": "CVE-2014-0160",
          "severity": "Low",
          "contribution": 1.67,
          "recommendation": "N.A."
        },
        {
          "parameter": "ROBOT",
          "observed": "Safe",
          "standard": "CVE-2017-13099",
          "severity": "Low",
          "contribution": 1.67,
          "recommendation": "N.A."
        },
        {
          "parameter": "CCS Injection",
          "observed": "Safe",
          "standard": "CVE-2014-0224",
          "severity": "Low",
          "contribution": 1.67,
          "recommendation": "N.A."
        },
        {
          "parameter": "POODLE SSL",
          "observed": "Safe",
          "standard": "CVE-2014-3566",
          "severity": "Low",
          "contribution": 1.67,
          "recommendation": "N.A."
        },
        {
          "parameter": "SWEET32",
          "observed": "Safe",
          "standard": "CVE-2016-2183",
          "severity": "Low",
          "contribution": 1.33,
          "recommendation": "N.A."
        },
        {
          "parameter": "BEAST",
          "observed": "Safe",
          "standard": "CVE-2011-3389",
          "severity": "Low",
          "contribution": 1.33,
          "recommendation": "N.A."
        },
        {
          "parameter": "CRIME TLS",
          "observed": "Safe",
          "standard": "CVE-2012-4929",
          "severity": "Low",
          "contribution": 1.33,
          "recommendation": "N.A."
        },
        {
          "parameter": "DROWN",
          "observed": "Safe",
          "standard": "CVE-2016-0800",
          "severity": "Low",
          "contribution": 1.67,
          "recommendation": "N.A."
        },
        {
          "parameter": "FREAK",
          "observed": "Safe",
          "standard": "CVE-2015-0204",
          "severity": "Low",
          "contribution": 1.33,
          "recommendation": "N.A."
        },
        {
          "parameter": "RC4 Flaw",
          "observed": "Safe",
          "standard": "CVE-2013-2566",
          "severity": "Low",
          "contribution": 1.33,
          "recommendation": "N.A."
        },
        {
          "parameter": "NULL Cipher",
          "observed": "Safe",
          "standard": "CVE-2002-20001",
          "severity": "Low",
          "contribution": 1.67,
          "recommendation": "N.A."
        },
        {
          "parameter": "Secure Renegotiation",
          "observed": "Safe",
          "standard": "RFC 5746 / CVE-2009-3555",
          "severity": "Low",
          "contribution": 1.33,
          "recommendation": "N.A."
        }
      ]
    },
    {
      "id": "cipher-categories",
      "name": "Cipher Categories",
      "weight": 2,
      "normalized": 83.9,
      "summary": "1 finding(s) need attention, including 3DES / IDEA.",
      "findings": [
        {
          "parameter": "NULL Ciphers",
          "observed": "Absent",
          "standard": "RFC 8996",
          "severity": "Low",
          "contribution": 0.28,
          "recommendation": "N.A."
        },
        {
          "parameter": "Anonymous NULL Ciphers",
          "observed": "Absent",
          "standard": "RFC 8996",
          "severity": "Low",
          "contribution": 0.28,
          "recommendation": "N.A."
        },
        {
          "parameter": "Export Ciphers",
          "observed": "Absent",
          "standard": "CVE-2015-0204",
          "severity": "Low",
          "contribution": 0.28,
          "recommendation": "N.A."
        },
        {
          "parameter": "LOW Ciphers (64-bit)",
          "observed": "Absent",
          "standard": "RFC 4346",
          "severity": "Low",
          "contribution": 0.28,
          "recommendation": "N.A."
        },
        {
          "parameter": "RC4",
          "observed": "Absent",
          "standard": "RFC 7465",
          "severity": "Low",
          "contribution": 0.28,
          "recommendation": "N.A."
        },
        {
          "parameter": "3DES / IDEA",
          "observed": "Present",
          "standard": "NIST SP 800-131A",
          "severity": "High",
          "contribution": -0.13,
          "recommendation": "Recommended to migrate away from obsolete block ciphers to AES or ChaCha20."
        },
        {
          "parameter": "Obsolete CBC Ciphers",
          "observed": "Present",
          "standard": "NIST SP 800-52r2",
          "severity": "Medium",
          "contribution": -0.03,
          "recommendation": "Prefer to phase out CBC suites in favor of AEAD (GCM/Poly1305)."
        },
        {
          "parameter": "Strong Encryption (AEAD)",
          "observed": "Present",
          "standard": "RFC 5116",
          "severity": "Low",
          "contribution": 0.22,
          "recommendation": "N.A."
        }
      ]
    },
    {
      "id": "cipher-suites",
      "name": "Cipher Suites",
      "weight": 23,
      "normalized": 57.9,
      "summary": "3 finding(s) need attention, including TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA (+1 more).",
      "findings": [
        {
          "parameter": "TLS_RSA_WITH_AES_256_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_128_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "High",
          "contribution": -0.57,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_256_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_128_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "High",
          "contribution": -0.57,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_256_GCM_SHA384",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Acceptable",
          "contribution": 0.48,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_256_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_128_GCM_SHA256",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Acceptable",
          "contribution": 0.48,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_AES_128_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "High",
          "contribution": -0.57,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Medium",
          "contribution": -0.19,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_CHACHA20_POLY1305_SHA256",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_AES_256_GCM_SHA384",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        },
        {
          "parameter": "TLS_AES_128_GCM_SHA256",
          "observed": "Supported",
          "standard": "RFC 8446 / RFC 5246",
          "severity": "Low",
          "contribution": 0.96,
          "recommendation": "Review the negotiated cipher suite list for legacy fallback removal."
        }
      ]
    },
    {
      "id": "pqc",
      "name": "PQC",
      "weight": 16,
      "normalized": 72.5,
      "summary": "No high-severity issues found across 7 checks.",
      "findings": [
        {
          "parameter": "PQC Key Encapsulation",
          "observed": "Hybrid PQC supported: X25519MLKEM768",
          "standard": "NIST FIPS 203",
          "severity": "Low",
          "contribution": 2.78,
          "recommendation": "N.A."
        },
        {
          "parameter": "PQC Certificate DSA",
          "observed": "Classical",
          "standard": "NIST FIPS 204, FIPS 205, FIPS 206",
          "severity": "Medium",
          "contribution": -0.56,
          "recommendation": "Enable PQC/hybrid key exchange support, Upgrade TLS libraries to versions supporting ML-KEM, Use hybrid TLS groups such as: X25519MLKEM768."
        },
        {
          "parameter": "PQC Sinkhole",
          "observed": "Classical / Partial",
          "standard": "NIST SP 800-52",
          "severity": "Medium",
          "contribution": -0.56,
          "recommendation": "Because PQC authentication chain is incomplete, a degraded value was given. Recommended(OPT) to ML DSA or SLH DSA for PQC environment"
        },
        {
          "parameter": "PQC Downgrade",
          "observed": "Well Supported",
          "standard": "RFC 8446",
          "severity": "Low",
          "contribution": 2.78,
          "recommendation": "N.A."
        },
        {
          "parameter": "Negotiated Group - secp256r1",
          "observed": "secp256r1",
          "standard": "NIST SP 800-186",
          "severity": "Acceptable",
          "contribution": 0.81,
          "recommendation": "Recommended to MLKEM786(or hybrid) for PQC"
        },
        {
          "parameter": "Negotiated Group - X25519",
          "observed": "X25519",
          "standard": "NIST SP 800-186",
          "severity": "Acceptable",
          "contribution": 0.81,
          "recommendation": "Recommended to MLKEM786(or hybrid) for PQC"
        },
        {
          "parameter": "Negotiated Group - (X25519)MLKEM768",
          "observed": "(X25519)MLKEM768",
          "standard": "CNSA 2.0 Standard",
          "severity": "Low",
          "contribution": 1.62,
          "recommendation": "N.A."
        }
      ]
    }
  ]
} as ScanReport;

export const mockReports: ScanReport[] = [demoReport];

export function getReportById(id: string): ScanReport {
  return mockReports.find((r) => r.id === id) ?? demoReport;
}

export function isDemoReportId(id: string): boolean {
  return id === DEMO_REPORT_ID;
}
