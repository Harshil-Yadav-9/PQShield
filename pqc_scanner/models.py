from pydantic import BaseModel
from typing import List, Dict, Any, Optional


class ScanMetadata(BaseModel):
    target: str
    ip: str
    port: int
    scan_start: str
    scan_end: str
    scan_duration_seconds: float
    scanner_version: str = "17.0.0-Fallback-Architecture"


class ProtocolSupport(BaseModel):
    protocol: str
    supported: bool


class CipherCategory(BaseModel):
    category: str
    supported: bool


class ScanResults(BaseModel):
    target: Dict[str, Any]
    scan_metadata: ScanMetadata
    protocols: List[ProtocolSupport]
    cipher_categories: List[CipherCategory]
    cipher_suites: List[Dict[str, Any]]
    tls_extensions: List[str]
    server_preferences: Dict[str, Any]
    active_transport_layer: Dict[str, Any]
    server_defaults: Dict[str, Any]
    certificates: List[Dict[str, Any]]
    trust_stores: Dict[str, Any]
    pfs: Dict[str, Any]
    capability_space: Dict[str, Any]
    vulnerabilities: Dict[str, Any]
    http_response: Dict[str, Any]
    crypto_inventory: Dict[str, Any]
    client_simulations: Dict[str, Any]
    pqc_active_probe: Dict[str, Any]
    pqc_analysis: List[Dict[str, Any]]
    pqc_migration_report: Dict[str, Any]
