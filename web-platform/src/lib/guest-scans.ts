import { ScanReport } from "@/lib/types";

// Guests (not signed in) get a handful of scans that live entirely in the
// browser — never sent to the database. Signing in is what upgrades scan
// history from "this device only" to a permanent, cross-device account tied
// to Postgres/Neon in production.
export const GUEST_SCAN_LIMIT = 2;

const STORAGE_KEY = "pqshield_guest_scans";

export interface GuestScanEntry {
  id: string;
  hostname: string;
  postureScore: number;
  riskBand: string;
  createdAt: string; // ISO
  report: ScanReport;
  raw: unknown; // raw CBOM scan data — needed so Export Excel/JSON work without a server-side record
}

function readAll(): GuestScanEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAll(entries: GuestScanEntry[]) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
    // Let other components (e.g. the sidebar) in the same tab know to re-read.
    window.dispatchEvent(new Event("pqshield_guest_scans_changed"));
  } catch {
    // localStorage full or unavailable (private browsing, quota, etc.) —
    // the scan still rendered from the API response, it just won't persist.
  }
}

export function getGuestScans(): GuestScanEntry[] {
  return readAll().sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
}

export function getGuestScanCount(): number {
  return readAll().length;
}

export function getGuestScanReport(id: string): ScanReport | null {
  const entry = readAll().find((e) => e.id === id);
  return entry?.report ?? null;
}

export function getGuestScanRaw(id: string): unknown | null {
  const entry = readAll().find((e) => e.id === id);
  return entry?.raw ?? null;
}

// Newest entries are kept; oldest is dropped once the limit is exceeded so a
// guest always sees their most recent scans without needing to sign in.
export function saveGuestScan(report: ScanReport, raw: unknown): void {
  const entries = readAll().filter((e) => e.id !== report.id);
  entries.push({
    id: report.id,
    hostname: report.target.hostname,
    postureScore: report.postureScore,
    riskBand: report.riskBand,
    createdAt: new Date().toISOString(),
    report,
    raw,
  });
  entries.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  writeAll(entries.slice(0, GUEST_SCAN_LIMIT));
}

export function clearGuestScans(): void {
  writeAll([]);
}
