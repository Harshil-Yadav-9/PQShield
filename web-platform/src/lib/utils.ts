import { Finding, ReportSection, Severity, SEVERITY_ORDER } from "./types";

export function severityCounts(findings: Finding[]): { severity: Severity; count: number }[] {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: findings.filter((f) => f.severity === severity).length,
  })).filter((row) => row.count > 0);
}

export function scoreBand(score: number): {
  label: string;
  className: string;
} {
  if (score >= 85) return { label: "Strong", className: "text-sev-acceptable" };
  if (score >= 65) return { label: "Moderate", className: "text-sev-low" };
  if (score >= 40) return { label: "At risk", className: "text-sev-medium" };
  return { label: "Critical", className: "text-sev-critical" };
}

export function allFindings(sections: ReportSection[]): Finding[] {
  return sections.flatMap((s) => s.findings);
}

export function topRisks(sections: ReportSection[], limit = 6): (Finding & { section: string })[] {
  return sections
    .flatMap((s) => s.findings.map((f) => ({ ...f, section: s.name })))
    .filter((f) => f.severity === "Critical" || f.severity === "High")
    .sort((a, b) => a.contribution - b.contribution)
    .slice(0, limit);
}

export function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Deterministic, UTC-based formatting. `toLocaleString` depends on the
// server's locale/timezone (Node) vs the browser's, which differ on Vercel
// (UTC) vs a visitor's machine — that mismatch is exactly what causes
// "Hydration failed because the server rendered HTML didn't match the
// client" errors. Formatting by hand from UTC fields keeps server and
// client output identical.
export function formatDate(iso: string): string {
  const d = new Date(iso);
  const day = String(d.getUTCDate()).padStart(2, "0");
  const month = MONTHS[d.getUTCMonth()];
  const year = d.getUTCFullYear();
  const hours24 = d.getUTCHours();
  const hours12 = hours24 % 12 || 12;
  const ampm = hours24 < 12 ? "AM" : "PM";
  const minutes = String(d.getUTCMinutes()).padStart(2, "0");
  return `${day} ${month} ${year}, ${hours12}:${minutes} ${ampm} UTC`;
}
