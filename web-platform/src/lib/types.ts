export type Severity = "Critical" | "High" | "Medium" | "Low" | "Acceptable";

export interface Finding {
  parameter: string;
  observed: string;
  standard: string;
  severity: Severity;
  contribution: number; // signed % contribution to the overall posture score
  recommendation: string;
}

export interface ReportSection {
  id: string;
  name: string;
  weight: number; // % weight of posture score, sums to 100 across sections
  normalized: number; // 0-100 section score after normalization
  summary: string;
  findings: Finding[];
}

export interface ScanTarget {
  hostname: string;
  ip: string;
  port: number;
  scanStart: string;
  scanEnd: string;
  durationSeconds: number;
  scannerVersion: string;
}

export interface ScanReport {
  id: string;
  target: ScanTarget;
  postureScore: number;
  riskBand: "Critical" | "At risk" | "Moderate" | "Strong" | "PQC ready";
  pqcReadiness: number; // 0-100, separate axis from overall posture
  scannedAt: string;
  sections: ReportSection[];
}

export const SEVERITY_ORDER: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Acceptable",
];

export const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "#ef4444",
  High: "#f0703b",
  Medium: "#f2b428",
  Low: "#3ecf9c",
  Acceptable: "#22a06b",
};
