"use client";

import { useState } from "react";
import TargetHeader from "@/components/TargetHeader";
import PostureGauge from "@/components/PostureGauge";
import SectionsOverviewChart from "@/components/SectionsOverviewChart";
import SectionCard from "@/components/SectionCard";
import SeverityBadge from "@/components/SeverityBadge";
import ChatPanel from "@/components/ChatPanel";
import RiskTargetSlider from "@/components/RiskTargetSlider";
import { ScanReport } from "@/lib/types";
import { allFindings, topRisks } from "@/lib/utils";

const TABS = ["Overview", "AI assistant"] as const;
type Tab = (typeof TABS)[number];

export default function ReportView({
  report,
  hostnameOverride,
  isGuest = false,
}: {
  report: ScanReport;
  hostnameOverride?: string;
  isGuest?: boolean;
}) {
  const [tab, setTab] = useState<Tab>("Overview");
  const { target, postureScore, sections, pqcReadiness, riskBand } = report;
  const findings = allFindings(sections);
  const critical = findings.filter((f) => f.severity === "Critical").length;
  const high = findings.filter((f) => f.severity === "High").length;
  const risks = topRisks(sections, 5);

  return (
    <div className="pb-16">
      <TargetHeader report={report} target={target} hostnameOverride={hostnameOverride} isGuest={isGuest} />

      <div className="print-hidden px-8 pt-5">
        <div className="inline-flex rounded-lg border border-ink-200 p-0.5 bg-ink-50">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded-md text-[13px] font-medium transition-colors ${
                tab === t ? "bg-white text-ink-950 shadow-sm" : "text-ink-500 hover:text-ink-800"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {tab === "Overview" ? (
        <div className="px-8 py-6 w-full max-w-[1400px] mx-auto">
          {/* hero row: score + PQC readiness + finding severity, side by side */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="panel p-6 flex flex-col items-center">
              <p className="text-[11px] uppercase tracking-wider text-ink-400 mb-4 self-start">
                Posture score
              </p>
              <PostureGauge postureScore={postureScore} sections={sections} />
              <p className="text-[11px] text-ink-400 mt-4 text-center">
                Weighted across {sections.length} sections · risk band{" "}
                <span className="text-ink-700">{riskBand}</span>
              </p>
            </div>

            <div className="panel p-5 flex flex-col">
              <p className="text-[11px] uppercase tracking-wider text-ink-400 mb-3">
                PQC readiness
              </p>
              <div className="flex items-end justify-between mb-2">
                <span className="data-mono text-[28px] font-semibold text-ink-950">
                  {pqcReadiness}%
                </span>
                <span className="text-[12px] text-sev-medium">
                  {pqcReadiness >= 60 ? "Mostly PQC ready" : "Not PQC ready"}
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-ink-100 overflow-hidden">
                <div className="h-full bg-ink-950" style={{ width: `${pqcReadiness}%` }} />
              </div>
              <p className="mt-3 text-[11.5px] text-ink-500 leading-relaxed">
                No ML-KEM key exchange or ML-DSA / SLH-DSA signatures negotiated in this handshake.
              </p>
            </div>

            <div className="panel p-5 flex flex-col">
              <div className="flex items-center justify-between mb-3">
                <p className="text-[11px] uppercase tracking-wider text-ink-400">
                  Finding severity
                </p>
                <span className="data-mono text-[11px] text-ink-400">{findings.length} total</span>
              </div>
              <div className="flex items-center gap-3 text-[12px]">
                <span className="text-sev-critical data-mono">{critical} critical</span>
                <span className="text-ink-200">·</span>
                <span className="text-sev-high data-mono">{high} high</span>
              </div>
              <div className="mt-4 space-y-2">
                {risks.map((r, i) => (
                  <div key={i} className="flex items-start justify-between gap-2 text-[12px]">
                    <div className="min-w-0">
                      <p className="truncate text-ink-800">{r.parameter}</p>
                      <p className="truncate text-ink-400 text-[11px]">{r.section}</p>
                    </div>
                    <SeverityBadge severity={r.severity} />
                  </div>
                ))}
                {risks.length === 0 && (
                  <p className="text-[12px] text-ink-400">No critical or high findings.</p>
                )}
              </div>
            </div>
          </div>

          {/* section scores chart, full width */}
          <div className="panel p-5 mt-5">
            <p className="text-[11px] uppercase tracking-wider text-ink-400 mb-4">
              Section scores vs weight allocation
            </p>
            <SectionsOverviewChart sections={sections} />
          </div>

          {/* full-width report — scroll down to see every parameter checked */}
          <div className="mt-8">
            <div className="flex items-baseline justify-between mb-3 px-1">
              <p className="text-[11px] uppercase tracking-wider text-ink-400">
                Full report — parameter breakdown by section
              </p>
              <span className="data-mono text-[11px] text-ink-400">
                {findings.length} parameters checked
              </span>
            </div>
            <div className="space-y-3">
              {sections.map((s) => (
                <SectionCard key={s.id} section={s} />
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="print-hidden px-8 py-8 grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-8">
          <ChatPanel report={report} />
          <div className="space-y-6">
            <RiskTargetSlider report={report} />
          </div>
        </div>
      )}
    </div>
  );
}
