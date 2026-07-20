"use client";

import { useState } from "react";
import { PieChart, Pie, Cell, Tooltip } from "recharts";
import { ReportSection } from "@/lib/types";
import { SEVERITY_COLOR } from "@/lib/types";
import { severityCounts, scoreBand } from "@/lib/utils";
import SeverityBadge from "./SeverityBadge";

export default function SectionCard({ section }: { section: ReportSection }) {
  const [open, setOpen] = useState(false);
  const counts = severityCounts(section.findings);
  const band = scoreBand(section.normalized);

  return (
    <div className="panel overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left"
      >
        <div className="flex items-center gap-4 min-w-0">
          <div className="shrink-0">
            <PieChart width={56} height={56}>
              <Pie
                data={counts}
                dataKey="count"
                nameKey="severity"
                innerRadius={16}
                outerRadius={27}
                stroke="#ffffff"
                strokeWidth={2}
              >
                {counts.map((c, i) => (
                  <Cell key={i} fill={SEVERITY_COLOR[c.severity]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#ffffff",
                  border: "1px solid #e5e5e8",
                  borderRadius: 8,
                  fontSize: 11,
                  boxShadow: "0 4px 16px rgba(0,0,0,0.06)",
                }}
              />
            </PieChart>
          </div>
          <div className="min-w-0">
            <p className="font-medium text-[14px] text-ink-950 truncate">{section.name}</p>
            <p className="text-[12px] text-ink-500 truncate">{section.summary}</p>
          </div>
        </div>

        <div className="flex items-center gap-6 shrink-0">
          <div className="text-right">
            <p className="data-mono text-[13px] text-ink-500">weight {section.weight}%</p>
            <p className={`data-mono text-[13px] ${band.className}`}>{section.normalized}/100</p>
          </div>
          <span
            className={`data-mono text-ink-400 text-[16px] transition-transform ${open ? "rotate-90" : ""}`}
          >
            {">"}
          </span>
        </div>
      </button>

      <div className={`section-details border-t border-ink-100 overflow-x-auto ${open ? "" : "hidden"}`}>
        <table className="w-full min-w-[720px] text-[12.5px]">
          <thead>
            <tr className="text-left text-ink-400 border-b border-ink-100">
              <th className="px-5 py-2 font-medium">Parameter</th>
              <th className="px-3 py-2 font-medium">Observed</th>
              <th className="px-3 py-2 font-medium">Standard</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Contribution</th>
              <th className="px-5 py-2 font-medium">Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {section.findings.map((f, i) => (
              <tr key={i} className="border-b border-ink-100 last:border-0 align-top">
                <td className="px-5 py-3 text-ink-800">{f.parameter}</td>
                <td className="px-3 py-3 data-mono text-ink-600">{f.observed}</td>
                <td className="px-3 py-3 text-ink-400">{f.standard}</td>
                <td className="px-3 py-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td
                  className={`px-3 py-3 data-mono ${
                    f.contribution < 0 ? "text-sev-high" : "text-sev-acceptable"
                  }`}
                >
                  {f.contribution > 0 ? "+" : ""}
                  {f.contribution.toFixed(1)}%
                </td>
                <td className="px-5 py-3 text-ink-500">{f.recommendation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
