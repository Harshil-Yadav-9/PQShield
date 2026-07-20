"use client";

import { useMemo, useState } from "react";
import { ScanReport } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";

export default function RiskTargetSlider({ report }: { report: ScanReport }) {
  const { postureScore, sections } = report;
  const [target, setTarget] = useState(Math.min(90, Math.ceil(postureScore / 5) * 5 + 10));

  const negativeFindings = useMemo(
    () =>
      sections
        .flatMap((s) => s.findings.map((f) => ({ ...f, section: s.name })))
        .filter((f) => f.contribution < 0)
        .sort((a, b) => a.contribution - b.contribution),
    [sections]
  );

  const { toFix, projected } = useMemo(() => {
    const gapNeeded = target - postureScore;
    let recovered = 0;
    const chosen: typeof negativeFindings = [];
    for (const f of negativeFindings) {
      if (recovered >= gapNeeded) break;
      chosen.push(f);
      recovered += Math.abs(f.contribution);
    }
    return {
      toFix: chosen,
      projected: Math.min(100, +(postureScore + recovered).toFixed(1)),
    };
  }, [negativeFindings, target, postureScore]);

  return (
    <div className="panel p-5">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[11px] uppercase tracking-wider text-ink-400">Risk-target planner</p>
        <span className="data-mono text-[12px] text-ink-700">
          {postureScore.toFixed(1)} → {projected.toFixed(1)}
        </span>
      </div>
      <p className="text-[11.5px] text-ink-500 mb-4">
        Choose a target posture score — the sorted fix list below shows the minimum set of findings to
        close the gap, starting with the heaviest-weighted risks.
      </p>

      <input
        type="range"
        min={Math.ceil(postureScore)}
        max={100}
        value={target}
        onChange={(e) => setTarget(Number(e.target.value))}
        className="w-full accent-ink-950"
      />
      <div className="flex justify-between text-[11px] data-mono text-ink-400 mt-1 mb-5">
        <span>current {postureScore.toFixed(1)}</span>
        <span className="text-ink-950">target {target}</span>
        <span>100</span>
      </div>

      <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
        {toFix.length === 0 && (
          <p className="text-[12px] text-ink-400">Move the slider to see the required fix list.</p>
        )}
        {toFix.map((f, i) => (
          <div
            key={i}
            className="flex items-center justify-between gap-3 rounded-lg border border-ink-100 px-3 py-2"
          >
            <div className="min-w-0">
              <p className="text-[12.5px] text-ink-900 truncate">{f.parameter}</p>
              <p className="text-[11px] text-ink-400 truncate">{f.section}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="data-mono text-[11px] text-sev-acceptable">
                +{Math.abs(f.contribution).toFixed(1)}%
              </span>
              <SeverityBadge severity={f.severity} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
