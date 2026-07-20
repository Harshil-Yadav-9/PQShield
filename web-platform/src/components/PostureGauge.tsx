"use client";

import { PieChart, Pie, Cell, Tooltip } from "recharts";
import { ReportSection } from "@/lib/types";
import { scoreBand } from "@/lib/utils";

function segmentColor(normalized: number): string {
  if (normalized >= 85) return "#15803d";
  if (normalized >= 65) return "#0f7a5c";
  if (normalized >= 40) return "#a15c07";
  return "#c62828";
}

export default function PostureGauge({
  postureScore,
  sections,
}: {
  postureScore: number;
  sections: ReportSection[];
}) {
  const band = scoreBand(postureScore);
  const data = sections.map((s) => ({
    name: s.name,
    value: s.weight,
    normalized: s.normalized,
  }));

  return (
    <div className="relative flex items-center justify-center">
      <PieChart width={240} height={240}>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          innerRadius={82}
          outerRadius={112}
          startAngle={90}
          endAngle={-270}
          paddingAngle={2}
          stroke="#ffffff"
          strokeWidth={2}
        >
          {data.map((entry, i) => (
            <Cell key={i} fill={segmentColor(entry.normalized)} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "#ffffff",
            border: "1px solid #e5e5e8",
            borderRadius: 8,
            fontSize: 12,
            boxShadow: "0 4px 16px rgba(0,0,0,0.06)",
          }}
          formatter={(value: number, _name, item) => [
            `${item.payload.normalized}/100 normalized`,
            `${item.payload.name} · ${value}% weight`,
          ]}
        />
      </PieChart>
      <div className="absolute flex flex-col items-center">
        <span className="data-mono text-[38px] font-semibold leading-none text-ink-950">
          {postureScore.toFixed(1)}
        </span>
        <span className={`mt-1 text-[12px] font-medium ${band.className}`}>
          {band.label} posture
        </span>
      </div>
    </div>
  );
}
