"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ResponsiveContainer,
} from "recharts";
import { ReportSection } from "@/lib/types";

function barColor(normalized: number): string {
  if (normalized >= 85) return "#15803d";
  if (normalized >= 65) return "#0f7a5c";
  if (normalized >= 40) return "#a15c07";
  return "#c62828";
}

export default function SectionsOverviewChart({ sections }: { sections: ReportSection[] }) {
  const data = [...sections]
    .sort((a, b) => b.weight - a.weight)
    .map((s) => ({
      name: s.name,
      normalized: s.normalized,
      weight: s.weight,
    }));

  return (
    <ResponsiveContainer width="100%" height={sections.length * 34 + 20}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 24, left: 0, bottom: 0 }}>
        <CartesianGrid horizontal={false} stroke="#eeeeef" />
        <XAxis
          type="number"
          domain={[0, 100]}
          tick={{ fill: "#9c9ca3", fontSize: 11 }}
          axisLine={{ stroke: "#e5e5e8" }}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="name"
          width={168}
          tick={{ fill: "#3a3a40", fontSize: 12 }}
          axisLine={{ stroke: "#e5e5e8" }}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: "rgba(10,10,12,0.03)" }}
          contentStyle={{
            background: "#ffffff",
            border: "1px solid #e5e5e8",
            borderRadius: 8,
            fontSize: 12,
            boxShadow: "0 4px 16px rgba(0,0,0,0.06)",
          }}
          formatter={(value: number, key) =>
            key === "normalized" ? [`${value}/100`, "Normalized score"] : [`${value}%`, "Weight"]
          }
        />
        <Bar dataKey="normalized" radius={[0, 4, 4, 0]} barSize={14}>
          {data.map((entry, i) => (
            <Cell key={i} fill={barColor(entry.normalized)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
