"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ScanReport, ScanTarget } from "@/lib/types";
import { formatDate, formatDuration } from "@/lib/utils";
import { getGuestScanRaw } from "@/lib/guest-scans";

async function downloadExport(reportId: string, format: "json" | "excel", isGuest: boolean, hostname: string) {
  const res = isGuest
    ? await fetch(`/api/reports/${reportId}/export?format=${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw: getGuestScanRaw(reportId), hostname }),
      })
    : await fetch(`/api/reports/${reportId}/export?format=${format}`);

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `Could not generate the ${format === "json" ? "JSON" : "Excel"} file.`);
  }
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match?.[1] || (format === "json" ? "cbom_export.json" : "TLS_PQC_Risk_Report.xlsx");

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function TargetHeader({
  report,
  target,
  hostnameOverride,
  isGuest = false,
}: {
  report: ScanReport;
  target: ScanTarget;
  hostnameOverride?: string;
  isGuest?: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<"excel" | "json" | "rescan" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleExport(format: "json" | "excel") {
    setError(null);
    setBusy(format);
    try {
      await downloadExport(report.id, format, isGuest, hostnameOverride || target.hostname);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    } finally {
      setBusy(null);
    }
  }

  function handlePrint() {
    window.print();
  }

  async function handleRescan() {
    setError(null);
    setBusy("rescan");
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: hostnameOverride || target.hostname }),
        signal: AbortSignal.timeout(115_000),
      });
      const text = await res.text();
      let data: { error?: string; id?: string } = {};
      if (text) {
        try {
          data = JSON.parse(text) as typeof data;
        } catch {
          data = { error: text.slice(0, 500) };
        }
      }
      if (!res.ok) throw new Error(data.error || "Rescan failed.");
      router.push(`/reports/${data.id}?target=${encodeURIComponent(hostnameOverride || target.hostname)}`);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rescan failed.");
      setBusy(null);
    }
  }

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 border-b border-ink-100 px-8 py-5">
      <div>
        <div className="flex items-baseline gap-2">
          <h1 className="font-display text-[20px] font-semibold text-ink-950">
            {hostnameOverride || target.hostname}
          </h1>
          <span className="data-mono text-[13px] text-ink-400">
            {target.ip}:{target.port}
          </span>
        </div>
        <p className="mt-1 text-[12px] text-ink-400">
          Scanned {formatDate(target.scanStart)} · elapsed {formatDuration(target.durationSeconds)} ·
          scanner v{target.scannerVersion}
        </p>
        {error && <p className="mt-1.5 text-[12px] text-sev-critical">{error}</p>}
      </div>

      <div className="print-hidden flex items-center gap-2">
        <button
          onClick={handlePrint}
          className="rounded-lg border border-ink-200 px-3.5 py-2 text-[12.5px] text-ink-700 hover:bg-ink-50 transition-colors"
        >
          Export PDF
        </button>
        <button
          onClick={() => handleExport("json")}
          disabled={busy !== null}
          className="rounded-lg border border-ink-200 px-3.5 py-2 text-[12.5px] text-ink-700 hover:bg-ink-50 disabled:opacity-60 transition-colors"
        >
          {busy === "json" ? "Preparing…" : "Export JSON"}
        </button>
        <button
          onClick={() => handleExport("excel")}
          disabled={busy !== null}
          className="rounded-lg border border-ink-200 px-3.5 py-2 text-[12.5px] text-ink-700 hover:bg-ink-50 disabled:opacity-60 transition-colors"
        >
          {busy === "excel" ? "Preparing…" : "Export Excel"}
        </button>
        <button
          onClick={handleRescan}
          disabled={busy !== null}
          className="rounded-lg bg-ink-950 text-white px-3.5 py-2 text-[12.5px] font-medium hover:bg-ink-800 disabled:opacity-60 transition-colors"
        >
          {busy === "rescan" ? "Rescanning…" : "Rescan target"}
        </button>
      </div>
    </header>
  );
}
