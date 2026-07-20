"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { saveGuestScan, GUEST_SCAN_LIMIT } from "@/lib/guest-scans";
import { ScanReport } from "@/lib/types";

const STEPS = [
  "Resolving target",
  "Probing TLS capability space",
  "Inspecting certificate chain",
  "Checking legacy vulnerabilities",
  "Scoring PQC readiness",
];

export default function ScanForm() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [scanning, setScanning] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [limitReached, setLimitReached] = useState(false);

  async function runScan(e: React.FormEvent) {
    e.preventDefault();
    const target = value.trim();
    if (!target || scanning) return;

    setScanning(true);
    setStepIndex(0);
    setError(null);
    setLimitReached(false);

    // The real scan takes a while (TLS negotiation across many cipher/group
    // combinations); step through the labels on a timer purely for feedback
    // while the request is in flight, and stop advancing before the last step
    // until the response actually comes back.
    const stepTimer = setInterval(() => {
      setStepIndex((i) => (i < STEPS.length - 1 ? i + 1 : i));
    }, 3000);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      const data = await res.json();

      if (!res.ok) {
        if (data.code === "SCAN_LIMIT_REACHED") setLimitReached(true);
        throw new Error(data.error || "Scan failed.");
      }

      clearInterval(stepTimer);
      setStepIndex(STEPS.length);
      if (!data.persisted) {
        // Guest scan — the server never stored it, so the browser is the
        // only place it exists. Save it before navigating so the report
        // page and sidebar can find it.
        saveGuestScan(data.report as ScanReport, data.raw);
      }
      setTimeout(() => {
        router.push(`/reports/${data.id}?target=${encodeURIComponent(target)}`);
      }, 300);
    } catch (err) {
      clearInterval(stepTimer);
      setScanning(false);
      setError(err instanceof Error ? err.message : "Scan failed.");
    }
  }

  return (
    <div className="w-full max-w-xl">
      <form onSubmit={runScan} className="relative">
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={scanning}
          placeholder="example.com, https://example.com, or an IP address"
          className="w-full rounded-2xl border border-ink-200 bg-white pl-5 pr-32 py-4 text-[15px] text-ink-950 placeholder:text-ink-400 shadow-sm focus:outline-none focus:border-ink-400 disabled:opacity-60 transition-colors"
        />
        <button
          type="submit"
          disabled={scanning}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-xl bg-ink-950 text-white text-[13px] font-medium px-5 py-2.5 hover:bg-ink-800 disabled:opacity-60 transition-colors"
        >
          {scanning ? "Scanning…" : "Scan"}
        </button>
      </form>

      {scanning && (
        <div className="mt-6 space-y-2.5">
          {STEPS.map((step, i) => {
            const done = i < stepIndex;
            const active = i === stepIndex;
            return (
              <div key={step} className="flex items-center gap-3">
                <span
                  className={`flex h-4 w-4 shrink-0 items-center justify-center rounded-full border text-[9px] ${
                    done
                      ? "bg-ink-950 border-ink-950 text-white"
                      : active
                        ? "border-ink-950 text-ink-950"
                        : "border-ink-200 text-ink-200"
                  }`}
                >
                  {done ? "✓" : ""}
                </span>
                <span
                  className={`text-[13px] ${done ? "text-ink-400" : active ? "text-ink-950" : "text-ink-300"}`}
                >
                  {step}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {error && (
        <p className="mt-4 text-[12px] text-sev-critical">
          {error}
          {limitReached && (
            <>
              {" "}
              <Link href="/login" className="underline hover:text-ink-950">
                Sign in
              </Link>
              .
            </>
          )}
        </p>
      )}

      {!scanning && !error && (
        <p className="mt-4 text-[12px] text-ink-400">
          Live scan — runs a real TLS/PQC probe against the target and can take up to a minute. Guests
          get {GUEST_SCAN_LIMIT} free scans on this device — sign in for unlimited scans and permanent
          history.
        </p>
      )}
    </div>
  );
}
