"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getGuestScans, GuestScanEntry } from "@/lib/guest-scans";

const BAND_COLOR: Record<string, string> = {
  Critical: "text-sev-critical",
  "At risk": "text-sev-high",
  Moderate: "text-sev-medium",
  Strong: "text-sev-low",
  "PQC ready": "text-sev-low",
};

export default function GuestScansList() {
  const [scans, setScans] = useState<GuestScanEntry[] | null>(null);

  useEffect(() => {
    const load = () => setScans(getGuestScans());
    load();
    window.addEventListener("pqshield_guest_scans_changed", load);
    window.addEventListener("storage", load);
    return () => {
      window.removeEventListener("pqshield_guest_scans_changed", load);
      window.removeEventListener("storage", load);
    };
  }, []);

  // Avoid a hydration mismatch: render nothing server-side / on first paint,
  // then fill in from localStorage once mounted.
  if (scans === null) return null;

  if (scans.length === 0) {
    return <p className="py-8 text-[13.5px] text-ink-400">No scans yet — run one from the home page.</p>;
  }

  return (
    <>
      {scans.map((s) => (
        <Link
          key={s.id}
          href={`/reports/${s.id}`}
          className="flex items-center justify-between py-4 hover:bg-ink-50 -mx-4 px-4 rounded-lg transition-colors"
        >
          <div>
            <p className="text-[14px] font-medium text-ink-950">{s.hostname}</p>
            <p className="text-[12px] text-ink-400 mt-0.5">{new Date(s.createdAt).toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-[14px] font-medium text-ink-950">{s.postureScore}</p>
            <p className={`text-[11.5px] mt-0.5 ${BAND_COLOR[s.riskBand] ?? "text-ink-500"}`}>
              {s.riskBand}
            </p>
          </div>
        </Link>
      ))}
    </>
  );
}
