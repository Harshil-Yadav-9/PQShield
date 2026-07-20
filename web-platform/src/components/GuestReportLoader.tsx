"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getGuestScanReport } from "@/lib/guest-scans";
import { ScanReport } from "@/lib/types";
import ReportView from "@/components/ReportView";

export default function GuestReportLoader({
  id,
  hostnameOverride,
}: {
  id: string;
  hostnameOverride?: string;
}) {
  const [report, setReport] = useState<ScanReport | null | undefined>(undefined);

  useEffect(() => {
    setReport(getGuestScanReport(id));
  }, [id]);

  // undefined = still checking localStorage (first client render); avoid a
  // flash of the "not found" message before we've actually looked.
  if (report === undefined) return null;

  if (!report) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-8 text-center">
        <p className="text-[15px] text-ink-700">
          This report isn&apos;t available on this device or account.
        </p>
        <p className="mt-1.5 text-[13px] text-ink-400">
          Guest scans are only saved in the browser that ran them.
        </p>
        <Link href="/" className="mt-6 text-[13px] font-medium text-ink-950 hover:underline">
          Run a new scan
        </Link>
      </div>
    );
  }

  return <ReportView report={report} hostnameOverride={hostnameOverride} isGuest />;
}
