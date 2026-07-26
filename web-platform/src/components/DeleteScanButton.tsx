"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { deleteGuestScan } from "@/lib/guest-scans";

export default function DeleteScanButton({
  scanId,
  hostname,
  compact = false,
}: {
  scanId: string;
  hostname: string;
  compact?: boolean;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function handleDelete(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();

    if (!confirm(`Delete the scan for ${hostname}? This can't be undone.`)) return;

    setPending(true);
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        alert(data.error ?? "Could not delete scan.");
        return;
      }
      // Defensive cleanup: if this scan is also sitting in localStorage
      // (e.g. it was migrated from a guest session but a stale copy is
      // still cached locally), drop it there too so DB and localStorage
      // never disagree about what still exists.
      deleteGuestScan(scanId);
      window.dispatchEvent(new Event("pqshield_user_scans_changed"));
      router.refresh();
    } finally {
      setPending(false);
    }
  }

  if (compact) {
    return (
      <button
        onClick={handleDelete}
        disabled={pending}
        aria-label={`Delete scan for ${hostname}`}
        title="Delete scan"
        className="shrink-0 h-5 w-5 flex items-center justify-center rounded text-ink-300 hover:text-sev-critical hover:bg-ink-50 transition-colors disabled:opacity-50 text-[13px] leading-none"
      >
        {pending ? "…" : "×"}
      </button>
    );
  }

  return (
    <button
      onClick={handleDelete}
      disabled={pending}
      aria-label={`Delete scan for ${hostname}`}
      className="text-[12px] text-ink-400 hover:text-sev-critical transition-colors disabled:opacity-50 px-2 py-1"
    >
      {pending ? "…" : "Delete"}
    </button>
  );
}
