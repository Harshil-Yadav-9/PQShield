"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function DeleteScanButton({ scanId, hostname }: { scanId: string; hostname: string }) {
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
      router.refresh();
    } finally {
      setPending(false);
    }
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
