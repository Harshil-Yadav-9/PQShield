"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession, signOut } from "next-auth/react";
import { mockReports } from "@/lib/mock-data";
import { scoreBand, formatDate } from "@/lib/utils";
import { getGuestScans, clearGuestScans, GuestScanEntry, GUEST_SCAN_LIMIT } from "@/lib/guest-scans";
import DeleteScanButton from "@/components/DeleteScanButton";

interface UserScan {
  id: string;
  hostname: string;
  postureScore: number;
  riskBand: string;
  createdAt: string;
}

export default function Sidebar() {
  const pathname = usePathname();
  const { data: session, status } = useSession();
  // Plain component state — resets to expanded on every fresh load/reopen,
  // by design (this is a per-visit UI preference, not saved anywhere).
  const [collapsed, setCollapsed] = useState(false);
  const [guestScans, setGuestScans] = useState<GuestScanEntry[]>([]);
  const [userScans, setUserScans] = useState<UserScan[]>([]);
  // Guards against re-running the migration+fetch more than once per sign-in
  // (effects can re-fire on fast refresh / re-renders in dev).
  const migratedRef = useRef(false);

  async function refreshUserScans() {
    try {
      const res = await fetch("/api/scans");
      if (!res.ok) return;
      const data = await res.json();
      setUserScans(Array.isArray(data.scans) ? data.scans : []);
    } catch {
      // Silent — sidebar list is a nice-to-have, not critical
    }
  }

  useEffect(() => {
    if (status === "authenticated") {
      if (migratedRef.current) return;
      migratedRef.current = true;

      (async () => {
        const pending = getGuestScans();
        if (pending.length > 0) {
          try {
            const res = await fetch("/api/scans", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                scans: pending.map((s) => ({ report: s.report, raw: s.raw })),
              }),
            });
            if (res.ok) {
              // Now live in the DB under this account — clear the local
              // copy so the two views can't drift out of sync.
              clearGuestScans();
            }
          } catch {
            // Non-fatal — the scans just stay in localStorage until the
            // next successful sign-in retries this.
          }
        }
        refreshUserScans();
      })();

      window.addEventListener("pqshield_user_scans_changed", refreshUserScans);
      return () => window.removeEventListener("pqshield_user_scans_changed", refreshUserScans);
    }

    migratedRef.current = false;
    const load = () => setGuestScans(getGuestScans());
    load();
    window.addEventListener("pqshield_guest_scans_changed", load);
    window.addEventListener("storage", load);
    return () => {
      window.removeEventListener("pqshield_guest_scans_changed", load);
      window.removeEventListener("storage", load);
    };
  }, [status]);

  function toggle() {
    setCollapsed((v) => !v);
  }

  if (collapsed) {
    return (
      <aside className="w-[64px] shrink-0 border-r border-ink-100 bg-canvas flex flex-col items-center h-screen sticky top-0 py-5 gap-5">
        <Link href="/" className="flex items-center justify-center">
          <span className="h-2.5 w-2.5 rounded-full bg-ink-950" />
        </Link>
        <button
          onClick={toggle}
          title="Expand sidebar"
          aria-label="Expand sidebar"
          className="flex h-8 w-8 items-center justify-center rounded-lg border border-ink-200 text-ink-500 hover:bg-ink-50 hover:text-ink-950 transition-colors"
        >
          »
        </button>
        <Link
          href="/"
          title="New scan"
          aria-label="New scan"
          className="flex h-9 w-9 items-center justify-center rounded-lg bg-ink-950 text-white text-[15px] font-medium hover:bg-ink-800 transition-colors"
        >
          +
        </Link>
        <Link
          href="/scans"
          title={status === "authenticated" ? "My scans" : "Scans on this device"}
          aria-label="My scans"
          className={`flex h-9 w-9 items-center justify-center rounded-lg text-[11px] font-medium transition-colors ${
            pathname === "/scans" ? "bg-white shadow-sm ring-1 ring-ink-100 text-ink-950" : "text-ink-400 hover:bg-ink-50"
          }`}
        >
          ⧉
        </Link>
        <div className="mt-auto">
          {status === "authenticated" ? (
            <button
              onClick={() => signOut({ callbackUrl: "/" })}
              title="Sign out"
              aria-label="Sign out"
              className="flex h-8 w-8 items-center justify-center rounded-lg text-ink-400 hover:text-ink-950 hover:bg-ink-50 transition-colors text-[11px]"
            >
              ⎋
            </button>
          ) : (
            <Link
              href="/login"
              title="Sign in"
              aria-label="Sign in"
              className="flex h-8 w-8 items-center justify-center rounded-lg text-ink-400 hover:text-ink-950 hover:bg-ink-50 transition-colors text-[11px]"
            >
              →
            </Link>
          )}
        </div>
      </aside>
    );
  }

  return (
    <aside className="w-[260px] shrink-0 border-r border-ink-100 bg-canvas flex flex-col h-screen sticky top-0">
      <div className="px-5 py-5 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-ink-950" />
          <span className="font-display font-bold tracking-tight text-[15px] text-ink-950">
            PQShield
          </span>
        </Link>
        <button
          onClick={toggle}
          title="Collapse sidebar"
          aria-label="Collapse sidebar"
          className="flex h-7 w-7 items-center justify-center rounded-lg text-ink-400 hover:bg-ink-50 hover:text-ink-950 transition-colors text-[13px]"
        >
          «
        </button>
      </div>

      <div className="px-3">
        <Link
          href="/"
          className="flex items-center justify-center gap-2 w-full rounded-lg bg-ink-950 text-white text-[13px] font-medium py-2.5 hover:bg-ink-800 transition-colors"
        >
          + New scan
        </Link>
      </div>

      <div className="mt-6 flex-1 overflow-y-auto px-3 pb-4">
        <Link
          href="/scans"
          className={`block rounded-lg px-3 py-2 mb-3 text-[12.5px] font-medium transition-colors ${
            pathname === "/scans" ? "bg-white shadow-sm ring-1 ring-ink-100 text-ink-950" : "text-ink-500 hover:bg-ink-50"
          }`}
        >
          {status === "authenticated" ? "My scans" : "Scans on this device"}
        </Link>

        {status !== "authenticated" && guestScans.length > 0 && (
          <>
            <p className="px-2 text-[11px] font-medium uppercase tracking-wider text-ink-400 mb-2">
              Your scans ({guestScans.length}/{GUEST_SCAN_LIMIT})
            </p>
            <div className="space-y-1 mb-4">
              {guestScans.map((s) => {
                const href = `/reports/${s.id}`;
                const active = pathname === href;
                const band = scoreBand(s.postureScore);
                return (
                  <Link
                    key={s.id}
                    href={href}
                    className={`block rounded-lg px-3 py-2.5 transition-colors ${
                      active ? "bg-white shadow-sm ring-1 ring-ink-100" : "hover:bg-ink-50"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-[13px] font-medium text-ink-900 truncate">{s.hostname}</p>
                      <span className={`data-mono text-[11px] shrink-0 ${band.className}`}>
                        {s.postureScore.toFixed(0)}
                      </span>
                    </div>
                    <p className="text-[11px] text-ink-400 mt-0.5">
                      {new Date(s.createdAt).toLocaleDateString()}
                    </p>
                  </Link>
                );
              })}
            </div>
          </>
        )}

        {status === "authenticated" && userScans.length > 0 && (
          <>
            <p className="px-2 text-[11px] font-medium uppercase tracking-wider text-ink-400 mb-2">
              Your scans
            </p>
            <div className="space-y-1 mb-4">
              {userScans.map((s) => {
                const href = `/reports/${s.id}`;
                const active = pathname === href;
                const band = scoreBand(s.postureScore);
                return (
                  <div
                    key={s.id}
                    className={`flex items-center gap-1.5 rounded-lg px-3 py-2.5 transition-colors ${
                      active ? "bg-white shadow-sm ring-1 ring-ink-100" : "hover:bg-ink-50"
                    }`}
                  >
                    <Link href={href} className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[13px] font-medium text-ink-900 truncate">{s.hostname}</p>
                        <span className={`data-mono text-[11px] shrink-0 ${band.className}`}>
                          {s.postureScore.toFixed(0)}
                        </span>
                      </div>
                      <p className="text-[11px] text-ink-400 mt-0.5">
                        {new Date(s.createdAt).toLocaleDateString()}
                      </p>
                    </Link>
                    <DeleteScanButton scanId={s.id} hostname={s.hostname} compact />
                  </div>
                );
              })}
            </div>
          </>
        )}

        <p className="px-2 text-[11px] font-medium uppercase tracking-wider text-ink-400 mb-2">
          Demo report
        </p>
        <div className="space-y-1">
          {mockReports.map((r) => {
            const href = `/reports/${r.id}`;
            const active = pathname === href;
            const band = scoreBand(r.postureScore);
            return (
              <Link
                key={r.id}
                href={href}
                className={`block rounded-lg px-3 py-2.5 transition-colors ${
                  active ? "bg-white shadow-sm ring-1 ring-ink-100" : "hover:bg-ink-50"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[13px] font-medium text-ink-900 truncate">
                    {r.target.hostname}
                  </p>
                  <span className={`data-mono text-[11px] shrink-0 ${band.className}`}>
                    {r.postureScore.toFixed(0)}
                  </span>
                </div>
                <p className="text-[11px] text-ink-400 mt-0.5">{formatDate(r.scannedAt)}</p>
              </Link>
            );
          })}
        </div>
      </div>

      <div className="px-5 py-4 border-t border-ink-100">
        {status === "authenticated" ? (
          <div className="flex items-center justify-between gap-2">
            <p className="text-[12px] text-ink-700 truncate">{session?.user?.email}</p>
            <button
              onClick={() => signOut({ callbackUrl: "/" })}
              className="text-[11.5px] text-ink-400 hover:text-ink-950 shrink-0"
            >
              Sign out
            </button>
          </div>
        ) : status === "loading" ? null : (
          <Link href="/login" className="text-[12.5px] font-medium text-ink-950 hover:underline">
            Sign in
          </Link>
        )}
        <p className="text-[10px] text-ink-400 leading-relaxed mt-3">
          IITISoC 2026 · PS-6 Cybersecurity
          <br />
          PQShield platform
        </p>
      </div>
    </aside>
  );
}
