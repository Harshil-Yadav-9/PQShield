import Link from "next/link";
import { auth } from "@/lib/auth";
import { listScansForOwner } from "@/lib/scan-store";
import GuestScansList from "@/components/GuestScansList";
import DeleteScanButton from "@/components/DeleteScanButton";
import { GUEST_SCAN_LIMIT } from "@/lib/guest-scans";

const BAND_COLOR: Record<string, string> = {
  Critical: "text-sev-critical",
  "At risk": "text-sev-high",
  Moderate: "text-sev-medium",
  Strong: "text-sev-low",
  "PQC ready": "text-sev-low",
};

export default async function ScansPage() {
  const session = await auth();
  const userId = session?.user?.id ?? null;

  const scans = userId ? await listScansForOwner({ userId }) : [];

  return (
    <div className="min-h-screen px-8 py-16 max-w-2xl mx-auto">
      <h1 className="font-display text-[26px] font-bold tracking-tight text-ink-950">
        {userId ? "Your scans" : "Scans on this device"}
      </h1>
      {!userId && (
        <p className="mt-2 text-[13px] text-ink-500">
          Guests get {GUEST_SCAN_LIMIT} free scans, stored only in this browser.{" "}
          <Link href="/login" className="underline hover:text-ink-950">
            Sign in
          </Link>{" "}
          to keep this history permanently and access it from any device.
        </p>
      )}

      <div className="mt-8 flex flex-col divide-y divide-ink-100 border-y border-ink-100">
        {userId ? (
          <>
            {scans.length === 0 && (
              <p className="py-8 text-[13.5px] text-ink-400">No scans yet — run one from the home page.</p>
            )}
            {scans.map((s) => (
              <div
                key={s.id}
                className="flex items-center justify-between py-4 hover:bg-ink-50 -mx-4 px-4 rounded-lg transition-colors"
              >
                <Link href={`/reports/${s.id}`} className="flex-1 min-w-0">
                  <p className="text-[14px] font-medium text-ink-950">{s.hostname}</p>
                  <p className="text-[12px] text-ink-400 mt-0.5">
                    {new Date(s.createdAt).toLocaleString()}
                  </p>
                </Link>
                <div className="flex items-center gap-3">
                  <Link href={`/reports/${s.id}`} className="text-right">
                    <p className="text-[14px] font-medium text-ink-950">{s.postureScore}</p>
                    <p className={`text-[11.5px] mt-0.5 ${BAND_COLOR[s.riskBand] ?? "text-ink-500"}`}>
                      {s.riskBand}
                    </p>
                  </Link>
                  <DeleteScanButton scanId={s.id} hostname={s.hostname} />
                </div>
              </div>
            ))}
          </>
        ) : (
          <GuestScansList />
        )}
      </div>
    </div>
  );
}
