import { cookies } from "next/headers";

const COUNT_COOKIE_NAME = "pqshield_guest_scan_count";

// Guests' scan *content* lives entirely in the browser's localStorage (see
// src/lib/guest-scans.ts) — never sent to the DB. This cookie is just a
// tamper-resistant counter — httpOnly so client JS can't reset it the way
// it could reset localStorage — used only to enforce the free-scan limit
// server-side before running an expensive scan.
export async function getGuestScanCount(): Promise<number> {
  const store = await cookies();
  const raw = store.get(COUNT_COOKIE_NAME)?.value;
  const n = raw ? parseInt(raw, 10) : 0;
  return Number.isFinite(n) ? n : 0;
}

export async function incrementGuestScanCount(): Promise<void> {
  const store = await cookies();
  const current = await getGuestScanCount();
  store.set(COUNT_COOKIE_NAME, String(current + 1), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
  });
}
