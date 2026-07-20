import { NextRequest, NextResponse } from "next/server";
import { ScanReport } from "@/lib/types";
import { saveScanReport } from "@/lib/scan-store";
import { auth } from "@/lib/auth";
import { getGuestScanCount, incrementGuestScanCount } from "@/lib/session";
import { GUEST_SCAN_LIMIT } from "@/lib/guest-scans";

export const runtime = "nodejs";
export const maxDuration = 120;

// URL of the deployed pqc_scanner FastAPI service (see pqc_scanner/service.py
// + Dockerfile). Locally this is just `uvicorn pqc_scanner.service:app`.
const SCANNER_URL = process.env.SCANNER_URL ?? "http://127.0.0.1:8000";

async function runScan(
  target: string,
): Promise<{ ok: true; report: ScanReport; raw: unknown } | { ok: false; error: string }> {
  try {
    const res = await fetch(`${SCANNER_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
      signal: AbortSignal.timeout(110_000),
    });

    const data = await res.json();

    if (!res.ok) {
      return { ok: false, error: data.detail || data.error || "Scan failed." };
    }
    // pqc_scanner/service.py POST /scan returns { report, raw }.
    return { ok: true, report: data.report as ScanReport, raw: data.raw };
  } catch (err) {
    if (err instanceof Error && err.name === "TimeoutError") {
      return { ok: false, error: `Scan of ${target} timed out.` };
    }
    return {
      ok: false,
      error: `Could not reach the scanner service at ${SCANNER_URL}. Is it running? (${
        err instanceof Error ? err.message : String(err)
      })`,
    };
  }
}

export async function POST(req: NextRequest) {
  let body: { target?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const target = body.target?.trim();
  if (!target) {
    return NextResponse.json({ error: "A target hostname is required." }, { status: 400 });
  }

  try {
    const session = await auth();
    const userId = session?.user?.id ?? null;

    // Guests get GUEST_SCAN_LIMIT scans, enforced by an httpOnly counter
    // cookie (can't be reset the way clearing localStorage would reset their
    // visible scan list). Their scan content never touches the database —
    // it's returned to the client, which stores it in localStorage.
    if (!userId) {
      const used = await getGuestScanCount();
      if (used >= GUEST_SCAN_LIMIT) {
        return NextResponse.json(
          {
            error: `You've used all ${GUEST_SCAN_LIMIT} free scans on this device. Sign in to run more scans and keep permanent history.`,
            code: "SCAN_LIMIT_REACHED",
          },
          { status: 403 },
        );
      }
    }

    const result = await runScan(target);
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: 502 });
    }

    if (userId) {
      // Signed-in users: unlimited, permanent history in Postgres/Neon. raw
      // is stored server-side, so no need to send it back down.
      await saveScanReport(result.report, userId, result.raw);
      return NextResponse.json({ id: result.report.id, report: result.report, persisted: true });
    }

    await incrementGuestScanCount();
    // Guests: nothing is stored server-side, so the client needs raw too —
    // it's what saveGuestScan() puts in localStorage for Export Excel/JSON.
    return NextResponse.json({
      id: result.report.id,
      report: result.report,
      raw: result.raw,
      persisted: false,
    });
  } catch (err) {
    // Anything unexpected here — auth()'s DB session lookup, the guest
    // counter cookie, or the save step — should never surface as Next's
    // HTML error page (which breaks the client's JSON.parse). Always
    // respond with JSON.
    console.error("scan route: unhandled error", err);
    return NextResponse.json(
      {
        error:
          "Something went wrong processing that scan (possibly a temporary database hiccup). Please try again.",
      },
      { status: 500 },
    );
  }
}
