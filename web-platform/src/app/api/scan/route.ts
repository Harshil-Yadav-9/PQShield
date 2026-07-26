import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { saveScanReport } from "@/lib/scan-store";
import { ScanReport } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 120;

const SCANNER_URL = process.env.SCANNER_URL ?? "http://127.0.0.1:8000";

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
    const res = await fetch(`${SCANNER_URL}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
      signal: AbortSignal.timeout(115_000),
    });

    const text = await res.text();
    if (!res.ok) {
      let detail = text;
      try {
        const parsed = text ? JSON.parse(text) : {};
        detail = parsed.detail || parsed.error || detail;
      } catch {
        // Keep the raw text if the scanner returns a non-JSON error page.
      }

      return NextResponse.json(
        { error: detail || "Scan failed.", code: res.status === 429 ? "SCAN_LIMIT_REACHED" : undefined },
        { status: res.status >= 400 && res.status < 600 ? res.status : 502 },
      );
    }

    let data: { report?: unknown; raw?: unknown; id?: string } = {};
    if (text) {
      try {
        data = JSON.parse(text) as typeof data;
      } catch {
        return NextResponse.json({ error: "Scanner returned invalid JSON." }, { status: 502 });
      }
    }

    const report = data.report as ScanReport | undefined;
    const session = await auth();
    const userId = session?.user?.id;

    if (report && userId) {
      await saveScanReport(report, userId, data.raw);
      return NextResponse.json({
        id: report.id,
        report,
        raw: data.raw,
        persisted: true,
      });
    }

    return NextResponse.json({
      id: data.id || report?.id,
      report,
      raw: data.raw,
      persisted: false,
    });
  } catch (err) {
    return NextResponse.json(
      {
        error: `Could not reach the scanner service. Is it running? (${
          err instanceof Error ? err.message : String(err)
        })`,
      },
      { status: 502 },
    );
  }
}
