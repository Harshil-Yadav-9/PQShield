import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import path from "path";
import { loadScanRaw, loadScanReport } from "@/lib/scan-store";
import { DEMO_REPORT_ID } from "@/lib/mock-data";

export const runtime = "nodejs";
export const maxDuration = 60;

const SCANNER_URL = process.env.SCANNER_URL ?? "http://127.0.0.1:8000";

function slug(hostname: string): string {
  return hostname.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
}

async function buildResponse(
  format: "json" | "excel",
  raw: unknown,
  filenameBase: string,
): Promise<NextResponse> {
  if (format === "json") {
    return new NextResponse(JSON.stringify(raw, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="cbom_${filenameBase}.json"`,
      },
    });
  }

  // format === "excel" — ask the scanner service to rebuild the xlsx from
  // raw CBOM data we already have. No re-scan of the target happens.
  try {
    const res = await fetch(`${SCANNER_URL}/export/excel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw, filename: `TLS_PQC_Risk_Report_${filenameBase}.xlsx` }),
      signal: AbortSignal.timeout(50_000),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      return NextResponse.json(
        { error: data.detail || "Could not generate the Excel report." },
        { status: 502 },
      );
    }

    const buf = await res.arrayBuffer();
    return new NextResponse(buf, {
      status: 200,
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": `attachment; filename="TLS_PQC_Risk_Report_${filenameBase}.xlsx"`,
      },
    });
  } catch (err) {
    return NextResponse.json(
      {
        error: `Could not reach the scanner service to build the Excel report. Is it running? (${
          err instanceof Error ? err.message : String(err)
        })`,
      },
      { status: 502 },
    );
  }
}

// Demo report and signed-in users' scans: both have a server-side record to
// look up (a bundled file, or a Postgres row), so a plain GET works.
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const format = req.nextUrl.searchParams.get("format");

  if (format !== "json" && format !== "excel") {
    return NextResponse.json({ error: "format must be 'json' or 'excel'." }, { status: 400 });
  }

  // The bundled demo report ships its own synthetic scan output — serve
  // those files directly, byte-for-byte, rather than regenerating them.
  if (id === DEMO_REPORT_ID) {
    const filename = format === "json" ? "cbom_demo.json" : "audit_demo.xlsx";
    const filePath = path.join(process.cwd(), "public", "demo", filename);
    const data = await readFile(filePath);
    const contentType =
      format === "json"
        ? "application/json"
        : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    return new NextResponse(new Uint8Array(data), {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  }

  const raw = await loadScanRaw(id);
  if (!raw) {
    return NextResponse.json(
      { error: "No raw scan data found for this report. Re-run the scan to enable export." },
      { status: 404 },
    );
  }

  const report = await loadScanReport(id);
  const filenameBase = report ? slug(report.target.hostname) : id;
  return buildResponse(format, raw, filenameBase);
}

// Guest scans have no server-side record at all (they live only in the
// browser's localStorage) — the client sends the raw CBOM data it already
// has, and this just turns it into a file. No DB lookup, no re-scan.
export async function POST(req: NextRequest) {
  const format = req.nextUrl.searchParams.get("format");
  if (format !== "json" && format !== "excel") {
    return NextResponse.json({ error: "format must be 'json' or 'excel'." }, { status: 400 });
  }

  let body: { raw?: unknown; hostname?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  if (!body.raw) {
    return NextResponse.json({ error: "raw scan data is required." }, { status: 400 });
  }

  const filenameBase = body.hostname ? slug(body.hostname) : "scan";
  return buildResponse(format, body.raw, filenameBase);
}
