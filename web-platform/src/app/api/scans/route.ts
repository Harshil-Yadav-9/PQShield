import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { listScansForOwner, migrateGuestScan } from "@/lib/scan-store";
import { ScanReport } from "@/lib/types";

export async function GET() {
  const session = await auth();
  const userId = session?.user?.id;

  if (!userId) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }

  try {
    const scans = await listScansForOwner({ userId });
    return NextResponse.json({ scans });
  } catch (err) {
    console.error("GET /api/scans: failed to list scans", err);
    return NextResponse.json({ error: "Could not load scans." }, { status: 500 });
  }
}

interface MigrateBody {
  scans?: { report: ScanReport; raw?: unknown }[];
}

// Called once, right after a guest signs in, with whatever scans were
// sitting in their browser's localStorage — folds them into their new
// permanent account history.
export async function POST(req: NextRequest) {
  const session = await auth();
  const userId = session?.user?.id;

  if (!userId) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }

  let body: MigrateBody;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const scans = Array.isArray(body.scans) ? body.scans : [];
  if (scans.length === 0) {
    return NextResponse.json({ migrated: 0 });
  }

  try {
    let migrated = 0;
    for (const entry of scans) {
      if (!entry?.report?.id) continue;
      await migrateGuestScan(entry.report, userId, entry.raw);
      migrated += 1;
    }
    return NextResponse.json({ migrated });
  } catch (err) {
    console.error("POST /api/scans: failed to migrate guest scans", err);
    return NextResponse.json({ error: "Could not save your previous scans." }, { status: 500 });
  }
}
