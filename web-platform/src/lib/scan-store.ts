import { prisma } from "@/lib/prisma";
import { ScanReport } from "@/lib/types";

// Only signed-in users' scans are stored here — this is what "My scans" and
// production Postgres/Neon persistence cover. Guests' scans live entirely
// in their browser's localStorage (see src/lib/guest-scans.ts) and are
// never written to this table.

export async function saveScanReport(report: ScanReport, userId: string, raw?: unknown): Promise<void> {
  await prisma.scan.create({
    data: {
      id: report.id,
      hostname: report.target.hostname,
      report: report as unknown as object,
      raw: (raw ?? undefined) as object | undefined,
      userId,
    },
  });
}

export async function loadScanReport(id: string): Promise<ScanReport | null> {
  const row = await prisma.scan.findUnique({ where: { id } });
  if (!row) return null;
  return row.report as unknown as ScanReport;
}

// The raw CBOM scan JSON (same shape as cbom_results.json) — source data for
// the Export Excel / Export JSON buttons, so exporting never re-scans the
// target. Null for scans saved before this field existed.
export async function loadScanRaw(id: string): Promise<unknown | null> {
  const row = await prisma.scan.findUnique({ where: { id }, select: { raw: true } });
  return row?.raw ?? null;
}

// Deletes a scan only if it belongs to the given user — returns true if a
// row was actually deleted, false if it didn't exist or belonged to someone
// else (so callers can return 404 rather than leaking whether an id exists).
export async function deleteScanReport(id: string, userId: string): Promise<boolean> {
  const result = await prisma.scan.deleteMany({
    where: { id, userId },
  });
  return result.count > 0;
}

export interface ScanListItem {
  id: string;
  hostname: string;
  createdAt: Date;
  postureScore: number;
  riskBand: string;
}

export async function listScansForOwner(owner: { userId: string }): Promise<ScanListItem[]> {
  const rows = await prisma.scan.findMany({
    where: { userId: owner.userId },
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return rows.map((r: { id: string; hostname: string; createdAt: Date; report: unknown }) => {
    const report = r.report as unknown as ScanReport;
    return {
      id: r.id,
      hostname: r.hostname,
      createdAt: r.createdAt,
      postureScore: report.postureScore,
      riskBand: report.riskBand,
    };
  });
}
