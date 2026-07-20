import { getReportById, mockReports } from "@/lib/mock-data";
import { loadScanReport } from "@/lib/scan-store";
import ReportView from "@/components/ReportView";
import GuestReportLoader from "@/components/GuestReportLoader";

export default async function ReportPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ target?: string }>;
}) {
  const { id } = await params;
  const { target } = await searchParams;

  // Three possible sources, checked in order: the bundled demo report,
  // a signed-in user's scan (persisted server-side in Postgres/Neon), or —
  // if neither matches — a guest's scan, which only ever exists in that
  // browser's localStorage and has to be loaded client-side.
  const isDemoId = mockReports.some((r) => r.id === id);
  if (isDemoId) {
    return <ReportView report={getReportById(id)} hostnameOverride={target} />;
  }

  const dbReport = await loadScanReport(id);
  if (dbReport) {
    return <ReportView report={dbReport} hostnameOverride={target} />;
  }

  return <GuestReportLoader id={id} hostnameOverride={target} />;
}
