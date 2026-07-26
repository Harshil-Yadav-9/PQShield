import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { deleteScanReport } from "@/lib/scan-store";

export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth();
  const userId = session?.user?.id;

  if (!userId) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "Missing scan id." }, { status: 400 });
  }

  const deleted = await deleteScanReport(id, userId);

  if (!deleted) {
    // Either the scan doesn't exist, or it belongs to someone else — same
    // response either way so we don't leak which.
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

  return NextResponse.json({ deleted: true });
}
