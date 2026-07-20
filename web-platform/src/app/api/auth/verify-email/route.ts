import { NextRequest, NextResponse } from "next/server";
import { consumeVerificationToken } from "@/lib/verification";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get("token");
  const email = req.nextUrl.searchParams.get("email");

  if (!token || !email) {
    return NextResponse.redirect(new URL("/login?verify=invalid", req.url));
  }

  const result = await consumeVerificationToken(email, token);

  if (result === "ok") {
    return NextResponse.redirect(new URL("/login?verify=success", req.url));
  }
  if (result === "expired") {
    return NextResponse.redirect(new URL(`/login?verify=expired&email=${encodeURIComponent(email)}`, req.url));
  }
  return NextResponse.redirect(new URL("/login?verify=invalid", req.url));
}
