import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { issueVerificationEmail } from "@/lib/verification";
import { EmailNotConfiguredError } from "@/lib/email";

export const runtime = "nodejs";

// Always returns the same generic response regardless of whether the email
// exists or is already verified — prevents this endpoint from being used to
// enumerate registered accounts.
const GENERIC_OK = NextResponse.json({
  message: "If that account needs verifying, we've sent a new link.",
});

export async function POST(req: NextRequest) {
  const { email } = await req.json();
  if (!email || typeof email !== "string") {
    return NextResponse.json({ error: "Email is required." }, { status: 400 });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (!user || user.emailVerified) {
    return GENERIC_OK;
  }

  try {
    await issueVerificationEmail(normalizedEmail, req.nextUrl.origin);
  } catch (err) {
    const message = err instanceof EmailNotConfiguredError ? err.message : "Could not send the email right now.";
    return NextResponse.json({ error: message }, { status: 502 });
  }

  return GENERIC_OK;
}
