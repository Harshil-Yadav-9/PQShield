import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { issueResetEmail } from "@/lib/password-reset";
import { EmailNotConfiguredError } from "@/lib/email";

export const runtime = "nodejs";

// Always the same generic response, whether the email exists or not — same
// reasoning as resend-verification/route.ts: prevents this endpoint from
// being used to check which emails have an account.
const GENERIC_OK = NextResponse.json({
  message: "If that email has an account, we've sent a link to reset the password.",
});

export async function POST(req: NextRequest) {
  const { email } = await req.json();
  if (!email || typeof email !== "string") {
    return NextResponse.json({ error: "Email is required." }, { status: 400 });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  // No account at all -> nothing to do, but still return the generic
  // response so this endpoint can't be used to enumerate accounts.
  if (!user) return GENERIC_OK;

  try {
    await issueResetEmail(normalizedEmail, req.nextUrl.origin);
  } catch (err) {
    // Only surface an error for the one case the user can actually act on
    // (email sending isn't configured on this deployment). Anything else
    // still returns the generic response to avoid leaking account state.
    if (err instanceof EmailNotConfiguredError) {
      return NextResponse.json({ error: err.message }, { status: 502 });
    }
    console.error("forgot-password: failed to send reset email", err);
  }

  return GENERIC_OK;
}
