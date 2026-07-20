import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { issueVerificationEmail } from "@/lib/verification";
import { EmailNotConfiguredError } from "@/lib/email";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  const { email, password, name } = await req.json();

  if (!email || typeof email !== "string" || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "Enter a valid email address." }, { status: 400 });
  }
  if (!password || typeof password !== "string" || password.length < 8) {
    return NextResponse.json(
      { error: "Password must be at least 8 characters." },
      { status: 400 },
    );
  }

  const normalizedEmail = email.trim().toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (existing?.emailVerified) {
    return NextResponse.json(
      { error: "An account with that email already exists. Try signing in instead." },
      { status: 409 },
    );
  }

  const passwordHash = await bcrypt.hash(password, 12);

  // If they started registering before but never clicked the verification
  // link, treat this as "try again" — update the password (they may have
  // mistyped it the first time) and send a fresh link, rather than telling
  // them the email is taken and leaving them stuck.
  const user = existing
    ? await prisma.user.update({
        where: { email: normalizedEmail },
        data: { passwordHash, name: name || existing.name },
      })
    : await prisma.user.create({
        data: { email: normalizedEmail, passwordHash, name: name || null },
      });

  try {
    await issueVerificationEmail(normalizedEmail, req.nextUrl.origin);
  } catch (err) {
    const message =
      err instanceof EmailNotConfiguredError
        ? err.message
        : `We created your account but couldn't send the verification email (${
            err instanceof Error ? err.message : String(err)
          }). Please try again in a moment.`;
    return NextResponse.json({ error: message }, { status: 502 });
  }

  return NextResponse.json({
    id: user.id,
    email: user.email,
    message: "Check your email for a verification link to finish setting up your account.",
  });
}
