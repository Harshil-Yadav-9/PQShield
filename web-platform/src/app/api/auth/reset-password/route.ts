import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { consumeResetToken } from "@/lib/password-reset";

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  const { email, token, password } = await req.json();

  if (!email || typeof email !== "string" || !token || typeof token !== "string") {
    return NextResponse.json({ error: "Invalid reset link." }, { status: 400 });
  }
  if (!password || typeof password !== "string" || password.length < 8) {
    return NextResponse.json(
      { error: "Password must be at least 8 characters." },
      { status: 400 },
    );
  }

  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await bcrypt.hash(password, 12);
  const result = await consumeResetToken(normalizedEmail, token, passwordHash);

  if (result === "ok") {
    return NextResponse.json({ message: "Password updated. You can sign in now." });
  }
  if (result === "expired") {
    return NextResponse.json(
      { error: "That reset link expired. Request a new one." },
      { status: 400 },
    );
  }
  return NextResponse.json({ error: "That reset link isn't valid." }, { status: 400 });
}
