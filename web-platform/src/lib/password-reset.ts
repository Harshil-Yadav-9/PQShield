import { randomBytes, createHash } from "crypto";
import { prisma } from "@/lib/prisma";
import { sendPasswordResetEmail } from "@/lib/email";

const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour — shorter than the 24h email-verify
// window, since a reset link is more sensitive (it changes a credential,
// not just a status flag) and is normally used within minutes of request.

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// Creates a fresh reset token for `email` and emails the link. Any previous
// unused tokens for this email are cleared first, same reasoning as
// verification.ts: only the most recently requested link should work.
export async function issueResetEmail(email: string, baseUrl: string): Promise<void> {
  await prisma.passwordResetToken.deleteMany({ where: { identifier: email } });

  const rawToken = randomBytes(32).toString("hex");
  await prisma.passwordResetToken.create({
    data: {
      identifier: email,
      token: hashToken(rawToken),
      expires: new Date(Date.now() + TOKEN_TTL_MS),
    },
  });

  const resetUrl = `${baseUrl}/reset-password?token=${rawToken}&email=${encodeURIComponent(email)}`;
  await sendPasswordResetEmail(email, resetUrl);
}

export type ResetResult = "ok" | "invalid" | "expired";

// Consumes the token and sets `newPasswordHash` in one step. Doing both
// together (rather than "verify token" then a separate "set password" call)
// closes the gap where a valid-but-unconsumed token could be replayed to
// set the password more than once.
export async function consumeResetToken(
  email: string,
  rawToken: string,
  newPasswordHash: string,
): Promise<ResetResult> {
  const hashed = hashToken(rawToken);
  const record = await prisma.passwordResetToken.findUnique({
    where: { identifier_token: { identifier: email, token: hashed } },
  });

  if (!record) return "invalid";

  // Always consume on read, regardless of outcome — a reset link should
  // only ever work once.
  await prisma.passwordResetToken.delete({
    where: { identifier_token: { identifier: email, token: hashed } },
  });

  if (record.expires < new Date()) return "expired";

  await prisma.user.update({
    where: { email },
    data: {
      passwordHash: newPasswordHash,
      // A Google-only account that uses this flow to add a password is,
      // by definition, proving control of the inbox for an email Google
      // had already verified — safe to (re)confirm here too, in case this
      // is the first time this account gets a passwordHash.
      emailVerified: new Date(),
    },
  });

  return "ok";
}
