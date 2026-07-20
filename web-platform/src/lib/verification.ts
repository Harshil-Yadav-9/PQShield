import { randomBytes, createHash } from "crypto";
import { prisma } from "@/lib/prisma";
import { sendVerificationEmail } from "@/lib/email";

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// Creates a fresh verification token for `email` and emails the link. Any
// previous unused tokens for this email are cleared first so only the most
// recently sent link works — old, leaked, or forwarded links stop being
// valid the moment a new one is requested.
export async function issueVerificationEmail(email: string, baseUrl: string): Promise<void> {
  await prisma.verificationToken.deleteMany({ where: { identifier: email } });

  const rawToken = randomBytes(32).toString("hex");
  await prisma.verificationToken.create({
    data: {
      identifier: email,
      token: hashToken(rawToken),
      expires: new Date(Date.now() + TOKEN_TTL_MS),
    },
  });

  const verifyUrl = `${baseUrl}/api/auth/verify-email?token=${rawToken}&email=${encodeURIComponent(email)}`;
  await sendVerificationEmail(email, verifyUrl);
}

export type VerifyResult = "ok" | "invalid" | "expired";

export async function consumeVerificationToken(email: string, rawToken: string): Promise<VerifyResult> {
  const hashed = hashToken(rawToken);
  const record = await prisma.verificationToken.findUnique({
    where: { identifier_token: { identifier: email, token: hashed } },
  });

  if (!record) return "invalid";

  // Always consume on read — a verification link should only work once.
  await prisma.verificationToken.delete({
    where: { identifier_token: { identifier: email, token: hashed } },
  });

  if (record.expires < new Date()) return "expired";

  await prisma.user.update({
    where: { email },
    data: { emailVerified: new Date() },
  });

  return "ok";
}
