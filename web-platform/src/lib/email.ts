import nodemailer, { Transporter } from "nodemailer";

// Real transactional email — this is what makes signup "verify by actually
// sending mail" rather than just trusting whatever string was typed into
// the email field.
//
// Sent through your own Gmail account over SMTP, not a third-party email
// API — there's no vendor, no plan, no free-tier-that-might-go-away later.
// It's exactly what any email client does when you hit send, just done
// programmatically. Setup (see .env.example / README "Email verification"):
//   1. Turn on 2-Step Verification on the Gmail account you want to send from.
//   2. Google Account → Security → App passwords → generate one for "Mail".
//   3. GMAIL_USER = that Gmail address, GMAIL_APP_PASSWORD = the 16-char app password.
// A regular Gmail account can send ~500 emails/day this way, which is far
// more than a student project's signup volume.
const gmailUser = process.env.GMAIL_USER;
const gmailAppPassword = process.env.GMAIL_APP_PASSWORD;
const emailFrom = process.env.EMAIL_FROM || gmailUser;

let transporter: Transporter | null = null;
if (gmailUser && gmailAppPassword) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: gmailUser, pass: gmailAppPassword },
  });
}

export class EmailNotConfiguredError extends Error {
  constructor() {
    super(
      "GMAIL_USER / GMAIL_APP_PASSWORD are not set, so PQShield cannot send verification emails. See .env.example / the README's \"Email verification\" section for the 2-minute Gmail App Password setup.",
    );
    this.name = "EmailNotConfiguredError";
  }
}

export async function sendVerificationEmail(email: string, verifyUrl: string): Promise<void> {
  if (!transporter) throw new EmailNotConfiguredError();

  await transporter.sendMail({
    from: `PQShield <${emailFrom}>`,
    to: email,
    subject: "Verify your PQShield account",
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
        <h1 style="font-size: 20px; color: #0a0a0a;">Verify your email</h1>
        <p style="font-size: 14px; color: #404040; line-height: 1.6;">
          Confirm this is your email address to finish setting up your PQShield account.
          This link expires in 24 hours.
        </p>
        <a href="${verifyUrl}"
           style="display: inline-block; margin-top: 12px; padding: 10px 20px; background: #0a0a0a; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 14px; font-weight: 500;">
          Verify email
        </a>
        <p style="font-size: 12px; color: #a3a3a3; margin-top: 24px;">
          If you didn't create a PQShield account, you can safely ignore this email.
        </p>
      </div>
    `,
    text: `Verify your PQShield account: ${verifyUrl}\n\nThis link expires in 24 hours. If you didn't create a PQShield account, you can ignore this email.`,
  });
}
