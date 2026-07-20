import NextAuth, { CredentialsSignin } from "next-auth";
import Google from "next-auth/providers/google";
import Credentials from "next-auth/providers/credentials";
import { PrismaAdapter } from "@auth/prisma-adapter";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";

const googleConfigured = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

// `npx auth secret` (Auth.js v5) writes AUTH_SECRET; older docs/tutorials
// (and this repo's own .env.example) say NEXTAUTH_SECRET — both are read
// here. Using `||` rather than `??` matters: a *present but empty* string
// (e.g. `NEXTAUTH_SECRET=""`, exactly what .env.example ships and what an
// unedited .env still has) is not `null`/`undefined`, so `??` would treat
// it as "already set" and hand NextAuth an empty secret — which fails in
// exactly the same generic "server configuration" way as no secret at all.
const authSecret = process.env.AUTH_SECRET || process.env.NEXTAUTH_SECRET || undefined;

if (!authSecret && process.env.NODE_ENV === "production") {
  // Fail loudly at boot in production rather than silently 500-ing on every
  // session check.
  throw new Error(
    "AUTH_SECRET (or NEXTAUTH_SECRET) is not set. Generate one with `npx auth secret` and add it to your environment.",
  );
}

class EmailNotVerifiedError extends CredentialsSignin {
  code = "email_not_verified";
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  secret: authSecret,
  // Auth.js v5 validates the incoming request's Host header against a
  // trusted list and throws a generic "server configuration" error for any
  // host it doesn't recognize. Vercel deployments are trusted automatically;
  // localhost and every other self-hosted target (Docker, a VPS, etc.) are
  // not, unless this is set explicitly. This is the fix for that exact
  // error showing up identically on `npm run dev` and in production.
  trustHost: true,
  // @auth/prisma-adapter's .d.ts still types its param against the old
  // `@prisma/client` default export location, which doesn't exist once you
  // use Prisma 7's required custom `output` path. This is a types-only
  // mismatch (see authjs.dev's own Prisma 7 setup docs) — the generated
  // client implements the same delegate shape at runtime.
  adapter: PrismaAdapter(prisma as unknown as Parameters<typeof PrismaAdapter>[0]),
  // Credentials + OAuth mixed together requires JWT sessions (the Prisma
  // adapter's database-session strategy doesn't support Credentials).
  session: { strategy: "jwt" },
  providers: [
    // Registering Google with empty clientId/clientSecret makes every
    // auth() call (including the session check the whole app makes on
    // every page load) throw a "server configuration" error — that's the
    // ClientFetchError / cascading "Maximum update depth exceeded" loop.
    // Only add it once real credentials are in .env.
    ...(googleConfigured
      ? [
          Google({
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          }),
        ]
      : []),
    Credentials({
      name: "Email and password",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        const email = credentials?.email as string | undefined;
        const password = credentials?.password as string | undefined;
        if (!email || !password) return null;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user?.passwordHash) return null; // no password set (e.g. Google-only account)

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return null;

        // The email on this account was never confirmed to actually belong
        // to whoever registered it — block sign-in until they click the
        // link Resend sent them (see src/lib/verification.ts).
        if (!user.emailVerified) throw new EmailNotVerifiedError();

        return { id: user.id, email: user.email, name: user.name, image: user.image };
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account }) {
      // Google already verified this email on their end — trust it and
      // mark it verified in our own records too, so a Google-only account
      // is never blocked by the emailVerified check above.
      if (account?.provider === "google" && user.id) {
        try {
          await prisma.user.update({
            where: { id: user.id },
            data: { emailVerified: new Date() },
          });
        } catch (err) {
          console.error("signIn callback: failed to mark emailVerified", err);
          // don't block login just because this update failed
        }
      }
      return true;
    },
    async jwt({ token, user }) {
      if (user) token.sub = user.id;
      return token;
    },
    async session({ session, token }) {
      if (session.user && token.sub) session.user.id = token.sub;
      return session;
    },
  },
  pages: {
    signIn: "/login",
  },
});
