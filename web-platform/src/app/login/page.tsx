"use client";

import { Suspense, useEffect, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";

function VerifyBanner({ onPrefillEmail }: { onPrefillEmail: (email: string) => void }) {
  const params = useSearchParams();
  const verify = params.get("verify");
  const email = params.get("email");

  useEffect(() => {
    if (email) onPrefillEmail(email);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email]);

  if (verify === "success") {
    return (
      <p className="mt-6 rounded-lg bg-sev-acceptable/10 px-4 py-2.5 text-[12.5px] text-sev-acceptable text-center">
        Email verified — you can sign in now.
      </p>
    );
  }
  if (verify === "expired") {
    return (
      <p className="mt-6 rounded-lg bg-sev-medium/10 px-4 py-2.5 text-[12.5px] text-sev-medium text-center">
        That verification link expired. Enter your email below and request a new one.
      </p>
    );
  }
  if (verify === "invalid") {
    return (
      <p className="mt-6 rounded-lg bg-sev-high/10 px-4 py-2.5 text-[12.5px] text-sev-high text-center">
        That verification link isn&apos;t valid. Request a new one below.
      </p>
    );
  }
  return null;
}

function LoginPageInner() {
  const router = useRouter();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [needsVerification, setNeedsVerification] = useState(false);
  const [loading, setLoading] = useState(false);
  const [resendState, setResendState] = useState<"idle" | "sending" | "sent">("idle");
  const [signupSent, setSignupSent] = useState(false);

  async function handleResend() {
    setResendState("sending");
    try {
      await fetch("/api/auth/resend-verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
    } finally {
      setResendState("sent");
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNeedsVerification(false);
    setLoading(true);

    try {
      if (mode === "signup") {
        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, name }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Could not create account.");

        // Real verification email was just sent — don't sign in until the
        // person actually clicks the link in their inbox.
        setSignupSent(true);
        setLoading(false);
        return;
      }

      const result = await signIn("credentials", { email, password, redirect: false });
      if (result?.error) {
        if (result.code === "email_not_verified") {
          setNeedsVerification(true);
          throw new Error("Verify your email before signing in.");
        }
        throw new Error("Invalid email or password.");
      }

      router.push("/");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  if (signupSent) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-8 py-24">
        <div className="w-full max-w-sm text-center">
          <h1 className="font-display text-[22px] font-bold tracking-tight text-ink-950">
            Check your email
          </h1>
          <p className="mt-3 text-[13.5px] text-ink-600 leading-relaxed">
            We sent a verification link to <span className="font-medium text-ink-950">{email}</span>.
            Click it to activate your account, then come back and sign in.
          </p>
          <button
            onClick={() => {
              setSignupSent(false);
              setMode("signin");
            }}
            className="mt-8 text-[13px] font-medium text-ink-950 hover:underline"
          >
            Back to sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-8 py-24">
      <div className="w-full max-w-sm">
        <h1 className="font-display text-[26px] font-bold tracking-tight text-ink-950 text-center">
          {mode === "signin" ? "Sign in" : "Create an account"}
        </h1>
        <p className="mt-2 text-[13px] text-ink-500 text-center">
          {mode === "signin" ? "Save and revisit your scan history." : "Takes a minute — no card required."}
        </p>

        <Suspense fallback={null}>
          <VerifyBanner onPrefillEmail={setEmail} />
        </Suspense>

        <button
          onClick={() => signIn("google", { callbackUrl: "/" })}
          className="mt-8 w-full rounded-xl border border-ink-200 bg-white py-2.5 text-[13.5px] font-medium text-ink-950 hover:bg-ink-50 transition-colors"
        >
          Continue with Google
        </button>

        <div className="mt-6 flex items-center gap-3">
          <div className="h-px flex-1 bg-ink-200" />
          <span className="text-[11px] text-ink-400">or</span>
          <div className="h-px flex-1 bg-ink-200" />
        </div>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-3">
          {mode === "signup" && (
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Name (optional)"
              className="w-full rounded-xl border border-ink-200 bg-white px-4 py-2.5 text-[13.5px] text-ink-950 placeholder:text-ink-400 focus:outline-none focus:border-ink-400"
            />
          )}
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            type="email"
            required
            placeholder="Email"
            className="w-full rounded-xl border border-ink-200 bg-white px-4 py-2.5 text-[13.5px] text-ink-950 placeholder:text-ink-400 focus:outline-none focus:border-ink-400"
          />
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            type="password"
            required
            minLength={8}
            placeholder="Password"
            className="w-full rounded-xl border border-ink-200 bg-white px-4 py-2.5 text-[13.5px] text-ink-950 placeholder:text-ink-400 focus:outline-none focus:border-ink-400"
          />

          {error && <p className="text-[12px] text-sev-critical">{error}</p>}

          {needsVerification && (
            <div className="rounded-lg bg-sev-medium/10 px-3.5 py-2.5">
              <p className="text-[12px] text-ink-700">Your email isn&apos;t verified yet.</p>
              <button
                type="button"
                onClick={handleResend}
                disabled={resendState !== "idle"}
                className="mt-1 text-[12px] font-medium text-ink-950 hover:underline disabled:opacity-60"
              >
                {resendState === "idle" && "Resend verification email"}
                {resendState === "sending" && "Sending…"}
                {resendState === "sent" && "Sent — check your inbox"}
              </button>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="mt-1 w-full rounded-xl bg-ink-950 text-white text-[13.5px] font-medium py-2.5 hover:bg-ink-800 disabled:opacity-60 transition-colors"
          >
            {loading ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>

        <p className="mt-6 text-[12.5px] text-ink-500 text-center">
          {mode === "signin" ? "Don't have an account? " : "Already have an account? "}
          <button
            onClick={() => {
              setError(null);
              setNeedsVerification(false);
              setMode(mode === "signin" ? "signup" : "signin");
            }}
            className="text-ink-950 font-medium hover:underline"
          >
            {mode === "signin" ? "Sign up" : "Sign in"}
          </button>
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginPageInner />
    </Suspense>
  );
}
