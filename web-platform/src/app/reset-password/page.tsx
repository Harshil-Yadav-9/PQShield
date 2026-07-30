"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function ResetPasswordInner() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token");
  const email = params.get("email");

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  const linkValid = Boolean(token && email);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, token, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not reset password.");
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  if (!linkValid) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-8 py-24">
        <div className="w-full max-w-sm text-center">
          <h1 className="font-display text-[22px] font-bold tracking-tight text-ink-950">
            Invalid link
          </h1>
          <p className="mt-3 text-[13.5px] text-ink-600 leading-relaxed">
            This reset link is missing its token. Request a new one from the sign-in page.
          </p>
          <button
            onClick={() => router.push("/login")}
            className="mt-8 text-[13px] font-medium text-ink-950 hover:underline"
          >
            Back to sign in
          </button>
        </div>
      </div>
    );
  }

  if (done) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-8 py-24">
        <div className="w-full max-w-sm text-center">
          <h1 className="font-display text-[22px] font-bold tracking-tight text-ink-950">
            Password updated
          </h1>
          <p className="mt-3 text-[13.5px] text-ink-600 leading-relaxed">
            You can sign in with your new password now.
          </p>
          <button
            onClick={() => router.push("/login")}
            className="mt-8 text-[13px] font-medium text-white bg-ink-950 rounded-xl px-6 py-2.5 hover:bg-ink-800 transition-colors"
          >
            Sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-8 py-24">
      <div className="w-full max-w-sm">
        <h1 className="font-display text-[26px] font-bold tracking-tight text-ink-950 text-center">
          Set a new password
        </h1>
        <p className="mt-2 text-[13px] text-ink-500 text-center">
          for <span className="font-medium text-ink-950">{email}</span>
        </p>

        <form onSubmit={handleSubmit} className="mt-8 flex flex-col gap-3">
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            type="password"
            required
            minLength={8}
            placeholder="New password"
            className="w-full rounded-xl border border-ink-200 bg-white px-4 py-2.5 text-[13.5px] text-ink-950 placeholder:text-ink-400 focus:outline-none focus:border-ink-400"
          />
          <input
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            type="password"
            required
            minLength={8}
            placeholder="Confirm new password"
            className="w-full rounded-xl border border-ink-200 bg-white px-4 py-2.5 text-[13.5px] text-ink-950 placeholder:text-ink-400 focus:outline-none focus:border-ink-400"
          />

          {error && <p className="text-[12px] text-sev-critical">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="mt-1 w-full rounded-xl bg-ink-950 text-white text-[13.5px] font-medium py-2.5 hover:bg-ink-800 disabled:opacity-60 transition-colors"
          >
            {loading ? "Please wait…" : "Reset password"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={null}>
      <ResetPasswordInner />
    </Suspense>
  );
}
