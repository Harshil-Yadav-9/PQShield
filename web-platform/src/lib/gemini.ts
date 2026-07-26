import { ScanReport, Severity } from "@/lib/types";

// Google AI Studio's free tier (no credit card): aistudio.google.com/apikey.
// Flash / Flash-Lite models are the ones with a free tier — Pro models are
// paid-only. As of mid-2026, Google restricted new API keys from using
// older models like gemini-2.5-flash/gemini-2.5-pro ("no longer available
// to new users") — gemini-3.1-flash-lite is the current generously-free
// default; swap to "gemini-3.5-flash" via GEMINI_MODEL below for noticeably
// better answer quality at the cost of a lower free-tier rate limit.
// Overridable via GEMINI_MODEL so a future model swap never needs a code
// change — check https://ai.google.dev/gemini-api/docs/models if this one
// also gets retired.
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.1-flash-lite";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

export class GeminiNotConfiguredError extends Error {
  constructor() {
    super(
      "GEMINI_API_KEY is not set. Get a free key (no credit card) at https://aistudio.google.com/apikey and add it to your environment.",
    );
    this.name = "GeminiNotConfiguredError";
  }
}

export type ChatMessage = { role: "user" | "assistant"; text: string };

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Acceptable: 4,
};

// Compact, plain-text summary of the report — not the raw JSON. Keeps the
// prompt small (fast, cheap, well within free-tier per-request limits) while
// still grounding every answer in this specific scan's real findings rather
// than generic TLS advice.
function buildReportContext(report: ScanReport): string {
  const { target, postureScore, riskBand, pqcReadiness, sections } = report;

  const allFindings = sections.flatMap((s) =>
    s.findings.map((f) => ({ ...f, section: s.name })),
  );
  const notableFindings = allFindings
    .filter((f) => f.severity === "Critical" || f.severity === "High" || f.severity === "Medium")
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

  const sectionLines = sections
    .map((s) => `- ${s.name}: score ${s.normalized}/100 (weight ${s.weight}%) — ${s.summary}`)
    .join("\n");

  const findingLines = notableFindings
    .map(
      (f) =>
        `- [${f.severity}] ${f.section} / ${f.parameter}: observed "${f.observed}", standard "${f.standard}", ${f.contribution > 0 ? "+" : ""}${f.contribution.toFixed(1)}% to score. Fix: ${f.recommendation}`,
    )
    .join("\n");

  const acceptableCount = allFindings.length - notableFindings.length;

  return `You are the PQShield assistant, embedded in a TLS/post-quantum-cryptography security scan report. Answer questions ONLY using the scan data below — don't invent findings that aren't listed. Be concise and specific (cite the actual parameter names, observed values, and score contributions from the data). If asked something the data doesn't cover, say so plainly instead of guessing.

SCAN SUMMARY
Target: ${target.hostname} (${target.ip}:${target.port})
Posture score: ${postureScore}/100 (${riskBand})
PQC readiness: ${pqcReadiness}/100
Scanned: ${target.scanStart}

SECTION SCORES
${sectionLines}

FINDINGS NEEDING ATTENTION (Critical/High/Medium, sorted by severity)
${findingLines || "None — every checked parameter came back Low or Acceptable."}

(${acceptableCount} additional Low/Acceptable findings not listed individually — those are fine as-is.)

Format with markdown where it helps readability — **bold** for key terms/values, bullet lists when covering multiple findings, backticks for header/parameter names. Keep replies focused and practical (a short paragraph or a few bullet points is usually enough; give a fuller breakdown only when asked), grounded in the data above.`;
}

export async function askGemini(report: ScanReport, history: ChatMessage[]): Promise<string> {
  if (!GEMINI_API_KEY) throw new GeminiNotConfiguredError();

  // Bound the conversation sent each time — keeps latency/cost predictable
  // even in a very long back-and-forth.
  const recentHistory = history.slice(-16);

  const contents = recentHistory.map((m) => ({
    role: m.role === "assistant" ? "model" : "user",
    parts: [{ text: m.text }],
  }));

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: buildReportContext(report) }] },
        contents,
        generationConfig: { temperature: 0.4, maxOutputTokens: 1536 },
      }),
      signal: AbortSignal.timeout(25_000),
    },
  );

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    const message = data?.error?.message || `Gemini API returned ${res.status}.`;
    if (res.status === 429) {
      throw new Error("Gemini's free-tier rate limit was hit — wait a few seconds and try again.");
    }
    throw new Error(message);
  }

  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.map((p: { text?: string }) => p.text ?? "").join("");

  if (!text) {
    const blockReason = data?.promptFeedback?.blockReason;
    if (blockReason) throw new Error(`Gemini declined to answer (${blockReason}).`);
    throw new Error("Gemini returned an empty response.");
  }

  return text.trim();
}
