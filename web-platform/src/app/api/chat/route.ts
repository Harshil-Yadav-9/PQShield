import { NextRequest, NextResponse } from "next/server";
import { askGemini, ChatMessage, GeminiNotConfiguredError } from "@/lib/gemini";
import { ScanReport } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 30;

export async function POST(req: NextRequest) {
  let body: { report?: ScanReport; messages?: ChatMessage[] };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  if (!body.report || !Array.isArray(body.messages) || body.messages.length === 0) {
    return NextResponse.json({ error: "report and messages are required." }, { status: 400 });
  }

  try {
    const reply = await askGemini(body.report, body.messages);
    return NextResponse.json({ reply });
  } catch (err) {
    const status = err instanceof GeminiNotConfiguredError ? 501 : 502;
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Could not reach Gemini." },
      { status },
    );
  }
}
