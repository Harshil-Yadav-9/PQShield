"use client";

import { useState, useRef, useEffect } from "react";
import { ScanReport } from "@/lib/types";
import { topRisks } from "@/lib/utils";

type Message = { role: "user" | "assistant"; text: string };

function craftReply(question: string, report: ScanReport): string {
  const q = question.toLowerCase();
  const risks = topRisks(report.sections, 3);

  if (q.includes("pqc") || q.includes("quantum")) {
    return `${report.target.hostname} isn't negotiating any post-quantum groups yet (PQC readiness ${report.pqcReadiness}%). The fastest path: enable a hybrid ML-KEM group (e.g. X25519MLKEM768) alongside your existing ECDHE groups so classical clients keep working while PQC-capable clients upgrade automatically, then plan certificate migration to ML-DSA once your CA supports it.`;
  }
  if (q.includes("tls 1.0") || q.includes("tls 1.1") || q.includes("legacy")) {
    return `Disabling TLS 1.0 and TLS 1.1 is the single highest-impact fix here — together they account for roughly 9.4% of the negative score contribution in the Protocol section. Most modern clients (2020+) don't need them; check your access logs for the last 30 days before disabling to confirm no legacy dependents.`;
  }
  if (q.includes("priorit") || q.includes("first") || q.includes("start")) {
    const list = risks.map((r) => `${r.parameter} (${r.section})`).join(", ");
    return `Based on contribution to the posture score, fix in this order: ${list}. These give the largest score recovery per unit of engineering effort.`;
  }
  return `Here's what I'd look at for ${report.target.hostname}: the posture score is ${report.postureScore}/100 (${report.riskBand}), driven mostly by legacy protocol support and missing PQC key exchange. Ask me about a specific section — protocol, certificate, cipher suites, or PQC — and I'll walk through the fix.`;
}

export default function ChatPanel({ report }: { report: ScanReport }) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      text: `I've read the audit report for ${report.target.hostname}. Ask me how to raise the posture score, or which finding to fix first.`,
    },
  ]);
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function send() {
    const text = input.trim();
    if (!text) return;
    const reply = craftReply(text, report);
    setMessages((m) => [...m, { role: "user", text }, { role: "assistant", text: reply }]);
    setInput("");
  }

  return (
    <div className="flex flex-col h-[600px] max-w-2xl mx-auto w-full">
      <div className="flex-1 overflow-y-auto px-2 py-6 space-y-6">
        {messages.map((m, i) =>
          m.role === "assistant" ? (
            <div key={i} className="flex gap-3">
              <span className="mt-1 h-6 w-6 shrink-0 rounded-full bg-ink-950 flex items-center justify-center">
                <span className="h-1.5 w-1.5 rounded-full bg-white" />
              </span>
              <p className="text-[14px] leading-relaxed text-ink-800 pt-0.5">{m.text}</p>
            </div>
          ) : (
            <div key={i} className="flex justify-end">
              <div className="max-w-[80%] rounded-2xl bg-ink-50 px-4 py-2.5 text-[14px] leading-relaxed text-ink-900">
                {m.text}
              </div>
            </div>
          )
        )}
        <div ref={bottomRef} />
      </div>

      <div className="border border-ink-200 rounded-2xl p-2 flex items-end gap-2 shadow-sm bg-white">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
          rows={1}
          placeholder="Ask about a finding, e.g. 'how do I fix PQC readiness?'"
          className="flex-1 resize-none bg-transparent px-3 py-2 text-[14px] text-ink-900 placeholder:text-ink-400 focus:outline-none"
        />
        <button
          onClick={send}
          className="rounded-xl bg-ink-950 text-white px-4 py-2.5 text-[13px] font-medium hover:bg-ink-800 transition-colors"
        >
          Send
        </button>
      </div>
      <p className="text-center text-[11px] text-ink-400 mt-3">
        Placeholder assistant · will connect to a real LLM once the mitigation API ships
      </p>
    </div>
  );
}
