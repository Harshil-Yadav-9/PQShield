"use client";

import { useState, useRef, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import { ScanReport } from "@/lib/types";

type Message = { role: "user" | "assistant"; text: string };

// Custom renderers so Gemini's markdown (bold, bullets, code, links) comes
// out styled to match the rest of the app instead of either raw asterisks
// or default browser/Tailwind-reset styling.
const markdownComponents = {
  p: (props: React.ComponentProps<"p">) => (
    <p className="text-[14px] leading-relaxed text-ink-800 [&:not(:first-child)]:mt-3" {...props} />
  ),
  strong: (props: React.ComponentProps<"strong">) => (
    <strong className="font-semibold text-ink-950" {...props} />
  ),
  em: (props: React.ComponentProps<"em">) => <em className="text-ink-700" {...props} />,
  ul: (props: React.ComponentProps<"ul">) => (
    <ul className="mt-2 space-y-1.5 list-disc pl-5 text-[14px] text-ink-800" {...props} />
  ),
  ol: (props: React.ComponentProps<"ol">) => (
    <ol className="mt-2 space-y-1.5 list-decimal pl-5 text-[14px] text-ink-800" {...props} />
  ),
  li: (props: React.ComponentProps<"li">) => <li className="leading-relaxed" {...props} />,
  code: (props: React.ComponentProps<"code">) => (
    <code className="data-mono rounded bg-ink-100 px-1.5 py-0.5 text-[12.5px] text-ink-900" {...props} />
  ),
  a: (props: React.ComponentProps<"a">) => (
    <a className="underline text-ink-950 hover:text-ink-700" target="_blank" rel="noreferrer" {...props} />
  ),
  h1: (props: React.ComponentProps<"h1">) => (
    <h3 className="mt-3 text-[15px] font-semibold text-ink-950" {...props} />
  ),
  h2: (props: React.ComponentProps<"h2">) => (
    <h3 className="mt-3 text-[14.5px] font-semibold text-ink-950" {...props} />
  ),
  h3: (props: React.ComponentProps<"h3">) => (
    <h3 className="mt-3 text-[14px] font-semibold text-ink-950" {...props} />
  ),
};

export default function ChatPanel({ report }: { report: ScanReport }) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      text: `I've read the audit report for ${report.target.hostname}. Ask me how to raise the posture score, or which finding to fix first.`,
    },
  ]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  async function send() {
    const text = input.trim();
    if (!text || sending) return;

    setError(null);
    const nextMessages = [...messages, { role: "user" as const, text }];
    setMessages(nextMessages);
    setInput("");
    setSending(true);

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report, messages: nextMessages }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not get a reply.");
      setMessages((m) => [...m, { role: "assistant", text: data.reply }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setSending(false);
    }
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
              <div className="pt-0.5 min-w-0">
                <ReactMarkdown components={markdownComponents}>{m.text}</ReactMarkdown>
              </div>
            </div>
          ) : (
            <div key={i} className="flex justify-end">
              <div className="max-w-[80%] rounded-2xl bg-ink-50 px-4 py-2.5 text-[14px] leading-relaxed text-ink-900">
                {m.text}
              </div>
            </div>
          ),
        )}
        {sending && (
          <div className="flex gap-3">
            <span className="mt-1 h-6 w-6 shrink-0 rounded-full bg-ink-950 flex items-center justify-center">
              <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
            </span>
            <p className="text-[14px] text-ink-400 pt-0.5">Thinking…</p>
          </div>
        )}
        {error && <p className="text-[12.5px] text-sev-critical">{error}</p>}
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
          disabled={sending}
          className="rounded-xl bg-ink-950 text-white px-4 py-2.5 text-[13px] font-medium hover:bg-ink-800 disabled:opacity-60 transition-colors"
        >
          {sending ? "…" : "Send"}
        </button>
      </div>
      <p className="text-center text-[11px] text-ink-400 mt-3">
        Powered by Gemini · answers are grounded in this report's actual findings
      </p>
    </div>
  );
}
