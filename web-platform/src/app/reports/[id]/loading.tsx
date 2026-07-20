export default function ReportLoading() {
  return (
    <div className="min-h-screen px-8 py-16 max-w-3xl mx-auto animate-pulse">
      <div className="h-3 w-24 rounded bg-ink-50" />
      <div className="mt-3 h-8 w-64 rounded bg-ink-100" />
      <div className="mt-2 h-4 w-40 rounded bg-ink-50" />

      <div className="mt-10 grid grid-cols-3 gap-4">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-24 rounded-xl bg-ink-50" />
        ))}
      </div>

      <div className="mt-8 flex flex-col gap-3">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="h-16 rounded-xl bg-ink-50" />
        ))}
      </div>

      <p className="mt-6 text-[12px] text-ink-400">Loading report…</p>
    </div>
  );
}
