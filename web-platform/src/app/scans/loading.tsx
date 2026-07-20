export default function ScansLoading() {
  return (
    <div className="min-h-screen px-8 py-16 max-w-2xl mx-auto animate-pulse">
      <div className="h-7 w-40 rounded bg-ink-100" />
      <div className="mt-2 h-4 w-72 rounded bg-ink-50" />

      <div className="mt-8 flex flex-col divide-y divide-ink-100 border-y border-ink-100">
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex items-center justify-between py-4">
            <div>
              <div className="h-4 w-32 rounded bg-ink-100" />
              <div className="mt-2 h-3 w-24 rounded bg-ink-50" />
            </div>
            <div className="h-4 w-12 rounded bg-ink-100" />
          </div>
        ))}
      </div>

      <p className="mt-6 text-[12px] text-ink-400">Loading your scans…</p>
    </div>
  );
}
