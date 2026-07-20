export default function RootLoading() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="flex items-center gap-3 text-[13px] text-ink-400">
        <span className="h-4 w-4 rounded-full border-2 border-ink-200 border-t-ink-500 animate-spin" />
        Loading…
      </div>
    </div>
  );
}
