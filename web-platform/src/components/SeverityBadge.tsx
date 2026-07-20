import { Severity } from "@/lib/types";

const STYLES: Record<Severity, string> = {
  Critical: "bg-red-50 text-sev-critical ring-1 ring-red-100",
  High: "bg-orange-50 text-sev-high ring-1 ring-orange-100",
  Medium: "bg-amber-50 text-sev-medium ring-1 ring-amber-100",
  Low: "bg-emerald-50 text-sev-low ring-1 ring-emerald-100",
  Acceptable: "bg-green-50 text-sev-acceptable ring-1 ring-green-100",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium data-mono ${STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}
