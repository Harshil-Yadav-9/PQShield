import Link from "next/link";
import ScanForm from "@/components/ScanForm";
import { DEMO_REPORT_ID } from "@/lib/mock-data";

export default function LandingPage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-8 py-24">
      <div className="w-full max-w-xl flex flex-col items-center text-center">
        <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-ink-400 mb-5">
          Post-quantum TLS assessment
        </span>
        <h1 className="font-display text-[44px] leading-[1.05] font-bold tracking-tight text-ink-950">
          PQShield
        </h1>
        <p className="mt-4 text-[15.5px] leading-relaxed text-ink-600 max-w-md">
          Scan any TLS endpoint for protocol weaknesses, certificate issues, and
          quantum-readiness. Get an explainable, standards-mapped posture score
          in under two minutes.
        </p>

        <div className="mt-10 w-full flex justify-center">
          <ScanForm />
        </div>

        <p className="mt-4 text-[12px] text-ink-400">
          Not sure where to start?{" "}
          <Link href={`/reports/${DEMO_REPORT_ID}`} className="text-ink-950 font-medium hover:underline">
            View a sample report
          </Link>
        </p>

        <div className="mt-14 grid grid-cols-3 gap-8 w-full max-w-md text-left">
          <div>
            <p className="text-[12.5px] font-medium text-ink-950">Full capability space</p>
            <p className="text-[11.5px] text-ink-500 mt-1 leading-relaxed">
              Not just negotiated ciphers — everything a server supports.
            </p>
          </div>
          <div>
            <p className="text-[12.5px] font-medium text-ink-950">PQC readiness</p>
            <p className="text-[11.5px] text-ink-500 mt-1 leading-relaxed">
              ML-KEM and ML-DSA checked against NIST FIPS 203/204/205.
            </p>
          </div>
          <div>
            <p className="text-[12.5px] font-medium text-ink-950">Explainable scoring</p>
            <p className="text-[11.5px] text-ink-500 mt-1 leading-relaxed">
              Every point traced to a standard, with a fix recommended.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
