import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Prisma's generated client + the Neon driver adapter do their own
  // dynamic requires that Next.js's bundler doesn't need to (and
  // shouldn't) try to trace/bundle — this keeps them as plain runtime
  // dependencies instead, which is what Prisma's own Next.js docs
  // recommend for driver-adapter setups.
  serverExternalPackages: ["@prisma/client", "@prisma/adapter-neon", "@neondatabase/serverless"],
};

export default nextConfig;
