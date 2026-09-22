import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";

// Production: a static export (`out/`) served by the FastAPI backend, so the app is same-origin
// with no Node server. Static export forbids rewrites even under `next dev`, so the dev server
// uses a normal config that proxies `/api/*` to the backend instead.
const BACKEND_URL = process.env.NIDS_BACKEND_URL ?? "http://localhost:8000";

export default function config(phase: string): NextConfig {
  const shared: NextConfig = {
    reactStrictMode: true,
    poweredByHeader: false,
    trailingSlash: true,
    images: { unoptimized: true },
  };

  if (phase === PHASE_DEVELOPMENT_SERVER) {
    return {
      ...shared,
      async rewrites() {
        return [{ source: "/api/:path*", destination: `${BACKEND_URL}/api/:path*` }];
      },
    };
  }

  return { ...shared, output: "export" };
}
