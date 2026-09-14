import { NextResponse } from "next/server";
import { getHealth } from "@/lib/api";
import { liveBackend } from "@/lib/config";

export const dynamic = "force-dynamic";

// Server-side proxy to the decision plane's /v1/health, so the status page polls
// same-origin (no CORS) and the backend URL/key stay server-side.
export async function GET() {
  const health = await getHealth();
  return NextResponse.json(
    { ...health, live: liveBackend(), checked_at: new Date().toISOString() },
    { headers: { "Cache-Control": "no-store" } },
  );
}
