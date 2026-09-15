import { NextResponse } from "next/server";
import { listDecisions } from "@/lib/api";

export const dynamic = "force-dynamic";

// Lightweight activity probe for the onboarding wizard: how many decisions the org has.
export async function GET() {
  const { data } = await listDecisions({ limit: 100 });
  return NextResponse.json({ decisions: data.length }, { headers: { "Cache-Control": "no-store" } });
}
