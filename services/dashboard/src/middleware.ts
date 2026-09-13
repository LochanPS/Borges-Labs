import { NextResponse, type NextRequest } from "next/server";
import { clerkMiddleware } from "@clerk/nextjs/server";

// Clerk is optional. With both keys present, enforce auth; otherwise run in dev-bypass
// mode (a banner is shown in the UI). clerkMiddleware() is only invoked when enabled.
const enabled = Boolean(
  process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY && process.env.CLERK_SECRET_KEY,
);

const handler = enabled ? clerkMiddleware() : (_req: NextRequest) => NextResponse.next();

export default handler;

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
