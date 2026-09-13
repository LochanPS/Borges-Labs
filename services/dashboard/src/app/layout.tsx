import type { Metadata } from "next";
import { ClerkProvider } from "@clerk/nextjs";
import "./globals.css";
import { Nav } from "@/components/nav";
import { Badge } from "@/components/ui";
import { clerkEnabled, liveBackend } from "@/lib/config";

export const metadata: Metadata = {
  title: "Trust Infrastructure — Control Plane",
  description: "Policy authoring, audit log, and decision-signature verification.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const authOn = clerkEnabled();
  const live = liveBackend();

  const shell = (
    <div className="flex">
      <Nav />
      <div className="flex-1 min-w-0">
        <header className="h-14 border-b border-[var(--line)] bg-[var(--panel)] flex items-center justify-between px-6">
          <div className="text-sm text-[var(--muted)]">Control Plane</div>
          <div className="flex items-center gap-2">
            {!live && <Badge className="text-[var(--review)] border-[var(--review)]/40 bg-[var(--review)]/10">mock data</Badge>}
            {!authOn && <Badge className="text-[var(--muted)]">dev mode · no auth</Badge>}
          </div>
        </header>
        <main className="p-6 max-w-6xl">{children}</main>
      </div>
    </div>
  );

  return (
    <html lang="en">
      <body>{authOn ? <ClerkProvider>{shell}</ClerkProvider> : shell}</body>
    </html>
  );
}
