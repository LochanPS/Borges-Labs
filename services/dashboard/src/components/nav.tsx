"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { ShieldCheck, LayoutDashboard, FileCog, ScrollText, KeyRound, Activity, Bot, Play } from "lucide-react";

const LINKS = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/policies", label: "Policies", icon: FileCog },
  { href: "/agents", label: "Agents", icon: Bot },
  { href: "/audit", label: "Audit log", icon: ScrollText },
  { href: "/playground", label: "Playground", icon: Play },
  { href: "/keys", label: "API keys", icon: KeyRound },
  { href: "/status", label: "Status", icon: Activity },
];

export function Nav() {
  const path = usePathname();
  return (
    <aside className="w-56 shrink-0 border-r border-[var(--line)] bg-[var(--panel)] min-h-screen p-4 hidden md:block">
      <div className="flex items-center gap-2 px-2 pb-5">
        <ShieldCheck className="size-5 text-[var(--accent)]" />
        <span className="font-semibold">Trust Infra</span>
      </div>
      <nav className="space-y-1">
        {LINKS.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? path === "/" : path.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                active ? "bg-[var(--accent)] text-[var(--accent-fg)]" : "hover:bg-[var(--bg)] text-[var(--fg)]",
              )}
            >
              <Icon className="size-4" />
              {label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
