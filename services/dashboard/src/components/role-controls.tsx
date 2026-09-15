"use client";
import * as React from "react";
import { Badge } from "@/components/ui";
import { setDevRoleAction } from "@/lib/actions";
import type { Role } from "@/lib/identity";

const ROLES: Role[] = ["owner", "admin", "developer", "viewer"];

/** Header role indicator. In dev mode (no Clerk) it doubles as a role switcher so
 *  RBAC is demonstrable; with Clerk the role is fixed by org membership. */
export function RoleControls({ role, source }: { role: Role; source: "clerk" | "dev" }) {
  const [pending, start] = React.useTransition();
  const admin = role === "owner" || role === "admin";

  if (source === "clerk") {
    return <Badge className={admin ? "text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10" : ""}>{role}</Badge>;
  }

  return (
    <label className="flex items-center gap-1 text-xs text-[var(--muted)]">
      role
      <select
        value={role}
        disabled={pending}
        onChange={(e) => start(() => void setDevRoleAction(e.target.value))}
        className="h-7 rounded-md border border-[var(--line)] bg-[var(--panel)] px-2 text-xs"
        title="Dev-only role switcher (RBAC demo)"
      >
        {ROLES.map((r) => (
          <option key={r} value={r}>{r}</option>
        ))}
      </select>
    </label>
  );
}
