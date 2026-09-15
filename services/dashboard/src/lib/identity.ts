import { cookies } from "next/headers";
import { clerkEnabled } from "./config";

/**
 * Who is acting, and what they may do (M1 RBAC). Identity is pluggable:
 *
 * - Clerk configured: user + org + role come from Clerk Organizations. A Clerk org
 *   role containing "admin" maps to `admin`, otherwise `developer`.
 * - Dev-bypass (no Clerk): a synthetic user in `org_demo`, whose role comes from the
 *   `ti-dev-role` cookie (default `owner`) so RBAC is demonstrable locally.
 *
 * Note (M1b): the dashboard still calls authorize-svc with a single server-side admin
 * key (its org). Per-org key routing — mapping each Clerk org to its own provisioned
 * key (via POST /v1/provision/keys) — is the next step. RBAC here governs WHO may act.
 */
export type Role = "owner" | "admin" | "developer" | "viewer";

const RANK: Record<Role, number> = { viewer: 0, developer: 1, admin: 2, owner: 3 };

export interface Identity {
  userId: string;
  orgId: string;
  role: Role;
  source: "clerk" | "dev";
}

/** True if `role` is at least `min` (owner ≥ admin ≥ developer ≥ viewer). */
export function atLeast(role: Role, min: Role): boolean {
  return RANK[role] >= RANK[min];
}

/** Can this role manage the control plane (create/publish policies, manage keys)? */
export function canManage(role: Role): boolean {
  return atLeast(role, "admin");
}

function normalizeClerkRole(orgRole: string | null | undefined): Role {
  const r = (orgRole ?? "").toLowerCase();
  if (r.includes("admin") || r.includes("owner")) return "admin";
  return "developer";
}

export async function currentIdentity(): Promise<Identity> {
  if (clerkEnabled()) {
    try {
      // Imported lazily so the dev path never initializes Clerk.
      const { auth } = await import("@clerk/nextjs/server");
      const a = await auth();
      return {
        userId: a.userId ?? "anon",
        orgId: a.orgId ?? "org_personal",
        role: normalizeClerkRole(a.orgRole),
        source: "clerk",
      };
    } catch {
      // Fall through to dev identity if Clerk is misconfigured at runtime.
    }
  }
  const jar = await cookies();
  const raw = (jar.get("ti-dev-role")?.value ?? "owner") as Role;
  const role: Role = raw in RANK ? raw : "owner";
  return { userId: "dev-user", orgId: "org_demo", role, source: "dev" };
}
