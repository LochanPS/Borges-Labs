"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as api from "./api";
import type { CreatedApiKey, Rule } from "./contracts";
import { canManage, currentIdentity } from "./identity";

/** Returns an error string when the caller lacks the admin role, else null. */
async function denyIfNotManager(): Promise<string | null> {
  const id = await currentIdentity();
  return canManage(id.role) ? null : `Requires an admin role (you are ${id.role}).`;
}

/** Throw for void form actions that mutate; UI hides these for non-admins too. */
async function assertManager(): Promise<void> {
  const err = await denyIfNotManager();
  if (err) throw new Error(err);
}

function parseRules(json: string): Rule[] {
  const parsed = JSON.parse(json);
  if (!Array.isArray(parsed)) throw new Error("rules must be a JSON array");
  return parsed as Rule[];
}

export async function savePolicyAction(
  id: string,
  _prev: { error?: string; ok?: boolean } | null,
  formData: FormData,
): Promise<{ error?: string; ok?: boolean }> {
  const denied = await denyIfNotManager();
  if (denied) return { error: denied };
  try {
    const name = String(formData.get("name") ?? "").trim();
    const agents = String(formData.get("agents") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const rules = parseRules(String(formData.get("rules") ?? "[]"));
    if (!name) return { error: "Name is required." };
    await api.updatePolicy(id, { name, agents, rules });
    revalidatePath(`/policies/${id}`);
    return { ok: true };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function createPolicyAction(
  _prev: { error?: string } | null,
  formData: FormData,
): Promise<{ error?: string }> {
  const denied = await denyIfNotManager();
  if (denied) return { error: denied };
  let newId: string;
  try {
    const name = String(formData.get("name") ?? "").trim();
    const agents = String(formData.get("agents") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const rules = parseRules(String(formData.get("rules") ?? "[]"));
    if (!name) return { error: "Name is required." };
    const policy = await api.createPolicy({ name, agents, rules });
    newId = policy.id;
  } catch (e) {
    return { error: (e as Error).message };
  }
  revalidatePath("/policies");
  redirect(`/policies/${newId}`);
}

export async function publishPolicyAction(id: string): Promise<void> {
  await assertManager();
  await api.publishPolicy(id);
  revalidatePath(`/policies/${id}`);
  revalidatePath("/");
}

export async function rollbackPolicyAction(id: string, versionHash: string): Promise<void> {
  await assertManager();
  await api.rollbackPolicy(id, versionHash);
  revalidatePath(`/policies/${id}`);
}

export async function createKeyAction(
  _prev: { key?: CreatedApiKey; error?: string } | null,
  formData: FormData,
): Promise<{ key?: CreatedApiKey; error?: string }> {
  const denied = await denyIfNotManager();
  if (denied) return { error: denied };
  try {
    const env = (String(formData.get("env")) === "live" ? "live" : "test") as "live" | "test";
    const shadow = formData.get("shadow") === "on";
    const key = await api.createKey({ env, shadow });
    revalidatePath("/keys");
    return { key };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function revokeKeyAction(id: string): Promise<void> {
  await assertManager();
  await api.revokeKey(id);
  revalidatePath("/keys");
}

/** Dev-only: switch the simulated role (RBAC demo when Clerk is not configured). */
export async function setDevRoleAction(role: string): Promise<void> {
  const jar = await import("next/headers").then((m) => m.cookies());
  (await jar).set("ti-dev-role", role, { path: "/", httpOnly: false, sameSite: "lax" });
  revalidatePath("/");
}

export async function playgroundAction(
  _prev: unknown,
  formData: FormData,
): Promise<{ decision?: import("./contracts").Decision; jwks?: import("./contracts").Jwks; error?: string }> {
  try {
    const amount = String(formData.get("amount") ?? "").trim();
    if (!/^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(amount)) {
      return { error: "amount must be a decimal string (e.g. 1200.00)" };
    }
    const { decision, jwks } = await api.authorizeTest({
      agent_id: String(formData.get("agent_id") ?? "procurement-agent-v2").trim() || "procurement-agent-v2",
      action: String(formData.get("action") ?? "payment.create").trim() || "payment.create",
      amount,
      currency: String(formData.get("currency") ?? "USD").trim() || "USD",
      vendor: String(formData.get("vendor") ?? "acme-supplies").trim() || "acme-supplies",
    });
    return { decision, jwks };
  } catch (e) {
    return { error: (e as Error).message };
  }
}
