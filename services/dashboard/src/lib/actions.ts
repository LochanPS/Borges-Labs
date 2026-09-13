"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as api from "./api";
import type { CreatedApiKey, Rule } from "./contracts";

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
  await api.publishPolicy(id);
  revalidatePath(`/policies/${id}`);
  revalidatePath("/");
}

export async function rollbackPolicyAction(id: string, versionHash: string): Promise<void> {
  await api.rollbackPolicy(id, versionHash);
  revalidatePath(`/policies/${id}`);
}

export async function createKeyAction(
  _prev: { key?: CreatedApiKey; error?: string } | null,
  formData: FormData,
): Promise<{ key?: CreatedApiKey; error?: string }> {
  try {
    const env = (String(formData.get("env")) === "live" ? "live" : "test") as "live" | "test";
    const shadow = formData.get("shadow") === "on";
    const key = await api.createKey({ env, shadow, scopes: ["authorize"] });
    revalidatePath("/keys");
    return { key };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function revokeKeyAction(id: string): Promise<void> {
  await api.revokeKey(id);
  revalidatePath("/keys");
}
