"use client";
import Link from "next/link";
import { useActionState } from "react";
import { ArrowLeft, Plus } from "lucide-react";
import { Button, Card, CardBody, CardHeader, CardTitle, Input, Label, Textarea } from "@/components/ui";
import { createPolicyAction } from "@/lib/actions";

const TEMPLATE = JSON.stringify(
  [
    { rule_id: "per_txn_5k", type: "per_transaction_limit", params: { limit: "5000.00", currency: "USD" } },
    { rule_id: "vendor_allowlist", type: "vendor_allowlist", params: { allow: ["acme-supplies"] } },
    { rule_id: "agent_can_pay", type: "agent_permission", params: { agent: "procurement-agent-v2", actions: ["payment.create"] } },
  ],
  null,
  2,
);

export default function NewPolicyPage() {
  const [state, formAction, pending] = useActionState(createPolicyAction, null);
  return (
    <div className="space-y-6 max-w-3xl">
      <Link href="/policies" className="inline-flex items-center gap-1 text-sm text-[var(--muted)] hover:text-[var(--fg)]">
        <ArrowLeft className="size-4" /> Policies
      </Link>
      <h1 className="text-2xl font-semibold">New policy</h1>

      <Card>
        <CardHeader><CardTitle>Draft</CardTitle></CardHeader>
        <CardBody>
          <form action={formAction} className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="name">Name</Label>
              <Input id="name" name="name" placeholder="Procurement agent guardrails" required />
            </div>
            <div className="space-y-1">
              <Label htmlFor="agents">Agents (comma-separated; empty = all agents)</Label>
              <Input id="agents" name="agents" placeholder="procurement-agent-v2" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="rules">Rules (JSON)</Label>
              <Textarea id="rules" name="rules" rows={14} defaultValue={TEMPLATE} />
            </div>
            <div className="flex items-center gap-3">
              <Button type="submit" disabled={pending}>
                <Plus className="size-4" /> {pending ? "Creating…" : "Create draft"}
              </Button>
              {state?.error && <span className="text-sm text-[var(--deny)]">{state.error}</span>}
            </div>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}
