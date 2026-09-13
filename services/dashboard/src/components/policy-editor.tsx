"use client";
import * as React from "react";
import { useActionState } from "react";
import { Save } from "lucide-react";
import { Button, Input, Label, Textarea } from "@/components/ui";
import type { Policy } from "@/lib/contracts";
import { savePolicyAction } from "@/lib/actions";

export function PolicyEditor({ policy }: { policy: Policy }) {
  const action = savePolicyAction.bind(null, policy.id);
  const [state, formAction, pending] = useActionState(action, null);

  return (
    <form action={formAction} className="space-y-4">
      <div className="space-y-1">
        <Label htmlFor="name">Name</Label>
        <Input id="name" name="name" defaultValue={policy.name} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="agents">Agents (comma-separated; empty = all agents)</Label>
        <Input id="agents" name="agents" defaultValue={policy.agents.join(", ")} placeholder="procurement-agent-v2" />
      </div>
      <div className="space-y-1">
        <Label htmlFor="rules">
          Rules (JSON) — types: per_transaction_limit, vendor_allowlist, vendor_blocklist, agent_permission,
          time_window, jurisdiction_currency, rolling_budget
        </Label>
        <Textarea id="rules" name="rules" rows={14} defaultValue={JSON.stringify(policy.rules, null, 2)} />
      </div>
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={pending}>
          <Save className="size-4" /> {pending ? "Saving…" : "Save draft"}
        </Button>
        {state?.ok && <span className="text-sm text-[var(--approve)]">Saved.</span>}
        {state?.error && <span className="text-sm text-[var(--deny)]">{state.error}</span>}
      </div>
    </form>
  );
}
