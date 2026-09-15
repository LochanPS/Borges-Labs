"use client";
import * as React from "react";
import { useActionState } from "react";
import { Play } from "lucide-react";
import { Button, Card, CardBody, CardHeader, CardTitle, Input, Label, VerdictBadge, Table, Td, Th } from "@/components/ui";
import { VerifyButton } from "@/components/verify-button";
import { playgroundAction } from "@/lib/actions";

const PRESETS = [
  { label: "Approve ($1,200 → acme-supplies)", amount: "1200.00", vendor: "acme-supplies" },
  { label: "Review ($5,200 → globex)", amount: "5200.00", vendor: "globex" },
  { label: "Deny · over budget ($9,000)", amount: "9000.00", vendor: "globex" },
  { label: "Deny · vendor blocked ($300)", amount: "300.00", vendor: "sketchy-vendor" },
];

export default function PlaygroundPage() {
  const [state, formAction, pending] = useActionState(playgroundAction, null);
  const [amount, setAmount] = React.useState("1200.00");
  const [vendor, setVendor] = React.useState("acme-supplies");

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-semibold">Playground</h1>
        <p className="text-[var(--muted)] text-sm">
          Fire a test authorization and see the signed decision. Verification runs in your browser.
          Uses live decisions when a backend is configured, otherwise a signed mock.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        {PRESETS.map((p) => (
          <button
            key={p.label}
            type="button"
            onClick={() => { setAmount(p.amount); setVendor(p.vendor); }}
            className="text-xs rounded-md border border-[var(--line)] px-2 py-1 hover:bg-[var(--bg)]"
          >
            {p.label}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle>Transaction</CardTitle></CardHeader>
        <CardBody>
          <form action={formAction} className="grid gap-4 sm:grid-cols-2">
            <Field name="agent_id" label="Agent" def="procurement-agent-v2" />
            <Field name="action" label="Action" def="payment.create" />
            <div className="space-y-1">
              <Label htmlFor="amount">Amount (decimal string)</Label>
              <Input id="amount" name="amount" value={amount} onChange={(e) => setAmount(e.target.value)} />
            </div>
            <Field name="currency" label="Currency" def="USD" />
            <div className="space-y-1">
              <Label htmlFor="vendor">Vendor (target id)</Label>
              <Input id="vendor" name="vendor" value={vendor} onChange={(e) => setVendor(e.target.value)} />
            </div>
            <div className="sm:col-span-2 flex items-center gap-3">
              <Button type="submit" disabled={pending}>
                <Play className="size-4" /> {pending ? "Authorizing…" : "Authorize"}
              </Button>
              {state?.error && <span className="text-sm text-[var(--deny)]">{state.error}</span>}
            </div>
          </form>
        </CardBody>
      </Card>

      {state?.decision && (
        <Card>
          <CardHeader className="flex items-center justify-between">
            <CardTitle>Decision</CardTitle>
            <VerdictBadge verdict={state.decision.verdict} />
          </CardHeader>
          <CardBody className="space-y-4">
            <p className="text-sm">{state.decision.explanation.summary}</p>
            {state.decision.explanation.matched_rules.length > 0 && (
              <Table>
                <thead><tr><Th>Rule</Th><Th>Type</Th><Th>Result</Th><Th>Detail</Th></tr></thead>
                <tbody>
                  {state.decision.explanation.matched_rules.map((r, i) => (
                    <tr key={i}>
                      <Td className="mono text-xs">{r.rule_id}</Td>
                      <Td className="mono text-xs text-[var(--muted)]">{r.type}</Td>
                      <Td className="mono text-xs">{r.result}</Td>
                      <Td className="text-xs">{r.detail}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
            {state.jwks && <VerifyButton decision={state.decision} jwks={state.jwks} />}
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function Field({ name, label, def }: { name: string; label: string; def: string }) {
  return (
    <div className="space-y-1">
      <Label htmlFor={name}>{label}</Label>
      <Input id={name} name={name} defaultValue={def} />
    </div>
  );
}
