"use client";
import * as React from "react";
import { useActionState } from "react";
import { KeyRound, Copy, Check, Trash2, TriangleAlert } from "lucide-react";
import { Button, Card, CardBody, CardHeader, CardTitle, Badge, Table, Td, Th, Label } from "@/components/ui";
import { createKeyAction, revokeKeyAction } from "@/lib/actions";
import { formatTime } from "@/lib/utils";
import type { ApiKey } from "@/lib/contracts";

export function KeyManager({ keys }: { keys: ApiKey[] }) {
  const [state, formAction, pending] = useActionState(createKeyAction, null);
  const [copied, setCopied] = React.useState(false);
  const secret = state?.key?.secret;

  async function copy() {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked; user can select manually */
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle>Create a key</CardTitle></CardHeader>
        <CardBody>
          <form action={formAction} className="flex flex-wrap items-end gap-4">
            <div className="space-y-1">
              <Label>Environment</Label>
              <select name="env" className="h-9 rounded-md border border-[var(--line)] bg-[var(--panel)] px-3 text-sm">
                <option value="test">test (azn_test_)</option>
                <option value="live">live (azn_live_)</option>
              </select>
            </div>
            <label className="flex items-center gap-2 text-sm h-9">
              <input type="checkbox" name="shadow" defaultChecked /> shadow (advisory)
            </label>
            <Button type="submit" disabled={pending}>
              <KeyRound className="size-4" /> {pending ? "Minting…" : "Create key"}
            </Button>
            {state?.error && <span className="text-sm text-[var(--deny)]">{state.error}</span>}
          </form>

          {secret && (
            <div className="mt-4 rounded-md border border-[var(--review)]/40 bg-[var(--review)]/10 p-4">
              <div className="flex items-center gap-2 text-[var(--review)] text-sm font-medium">
                <TriangleAlert className="size-4" /> Copy this key now — it is shown once and cannot be retrieved again.
              </div>
              <div className="mt-2 flex items-center gap-2">
                <code className="mono text-sm break-all flex-1 rounded bg-[var(--panel)] border border-[var(--line)] px-3 py-2">{secret}</code>
                <Button variant="outline" size="sm" onClick={copy} type="button">
                  {copied ? <Check className="size-4" /> : <Copy className="size-4" />} {copied ? "Copied" : "Copy"}
                </Button>
              </div>
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Keys</CardTitle></CardHeader>
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr>
                <Th>Prefix</Th>
                <Th>Mode</Th>
                <Th>Status</Th>
                <Th>Created</Th>
                <Th>Last used</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <Td className="mono text-xs">{k.prefix}…</Td>
                  <Td>{k.shadow ? <Badge className="text-[var(--review)] border-[var(--review)]/40 bg-[var(--review)]/10">shadow</Badge> : <Badge className="text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10">enforce</Badge>}</Td>
                  <Td>{k.is_active ? "active" : "revoked"}</Td>
                  <Td className="mono text-xs text-[var(--muted)]">{formatTime(k.created_at)}</Td>
                  <Td className="mono text-xs text-[var(--muted)]">{formatTime(k.last_used_at)}</Td>
                  <Td>
                    {k.is_active && (
                      <form action={revokeKeyAction.bind(null, k.id)}>
                        <button className="inline-flex items-center gap-1 text-sm text-[var(--deny)]">
                          <Trash2 className="size-3.5" /> Revoke
                        </button>
                      </form>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </CardBody>
      </Card>
    </div>
  );
}
