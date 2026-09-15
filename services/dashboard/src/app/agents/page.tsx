import Link from "next/link";
import { Bot } from "lucide-react";
import { Card, CardBody, CardHeader, CardTitle, Badge, Table, Td, Th } from "@/components/ui";
import { listPolicies } from "@/lib/api";

export const dynamic = "force-dynamic";

// Agents referenced by the org's policies. (Per-agent enforce/shadow is currently a
// property of the API key, not the agent — see the roadmap note below. A first-class
// agent registry + per-agent enforce toggle is milestone M2.)
export default async function AgentsPage() {
  const policies = await listPolicies();
  const agents = new Map<string, string[]>(); // agent id -> policy names targeting it
  for (const p of policies) {
    const targets = p.agents.length ? p.agents : ["(all agents)"];
    for (const a of targets) {
      agents.set(a, [...(agents.get(a) ?? []), p.name]);
    }
  }
  const rows = [...agents.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Agents</h1>
        <p className="text-[var(--muted)] text-sm">
          Agents your policies govern. Open an agent&apos;s audit trail to see its decisions.
        </p>
      </div>

      <Card>
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr><Th>Agent</Th><Th>Governed by</Th><Th /></tr>
            </thead>
            <tbody>
              {rows.map(([agent, policyNames]) => (
                <tr key={agent} className="hover:bg-[var(--bg)]">
                  <Td>
                    <span className="flex items-center gap-2">
                      <Bot className="size-4 text-[var(--muted)]" />
                      <span className="mono">{agent}</span>
                    </span>
                  </Td>
                  <Td className="text-xs text-[var(--muted)]">{[...new Set(policyNames)].join(", ")}</Td>
                  <Td>
                    {agent !== "(all agents)" && (
                      <Link href={`/audit?agent_id=${encodeURIComponent(agent)}`} className="text-sm text-[var(--accent)]">
                        Audit trail →
                      </Link>
                    )}
                  </Td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><Td colSpan={3}><div className="py-8 text-center text-[var(--muted)]">No agents yet — add agents to a policy.</div></Td></tr>
              )}
            </tbody>
          </Table>
        </CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Rolling out an agent (shadow → enforce)</CardTitle></CardHeader>
        <CardBody className="text-sm text-[var(--muted)] space-y-2">
          <p>
            New keys are <Badge className="text-[var(--review)] border-[var(--review)]/40 bg-[var(--review)]/10">shadow</Badge> by
            default — decisions are evaluated and audited but never block. Review the audit trail, then flip one
            agent&apos;s key to enforce.
          </p>
          <p>
            Manage keys under <Link href="/keys" className="text-[var(--accent)]">API keys</Link>. A first-class
            per-agent enforce toggle is on the roadmap (M2).
          </p>
        </CardBody>
      </Card>
    </div>
  );
}
