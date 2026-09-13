import Link from "next/link";
import { Plus } from "lucide-react";
import { Card, CardBody, Badge, Table, Td, Th } from "@/components/ui";
import { listPolicies } from "@/lib/api";
import { formatTime, shortId } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function PoliciesPage() {
  const policies = await listPolicies();
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Policies</h1>
          <p className="text-[var(--muted)] text-sm">Author rules, publish an immutable signed version, roll back if needed.</p>
        </div>
        <Link
          href="/policies/new"
          className="inline-flex items-center gap-2 h-9 rounded-md bg-[var(--accent)] text-[var(--accent-fg)] px-4 text-sm font-medium"
        >
          <Plus className="size-4" /> New policy
        </Link>
      </div>

      <Card>
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Status</Th>
                <Th>Agents</Th>
                <Th>Rules</Th>
                <Th>Active version</Th>
                <Th>Updated</Th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="hover:bg-[var(--bg)]">
                  <Td>
                    <Link href={`/policies/${p.id}`} className="text-[var(--accent)] font-medium">
                      {p.name}
                    </Link>
                  </Td>
                  <Td>
                    <Badge className={p.status === "published" ? "text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10" : ""}>
                      {p.status}
                    </Badge>
                  </Td>
                  <Td className="text-xs">{p.agents.length ? p.agents.join(", ") : "all agents"}</Td>
                  <Td className="mono text-xs">{p.rules.length}</Td>
                  <Td className="mono text-xs text-[var(--muted)]">{p.active_version_hash ? shortId(p.active_version_hash, 12) : "—"}</Td>
                  <Td className="mono text-xs text-[var(--muted)]">{formatTime(p.updated_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </CardBody>
      </Card>
    </div>
  );
}
