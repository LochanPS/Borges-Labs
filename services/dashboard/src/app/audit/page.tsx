import Link from "next/link";
import { Card, CardBody, Table, Td, Th, VerdictBadge } from "@/components/ui";
import { listDecisions, type DecisionFilters } from "@/lib/api";
import { formatTime, shortId } from "@/lib/utils";
import type { Verdict } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const VERDICTS: (Verdict | "")[] = ["", "APPROVE", "DENY", "REVIEW"];

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ verdict?: string; agent_id?: string }>;
}) {
  const sp = await searchParams;
  const filters: DecisionFilters = {
    verdict: (["APPROVE", "DENY", "REVIEW"].includes(sp.verdict ?? "") ? sp.verdict : undefined) as Verdict | undefined,
    agent_id: sp.agent_id || undefined,
    limit: 100,
  };
  const { data } = await listDecisions(filters);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <p className="text-[var(--muted)] text-sm">Every decision is a stored, tamper-evident record. Filter, then open a row for the receipt.</p>
      </div>

      <Card>
        <CardBody>
          <form className="flex flex-wrap items-end gap-3" method="get">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-[var(--muted)]">Verdict</label>
              <select
                name="verdict"
                defaultValue={sp.verdict ?? ""}
                className="h-9 rounded-md border border-[var(--line)] bg-[var(--panel)] px-3 text-sm"
              >
                {VERDICTS.map((v) => (
                  <option key={v || "all"} value={v}>
                    {v || "All"}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs text-[var(--muted)]">Agent</label>
              <input
                name="agent_id"
                defaultValue={sp.agent_id ?? ""}
                placeholder="agent id"
                className="h-9 rounded-md border border-[var(--line)] bg-[var(--panel)] px-3 text-sm"
              />
            </div>
            <button className="h-9 rounded-md bg-[var(--accent)] text-[var(--accent-fg)] px-4 text-sm font-medium">Filter</button>
            {(sp.verdict || sp.agent_id) && (
              <Link href="/audit" className="h-9 inline-flex items-center px-3 text-sm text-[var(--muted)]">
                Clear
              </Link>
            )}
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr>
                <Th>Verdict</Th>
                <Th>Decision</Th>
                <Th>Summary</Th>
                <Th>Latency</Th>
                <Th>Evaluated</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {data.map((d) => (
                <tr key={d.decision_id} className="hover:bg-[var(--bg)]">
                  <Td><VerdictBadge verdict={d.verdict} /></Td>
                  <Td className="mono text-xs text-[var(--muted)]">{shortId(d.decision_id, 14)}</Td>
                  <Td className="max-w-[360px]">{d.explanation.summary}</Td>
                  <Td className="mono text-xs">{d.latency_ms ?? "—"} ms</Td>
                  <Td className="mono text-xs text-[var(--muted)]">{formatTime(d.evaluated_at)}</Td>
                  <Td>
                    <Link href={`/decisions/${d.decision_id}`} className="text-sm text-[var(--accent)]">
                      Receipt →
                    </Link>
                  </Td>
                </tr>
              ))}
              {data.length === 0 && (
                <tr>
                  <Td colSpan={6}>
                    <div className="py-8 text-center text-[var(--muted)]">No decisions match.</div>
                  </Td>
                </tr>
              )}
            </tbody>
          </Table>
        </CardBody>
      </Card>
    </div>
  );
}
