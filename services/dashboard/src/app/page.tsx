import Link from "next/link";
import { Card, CardBody, CardHeader, CardTitle, VerdictBadge } from "@/components/ui";
import { getActivePolicy, getHealth, listDecisions } from "@/lib/api";
import { formatTime, shortId } from "@/lib/utils";

export const dynamic = "force-dynamic";

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <Card>
      <CardBody>
        <div className="text-sm text-[var(--muted)]">{label}</div>
        <div className="text-2xl font-semibold mt-1">{value}</div>
        {sub && <div className="text-xs text-[var(--muted)] mt-1">{sub}</div>}
      </CardBody>
    </Card>
  );
}

export default async function OverviewPage() {
  const [{ data: decisions }, active, health] = await Promise.all([
    listDecisions({ limit: 100 }),
    getActivePolicy(),
    getHealth(),
  ]);

  const total = decisions.length;
  const mix = { APPROVE: 0, DENY: 0, REVIEW: 0 } as Record<string, number>;
  for (const d of decisions) mix[d.verdict] = (mix[d.verdict] ?? 0) + 1;
  const latencies = decisions.map((d) => d.latency_ms ?? 0);
  const p50 = percentile(latencies, 50);
  const p95 = percentile(latencies, 95);
  const recent = [...decisions].slice(0, 6);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Overview</h1>
        <p className="text-[var(--muted)] text-sm">
          Decision volume, verdict mix, latency, and the active policy version.{" "}
          <span className="mono">status: {health.status}</span>
          {health.enrichment ? <span className="mono"> · enrichment: {health.enrichment}</span> : null}
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Decisions" value={String(total)} sub="most recent window" />
        <Stat
          label="Verdict mix"
          value={`${mix.APPROVE}/${mix.DENY}/${mix.REVIEW}`}
          sub="APPROVE / DENY / REVIEW"
        />
        <Stat label="Latency p50 / p95" value={`${p50} / ${p95} ms`} sub="evaluation only" />
        <Stat
          label="Active policy version"
          value={active ? shortId(active.version_hash, 12) : "—"}
          sub={active ? formatTime(active.updated_at) : "no active bundle"}
        />
      </div>

      <Card>
        <CardHeader className="flex items-center justify-between">
          <CardTitle>Recent decisions</CardTitle>
          <Link href="/audit" className="text-sm text-[var(--accent)]">
            View audit log →
          </Link>
        </CardHeader>
        <CardBody className="p-0">
          <div className="divide-y divide-[var(--line)]">
            {recent.map((d) => (
              <Link
                key={d.decision_id}
                href={`/decisions/${d.decision_id}`}
                className="flex items-center justify-between px-5 py-3 hover:bg-[var(--bg)]"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <VerdictBadge verdict={d.verdict} />
                  <span className="mono text-sm text-[var(--muted)] truncate">{shortId(d.decision_id, 16)}</span>
                </div>
                <div className="text-sm text-[var(--muted)] truncate max-w-[45%]">{d.explanation.summary}</div>
                <div className="mono text-xs text-[var(--muted)]">{formatTime(d.evaluated_at)}</div>
              </Link>
            ))}
            {recent.length === 0 && <div className="px-5 py-8 text-center text-[var(--muted)]">No decisions yet.</div>}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
