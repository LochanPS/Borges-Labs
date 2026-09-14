"use client";
import * as React from "react";
import { Activity, CheckCircle2, AlertTriangle, RefreshCw } from "lucide-react";
import { Card, CardBody, CardHeader, CardTitle, Badge } from "@/components/ui";

type Health = {
  status?: "ok" | "degraded";
  build?: string;
  enrichment?: "ok" | "degraded" | "disabled";
  live?: boolean;
  checked_at?: string;
  error?: boolean;
};

const REFRESH_MS = 5000;

export default function StatusPage() {
  const [health, setHealth] = React.useState<Health | null>(null);
  const [loading, setLoading] = React.useState(true);

  const poll = React.useCallback(async () => {
    try {
      const res = await fetch("/api/health", { cache: "no-store" });
      setHealth(await res.json());
    } catch {
      setHealth({ status: "degraded", error: true });
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    poll();
    const t = setInterval(poll, REFRESH_MS);
    return () => clearInterval(t);
  }, [poll]);

  const ok = health?.status === "ok";
  const color = ok ? "var(--approve)" : "var(--deny)";

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Status</h1>
          <p className="text-[var(--muted)] text-sm">Live decision-plane health, polled every {REFRESH_MS / 1000}s.</p>
        </div>
        <button onClick={poll} className="inline-flex items-center gap-2 h-9 rounded-md border border-[var(--line)] px-3 text-sm">
          <RefreshCw className={"size-4 " + (loading ? "animate-spin" : "")} /> Refresh
        </button>
      </div>

      <Card>
        <CardBody className="flex items-center gap-4">
          {ok ? (
            <CheckCircle2 className="size-10" style={{ color }} />
          ) : (
            <AlertTriangle className="size-10" style={{ color }} />
          )}
          <div>
            <div className="text-xl font-semibold" style={{ color }}>
              {loading && !health ? "Checking…" : ok ? "All systems operational" : "Degraded"}
            </div>
            <div className="text-sm text-[var(--muted)]">
              {health?.live === false ? "mock backend (no live decision plane configured)" : "decision plane /v1/health"}
              {health?.checked_at ? ` · checked ${new Date(health.checked_at).toLocaleTimeString()}` : ""}
            </div>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Components</CardTitle></CardHeader>
        <CardBody className="space-y-3">
          <Row label="Decision plane" icon>
            <StatusBadge value={health?.status ?? "…"} good="ok" />
          </Row>
          <Row label="Enrichment (sanctions / vendor risk)">
            <StatusBadge value={health?.enrichment ?? "disabled"} good="ok" neutral="disabled" />
          </Row>
          <Row label="Build">
            <span className="mono text-sm text-[var(--muted)]">{health?.build ?? "—"}</span>
          </Row>
        </CardBody>
      </Card>
    </div>
  );
}

function Row({ label, children, icon }: { label: string; children: React.ReactNode; icon?: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="flex items-center gap-2 text-sm">
        {icon && <Activity className="size-4 text-[var(--muted)]" />}
        {label}
      </span>
      {children}
    </div>
  );
}

function StatusBadge({ value, good, neutral }: { value: string; good: string; neutral?: string }) {
  const cls =
    value === good
      ? "text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10"
      : value === neutral
        ? "text-[var(--muted)]"
        : "text-[var(--deny)] border-[var(--deny)]/40 bg-[var(--deny)]/10";
  return <Badge className={"mono " + cls}>{value}</Badge>;
}
