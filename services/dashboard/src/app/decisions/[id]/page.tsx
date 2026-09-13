import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Card, CardBody, CardHeader, CardTitle, VerdictBadge, Badge, Table, Td, Th } from "@/components/ui";
import { VerifyButton } from "@/components/verify-button";
import { getDecision, getPublicKeys } from "@/lib/api";
import { formatTime } from "@/lib/utils";

export const dynamic = "force-dynamic";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-3 py-2 border-b border-[var(--line)] last:border-0">
      <div className="text-sm text-[var(--muted)]">{label}</div>
      <div className="text-sm mono break-all">{children}</div>
    </div>
  );
}

export default async function ReceiptPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [decision, jwks] = await Promise.all([getDecision(id), getPublicKeys()]);
  if (!decision) notFound();

  return (
    <div className="space-y-6">
      <Link href="/audit" className="inline-flex items-center gap-1 text-sm text-[var(--muted)] hover:text-[var(--fg)]">
        <ArrowLeft className="size-4" /> Audit log
      </Link>

      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold">Decision receipt</h1>
        <VerdictBadge verdict={decision.verdict} />
        {decision.shadow && <Badge className="text-[var(--review)] border-[var(--review)]/40 bg-[var(--review)]/10">shadow</Badge>}
      </div>

      <Card>
        <CardHeader><CardTitle>Verify signature</CardTitle></CardHeader>
        <CardBody>
          <p className="text-sm text-[var(--muted)] mb-3">
            Ed25519 receipt, verifiable by anyone against the published public key
            (<span className="mono">GET /v1/keys/public</span>) — no shared secret. Verification runs entirely in your browser.
          </p>
          <VerifyButton decision={decision} jwks={jwks} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Decision</CardTitle></CardHeader>
        <CardBody className="py-1">
          <Field label="decision_id">{decision.decision_id}</Field>
          <Field label="verdict">{decision.verdict}</Field>
          <Field label="policy_version_hash">{decision.policy_version_hash}</Field>
          <Field label="evaluated_at">{formatTime(decision.evaluated_at)}</Field>
          <Field label="latency_ms">{decision.latency_ms ?? "—"}</Field>
          {decision.record_hash && <Field label="record_hash">{decision.record_hash}</Field>}
          <Field label="summary"><span className="font-sans">{decision.explanation.summary}</span></Field>
        </CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Matched rules</CardTitle></CardHeader>
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr>
                <Th>Rule</Th>
                <Th>Type</Th>
                <Th>Result</Th>
                <Th>Detail</Th>
              </tr>
            </thead>
            <tbody>
              {decision.explanation.matched_rules.map((r, i) => (
                <tr key={i}>
                  <Td className="mono text-xs">{r.rule_id}</Td>
                  <Td className="mono text-xs text-[var(--muted)]">{r.type}</Td>
                  <Td className="mono text-xs">{r.result}</Td>
                  <Td className="text-xs">{r.detail}</Td>
                </tr>
              ))}
              {decision.explanation.matched_rules.length === 0 && (
                <tr><Td colSpan={4}><div className="py-4 text-center text-[var(--muted)]">No rules recorded.</div></Td></tr>
              )}
            </tbody>
          </Table>
        </CardBody>
      </Card>

      {decision.obligations.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Obligations</CardTitle></CardHeader>
          <CardBody className="space-y-2">
            {decision.obligations.map((o, i) => (
              <div key={i} className="text-sm">
                <span className="mono">{o.type}</span>
                {o.detail ? <span className="text-[var(--muted)]"> — {o.detail}</span> : null}
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {decision.signature && (
        <Card>
          <CardHeader><CardTitle>Signature</CardTitle></CardHeader>
          <CardBody className="py-1">
            <Field label="algorithm">{decision.signature.algorithm}</Field>
            <Field label="key_id">{decision.signature.key_id}</Field>
            <Field label="canonicalization">{decision.signature.canonicalization}</Field>
            <Field label="value">{decision.signature.value}</Field>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
