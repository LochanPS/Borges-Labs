import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Rocket, RotateCcw } from "lucide-react";
import { Card, CardBody, CardHeader, CardTitle, Badge, Table, Td, Th } from "@/components/ui";
import { PolicyEditor } from "@/components/policy-editor";
import { getPolicy, listPolicyVersions } from "@/lib/api";
import { publishPolicyAction, rollbackPolicyAction } from "@/lib/actions";
import { canManage, currentIdentity } from "@/lib/identity";
import { formatTime, shortId } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function PolicyDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [policy, versions, identity] = await Promise.all([getPolicy(id), listPolicyVersions(id), currentIdentity()]);
  if (!policy) notFound();
  const manage = canManage(identity.role);

  return (
    <div className="space-y-6">
      <Link href="/policies" className="inline-flex items-center gap-1 text-sm text-[var(--muted)] hover:text-[var(--fg)]">
        <ArrowLeft className="size-4" /> Policies
      </Link>

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold">{policy.name}</h1>
          <Badge className={policy.status === "published" ? "text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10" : ""}>
            {policy.status}
          </Badge>
        </div>
        {manage && (
          <form action={publishPolicyAction.bind(null, policy.id)}>
            <button className="inline-flex items-center gap-2 h-9 rounded-md bg-[var(--accent)] text-[var(--accent-fg)] px-4 text-sm font-medium">
              <Rocket className="size-4" /> Validate &amp; publish
            </button>
          </form>
        )}
      </div>

      <Card>
        <CardHeader><CardTitle>Working copy</CardTitle></CardHeader>
        <CardBody><PolicyEditor policy={policy} canManage={manage} /></CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Version history</CardTitle></CardHeader>
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr>
                <Th>Version</Th>
                <Th>Author</Th>
                <Th>Published</Th>
                <Th>Signature</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => {
                const isActive = v.version_hash === policy.active_version_hash;
                return (
                  <tr key={v.version_hash}>
                    <Td className="mono text-xs">
                      {shortId(v.version_hash, 16)}{" "}
                      {isActive && <Badge className="ml-1 text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10">active</Badge>}
                    </Td>
                    <Td className="text-xs">{v.author}</Td>
                    <Td className="mono text-xs text-[var(--muted)]">{formatTime(v.published_at)}</Td>
                    <Td className="mono text-xs text-[var(--muted)]">{v.signature.algorithm} · {shortId(v.signature.key_id, 10)}</Td>
                    <Td>
                      {!isActive && manage && (
                        <form action={rollbackPolicyAction.bind(null, policy.id, v.version_hash)}>
                          <button className="inline-flex items-center gap-1 text-sm text-[var(--accent)]">
                            <RotateCcw className="size-3.5" /> Roll back
                          </button>
                        </form>
                      )}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </CardBody>
      </Card>
    </div>
  );
}
