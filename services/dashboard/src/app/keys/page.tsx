import { KeyManager } from "@/components/key-manager";
import { listKeys } from "@/lib/api";
import { canManage, currentIdentity } from "@/lib/identity";

export const dynamic = "force-dynamic";

export default async function KeysPage() {
  const [keys, identity] = await Promise.all([listKeys(), currentIdentity()]);
  const manage = canManage(identity.role);
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">API keys</h1>
        <p className="text-[var(--muted)] text-sm">
          Per-key credentials, prefix <span className="mono">azn_live_</span> / <span className="mono">azn_test_</span>. The secret is
          shown once at creation; only its hash is stored.
        </p>
      </div>
      <KeyManager keys={keys} canManage={manage} />
    </div>
  );
}
