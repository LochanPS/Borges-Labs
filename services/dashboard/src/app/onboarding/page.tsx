"use client";
import * as React from "react";
import Link from "next/link";
import { useActionState } from "react";
import { KeyRound, Copy, Check, CheckCircle2, Circle } from "lucide-react";
import { Button, Card, CardBody, CardHeader, CardTitle, Badge } from "@/components/ui";
import { createKeyAction } from "@/lib/actions";

export default function OnboardingPage() {
  const [state, formAction, pending] = useActionState(createKeyAction, null);
  const secret = state?.key?.secret;
  const key = secret ?? "azn_test_YOUR_KEY";
  const [lang, setLang] = React.useState<"py" | "ts">("py");
  const [copied, setCopied] = React.useState(false);
  const [activity, setActivity] = React.useState<number | null>(null);

  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch {}
  }
  async function checkActivity() {
    try { const r = await fetch("/api/activity", { cache: "no-store" }); setActivity((await r.json()).decisions); } catch { setActivity(0); }
  }

  const snippet = lang === "py"
    ? `pip install trust-infra-sdk\n\nfrom trust_infra import Client\nclient = Client(api_key="${key}", base_url="https://<your-host>")\nclient.authorize(txn).enforce()   # raises unless APPROVE\ncharge(txn)`
    : `npm install @trust-infra/sdk\n\nimport { Client } from "@trust-infra/sdk";\nconst client = new Client({ apiKey: "${key}", baseUrl: "https://<your-host>" });\n(await client.authorize(txn)).enforce();  // throws unless APPROVE\nawait charge(txn);`;

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-semibold">Connect your agent</h1>
        <p className="text-[var(--muted)] text-sm">Key → first authorize in three steps. New keys are shadow (advisory) by default — safe to run against real traffic.</p>
      </div>

      <Step n={1} title="Get a test key" done={!!secret}>
        {secret ? (
          <div className="rounded-md border border-[var(--review)]/40 bg-[var(--review)]/10 p-3">
            <div className="text-[var(--review)] text-sm mb-2">Copy this key now — it is shown once.</div>
            <div className="flex items-center gap-2">
              <code className="mono text-sm break-all flex-1 rounded bg-[var(--panel)] border border-[var(--line)] px-3 py-2">{secret}</code>
              <Button variant="outline" size="sm" type="button" onClick={() => copy(secret)}>
                {copied ? <Check className="size-4" /> : <Copy className="size-4" />} Copy
              </Button>
            </div>
          </div>
        ) : (
          <form action={formAction} className="flex items-center gap-3">
            <input type="hidden" name="env" value="test" />
            <input type="hidden" name="shadow" value="on" />
            <Button type="submit" disabled={pending}><KeyRound className="size-4" /> {pending ? "Minting…" : "Create test key"}</Button>
            {state?.error && <span className="text-sm text-[var(--deny)]">{state.error} — ask an admin, or create one under <Link href="/keys" className="text-[var(--accent)]">API keys</Link>.</span>}
          </form>
        )}
      </Step>

      <Step n={2} title="Add the SDK to your agent" done={false}>
        <div className="flex gap-1 mb-2">
          {(["py", "ts"] as const).map((l) => (
            <button key={l} onClick={() => setLang(l)} className={"px-3 py-1 text-xs rounded-md border " + (lang === l ? "bg-[var(--accent)] text-[var(--accent-fg)] border-[var(--accent)]" : "border-[var(--line)]")}>
              {l === "py" ? "Python" : "TypeScript"}
            </button>
          ))}
        </div>
        <div className="relative">
          <pre className="rounded-md bg-[#0f1419] text-[#e6edf3] p-4 text-xs overflow-x-auto mono">{snippet}</pre>
          <button onClick={() => copy(snippet)} className="absolute top-2 right-2 text-xs rounded border border-white/20 text-white/80 px-2 py-1">Copy</button>
        </div>
      </Step>

      <Step n={3} title="Run it and watch decisions arrive" done={(activity ?? 0) > 0}>
        <p className="text-sm text-[var(--muted)] mb-3">
          Try it now in the <Link href="/playground" className="text-[var(--accent)]">Playground</Link>, or run the free demo agent:
        </p>
        <pre className="rounded-md bg-[#0f1419] text-[#e6edf3] p-3 text-xs overflow-x-auto mono">python examples/demo-agent/agent.py</pre>
        <div className="flex items-center gap-3 mt-3">
          <Button variant="outline" type="button" onClick={checkActivity}>Check for activity</Button>
          {activity !== null && (
            <Badge className={activity > 0 ? "text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10" : "text-[var(--muted)]"}>
              {activity > 0 ? `${activity} decision${activity === 1 ? "" : "s"} seen` : "no decisions yet"}
            </Badge>
          )}
        </div>
      </Step>
    </div>
  );
}

function Step({ n, title, done, children }: { n: number; title: string; done: boolean; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="flex items-center gap-3">
        {done ? <CheckCircle2 className="size-5 text-[var(--approve)]" /> : <Circle className="size-5 text-[var(--muted)]" />}
        <CardTitle>Step {n} · {title}</CardTitle>
      </CardHeader>
      <CardBody>{children}</CardBody>
    </Card>
  );
}
