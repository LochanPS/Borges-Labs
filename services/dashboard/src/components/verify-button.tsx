"use client";
import * as React from "react";
import { BadgeCheck, ShieldAlert, Loader2 } from "lucide-react";
import { Button } from "@/components/ui";
import { verifyDecision, type VerifyOutcome } from "@/lib/verify";
import type { Decision, Jwks } from "@/lib/contracts";

/**
 * Verifies the decision's Ed25519 signature entirely in the browser against the
 * published public keys — no secret, no server round trip. The "tamper" control
 * mutates a signed field and re-verifies to show detection.
 */
export function VerifyButton({ decision, jwks }: { decision: Decision; jwks: Jwks }) {
  const [state, setState] = React.useState<"idle" | "checking">("idle");
  const [result, setResult] = React.useState<(VerifyOutcome & { tampered?: boolean }) | null>(null);

  async function run(tampered: boolean) {
    setState("checking");
    setResult(null);
    const subject = tampered
      ? { ...decision, verdict: decision.verdict === "APPROVE" ? "DENY" : "APPROVE" }
      : decision;
    const outcome = await verifyDecision(subject as Decision, jwks);
    setResult({ ...outcome, tampered });
    setState("idle");
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => run(false)} disabled={state === "checking"}>
          {state === "checking" ? <Loader2 className="size-4 animate-spin" /> : <BadgeCheck className="size-4" />}
          Verify signature
        </Button>
        <Button variant="outline" onClick={() => run(true)} disabled={state === "checking"}>
          <ShieldAlert className="size-4" />
          Simulate tamper
        </Button>
      </div>

      {result && (
        <div
          className={
            "rounded-md border p-3 text-sm " +
            (result.ok
              ? "border-[var(--approve)]/40 bg-[var(--approve)]/10 text-[var(--approve)]"
              : "border-[var(--deny)]/40 bg-[var(--deny)]/10 text-[var(--deny)]")
          }
        >
          {result.ok ? (
            <span className="flex items-center gap-2">
              <BadgeCheck className="size-4" /> Signature valid — verified client-side against key <span className="mono">{result.keyId}</span>.
            </span>
          ) : (
            <span className="flex items-center gap-2">
              <ShieldAlert className="size-4" />
              {result.tampered ? "Tampered decision rejected: " : "Verification failed: "}
              {result.reason}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
