import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

// Button ------------------------------------------------------------------- //
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]",
  {
    variants: {
      variant: {
        primary: "bg-[var(--accent)] text-[var(--accent-fg)] hover:opacity-90",
        outline: "border border-[var(--line)] bg-[var(--panel)] hover:bg-[var(--bg)]",
        ghost: "hover:bg-[var(--bg)]",
        danger: "border border-[var(--deny)] text-[var(--deny)] hover:bg-[var(--deny)] hover:text-white",
      },
      size: { sm: "h-8 px-3", md: "h-9 px-4", lg: "h-10 px-5 text-base" },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  ),
);
Button.displayName = "Button";

// Card --------------------------------------------------------------------- //
export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-[var(--line)] bg-[var(--panel)]", className)} {...props} />;
}
export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5 border-b border-[var(--line)]", className)} {...props} />;
}
export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("font-semibold tracking-tight", className)} {...props} />;
}
export function CardBody({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5", className)} {...props} />;
}

// Badge -------------------------------------------------------------------- //
export function Badge({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium border border-[var(--line)]", className)}
      {...props}
    />
  );
}

const VERDICT_STYLES: Record<string, string> = {
  APPROVE: "text-[var(--approve)] border-[var(--approve)]/40 bg-[var(--approve)]/10",
  DENY: "text-[var(--deny)] border-[var(--deny)]/40 bg-[var(--deny)]/10",
  REVIEW: "text-[var(--review)] border-[var(--review)]/40 bg-[var(--review)]/10",
};
export function VerdictBadge({ verdict }: { verdict: string }) {
  return <Badge className={cn("mono", VERDICT_STYLES[verdict] ?? "")}>{verdict}</Badge>;
}

// Inputs ------------------------------------------------------------------- //
export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-md border border-[var(--line)] bg-[var(--panel)] px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]",
        className,
      )}
      {...props}
    />
  );
}
export function Textarea({ className, ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "w-full rounded-md border border-[var(--line)] bg-[var(--panel)] p-3 text-sm mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]",
        className,
      )}
      {...props}
    />
  );
}
export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("text-sm font-medium", className)} {...props} />;
}

// Table -------------------------------------------------------------------- //
export function Table({ className, ...props }: React.TableHTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full text-sm", className)} {...props} />
    </div>
  );
}
export function Th({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return <th className={cn("text-left font-medium text-[var(--muted)] px-3 py-2 border-b border-[var(--line)]", className)} {...props} />;
}
export function Td({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("px-3 py-2 border-b border-[var(--line)] align-top", className)} {...props} />;
}
