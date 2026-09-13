import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function formatAmount(amount?: string, currency?: string): string {
  if (!amount) return "—";
  return currency ? `${amount} ${currency}` : amount;
}

export function shortId(id: string, head = 10): string {
  return id.length > head + 4 ? `${id.slice(0, head)}…${id.slice(-4)}` : id;
}

export function formatTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}
