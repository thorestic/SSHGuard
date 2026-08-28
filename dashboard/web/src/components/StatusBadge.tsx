import { humanize } from "../utils/format";

const positive = new Set(["resolved", "successful_login", "expired"]);
const negative = new Set(["blocked", "response_failed", "failed_login", "block"]);
const warning = new Set(["detected", "response_skipped", "manual_unblock"]);

export function StatusBadge({ value }: { value: string | null }) {
  const normalized = value ?? "pending";
  const tone = positive.has(normalized)
    ? "positive"
    : negative.has(normalized)
      ? "negative"
      : warning.has(normalized)
        ? "warning"
        : "neutral";

  return <span className={`status status--${tone}`}>{humanize(value)}</span>;
}

