import { RefreshCw } from "lucide-react";

export function PageHeader({
  eyebrow,
  title,
  description,
  onRefresh,
}: {
  eyebrow: string;
  title: string;
  description: string;
  onRefresh?: () => void;
}) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {onRefresh ? (
        <button className="button button--quiet" onClick={onRefresh} type="button">
          <RefreshCw size={16} /> Refresh
        </button>
      ) : null}
    </header>
  );
}

