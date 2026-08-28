import { AlertTriangle, Database, LoaderCircle, RefreshCw } from "lucide-react";

export function LoadingState({ label = "Loading security data" }: { label?: string }) {
  return (
    <div className="state-card">
      <LoaderCircle className="spin" size={22} />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="state-card state-card--error">
      <AlertTriangle size={22} />
      <div>
        <strong>Security data unavailable</strong>
        <p>{message}</p>
      </div>
      <button className="button button--quiet" onClick={onRetry} type="button">
        <RefreshCw size={15} /> Retry
      </button>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="state-card">
      <Database size={22} />
      <span>{message}</span>
    </div>
  );
}

