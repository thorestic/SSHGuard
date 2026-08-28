import { Search } from "lucide-react";
import { useMemo, useState } from "react";

import { toQuery } from "../api/client";
import type { AuthenticationEvent, PaginatedResponse } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { PaginationControls } from "../components/PaginationControls";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { useApi } from "../hooks/useApi";
import { formatDateTime } from "../utils/format";

const limit = 25;

export function AuthenticationPage() {
  const [offset, setOffset] = useState(0);
  const [eventType, setEventType] = useState("");
  const [source, setSource] = useState("");
  const path = useMemo(() => `/authentication-events${toQuery({ limit, offset, event_type: eventType, source_ip: source })}`, [offset, eventType, source]);
  const { data, error, loading, refresh } = useApi<PaginatedResponse<AuthenticationEvent>>(path);

  return (
    <>
      <PageHeader description="Review normalized SSH login activity captured by the monitoring pipeline." eyebrow="Identity telemetry" onRefresh={refresh} title="Authentication" />
      <section className="panel">
        <div className="filters">
          <label className="search-field"><Search size={16} /><input onChange={(event) => { setSource(event.target.value); setOffset(0); }} placeholder="Filter source IP" value={source} /></label>
          <select onChange={(event) => { setEventType(event.target.value); setOffset(0); }} value={eventType}><option value="">All outcomes</option><option value="failed_login">Failed login</option><option value="successful_login">Successful login</option></select>
        </div>
        {loading && !data ? <LoadingState /> : null}
        {error && !data ? <ErrorState message={error} onRetry={refresh} /> : null}
        {data?.items.length === 0 ? <EmptyState message="No authentication events match the current filters." /> : null}
        {data && data.items.length > 0 ? (
          <div className="table-wrap"><table><thead><tr><th>Time</th><th>Outcome</th><th>Source</th><th>Port</th><th>Username</th><th>User validity</th></tr></thead><tbody>
            {data.items.map((event) => <tr key={event.id}><td>{formatDateTime(event.timestamp)}</td><td><StatusBadge value={event.event_type} /></td><td><span className="mono">{event.source_ip}</span></td><td className="mono">{event.source_port ?? "—"}</td><td>{event.username ?? "Unknown"}</td><td>{event.invalid_user ? <span className="invalid-user">Invalid account</span> : <span className="muted">Known account</span>}</td></tr>)}
          </tbody></table></div>
        ) : null}
        {data ? <PaginationControls limit={limit} offset={offset} onChange={setOffset} total={data.pagination.total} /> : null}
      </section>
    </>
  );
}

