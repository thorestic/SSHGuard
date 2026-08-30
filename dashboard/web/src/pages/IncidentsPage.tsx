import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { toQuery } from "../api/client";
import type { Incident, PaginatedResponse } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { PaginationControls } from "../components/PaginationControls";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { useApi } from "../hooks/useApi";
import { formatDateTime } from "../utils/format";

const limit = 20;

export function IncidentsPage() {
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState("");
  const [source, setSource] = useState("");
  const path = useMemo(() => `/incidents${toQuery({ limit, offset, status, source_ip: source })}`, [offset, status, source]);
  const { data, error, loading, refresh } = useApi<PaginatedResponse<Incident>>(path);

  return (
    <>
      <PageHeader description="Investigate brute-force detections and the outcome of each automated response." eyebrow="Detection ledger" onRefresh={refresh} title="Incidents" />
      <section className="panel">
        <div className="filters">
          <label className="search-field"><Search size={16} /><input onChange={(event) => { setSource(event.target.value); setOffset(0); }} placeholder="Filter source IP" value={source} /></label>
          <select onChange={(event) => { setStatus(event.target.value); setOffset(0); }} value={status}>
            <option value="">All statuses</option>
            <option value="detected">Detected</option>
            <option value="blocked">Blocked</option>
            <option value="resolved">Resolved</option>
            <option value="response_skipped">Response skipped</option>
            <option value="response_failed">Response failed</option>
          </select>
        </div>
        {loading && !data ? <LoadingState /> : null}
        {error && !data ? <ErrorState message={error} onRetry={refresh} /> : null}
        {data?.items.length === 0 ? <EmptyState message="No incidents match the current filters." /> : null}
        {data && data.items.length > 0 ? (
          <div className="table-wrap"><table><thead><tr><th>ID</th><th>Source</th><th>Target</th><th>Attempts</th><th>Status</th><th>Response</th><th>First seen</th><th>Last seen</th><th>Investigation</th></tr></thead><tbody>
            {data.items.map((incident) => <tr key={incident.id}><td><Link className="incident-link" to={`/incidents/${incident.id}`}>#{incident.id}</Link></td><td><span className="mono">{incident.source_ip}</span></td><td>{incident.username ?? "Unknown"}</td><td><strong>{incident.attempt_count}</strong><span className="cell-note">/{incident.window_seconds}s</span></td><td><StatusBadge value={incident.status} /></td><td><StatusBadge value={incident.response_outcome} /></td><td>{formatDateTime(incident.first_seen)}</td><td>{formatDateTime(incident.last_seen)}</td><td><Link className="text-link" to={`/incidents/${incident.id}`}>View details →</Link></td></tr>)}
          </tbody></table></div>
        ) : null}
        {data ? <PaginationControls limit={limit} offset={offset} onChange={setOffset} total={data.pagination.total} /> : null}
      </section>
    </>
  );
}

