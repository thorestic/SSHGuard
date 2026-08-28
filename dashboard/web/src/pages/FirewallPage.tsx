import { Search } from "lucide-react";
import { useMemo, useState } from "react";

import { toQuery } from "../api/client";
import type { FirewallAction, PaginatedResponse } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { PaginationControls } from "../components/PaginationControls";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { useApi } from "../hooks/useApi";
import { formatDateTime } from "../utils/format";

const limit = 20;

export function FirewallPage() {
  const [offset, setOffset] = useState(0);
  const [action, setAction] = useState("");
  const [source, setSource] = useState("");
  const path = useMemo(() => `/firewall-actions${toQuery({ limit, offset, action, source_ip: source })}`, [offset, action, source]);
  const { data, error, loading, refresh } = useApi<PaginatedResponse<FirewallAction>>(path);

  return (
    <>
      <PageHeader description="Audit every stored nftables lifecycle action and its originating incident." eyebrow="Response ledger" onRefresh={refresh} title="Firewall actions" />
      <section className="panel">
        <div className="filters">
          <label className="search-field"><Search size={16} /><input onChange={(event) => { setSource(event.target.value); setOffset(0); }} placeholder="Filter source IP" value={source} /></label>
          <select onChange={(event) => { setAction(event.target.value); setOffset(0); }} value={action}><option value="">All actions</option><option value="block">Block</option><option value="expired">Expired</option><option value="manual_unblock">Manual unblock</option></select>
        </div>
        {loading && !data ? <LoadingState /> : null}
        {error && !data ? <ErrorState message={error} onRetry={refresh} /> : null}
        {data?.items.length === 0 ? <EmptyState message="No firewall actions match the current filters." /> : null}
        {data && data.items.length > 0 ? (
          <div className="table-wrap"><table><thead><tr><th>Action ID</th><th>Action</th><th>Source</th><th>Incident</th><th>Related action</th><th>Applied</th><th>Expires</th></tr></thead><tbody>
            {data.items.map((item) => <tr key={item.id}><td className="muted">#{item.id}</td><td><StatusBadge value={item.action} /></td><td><span className="mono">{item.source_ip}</span></td><td>{item.incident_id ? `#${item.incident_id}` : "—"}</td><td>{item.related_action_id ? `#${item.related_action_id}` : "—"}</td><td>{formatDateTime(item.timestamp)}</td><td>{formatDateTime(item.expires_at)}</td></tr>)}
          </tbody></table></div>
        ) : null}
        {data ? <PaginationControls limit={limit} offset={offset} onChange={setOffset} total={data.pagination.total} /> : null}
      </section>
    </>
  );
}

