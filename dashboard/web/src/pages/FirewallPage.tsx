import { Search, ShieldCheck, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { toQuery } from "../api/client";
import type {
  FirewallAction,
  FirewallReconciliation,
  PaginatedResponse,
} from "../api/types";
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
  const actions = useApi<PaginatedResponse<FirewallAction>>(path);
  const reconciliation = useApi<FirewallReconciliation>(
    "/firewall-reconciliation",
  );

  const refresh = () => {
    actions.refresh();
    reconciliation.refresh();
  };

  const integrity = reconciliation.data;
  const integrityTitle = integrity?.status === "in_sync"
    ? "Enforcement is in sync"
    : integrity?.status === "drift"
      ? "Enforcement drift detected"
      : integrity?.status === "unavailable"
        ? "Enforcement inspection unavailable"
        : integrity?.status === "stale"
          ? "Enforcement report is stale"
        : "Waiting for the first enforcement check";
  const integrityDetail = integrity?.status === "in_sync"
    ? "Stored active blocks match the addresses currently enforced by nftables."
    : integrity?.status === "drift"
      ? "The database and nftables disagree. SSHGuard is reporting the difference without changing firewall state."
      : integrity?.status === "unavailable"
        ? "The security core could not safely read the current nftables state. No automatic repair was attempted."
        : integrity?.status === "stale"
          ? "The last comparison is older than expected. The displayed counts may no longer represent current enforcement."
        : "The root security service has not published a reconciliation snapshot yet.";

  return (
    <>
      <PageHeader description="Audit every stored nftables lifecycle action and its originating incident." eyebrow="Response ledger" onRefresh={refresh} title="Firewall actions" />

      <section className={`panel reconciliation-panel reconciliation-panel--${integrity?.status ?? "pending"}`}>
        {reconciliation.loading && !integrity ? <LoadingState /> : null}
        {reconciliation.error && !integrity ? (
          <ErrorState message={reconciliation.error} onRetry={reconciliation.refresh} />
        ) : null}
        {integrity ? (
          <>
            <div className="reconciliation-panel__summary">
              <span className="reconciliation-panel__icon">
                {integrity.status === "in_sync" ? <ShieldCheck size={22} /> : <TriangleAlert size={22} />}
              </span>
              <div>
                <span className="eyebrow">ENFORCEMENT INTEGRITY</span>
                <h2>{integrityTitle}</h2>
                <p>{integrityDetail}</p>
              </div>
              <div className="reconciliation-panel__status">
                <StatusBadge value={integrity.status} />
                <small>Checked {formatDateTime(integrity.checked_at)}</small>
              </div>
            </div>

            <div className="reconciliation-metrics">
              <div><span>Expected in SQLite</span><strong>{integrity.expected_count}</strong></div>
              <div><span>Enforced by nftables</span><strong>{integrity.actual_count ?? "—"}</strong></div>
              <div><span>Missing in firewall</span><strong>{integrity.missing_in_firewall.length}</strong></div>
              <div><span>Unexpected in firewall</span><strong>{integrity.unexpected_in_firewall.length}</strong></div>
            </div>

            {integrity.status === "drift" ? (
              <div className="reconciliation-drift">
                <div>
                  <strong>Missing in firewall</strong>
                  {integrity.missing_in_firewall.length > 0
                    ? integrity.missing_in_firewall.map((address) => <code key={address}>{address}</code>)
                    : <span>None</span>}
                </div>
                <div>
                  <strong>Unexpected in firewall</strong>
                  {integrity.unexpected_in_firewall.length > 0
                    ? integrity.unexpected_in_firewall.map((address) => <code key={address}>{address}</code>)
                    : <span>None</span>}
                </div>
              </div>
            ) : null}
          </>
        ) : null}
      </section>

      <section className="panel">
        <div className="filters">
          <label className="search-field"><Search size={16} /><input onChange={(event) => { setSource(event.target.value); setOffset(0); }} placeholder="Filter source IP" value={source} /></label>
          <select onChange={(event) => { setAction(event.target.value); setOffset(0); }} value={action}><option value="">All actions</option><option value="block">Block</option><option value="expired">Expired</option><option value="manual_unblock">Manual unblock</option></select>
        </div>
        {actions.loading && !actions.data ? <LoadingState /> : null}
        {actions.error && !actions.data ? <ErrorState message={actions.error} onRetry={actions.refresh} /> : null}
        {actions.data?.items.length === 0 ? <EmptyState message="No firewall actions match the current filters." /> : null}
        {actions.data && actions.data.items.length > 0 ? (
          <div className="table-wrap"><table><thead><tr><th>Action ID</th><th>Action</th><th>Source</th><th>Incident</th><th>Related action</th><th>Applied</th><th>Expires</th></tr></thead><tbody>
            {actions.data.items.map((item) => <tr key={item.id}><td className="muted">#{item.id}</td><td><StatusBadge value={item.action} /></td><td><span className="mono">{item.source_ip}</span></td><td>{item.incident_id ? <Link className="incident-link" to={`/incidents/${item.incident_id}`}>#{item.incident_id}</Link> : "—"}</td><td>{item.related_action_id ? `#${item.related_action_id}` : "—"}</td><td>{formatDateTime(item.timestamp)}</td><td>{formatDateTime(item.expires_at)}</td></tr>)}
          </tbody></table></div>
        ) : null}
        {actions.data ? <PaginationControls limit={limit} offset={offset} onChange={setOffset} total={actions.data.pagination.total} /> : null}
      </section>
    </>
  );
}

