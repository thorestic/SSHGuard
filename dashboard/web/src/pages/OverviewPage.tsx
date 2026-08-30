import { Ban, CircleCheck, Network, ShieldAlert, TriangleAlert, Users } from "lucide-react";
import { Link } from "react-router-dom";

import type { OverviewResponse } from "../api/types";
import { MetricCard } from "../components/MetricCard";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { useApi } from "../hooks/useApi";
import { formatDateTime } from "../utils/format";

export function OverviewPage() {
  const { data, error, loading, refresh } = useApi<OverviewResponse>("/overview");

  return (
    <>
      <PageHeader
        description="A consolidated view of authentication pressure, detected incidents, and automated response."
        eyebrow="Security posture"
        onRefresh={refresh}
        title="Operations overview"
      />

      {loading && !data ? <LoadingState /> : null}
      {error && !data ? <ErrorState message={error} onRetry={refresh} /> : null}

      {data ? (
        <>
          <section className="metric-grid">
            <MetricCard detail="Recorded across all time" icon={ShieldAlert} label="Total incidents" value={data.metrics.incidents_total} />
            <MetricCard detail="Detected during the last 24 hours" icon={TriangleAlert} label="Incidents · 24h" tone="danger" value={data.metrics.incidents_24h} />
            <MetricCard detail="Rejected SSH authentication attempts" icon={Ban} label="Failed logins · 24h" tone="danger" value={data.metrics.failed_logins_24h} />
            <MetricCard detail="Expected from active SQLite records" icon={Network} label="Active blocks" value={data.metrics.active_blocks} />
            <MetricCard detail="Distinct IP addresses observed" icon={Users} label="Unique sources · 24h" value={data.metrics.unique_sources_24h} />
            <MetricCard detail="Accepted SSH sessions" icon={CircleCheck} label="Successful logins · 24h" tone="success" value={data.metrics.successful_logins_24h} />
          </section>

          <section className="content-grid content-grid--wide">
            <article className="panel">
              <div className="panel__header">
                <div><span className="eyebrow">LATEST DETECTIONS</span><h2>Recent incidents</h2></div>
                <Link className="text-link" to="/incidents">View all</Link>
              </div>
              {data.recent_incidents.length === 0 ? (
                <EmptyState message="No security incidents have been recorded." />
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Source</th><th>Target</th><th>Attempts</th><th>Status</th><th>Last seen</th></tr></thead>
                    <tbody>
                      {data.recent_incidents.map((incident) => (
                        <tr key={incident.id}>
                          <td><span className="mono">{incident.source_ip}</span></td>
                          <td>{incident.username ?? "Unknown"}</td>
                          <td>{incident.attempt_count}</td>
                          <td><StatusBadge value={incident.status} /></td>
                          <td>{formatDateTime(incident.last_seen)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </article>

            <aside className="panel integrity-panel">
              <span className="eyebrow">CONTROL PLANE</span>
              <h2>Protection integrity</h2>
              <div className="integrity-score"><strong>Read-only</strong><span>API posture</span></div>
              <ul className="check-list">
                <li><CircleCheck size={16} />Security core remains isolated</li>
                <li><CircleCheck size={16} />SQLite opened in query-only mode</li>
                <li><CircleCheck size={16} />nftables is not exposed to clients</li>
                <li><CircleCheck size={16} />Versioned API contract</li>
              </ul>
              <p className="updated-at">Snapshot {formatDateTime(data.generated_at)}</p>
            </aside>
          </section>
        </>
      ) : null}
    </>
  );
}

