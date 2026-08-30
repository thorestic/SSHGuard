import {
  ArrowLeft,
  Ban,
  CheckCircle2,
  Clock3,
  Fingerprint,
  Network,
  ShieldAlert,
  UserRound,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";

import type { IncidentDetail } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { useApi } from "../hooks/useApi";
import { formatDateTime, humanize } from "../utils/format";

interface TimelineItem {
  id: string;
  timestamp: string;
  title: string;
  detail: string;
  tone: "evidence" | "detection" | "response" | "resolved";
}

export function IncidentDetailPage() {
  const { incidentId } = useParams();
  const { data, error, loading, refresh } = useApi<IncidentDetail>(
    `/incidents/${incidentId ?? ""}`,
  );

  if (loading && !data) return <LoadingState label="Loading incident evidence" />;
  if (error && !data) return <ErrorState message={error} onRetry={refresh} />;
  if (!data) return <EmptyState message="Incident details are unavailable." />;

  const { incident, authentication_events: evidence, firewall_actions: actions } = data;
  const timeline: TimelineItem[] = [
    ...evidence.map((event, index) => ({
      id: `auth-${event.id}`,
      timestamp: event.timestamp,
      title: `Failed authentication ${index + 1} of ${incident.attempt_count}`,
      detail: `${event.username ?? "Unknown user"} from source port ${event.source_port ?? "unknown"}${event.invalid_user ? " · username does not exist" : ""}`,
      tone: "evidence" as const,
    })),
    {
      id: `incident-${incident.id}`,
      timestamp: incident.last_seen,
      title: `Brute-force incident #${incident.id} detected`,
      detail: `${incident.attempt_count} failures crossed the configured threshold within ${incident.window_seconds} seconds.`,
      tone: "detection" as const,
    },
    ...actions.map((action) => ({
      id: `action-${action.id}`,
      timestamp: action.timestamp,
      title: action.action === "block"
        ? `Firewall action #${action.id} blocked the source`
        : action.action === "expired"
          ? `Firewall action #${action.id} recorded block expiration`
          : `Firewall action #${action.id}: ${humanize(action.action)}`,
      detail: action.action === "block"
        ? `nftables enforcement was scheduled to expire ${formatDateTime(action.expires_at)}.`
        : action.related_action_id
          ? `This lifecycle event relates to firewall action #${action.related_action_id}.`
          : "The response lifecycle was updated.",
      tone: action.action === "block" ? "response" as const : "resolved" as const,
    })),
  ].sort((left, right) => new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime());

  return (
    <>
      <Link className="back-link" to="/incidents"><ArrowLeft size={15} />Back to incidents</Link>
      <PageHeader
        description="Follow the evidence, detection decision, and automated response as one connected security story."
        eyebrow="Incident investigation"
        onRefresh={refresh}
        title={`Incident #${incident.id}`}
      />

      <section className="incident-summary panel">
        <div className="incident-summary__heading">
          <div><span className="eyebrow">CURRENT STATE</span><h2>Brute-force activity investigated</h2></div>
          <div className="incident-summary__badges">
            <span><small>Lifecycle</small><StatusBadge value={incident.status} /></span>
            <span><small>Response</small><StatusBadge value={incident.response_outcome} /></span>
          </div>
        </div>
        <div className="incident-facts">
          <div><Network size={17} /><span>Source IP</span><strong className="mono">{incident.source_ip}</strong></div>
          <div><UserRound size={17} /><span>Target account</span><strong>{incident.username ?? "Unknown"}</strong></div>
          <div><Fingerprint size={17} /><span>Failed attempts</span><strong>{incident.attempt_count}</strong></div>
          <div><Clock3 size={17} /><span>Detection window</span><strong>{incident.window_seconds}s</strong></div>
        </div>
      </section>

      <div className="incident-layout">
        <section className="panel">
          <div className="panel__header"><div><span className="eyebrow">CONNECTED STORY</span><h2>Incident timeline</h2></div><ShieldAlert size={19} /></div>
          <ol className="incident-timeline">
            {timeline.map((item) => (
              <li className={`incident-timeline__item incident-timeline__item--${item.tone}`} key={item.id}>
                <span className="incident-timeline__marker">
                  {item.tone === "resolved" ? <CheckCircle2 size={15} /> : item.tone === "response" ? <Ban size={15} /> : item.tone === "detection" ? <ShieldAlert size={15} /> : <Fingerprint size={15} />}
                </span>
                <div><time>{formatDateTime(item.timestamp)}</time><strong>{item.title}</strong><p>{item.detail}</p></div>
              </li>
            ))}
          </ol>
        </section>

        <aside className="incident-side">
          <section className="panel incident-context">
            <span className="eyebrow">DETECTION CONTEXT</span>
            <h2>Why it became an incident</h2>
            <p>The same source targeted the same username {incident.attempt_count} times between {formatDateTime(incident.first_seen)} and {formatDateTime(incident.last_seen)}.</p>
            <dl>
              <div><dt>Evidence records</dt><dd>{evidence.length}</dd></div>
              <div><dt>Response actions</dt><dd>{actions.length}</dd></div>
              <div><dt>Final response</dt><dd>{humanize(incident.response_outcome)}</dd></div>
            </dl>
          </section>
        </aside>
      </div>

      <section className="panel incident-evidence">
        <div className="panel__header"><div><span className="eyebrow">RAW EVIDENCE</span><h2>Authentication attempts used by detection</h2></div></div>
        {evidence.length === 0 ? <EmptyState message="No matching authentication evidence was found for this historical incident." /> : (
          <div className="table-wrap"><table><thead><tr><th>Event</th><th>Username</th><th>Source</th><th>Source port</th><th>User validity</th><th>Observed</th></tr></thead><tbody>
            {evidence.map((event) => <tr key={event.id}><td>#{event.id}</td><td>{event.username ?? "Unknown"}</td><td><span className="mono">{event.source_ip}</span></td><td>{event.source_port ?? "—"}</td><td className={event.invalid_user ? "invalid-user" : ""}>{event.invalid_user ? "Invalid user" : "Known user"}</td><td>{formatDateTime(event.timestamp)}</td></tr>)}
          </tbody></table></div>
        )}
      </section>
    </>
  );
}
