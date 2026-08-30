export interface Pagination {
  total: number;
  limit: number;
  offset: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: Pagination;
}

export interface Incident {
  id: number;
  source_ip: string;
  username: string | null;
  attempt_count: number;
  first_seen: string;
  last_seen: string;
  window_seconds: number;
  status: string;
  response_outcome: string | null;
}

export interface AuthenticationEvent {
  id: number;
  event_type: string;
  username: string | null;
  source_ip: string;
  source_port: number | null;
  invalid_user: boolean;
  timestamp: string;
}

export interface FirewallAction {
  id: number;
  source_ip: string;
  action: string;
  timestamp: string;
  expires_at: string | null;
  incident_id: number | null;
  related_action_id: number | null;
}

export interface FirewallReconciliation {
  status: "pending" | "in_sync" | "drift" | "unavailable" | "stale";
  checked_at: string | null;
  expected_count: number;
  actual_count: number | null;
  missing_in_firewall: string[];
  unexpected_in_firewall: string[];
  error_code: string | null;
}

export interface OverviewMetrics {
  incidents_total: number;
  incidents_24h: number;
  failed_logins_24h: number;
  successful_logins_24h: number;
  active_blocks: number;
  unique_sources_24h: number;
}

export interface OverviewResponse {
  generated_at: string;
  metrics: OverviewMetrics;
  recent_incidents: Incident[];
}

export interface TimeBucket {
  bucket: string;
  authentication_events: number;
  incidents: number;
}

export interface RankedValue {
  value: string;
  count: number;
}

export interface BreakdownValue {
  label: string;
  count: number;
}

export interface AnalyticsResponse {
  generated_at: string;
  hours: number;
  timeline: TimeBucket[];
  top_sources: RankedValue[];
  targeted_users: RankedValue[];
  incident_statuses: BreakdownValue[];
  response_outcomes: BreakdownValue[];
}

