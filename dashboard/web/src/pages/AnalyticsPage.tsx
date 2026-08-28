import { BarChart3 } from "lucide-react";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { toQuery } from "../api/client";
import type { AnalyticsResponse, RankedValue } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { useApi } from "../hooks/useApi";
import { formatShortTime, humanize } from "../utils/format";

function Ranking({ items, empty, title }: { items: RankedValue[]; empty: string; title: string }) {
  const maximum = Math.max(...items.map((item) => item.count), 1);
  return <article className="panel ranking"><div className="panel__header"><div><span className="eyebrow">RANKING</span><h2>{title}</h2></div></div>{items.length === 0 ? <EmptyState message={empty} /> : <ol>{items.map((item, index) => <li key={item.value}><span className="ranking__index">{String(index + 1).padStart(2, "0")}</span><span className="mono ranking__value">{item.value}</span><span className="ranking__bar"><i style={{ width: `${(item.count / maximum) * 100}%` }} /></span><strong>{item.count}</strong></li>)}</ol>}</article>;
}

export function AnalyticsPage() {
  const [hours, setHours] = useState(24);
  const { data, error, loading, refresh } = useApi<AnalyticsResponse>(`/analytics${toQuery({ hours })}`);
  const timeline = data?.timeline.map((item) => ({ ...item, label: formatShortTime(item.bucket) })) ?? [];

  return (
    <>
      <PageHeader description="Explore attack volume, source concentration, target accounts, and response outcomes." eyebrow="Threat intelligence" onRefresh={refresh} title="Analytics" />
      <div className="analytics-toolbar"><span>Analysis window</span><div>{[24, 72, 168, 720].map((value) => <button className={hours === value ? "chip chip--active" : "chip"} key={value} onClick={() => setHours(value)} type="button">{value === 24 ? "24h" : value === 72 ? "3d" : value === 168 ? "7d" : "30d"}</button>)}</div></div>
      {loading && !data ? <LoadingState label="Calculating threat analytics" /> : null}
      {error && !data ? <ErrorState message={error} onRetry={refresh} /> : null}
      {data ? <>
        <section className="content-grid">
          <article className="panel chart-panel"><div className="panel__header"><div><span className="eyebrow">TIME SERIES</span><h2>Authentication pressure</h2></div><BarChart3 size={19} /></div>{timeline.length === 0 ? <EmptyState message="No timeline data is available for this period." /> : <div className="chart"><ResponsiveContainer height="100%" width="100%"><LineChart data={timeline}><CartesianGrid stroke="#24332f" strokeDasharray="3 5" vertical={false} /><XAxis axisLine={false} dataKey="label" minTickGap={28} tick={{ fill: "#82938e", fontSize: 11 }} tickLine={false} /><YAxis axisLine={false} allowDecimals={false} tick={{ fill: "#82938e", fontSize: 11 }} tickLine={false} width={30} /><Tooltip contentStyle={{ background: "#101c19", border: "1px solid #2b3d38", borderRadius: 8 }} /><Legend /><Line dataKey="authentication_events" dot={false} name="Authentication events" stroke="#6ee7b7" strokeWidth={2} type="monotone" /><Line dataKey="incidents" dot={false} name="Incidents" stroke="#fb7185" strokeWidth={2} type="monotone" /></LineChart></ResponsiveContainer></div>}</article>
          <article className="panel chart-panel"><div className="panel__header"><div><span className="eyebrow">DISTRIBUTION</span><h2>Incident status</h2></div></div>{data.incident_statuses.length === 0 ? <EmptyState message="No incidents occurred in this period." /> : <div className="chart"><ResponsiveContainer height="100%" width="100%"><BarChart data={data.incident_statuses.map((item) => ({ ...item, label: humanize(item.label) }))}><CartesianGrid stroke="#24332f" strokeDasharray="3 5" vertical={false} /><XAxis axisLine={false} dataKey="label" tick={{ fill: "#82938e", fontSize: 11 }} tickLine={false} /><YAxis axisLine={false} allowDecimals={false} tick={{ fill: "#82938e", fontSize: 11 }} tickLine={false} width={30} /><Tooltip contentStyle={{ background: "#101c19", border: "1px solid #2b3d38", borderRadius: 8 }} /><Bar dataKey="count" fill="#5ee6b3" name="Incidents" radius={[5, 5, 0, 0]} /></BarChart></ResponsiveContainer></div>}</article>
        </section>
        <section className="content-grid"><Ranking empty="No source activity in this period." items={data.top_sources} title="Top source addresses" /><Ranking empty="No targeted accounts in this period." items={data.targeted_users} title="Targeted usernames" /></section>
        <article className="panel outcome-strip"><div><span className="eyebrow">AUTOMATED RESPONSE</span><h2>Response outcomes</h2></div><div className="outcome-strip__items">{data.response_outcomes.map((item) => <div key={item.label}><strong>{item.count}</strong><span>{humanize(item.label)}</span></div>)}</div></article>
      </> : null}
    </>
  );
}

