import {
  ArrowLeft,
  BrainCircuit,
  FileSearch2,
  MonitorSmartphone,
  ShieldCheck,
  UserRoundCog,
  UsersRound,
} from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";

const roadmap = [
  {
    icon: UsersRound,
    title: "SOC analyst workflow",
    text: "Add triage queues, analyst decisions, investigation notes, and a documented incident-response workflow.",
  },
  {
    icon: UserRoundCog,
    title: "Authentication and roles",
    text: "Introduce sign-in and separate Viewer, Analyst, and Administrator permissions using least privilege.",
  },
  {
    icon: BrainCircuit,
    title: "Human-guided AI assistance",
    text: "Generate explainable summaries and recommendations while keeping firewall decisions under deterministic rules and human control.",
  },
  {
    icon: ShieldCheck,
    title: "Controlled response actions",
    text: "Design audited manual unblock and risk-based block policies with explicit authorization and safety controls.",
  },
  {
    icon: FileSearch2,
    title: "Broader security telemetry",
    text: "Evaluate additional Linux authentication and service logs without weakening the current SSH-focused security core.",
  },
  {
    icon: MonitorSmartphone,
    title: "Additional API clients",
    text: "Reuse the same versioned read-only API in a future Windows desktop client instead of rewriting detection logic.",
  },
];

export function RoadmapPage() {
  return (
    <>
      <Link className="back-link" to="/about"><ArrowLeft size={15} />Back to About</Link>
      <PageHeader
        description="A documented direction for later versions. These items are intentionally outside the current stable release."
        eyebrow="Future development"
        title="SSHGuard roadmap"
      />

      <section className="panel roadmap-notice">
        <span className="planned-badge">DOCUMENTATION ONLY</span>
        <div>
          <h2>Stable scope is frozen</h2>
          <p>The current product remains focused on SSH monitoring, deterministic detection, automated nftables containment, investigation, and read-only visibility.</p>
        </div>
      </section>

      <section className="roadmap-grid">
        {roadmap.map(({ icon: Icon, title, text }, index) => (
          <article className="roadmap-card" key={title}>
            <div className="roadmap-card__top">
              <span className="about-card__icon"><Icon size={20} /></span>
              <span>{String(index + 1).padStart(2, "0")}</span>
            </div>
            <h2>{title}</h2>
            <p>{text}</p>
            <span className="planned-badge">PLANNED</span>
          </article>
        ))}
      </section>
    </>
  );
}
