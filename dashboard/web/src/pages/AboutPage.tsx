import {
  BrainCircuit,
  Code2,
  GraduationCap,
  LockKeyhole,
  Network,
  ShieldCheck,
  UserRoundSearch,
  Users,
} from "lucide-react";

import { PageHeader } from "../components/PageHeader";

const team = ["محمد", "ندى", "ضحى"];

const architecture = [
  {
    icon: ShieldCheck,
    title: "Security core",
    text: "Python monitors SSH authentication activity, detects brute-force behavior, and coordinates response.",
  },
  {
    icon: LockKeyhole,
    title: "Protected response",
    text: "nftables enforcement remains isolated from dashboard clients and is never exposed through a write API.",
  },
  {
    icon: Network,
    title: "Reusable API",
    text: "FastAPI exposes a versioned, read-only contract for this dashboard and a future Windows client.",
  },
];

const roadmap = [
  {
    icon: UserRoundSearch,
    title: "SOC analyst workflow",
    text: "Alert triage, evidence review, temporary containment, analyst decisions, and incident response notes.",
  },
  {
    icon: BrainCircuit,
    title: "Human-guided AI",
    text: "Incident summaries, timeline explanation, clustering, and recommendations without autonomous firewall control.",
  },
  {
    icon: Users,
    title: "Role-based access",
    text: "Viewer, Analyst, and Administrator accounts with least privilege and a complete audit trail.",
  },
];

export function AboutPage() {
  return (
    <>
      <PageHeader
        description="The people, architecture, and future direction behind the SSHGuard graduation project."
        eyebrow="Project identity"
        title="About SSHGuard"
      />

      <section className="panel about-hero">
        <img
          alt="SSHGuard protecting SSH traffic before it reaches a Linux server"
          className="about-hero__image"
          src="/brand/sshguard-cover.png"
        />
        <div className="about-hero__copy">
          <span className="eyebrow">MISSION</span>
          <h2>Detect quickly. Contain safely. Investigate clearly.</h2>
          <p>
            SSHGuard is a defensive cybersecurity system that turns Linux SSH logs into structured
            security events, incidents, and controlled firewall responses while preserving a clear
            boundary between monitoring, response, and presentation.
          </p>
          <div className="about-tags">
            <span>Python</span><span>FastAPI</span><span>React</span><span>SQLite</span><span>nftables</span>
          </div>
        </div>
      </section>

      <section className="about-section">
        <div className="about-section__heading">
          <span className="eyebrow">SYSTEM DESIGN</span>
          <h2>Clear security boundaries</h2>
        </div>
        <div className="about-card-grid">
          {architecture.map(({ icon: Icon, title, text }) => (
            <article className="about-card" key={title}>
              <span className="about-card__icon"><Icon size={20} /></span>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="content-grid about-people-grid">
        <article className="panel about-panel">
          <div className="about-section__heading">
            <span className="eyebrow">PROJECT TEAM</span>
            <h2>Built by</h2>
          </div>
          <div className="team-list">
            {team.map((name, index) => (
              <div className="team-member" key={name}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong lang="ar" dir="rtl">{name}</strong>
                <small>Cybersecurity student</small>
              </div>
            ))}
          </div>
          <div className="supervisor-row">
            <GraduationCap size={19} />
            <div><span>Project supervisor</span><strong lang="ar" dir="rtl">المهندس عبدالرحمن</strong></div>
          </div>
        </article>

        <article className="panel about-panel">
          <div className="about-section__heading">
            <span className="eyebrow">ACADEMIC CONTEXT</span>
            <h2>University & training</h2>
          </div>
          <div className="affiliation-grid">
            <a
              aria-label="Philadelphia University official website"
              href="https://www.philadelphia.edu.jo/ar/"
              rel="noreferrer"
              target="_blank"
            >
              <img alt="Philadelphia University" src="/brand/philadelphia-university.png" />
            </a>
            <a
              aria-label="Pioneers Academy official website"
              href="https://www.pioneersacademy.com/en"
              rel="noreferrer"
              target="_blank"
            >
              <img alt="Pioneers Academy" src="/brand/pioneers-academy.svg" />
            </a>
          </div>
          <a
            className="about-github"
            href="https://github.com/thorestic/SSHGuard"
            rel="noreferrer"
            target="_blank"
          >
            <Code2 size={17} /> View project repository
          </a>
        </article>
      </section>

      <section className="about-section">
        <div className="about-section__heading">
          <span className="eyebrow">FUTURE VISION</span>
          <h2>Planned capabilities</h2>
          <p>These capabilities describe the roadmap and are not presented as active features.</p>
        </div>
        <div className="about-card-grid">
          {roadmap.map(({ icon: Icon, title, text }) => (
            <article className="about-card about-card--future" key={title}>
              <div className="about-card__top">
                <span className="about-card__icon"><Icon size={20} /></span>
                <span className="planned-badge">PLANNED</span>
              </div>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}
