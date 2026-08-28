import {
  Activity,
  BarChart3,
  Fingerprint,
  Info,
  LayoutDashboard,
  Menu,
  Server,
  Shield,
  ShieldAlert,
  X,
} from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";

const navigation = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/authentication", label: "Authentication", icon: Fingerprint },
  { to: "/firewall", label: "Firewall Actions", icon: Shield },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/about", label: "About", icon: Info },
];

export function AppShell() {
  const [open, setOpen] = useState(false);

  return (
    <div className="app-shell">
      <button
        aria-label="Open navigation"
        className="mobile-menu"
        onClick={() => setOpen(true)}
        type="button"
      >
        <Menu size={21} />
      </button>

      <aside className={`sidebar ${open ? "sidebar--open" : ""}`}>
        <div className="brand">
          <span className="brand__mark">
            <img alt="" src="/brand/sshguard-mark.png" />
          </span>
          <div>
            <strong>SSHGuard</strong>
            <span>Security Console</span>
          </div>
          <button
            aria-label="Close navigation"
            className="sidebar__close"
            onClick={() => setOpen(false)}
            type="button"
          >
            <X size={20} />
          </button>
        </div>

        <p className="sidebar__label">OPERATIONS</p>
        <nav className="navigation">
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink
              className={({ isActive }) => isActive ? "nav-link nav-link--active" : "nav-link"}
              end={to === "/"}
              key={to}
              onClick={() => setOpen(false)}
              to={to}
            >
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__system">
          <div className="system-row">
            <span className="live-dot" />
            <div><strong>Monitoring active</strong><span>Read-only console</span></div>
          </div>
          <div className="system-row">
            <Server size={16} />
            <div><strong>Linux sensor</strong><span>nftables protected</span></div>
          </div>
        </div>
      </aside>

      {open ? <button aria-label="Close navigation" className="backdrop" onClick={() => setOpen(false)} /> : null}

      <main className="main-content">
        <div className="topbar">
          <div className="topbar__status"><Activity size={15} /><span>Security telemetry</span></div>
          <span>{new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date())}</span>
        </div>
        <div className="page-content"><Outlet /></div>
      </main>
    </div>
  );
}

