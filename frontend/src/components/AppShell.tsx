import {
  Activity,
  Beaker,
  Binary,
  Gauge,
  Radio,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

const navigation = [
  { to: "/", label: "Overview", icon: Gauge },
  { to: "/policy", label: "Policy decisions", icon: Binary },
  { to: "/messaging", label: "Secure messaging", icon: Radio },
  { to: "/experiments", label: "Experiments", icon: Beaker },
  { to: "/firmware", label: "Firmware assurance", icon: ShieldCheck },
];

export function AppShell() {
  const health = useQuery({
    queryKey: ["status"],
    queryFn: api.status,
    refetchInterval: 15_000,
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">VX</div>
          <div>
            <strong>Adaptive V2X</strong>
            <span>Security Console</span>
          </div>
        </div>
        <nav aria-label="Primary navigation">
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) => (isActive ? "active" : undefined)}
            >
              <Icon size={17} strokeWidth={1.8} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className={`status-dot ${health.isError ? "critical" : "ok"}`} />
          <div>
            <strong>{health.isError ? "API unavailable" : "API operational"}</strong>
            <span>Refresh interval 15s</span>
          </div>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="environment">
            <Activity size={15} />
            <span>EDGE SECURITY</span>
            <span className="separator">/</span>
            <strong>RESEARCH LAB</strong>
          </div>
          <div className="topbar-meta">
            <span>Model {health.data?.model.version ?? "not loaded"}</span>
            <span className="live-indicator">
              <i />
              LIVE
            </span>
          </div>
        </header>
        <div className="page-container">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
