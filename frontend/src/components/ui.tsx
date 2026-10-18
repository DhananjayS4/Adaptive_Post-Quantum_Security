import type { ReactNode } from "react";

export function Panel({
  title,
  detail,
  actions,
  children,
  className = "",
}: {
  title: string;
  detail?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-header">
        <div>
          <h2>{title}</h2>
          {detail && <p>{detail}</p>}
        </div>
        {actions && <div className="panel-actions">{actions}</div>}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function Metric({
  label,
  value,
  unit,
  status,
}: {
  label: string;
  value: string | number;
  unit?: string;
  status?: "ok" | "warn" | "critical" | "neutral";
}) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value">
        {status && <span className={`status-dot ${status}`} />}
        {value}
        {unit && <span className="metric-unit">{unit}</span>}
      </div>
    </div>
  );
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "ok" | "warn" | "critical" | "neutral" | "info";
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

export function ErrorNotice({ error }: { error: Error }) {
  return (
    <div className="notice critical" role="alert">
      <strong>Request failed</strong>
      <span>{error.message}</span>
    </div>
  );
}

export function LoadingBlock() {
  return <div className="loading-block">Loading current telemetry…</div>;
}

export function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}
