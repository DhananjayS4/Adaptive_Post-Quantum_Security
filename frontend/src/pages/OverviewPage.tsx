import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { ConsoleChart } from "../components/ConsoleChart";
import {
  Badge,
  ErrorNotice,
  LoadingBlock,
  Metric,
  Panel,
} from "../components/ui";

function percent(value: unknown) {
  return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "—";
}

export function OverviewPage() {
  const status = useQuery({ queryKey: ["status"], queryFn: api.status });
  const results = useQuery({ queryKey: ["results"], queryFn: api.results });

  if (status.isLoading || results.isLoading) return <LoadingBlock />;
  if (status.error) return <ErrorNotice error={status.error} />;
  if (results.error) return <ErrorNotice error={results.error} />;

  const data = status.data!;
  const train = results.data?.train ?? {};
  const benchmark = results.data?.benchmark ?? {};
  const demo = results.data?.demo ?? {};
  const latency = benchmark.latency ?? {};
  const workload = benchmark.central_workload ?? demo.adaptive_vs_send_all ?? {};
  const reduction = workload.reduction ?? {};
  const profiles = demo.profiles ?? {};

  const latencyOption = {
    legend: { data: ["Median", "P95", "P99"], textStyle: { color: "#95a3b7" } },
    xAxis: {
      type: "category" as const,
      data: ["Inference", "Policy", "Protect", "Open"],
    },
    yAxis: { type: "value" as const, name: "ms" },
    series: [
      {
        name: "Median",
        type: "bar" as const,
        data: [
          latency.inference_ms?.median,
          latency.policy_ms?.median,
          latency.security_classical?.protect_ms?.median,
          latency.security_classical?.open_ms?.median,
        ],
      },
      {
        name: "P95",
        type: "bar" as const,
        data: [
          latency.inference_ms?.p95,
          latency.policy_ms?.p95,
          latency.security_classical?.protect_ms?.p95,
          latency.security_classical?.open_ms?.p95,
        ],
      },
      {
        name: "P99",
        type: "bar" as const,
        data: [
          latency.inference_ms?.p99,
          latency.policy_ms?.p99,
          latency.security_classical?.protect_ms?.p99,
          latency.security_classical?.open_ms?.p99,
        ],
      },
    ],
  };

  const workloadOption = {
    tooltip: { trigger: "axis" as const },
    legend: { data: ["Send all", "Adaptive"], textStyle: { color: "#95a3b7" } },
    xAxis: { type: "category" as const, data: ["Messages", "Bytes"] },
    yAxis: { type: "log" as const },
    series: [
      {
        name: "Send all",
        type: "bar" as const,
        data: [workload.send_all?.messages ?? 0, workload.send_all?.bytes ?? 0],
      },
      {
        name: "Adaptive",
        type: "bar" as const,
        data: [workload.adaptive?.messages ?? 0, workload.adaptive?.bytes ?? 0],
      },
    ],
  };

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Operational summary</p>
          <h1>System overview</h1>
          <p>Edge policy, protected transport, and firmware assurance telemetry.</p>
        </div>
        <Badge tone={data.assurance.secure_boot_allowed ? "ok" : "critical"}>
          Secure boot {data.assurance.secure_boot_allowed ? "verified" : "unverified"}
        </Badge>
      </div>

      <div className="metric-grid">
        <Metric
          label="Message reduction"
          value={percent(reduction.messages)}
          status="ok"
        />
        <Metric label="Byte reduction" value={percent(reduction.bytes)} />
        <Metric
          label="Accepted deliveries"
          value={data.edge.accepted_deliveries.toLocaleString()}
        />
        <Metric
          label="Fail-closed events"
          value={data.edge.fail_closed.toLocaleString()}
          status={data.edge.fail_closed > 0 ? "warn" : "ok"}
        />
        <Metric
          label="Held-out F1"
          value={
            typeof train.held_out_test_metrics?.f1 === "number"
              ? train.held_out_test_metrics.f1.toFixed(3)
              : "—"
          }
        />
        <Metric
          label="PQC provider"
          value={data.assurance.pqc.available ? "Available" : "Fallback"}
          status={data.assurance.pqc.available ? "ok" : "warn"}
        />
      </div>

      <div className="content-grid two-thirds">
        <Panel
          title="Pipeline latency"
          detail="Median, p95 and p99 measured execution time"
        >
          <ConsoleChart option={latencyOption} height={300} />
        </Panel>
        <Panel title="Runtime state" detail="Current generated artifacts and controls">
          <dl className="key-value-list">
            <div><dt>Model version</dt><dd>{data.model.version ?? "Not loaded"}</dd></div>
            <div><dt>Dataset</dt><dd>{data.model.dataset ?? "—"}</dd></div>
            <div><dt>Calibration</dt><dd>{data.model.calibrated ? "Enabled" : "Disabled"}</dd></div>
            <div><dt>Active firmware slot</dt><dd>{data.assurance.active_slot ?? "—"}</dd></div>
            <div><dt>Records replayed</dt><dd>{data.edge.records_replayed.toLocaleString()}</dd></div>
            <div><dt>Console snapshot</dt><dd>{new Date(data.generated_at).toLocaleTimeString()}</dd></div>
          </dl>
        </Panel>
      </div>

      <div className="content-grid equal">
        <Panel title="Central workload" detail="Adaptive edge processing versus send-all">
          <ConsoleChart option={workloadOption} height={260} />
        </Panel>
        <Panel title="Protection profiles" detail="Decisions recorded in the latest replay">
          <div className="distribution-list">
            {Object.entries(profiles).map(([label, count]) => (
              <div key={label}>
                <span>{label.replaceAll("_", " ")}</span>
                <strong>{String(count)}</strong>
                <i
                  style={{
                    width: `${Math.max(3, (Number(count) / Math.max(...Object.values(profiles).map(Number))) * 100)}%`,
                  }}
                />
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
