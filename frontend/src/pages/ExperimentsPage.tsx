import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { Badge, ErrorNotice, Panel } from "../components/ui";

const experimentDescriptions: Record<string, string> = {
  audit: "Inspect schema, labels, duplicates, and bounded dataset quality.",
  train: "Fit and calibrate the edge threat classifier.",
  demo: "Replay records through protected simulated ECUs.",
  benchmark: "Measure policy, model, cryptographic, and workload performance.",
};

export function ExperimentsPage() {
  const [kind, setKind] = useState("demo");
  const [rows, setRows] = useState(20);
  const [iterations, setIterations] = useState(20);
  const queryClient = useQueryClient();
  const jobs = useQuery({
    queryKey: ["jobs"],
    queryFn: api.jobs,
    refetchInterval: (query) =>
      query.state.data?.some((job) => ["queued", "running"].includes(job.status))
        ? 1500
        : 10_000,
  });
  const submit = useMutation({
    mutationFn: ({ jobKind, options }: { jobKind: string; options: Record<string, unknown> }) =>
      api.submitJob(jobKind, options),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const active = jobs.data?.some((job) => ["queued", "running"].includes(job.status));

  function options() {
    if (kind === "audit" || kind === "train") {
      return { dataset: "edge-iiot", task: "binary", max_rows: rows, random_state: 42 };
    }
    if (kind === "benchmark") {
      return { max_records: rows, iterations, payload_bytes: 256, random_state: 42 };
    }
    return { max_records: rows, random_state: 42 };
  }

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Controlled execution</p>
          <h1>Experiments</h1>
          <p>Launch bounded workloads and review durable execution records.</p>
        </div>
        <Badge tone={active ? "warn" : "ok"}>{active ? "Workload active" : "Executor idle"}</Badge>
      </div>

      <div className="content-grid experiment-layout">
        <Panel title="Run experiment" detail="Only one compute-intensive operation runs at a time">
          <form
            className="control-form"
            onSubmit={(event) => {
              event.preventDefault();
              submit.mutate({ jobKind: kind, options: options() });
            }}
          >
            <label>
              <span>Operation</span>
              <select value={kind} onChange={(event) => setKind(event.target.value)}>
                {Object.keys(experimentDescriptions).map((name) => (
                  <option value={name} key={name}>{name}</option>
                ))}
              </select>
            </label>
            <div className="operation-description">{experimentDescriptions[kind]}</div>
            <label>
              <span>{kind === "audit" || kind === "train" ? "Maximum rows" : "Replay records"}</span>
              <input
                type="number"
                min={kind === "train" ? 1000 : kind === "audit" ? 100 : 4}
                max={kind === "train" ? 25000 : kind === "audit" ? 10000 : 200}
                value={rows}
                onChange={(event) => setRows(Number(event.target.value))}
              />
            </label>
            {kind === "benchmark" && (
              <label>
                <span>Benchmark iterations</span>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={iterations}
                  onChange={(event) => setIterations(Number(event.target.value))}
                />
              </label>
            )}
            {submit.error && <ErrorNotice error={submit.error} />}
            <button className="primary-button" disabled={active || submit.isPending}>
              {active ? "Executor busy" : submit.isPending ? "Submitting…" : `Run ${kind}`}
            </button>
          </form>
        </Panel>

        <Panel title="Execution controls" detail="Safety bounds applied by the backend">
          <dl className="key-value-list">
            <div><dt>Concurrency</dt><dd>Single flight</dd></div>
            <div><dt>Job metadata</dt><dd>Persisted</dd></div>
            <div><dt>Dataset paths</dt><dd>Redacted</dd></div>
            <div><dt>Random state</dt><dd>42</dd></div>
            <div><dt>Training maximum</dt><dd>25,000 rows</dd></div>
            <div><dt>Benchmark maximum</dt><dd>100 iterations</dd></div>
          </dl>
        </Panel>
      </div>

      <Panel title="Job history" detail="Most recent operations and sanitized outcomes">
        {jobs.error && <ErrorNotice error={jobs.error} />}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Operation</th>
                <th>Submitted</th>
                <th>Duration</th>
                <th>Job ID</th>
              </tr>
            </thead>
            <tbody>
              {jobs.data?.map((job) => {
                const duration = job.started_at && job.completed_at
                  ? `${((Date.parse(job.completed_at) - Date.parse(job.started_at)) / 1000).toFixed(1)}s`
                  : "—";
                const tone = job.status === "succeeded"
                  ? "ok"
                  : job.status === "failed"
                    ? "critical"
                    : "warn";
                return (
                  <tr key={job.id}>
                    <td><Badge tone={tone}>{job.status}</Badge></td>
                    <td>{job.kind}</td>
                    <td>{new Date(job.submitted_at).toLocaleString()}</td>
                    <td className="mono">{duration}</td>
                    <td className="mono">{job.id.slice(0, 12)}</td>
                  </tr>
                );
              })}
              {!jobs.data?.length && (
                <tr><td colSpan={5} className="empty-cell">No jobs recorded.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
