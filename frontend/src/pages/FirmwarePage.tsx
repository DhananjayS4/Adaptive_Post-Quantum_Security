import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { Badge, ErrorNotice, Metric, Panel } from "../components/ui";

export function FirmwarePage() {
  const [target, setTarget] = useState("ecu-gateway");
  const queryClient = useQueryClient();
  const results = useQuery({ queryKey: ["results"], queryFn: api.results });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: api.jobs, refetchInterval: 3000 });
  const run = useMutation({
    mutationFn: () => api.submitJob("ota", { target }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const ota = results.data?.ota ?? {};
  const boot = ota.secure_boot ?? {};
  const update = ota.ab_update ?? {};
  const pqc = ota.pqc ?? {};
  const active = jobs.data?.some((job) => ["queued", "running"].includes(job.status));

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Update trust chain</p>
          <h1>Firmware assurance</h1>
          <p>Signed manifests, secure-boot decisions, A/B activation, and rollback evidence.</p>
        </div>
        <Badge tone={boot.allowed ? "ok" : "critical"}>
          Boot {boot.allowed ? "allowed" : "blocked"}
        </Badge>
      </div>

      <div className="metric-grid four">
        <Metric label="Verified components" value={boot.verified_components?.length ?? 0} />
        <Metric label="Active slot" value={update.active_slot_after_scenarios ?? "—"} />
        <Metric
          label="Rollback exercised"
          value={update.rollback_scenario?.rolled_back ? "Yes" : "No"}
          status={update.rollback_scenario?.rolled_back ? "ok" : "neutral"}
        />
        <Metric
          label="PQC signatures"
          value={pqc.manifest_pqc_signatures_used ? "Enabled" : "Classical"}
          status={pqc.manifest_pqc_signatures_used ? "ok" : "warn"}
        />
      </div>

      <div className="content-grid two-thirds">
        <Panel title="Assurance timeline" detail="Latest simulated update and rollback lifecycle">
          <ol className="timeline">
            {(update.audit_log ?? []).map((event: string, index: number) => (
              <li key={`${index}-${event}`}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{index === 0 ? "Simulation boundary" : "Lifecycle event"}</strong>
                  <p>{event}</p>
                </div>
              </li>
            ))}
            {!update.audit_log?.length && <li className="empty-state">No OTA evidence generated.</li>}
          </ol>
        </Panel>

        <Panel title="Run assurance check" detail="Generate signed demo packages for a bounded target">
          <form
            className="control-form"
            onSubmit={(event) => {
              event.preventDefault();
              run.mutate();
            }}
          >
            <label>
              <span>Target device</span>
              <input
                value={target}
                maxLength={64}
                onChange={(event) => setTarget(event.target.value)}
              />
            </label>
            <div className="operation-description">
              Executes manifest verification, simulated secure boot, A/B activation,
              health validation, and rollback.
            </div>
            {run.error && <ErrorNotice error={run.error} />}
            <button className="primary-button" disabled={active || run.isPending || !target.trim()}>
              {active ? "Executor busy" : run.isPending ? "Submitting…" : "Run OTA assurance"}
            </button>
          </form>
        </Panel>
      </div>

      <Panel title="Signed package inventory" detail="Manifest metadata exposed without local paths or key material">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Package</th>
                <th>Type</th>
                <th>Version</th>
                <th>Target</th>
                <th>Size</th>
                <th>Signature</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(ota.manifests ?? {}).map(([name, value]: [string, any]) => (
                <tr key={name}>
                  <td>{name.replaceAll("_", " ")}</td>
                  <td>{value.manifest?.artifact_type}</td>
                  <td className="mono">{value.manifest?.version}</td>
                  <td>{value.manifest?.target}</td>
                  <td className="mono">{Number(value.manifest?.size ?? 0).toLocaleString()} B</td>
                  <td>{value.signature_algorithms?.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="notice neutral">
        <strong>Simulation boundary</strong>
        <span>{boot.simulation_notice ?? "This console does not represent a hardware root of trust."}</span>
      </div>
    </div>
  );
}
