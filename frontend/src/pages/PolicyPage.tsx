import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { ConsoleChart } from "../components/ConsoleChart";
import { Badge, ErrorNotice, JsonView, Panel } from "../components/ui";
import type { JsonObject } from "../types";

const initial = {
  threat_probability: 0.65,
  data_class: "sensitive",
  zone: "public_road",
  interface: "v2x",
  assurance: "simulated_trusted",
  cpu_percent: 42,
  memory_percent: 48,
  latency_ms: 12,
  traffic_density: 0.5,
};

const choices = {
  data_class: ["public", "internal", "sensitive", "safety_critical"],
  zone: ["trusted_internal", "trusted_external", "public_road", "restricted"],
  interface: ["internal_bus", "wifi", "bluetooth", "ota", "v2x", "unknown"],
  assurance: ["attested", "simulated_trusted", "self_reported", "unavailable"],
};

export function PolicyPage() {
  const [form, setForm] = useState<JsonObject>(initial);
  const results = useQuery({ queryKey: ["results"], queryFn: api.results });
  const evaluation = useMutation({ mutationFn: api.evaluatePolicy });
  const location = results.data?.demo?.location_aware_policy ?? {};

  const riskOption = {
    legend: { data: ["Minimum", "Mean", "Maximum"], textStyle: { color: "#95a3b7" } },
    xAxis: {
      type: "category" as const,
      data: Object.keys(location).map((key) => key.replaceAll("_", " ")),
      axisLabel: { rotate: 18 },
    },
    yAxis: { type: "value" as const, min: 0, max: 1 },
    series: [
      {
        name: "Minimum",
        type: "bar" as const,
        data: Object.values(location).map((item: any) => item.risk?.min ?? 0),
      },
      {
        name: "Mean",
        type: "bar" as const,
        data: Object.values(location).map((item: any) => item.risk?.mean ?? 0),
      },
      {
        name: "Maximum",
        type: "bar" as const,
        data: Object.values(location).map((item: any) => item.risk?.max ?? 0),
      },
    ],
  };

  function update(name: string, value: string | number) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Decision engine</p>
          <h1>Policy decisions</h1>
          <p>Evaluate security floors against data sensitivity, location, interface, and edge load.</p>
        </div>
        <Badge tone="info">Local inference</Badge>
      </div>

      <div className="content-grid policy-layout">
        <Panel title="Decision inputs" detail="All values are evaluated by the configured policy engine">
          <form
            className="control-form"
            onSubmit={(event) => {
              event.preventDefault();
              evaluation.mutate(form);
            }}
          >
            <div className="form-grid">
              {Object.entries(choices).map(([name, options]) => (
                <label key={name}>
                  <span>{name.replaceAll("_", " ")}</span>
                  <select
                    value={String(form[name])}
                    onChange={(event) => update(name, event.target.value)}
                  >
                    {options.map((option) => (
                      <option key={option} value={option}>
                        {option.replaceAll("_", " ")}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              {[
                ["threat_probability", 0, 1, 0.01],
                ["cpu_percent", 0, 100, 1],
                ["memory_percent", 0, 100, 1],
                ["latency_ms", 0, 1000, 1],
                ["traffic_density", 0, 1, 0.01],
              ].map(([name, min, max, step]) => (
                <label key={String(name)}>
                  <span>{String(name).replaceAll("_", " ")}</span>
                  <input
                    type="number"
                    min={min}
                    max={max}
                    step={step}
                    value={Number(form[String(name)])}
                    onChange={(event) => update(String(name), Number(event.target.value))}
                  />
                </label>
              ))}
            </div>
            <button className="primary-button" disabled={evaluation.isPending}>
              {evaluation.isPending ? "Evaluating…" : "Evaluate policy"}
            </button>
          </form>
        </Panel>

        <Panel title="Decision output" detail="Enforced edge action and cryptographic profile">
          {evaluation.error && <ErrorNotice error={evaluation.error} />}
          {!evaluation.data && !evaluation.error && (
            <div className="empty-state">Submit the current context to inspect a decision.</div>
          )}
          {evaluation.data && (
            <>
              <div className="decision-summary">
                <div>
                  <span>Profile</span>
                  <strong>{String(evaluation.data.profile_id).replaceAll("_", " ")}</strong>
                </div>
                <div>
                  <span>Edge action</span>
                  <strong>{String(evaluation.data.action).replaceAll("_", " ")}</strong>
                </div>
                <div>
                  <span>Security floor</span>
                  <strong>Level {evaluation.data.security_floor}</strong>
                </div>
                <div>
                  <span>Risk score</span>
                  <strong>{Number(evaluation.data.risk_score ?? 0).toFixed(3)}</strong>
                </div>
              </div>
              <JsonView value={evaluation.data} />
            </>
          )}
        </Panel>
      </div>

      <Panel title="Location risk posture" detail="Min, mean, and max risk from the latest replay">
        <ConsoleChart option={riskOption} height={290} />
      </Panel>
    </div>
  );
}
