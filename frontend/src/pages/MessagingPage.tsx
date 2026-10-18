import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Badge, ErrorNotice, JsonView, Metric, Panel } from "../components/ui";

export function MessagingPage() {
  const [signal, setSignal] = useState("brake");
  const [aead, setAead] = useState("AES-256-GCM");
  const [pqcMode, setPqcMode] = useState("classical_only");
  const [ttl, setTtl] = useState(5000);
  const results = useQuery({ queryKey: ["results"], queryFn: api.results });
  const roundTrip = useMutation({ mutationFn: api.secureRoundTrip });
  const benchmark = results.data?.benchmark?.latency?.security_classical ?? {};
  const pqc = results.data?.benchmark?.pqc ?? results.data?.demo?.pqc ?? {};

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Protected transport</p>
          <h1>Secure messaging</h1>
          <p>Establish an authenticated session, protect a signal, and verify it at the receiving edge.</p>
        </div>
        <Badge tone={pqc.available ? "ok" : "warn"}>
          PQC {pqc.available ? "available" : "classical fallback"}
        </Badge>
      </div>

      <div className="metric-grid four">
        <Metric label="Key exchange" value={benchmark.key_exchange ?? "X25519"} />
        <Metric label="Signature" value={benchmark.signature ?? "Ed25519"} />
        <Metric
          label="Protect p95"
          value={Number(benchmark.protect_ms?.p95 ?? 0).toFixed(3)}
          unit="ms"
        />
        <Metric
          label="Open p95"
          value={Number(benchmark.open_ms?.p95 ?? 0).toFixed(3)}
          unit="ms"
        />
      </div>

      <div className="content-grid equal">
        <Panel title="Session test" detail="Payload contents remain in process and are not logged">
          <form
            className="control-form"
            onSubmit={(event) => {
              event.preventDefault();
              roundTrip.mutate({
                payload: {
                  signal,
                  value: signal === "brake" ? true : 42,
                  data_class: signal === "brake" || signal === "steering"
                    ? "safety_critical"
                    : "sensitive",
                  location: { category: "withheld" },
                },
                aead,
                pqc_mode: pqcMode,
                ttl_ms: ttl,
              });
            }}
          >
            <div className="form-grid single">
              <label>
                <span>Signal class</span>
                <select value={signal} onChange={(event) => setSignal(event.target.value)}>
                  <option value="brake">Brake command</option>
                  <option value="steering">Steering command</option>
                  <option value="sensor">Sensor reading</option>
                  <option value="diagnostic">Diagnostic event</option>
                </select>
              </label>
              <label>
                <span>AEAD cipher</span>
                <select value={aead} onChange={(event) => setAead(event.target.value)}>
                  <option>AES-256-GCM</option>
                  <option>ChaCha20-Poly1305</option>
                </select>
              </label>
              <label>
                <span>PQC mode</span>
                <select value={pqcMode} onChange={(event) => setPqcMode(event.target.value)}>
                  <option value="classical_only">Classical only</option>
                  <option value="pqc_preferred">PQC preferred</option>
                  <option value="pqc_required">PQC required</option>
                </select>
              </label>
              <label>
                <span>Message TTL (ms)</span>
                <input
                  type="number"
                  min={100}
                  max={60000}
                  value={ttl}
                  onChange={(event) => setTtl(Number(event.target.value))}
                />
              </label>
            </div>
            <button className="primary-button" disabled={roundTrip.isPending}>
              {roundTrip.isPending ? "Protecting and verifying…" : "Run secure round trip"}
            </button>
          </form>
        </Panel>

        <Panel title="Verification result" detail="Authenticated envelope measurements">
          {roundTrip.error && <ErrorNotice error={roundTrip.error} />}
          {!roundTrip.data && !roundTrip.error && (
            <div className="empty-state">No session test has been run.</div>
          )}
          {roundTrip.data && (
            <>
              <div className={`verification-banner ${roundTrip.data.verified ? "ok" : "critical"}`}>
                <strong>{roundTrip.data.verified ? "Integrity verified" : "Verification failed"}</strong>
                <span>{roundTrip.data.pqc_status}</span>
              </div>
              <div className="decision-summary compact">
                <div><span>Envelope</span><strong>{roundTrip.data.envelope_bytes} B</strong></div>
                <div><span>Overhead</span><strong>{roundTrip.data.overhead_bytes} B</strong></div>
                <div><span>Protect</span><strong>{Number(roundTrip.data.protect_ms).toFixed(3)} ms</strong></div>
                <div><span>Open</span><strong>{Number(roundTrip.data.open_ms).toFixed(3)} ms</strong></div>
              </div>
              <JsonView value={roundTrip.data.audit} />
            </>
          )}
        </Panel>
      </div>

      <Panel title="PQC provider status" detail="No synthetic PQC is reported as secure">
        <dl className="key-value-list horizontal">
          <div><dt>ML-KEM</dt><dd>{pqc.kem_algorithm ?? "ML-KEM-768"}</dd></div>
          <div><dt>ML-DSA</dt><dd>{pqc.signature_algorithm ?? "ML-DSA-65"}</dd></div>
          <div><dt>Measured</dt><dd>{pqc.measured ? "Yes" : "No"}</dd></div>
          <div><dt>Provider state</dt><dd>{pqc.reason ?? "Available"}</dd></div>
        </dl>
      </Panel>
    </div>
  );
}
