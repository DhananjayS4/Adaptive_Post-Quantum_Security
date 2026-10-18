# Adaptive V2X Edge Security

Runnable research prototype for AI-driven security decisions at vehicle edge
gateways and ECUs.

The system combines:

- Leakage-safe Edge-IIoTset training and a pluggable VeReMi adapter.
- Local threat scoring and context-aware policy selection.
- Data-aware and location/interface-aware security floors.
- AES-256-GCM or ChaCha20-Poly1305 authenticated encryption.
- X25519/Ed25519 classical security and optional ML-KEM-768/ML-DSA-65.
- Replay-protected V2X envelopes and explicit downgrade handling.
- Simulated ECU, V2X channel, central workload, secure boot, and signed OTA.

## Security objectives

| Objective | Implementation |
| --- | --- |
| Intelligent edge decisions | Local calibrated IDS score plus policy engine; central server receives alerts and summaries rather than every record |
| Data-aware protection | Brake, steering, and alert messages are safety-critical; sensors are sensitive; mandatory security floors apply |
| Location-based security | Geographic zone, location assurance, and interface type affect risk; Wi-Fi, Bluetooth, OTA, and V2X receive stricter floors |
| Confidentiality | AES-256-GCM and ChaCha20-Poly1305 |
| Integrity and authenticity | AEAD tags, Ed25519 signatures, optional ML-DSA-65, freshness, and replay checks |
| Secure updates | Signed manifests, artifact hashes, target/version/expiry validation, anti-rollback checks, and simulated A/B activation |
| PQC readiness | Optional real liboqs ML-KEM-768 and ML-DSA-65 provider; no synthetic PQC is reported as secure |

## Installation

From PowerShell:

```powershell
cd D:\Freelancing\adaptive_v2x_security
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

Optional post-quantum support requires a compatible native `liboqs` installation:

```powershell
python -m pip install -e ".[pqc,test]"
```

If liboqs is unavailable, `pqc_preferred` records an audited classical fallback
and `pqc_required` fails closed.

## Quick start

The configured Edge-IIoTset ML CSV is already present one directory above this
project.

```powershell
# Inspect a bounded sample
adaptive-v2x audit-data --dataset edge-iiot --max-rows 10000

# Train an honest binary baseline and save its complete artifact
adaptive-v2x train --dataset edge-iiot --task binary --max-rows 50000

# Replay records through two protected simulated ECUs
adaptive-v2x demo --artifact-dir results/model --max-rows 30

# Measure inference, policy, cryptographic and central workload metrics
adaptive-v2x benchmark --artifact-dir results/model --iterations 100

# Verify signed boot components and exercise A/B update + rollback
adaptive-v2x ota-demo --artifact-dir results/model

# Launch the monitoring console (API + compiled React UI)
adaptive-v2x-console

# Run automated verification
python -m pytest
```

Outputs are written as strict JSON under `results/`.

## Monitoring console

The primary interface is a React/TypeScript operations console backed by
FastAPI. It opens at `http://127.0.0.1:8000` and provides:

- System telemetry for model quality, edge workload, latency, and PQC status.
- Interactive context-aware policy evaluation.
- Authenticated AES-GCM or ChaCha20-Poly1305 session verification.
- Bounded, single-flight experiment execution with durable job records.
- Signed secure-boot, A/B activation, health-check, and rollback evidence.

Build the web application once before launching:

```powershell
cd frontend
npm install
npm run build
cd ..
adaptive-v2x-console
```

For frontend development, run `npm run dev` in `frontend/` while
`adaptive-v2x-console --reload` runs in a second terminal. Vite proxies `/api`
to FastAPI.

API documentation is available at `http://127.0.0.1:8000/api/docs`. All API
responses redact exact locations, secrets, key material, raw envelopes, and
local paths. The previous Streamlit interface remains available through
`adaptive-v2x-ui` as a temporary fallback.

## VeReMi support

The adapter expects a CSV containing the notebook schema, including binary
`attack` and optional multiclass `attack_type` labels. The dataset is not
currently present:

```powershell
adaptive-v2x train --dataset veremi --path D:\data\Veremi_final_dataset.csv --task binary
```

Edge-IIoTset and VeReMi use separate feature spaces. They share a training and
artifact contract but are never incorrectly merged into one feature matrix.

## Project layout

```text
config/                     Risk, dataset, model and simulation settings
src/adaptive_v2x_security/
  data/                     Edge-IIoTset and VeReMi adapters
  ml/                       Model training, evaluation and signed-ready artifacts
  policy/                   Context-aware risk and mandatory security floors
  security/                 Providers, canonical envelopes and secure sessions
  simulation/               ECUs, V2X channel and central workload simulation
  updates/                  Signed manifests, secure-boot and A/B OTA simulation
  experiments/              Audit, training, demo and benchmark runners
  api/                      FastAPI contracts, durable jobs, and console launcher
  ui/                       Shared UI services and legacy Streamlit fallback
frontend/                   React/TypeScript monitoring console
tests/                      Security, ML, policy, simulation and update tests
```

## Research integrity

- Preprocessors and encoders are fitted only on training data.
- Target columns are removed before feature preparation.
- Train, validation, and test indices are disjoint.
- Thresholds are not tuned on the held-out test partition.
- Accuracy is not reported alone; F1, recall, false-negative rate, PR-AUC,
  confusion matrices, latency, packet size, and workload are retained.
- Existing notebook results are not reused because several experiments contain
  target leakage or test-set threshold tuning.
- The included bounded verification run is a software smoke test, not a final
  publication result. Final claims should use full predefined capture/run,
  temporal, or vehicle-level holdouts rather than relying only on a random
  row split.

## Important limitations

- ECU, radio, location assurance, secure boot, and A/B slots are software
  simulations. They do not provide TPM, HSM, ROM, RF, or physical-tamper
  guarantees.
- `liboqs` is research software and should not be treated as a production
  certification.
- The in-process handshake is suitable for controlled experiments, not a
  standardized production V2X protocol.
- SHA-256 model manifests detect corruption. Authentic model deployment should
  package them in the signed update workflow before untrusted deserialization.
- Exact locations, plaintext signals, and secrets must not be written to
  production logs.
- Edge-IIoTset grants academic use; commercial use requires permission from its
  lead author.
