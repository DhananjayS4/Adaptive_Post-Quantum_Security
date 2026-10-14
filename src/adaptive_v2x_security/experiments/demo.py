from __future__ import annotations

from collections import Counter
from pathlib import Path
from statistics import fmean
from typing import Any

from adaptive_v2x_security.config import DEFAULT_CONFIG_DIR
from adaptive_v2x_security.domain import (
    DataClass,
    GeoZone,
    Interface,
    LocationAssurance,
    LocationContext,
    ResourceState,
)
from adaptive_v2x_security.ml import ThreatPredictor, load_model_artifact
from adaptive_v2x_security.policy import RiskEngine
from adaptive_v2x_security.security import OQSPQCProvider
from adaptive_v2x_security.simulation import (
    CentralMonitor,
    ChannelConfig,
    ScenarioEvent,
    ScenarioRunner,
    SimulatedECU,
    SimulatedV2XChannel,
)

from .common import (
    dataset_path,
    json_safe,
    make_adapter,
    normalize_categorical_features,
    write_json,
)
from .comparison import adaptive_vs_send_all


def _policy_breakdown(outcomes: list[Any], attribute: str) -> dict[str, Any]:
    grouped: dict[str, list[Any]] = {}
    for outcome in outcomes:
        if attribute == "data_class":
            key = outcome.message.data_class.value
        else:
            key = outcome.message.location.zone.value
        grouped.setdefault(key, []).append(outcome)
    return {
        key: {
            "records": len(values),
            "risk": {
                "min": min(item.decision.risk_score for item in values),
                "mean": fmean(item.decision.risk_score for item in values),
                "max": max(item.decision.risk_score for item in values),
            },
            "profiles": dict(
                Counter(item.decision.profile_id for item in values)
            ),
            "security_floors": dict(
                Counter(str(item.decision.security_floor) for item in values)
            ),
        }
        for key, values in grouped.items()
    }


def run_demo(
    *,
    artifact_dir: str | Path,
    dataset: str | None,
    path: str | Path | None,
    max_records: int,
    random_state: int,
    outage_start: int | None,
    outage_stop: int | None,
    output: str | Path,
) -> dict[str, Any]:
    model = load_model_artifact(artifact_dir)
    selected_dataset = dataset or str(model.metadata.get("dataset", "edge-iiot"))
    if selected_dataset not in {"edge-iiot", "veremi"}:
        raise ValueError("Model metadata does not identify a supported dataset")
    source_hint = path or model.metadata.get("dataset_source")
    source = dataset_path(selected_dataset, source_hint)
    loaded = normalize_categorical_features(
        make_adapter(
            selected_dataset,
            source,
            task=model.task,
            max_rows=max_records,
            random_state=random_state,
            target_column=model.metadata.get("target_column"),
        ).load()
    )

    policy = RiskEngine.from_yaml(DEFAULT_CONFIG_DIR / "security_policy.yaml")
    monitor = CentralMonitor(summary_every=max(1, min(5, max_records // 3 or 1)))
    predictor = ThreatPredictor(model)
    sender = SimulatedECU("ecu-powertrain", policy, predictor, central_monitor=monitor)
    receiver = SimulatedECU("ecu-gateway", policy, predictor)
    channel = SimulatedV2XChannel(ChannelConfig(seed=random_state))
    runner = ScenarioRunner(sender, receiver, channel, central_monitor=monitor)

    classes = (
        DataClass.PUBLIC,
        DataClass.INTERNAL,
        DataClass.SENSITIVE,
        DataClass.SAFETY_CRITICAL,
    )
    zones = (
        GeoZone.TRUSTED_INTERNAL,
        GeoZone.TRUSTED_EXTERNAL,
        GeoZone.PUBLIC_ROAD,
        GeoZone.RESTRICTED,
    )
    interfaces = (
        Interface.INTERNAL_BUS,
        Interface.BLUETOOTH,
        Interface.WIFI,
        Interface.V2X,
    )
    events: list[ScenarioEvent] = []
    for index, (_, row) in enumerate(loaded.X.iterrows()):
        record = json_safe(row.to_dict())
        data_class = classes[index % len(classes)]
        zone = zones[index % len(zones)]
        events.append(
            ScenarioEvent(
                signal_type=("sensor_telemetry" if index % 2 else "vehicle_status"),
                payload={
                    "record_index": index,
                    "source": selected_dataset,
                },
                observed_features=record,
                data_class=data_class,
                location=LocationContext(
                    zone=zone,
                    interface=interfaces[index % len(interfaces)],
                    assurance=LocationAssurance.SIMULATED_TRUSTED,
                ),
                resource_state=ResourceState(
                    cpu_percent=20.0 + index % 30,
                    memory_percent=35.0,
                    latency_ms=2.0,
                    traffic_density=min(1.0, index / max(max_records, 1)),
                ),
            )
        )

    event_count = len(events)
    default_start = event_count // 3
    default_stop = min(event_count, max(default_start + 1, (2 * event_count) // 3))
    start = default_start if outage_start is None else outage_start
    stop = default_stop if outage_stop is None else outage_stop
    if not 0 <= start <= stop <= len(events):
        raise ValueError("Central outage must satisfy 0 <= start <= stop <= records")
    scenario = runner.run(events, central_outage=(start, stop))

    decisions = Counter(outcome.decision.profile_id for outcome in scenario.outcomes)
    actions = Counter(outcome.decision.action.value for outcome in scenario.outcomes)
    outcome_list = list(scenario.outcomes)
    outage_outcomes = outcome_list[start:stop]
    comparison = scenario.workload
    assert comparison is not None
    pqc = OQSPQCProvider.availability()
    result = {
        "command": "demo",
        "model_version": model.model_version,
        "dataset": selected_dataset,
        "source": source,
        "records_replayed": len(events),
        "ecus": [sender.ecu_id, receiver.ecu_id],
        "central_outage": {"start": start, "stop": stop},
        "peer_processing_during_outage": {
            "local_decisions": len(outage_outcomes),
            "protected_sends": sum(outcome.sent for outcome in outage_outcomes),
            "accepted_deliveries": sum(
                1
                for outcome in outage_outcomes
                for delivery in outcome.deliveries
                if getattr(delivery.receiver_result, "accepted", False)
            ),
        },
        "sent": sum(outcome.sent for outcome in scenario.outcomes),
        "fail_closed": {
            "count": sum(outcome.error is not None for outcome in scenario.outcomes),
            "errors": dict(
                Counter(
                    outcome.error
                    for outcome in scenario.outcomes
                    if outcome.error is not None
                )
            ),
        },
        "accepted_deliveries": scenario.accepted,
        "profiles": dict(decisions),
        "actions": dict(actions),
        "data_aware_policy": _policy_breakdown(outcome_list, "data_class"),
        "location_aware_policy": _policy_breakdown(outcome_list, "location"),
        "adaptive_vs_send_all": adaptive_vs_send_all(comparison),
        "pqc": {
            "available": pqc.available,
            "kem_algorithm": pqc.kem_algorithm,
            "signature_algorithm": pqc.signature_algorithm,
            "reason": pqc.reason,
            "synthetic_pqc_used": False,
        },
    }
    write_json(output, result)
    return result
