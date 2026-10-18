"""Streamlit research dashboard for the adaptive V2X security prototype."""

from __future__ import annotations

from typing import Any, Callable

import pandas as pd
import streamlit as st

from adaptive_v2x_security.domain import (
    DataClass,
    GeoZone,
    Interface,
    LocationAssurance,
    PQCMode,
)
from adaptive_v2x_security.security import AES_256_GCM, CHACHA20_POLY1305

from adaptive_v2x_security.ui import services


st.set_page_config(
    page_title="Adaptive V2X Security",
    layout="wide",
)

st.markdown(
    """
    <style>
    :root {
        --canvas: #0a1018;
        --surface: #101923;
        --surface-raised: #141f2b;
        --border: #263646;
        --text: #dbe4ec;
        --muted: #8f9dab;
        --accent: #2fb8ad;
        --accent-dim: rgba(47, 184, 173, .12);
    }
    html, body, [class*="css"] {
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
            "Segoe UI", sans-serif;
    }
    [data-testid="stAppViewContainer"] {
        background: var(--canvas);
        color: var(--text);
    }
    [data-testid="stHeader"] {
        background: var(--canvas);
        height: 0;
        min-height: 0;
    }
    [data-testid="stToolbar"] {display: none;}
    [data-testid="stDecoration"] {display: none;}
    .block-container {
        max-width: 1280px;
        padding-top: 1.15rem;
        padding-bottom: 3rem;
    }
    h1, h2, h3 {
        letter-spacing: -.015em;
        color: var(--text);
    }
    h1 {
        font-size: 1.65rem !important;
        font-weight: 650 !important;
        margin: 0 0 .2rem !important;
    }
    h2 {
        font-size: 1.12rem !important;
        font-weight: 620 !important;
        margin-top: 1.4rem !important;
    }
    h3 {
        font-size: .98rem !important;
        font-weight: 620 !important;
    }
    p, label, [data-testid="stCaptionContainer"] {color: var(--muted);}
    hr {border-color: var(--border) !important;}
    [data-testid="stMetric"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: .7rem .8rem;
        min-height: 88px;
    }
    [data-testid="stMetricValue"] {
        color: var(--text);
        font-size: 1.35rem;
    }
    [data-testid="stMetricLabel"] {
        color: var(--muted);
        font-size: .75rem;
        letter-spacing: .02em;
    }
    [data-testid="stMetricDelta"] {font-size: .72rem;}
    div.stButton > button, div.stFormSubmitButton > button {
        border-radius: 4px;
        border: 1px solid #398d89;
        background: #15232d;
        color: #f0f7f8;
        font-weight: 600;
        min-height: 2.35rem;
    }
    div.stButton > button p,
    div.stButton > button span,
    div.stFormSubmitButton > button p,
    div.stFormSubmitButton > button span {
        color: inherit !important;
    }
    div.stButton > button:hover,
    div.stFormSubmitButton > button:hover {
        background: #1b333c;
        border-color: #43c8bd;
        color: #ffffff;
    }
    button[kind="primary"],
    button[kind="primaryFormSubmit"] {
        background: #2fb8ad !important;
        border-color: #2fb8ad !important;
        color: #061715 !important;
    }
    button[kind="primary"]:hover,
    button[kind="primaryFormSubmit"]:hover {
        background: #51ccc2 !important;
        border-color: #51ccc2 !important;
        color: #03100f !important;
    }
    div.stButton > button:focus-visible,
    div.stFormSubmitButton > button:focus-visible {
        outline: 2px solid #77ddd5;
        outline-offset: 2px;
    }
    div[data-baseweb="select"] > div,
    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input,
    [data-testid="stTextArea"] textarea {
        border-radius: 4px !important;
    }
    [data-testid="stForm"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 1rem;
    }
    [data-testid="stDataFrame"],
    [data-testid="stTable"],
    [data-testid="stExpander"] {
        border-color: var(--border) !important;
        border-radius: 4px !important;
    }
    [data-testid="stAlert"] {border-radius: 4px;}
    [data-testid="stTabs"] [data-baseweb="tab-list"] {
        gap: 1.35rem;
        border-bottom: 1px solid var(--border);
    }
    [data-testid="stTabs"] [data-baseweb="tab"] {
        border-radius: 0;
        padding-left: 0;
        padding-right: 0;
    }
    [data-testid="stSegmentedControl"] {
        overflow-x: auto;
        padding-bottom: .1rem;
    }
    [data-testid="stSegmentedControl"] [data-baseweb="button-group"] {
        min-width: max-content;
        border-radius: 4px;
    }
    [data-testid="stSegmentedControl"] button {border-radius: 3px !important;}
    .app-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        border-bottom: 1px solid var(--border);
        padding: .2rem 0 .75rem;
        margin-bottom: .65rem;
    }
    .app-identity {
        display: flex;
        align-items: baseline;
        gap: .7rem;
        min-width: 0;
    }
    .app-name {
        color: var(--text);
        font-size: .95rem;
        font-weight: 680;
        white-space: nowrap;
    }
    .app-edition {
        color: var(--muted);
        font-size: .72rem;
        letter-spacing: .08em;
        text-transform: uppercase;
    }
    .runtime-state {
        color: var(--accent);
        font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
        font-size: .7rem;
        letter-spacing: .04em;
        white-space: nowrap;
    }
    .view-label {
        color: var(--accent);
        font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
        font-size: .69rem;
        font-weight: 650;
        letter-spacing: .1em;
        text-transform: uppercase;
        margin-top: 1rem;
        margin-bottom: .2rem;
    }
    .view-copy {
        color: var(--muted);
        font-size: .88rem;
        max-width: 860px;
        margin: 0 0 1.15rem;
    }
    .section-label {
        color: var(--muted);
        font-size: .69rem;
        font-weight: 650;
        letter-spacing: .08em;
        text-transform: uppercase;
        margin: 1.2rem 0 .45rem;
    }
    @media (max-width: 800px) {
        .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
            padding-top: .85rem;
        }
        .app-header {
            align-items: flex-start;
            flex-direction: column;
            gap: .2rem;
        }
        .app-identity {flex-wrap: wrap; gap: .2rem .6rem;}
        h1 {font-size: 1.42rem !important;}
        [data-testid="stMetric"] {min-height: 82px; padding: .6rem;}
        [data-testid="stMetricValue"] {font-size: 1.15rem;}
    }
    </style>
    """,
    unsafe_allow_html=True,
)


VIEWS = (
    "Overview",
    "Policy Lab",
    "Secure V2X",
    "Experiments",
    "Boot / OTA",
)


def _application_header() -> None:
    st.markdown(
        """
        <div class="app-header">
            <div class="app-identity">
                <span class="app-name">Adaptive V2X Security</span>
                <span class="app-edition">Engineering research console</span>
            </div>
            <span class="runtime-state">LOCAL RUNTIME / RESEARCH USE</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _view_header(label: str, title: str, copy: str) -> None:
    st.markdown(f'<div class="view-label">{label}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<p class="view-copy">{copy}</p>', unsafe_allow_html=True)


def _section_label(label: str) -> None:
    st.markdown(f'<div class="section-label">{label}</div>', unsafe_allow_html=True)


def _fmt(value: Any, digits: int = 2, suffix: str = "") -> str:
    if value is None:
        return "Not available"
    try:
        return f"{float(value):,.{digits}f}{suffix}"
    except (TypeError, ValueError):
        return str(value)


def _pct(value: Any) -> str:
    return _fmt(None if value is None else float(value) * 100, 1, "%")


def _human_bytes(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "Not available"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024 or unit == "GB":
            return f"{size:,.1f} {unit}"
        size /= 1024
    return "Not available"


def _missing(name: str) -> None:
    st.info(f"No valid {name} result is available yet. Run the bounded workflow below.")


def _flash() -> None:
    message = st.session_state.pop("_flash", None)
    if message:
        st.success(message)


def _run_with_feedback(label: str, operation: Callable[[], Any]) -> None:
    with st.spinner(label):
        _, error = services.safe_call(operation)
    if error:
        st.error(f"Operation stopped safely — {error}")
    else:
        st.session_state["_flash"] = f"{label} completed and the result was saved."
        st.rerun()


def _objective_evidence(results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    train = results["train"]
    demo = results["demo"]
    benchmark = results["benchmark"]
    ota = results["ota"]
    return [
        {"Objective": "Intelligent edge decisions", "Evidence": bool(train and demo)},
        {"Objective": "Data-aware protection", "Evidence": bool(demo.get("data_aware_policy"))},
        {
            "Objective": "Location-aware security",
            "Evidence": bool(demo.get("location_aware_policy")),
        },
        {
            "Objective": "Confidentiality",
            "Evidence": bool(
                benchmark.get("latency", {}).get("security_classical")
            ),
        },
        {"Objective": "Integrity & authenticity", "Evidence": bool(demo)},
        {"Objective": "Secure updates", "Evidence": bool(ota.get("secure_boot"))},
        {"Objective": "PQC readiness", "Evidence": bool(demo.get("pqc") or ota.get("pqc"))},
    ]


def overview() -> None:
    _view_header(
        "Operations / evidence",
        "System status",
        "Current research artifacts, measured behavior, and runtime capability. "
        "Values shown here are experimental evidence, not deployment assurance.",
    )
    results = services.load_results()
    train, demo, benchmark = results["train"], results["demo"], results["benchmark"]
    model = services.latest_model()
    pqc = services.pqc_availability()
    test = train.get("held_out_test_metrics", {})
    reduction = (
        demo.get("adaptive_vs_send_all", {}).get("reduction", {})
        or benchmark.get("central_workload", {}).get("reduction", {})
    )
    latency = benchmark.get("latency", {}).get("inference_ms", {})
    objectives = _objective_evidence(results)
    covered = sum(bool(item["Evidence"]) for item in objectives)

    _section_label("Latest measured state")
    cols = st.columns(3)
    cols[0].metric("Latest model", model.get("model_version", "Not available"))
    cols[1].metric("Held-out F1", _fmt(test.get("f1"), 3))
    cols[2].metric("Held-out recall", _fmt(test.get("recall"), 3))
    cols = st.columns(3)
    cols[0].metric("Central bytes reduced", _pct(reduction.get("bytes")))
    cols[1].metric("Median inference", _fmt(latency.get("median"), 2, " ms"))
    cols[2].metric(
        "PQC provider",
        "Available" if pqc.get("available") else "Unavailable",
        "real liboqs" if pqc.get("available") else "classical fallback only",
    )

    left, right = st.columns((1.35, 1), gap="large")
    with left:
        st.subheader("Objective evidence")
        st.progress(
            covered / len(objectives),
            text=f"{covered} of {len(objectives)} objectives have generated evidence",
        )
        objective_frame = pd.DataFrame(objectives)
        objective_frame["Status"] = objective_frame["Evidence"].map(
            {True: "Evidenced", False: "Awaiting result"}
        )
        st.dataframe(
            objective_frame[["Objective", "Status"]],
            width="stretch",
            hide_index=True,
        )
    with right:
        st.subheader("Runtime capability")
        runtime_rows = [
            {"Capability": "Model dataset", "State": model.get("dataset", "Not available")},
            {
                "Capability": "Evaluation task",
                "State": model.get("task", train.get("task", "Not available")),
            },
            {
                "Capability": "Post-quantum provider",
                "State": "Available" if pqc.get("available") else "Unavailable",
            },
            {
                "Capability": "Configured algorithms",
                "State": (
                    f"{pqc.get('kem_algorithm', 'ML-KEM-768')} / "
                    f"{pqc.get('signature_algorithm', 'ML-DSA-65')}"
                ),
            },
        ]
        st.dataframe(
            pd.DataFrame(runtime_rows),
            width="stretch",
            hide_index=True,
        )
        if not pqc.get("available"):
            st.warning(
                "PQC provider unavailable. Preferred mode can record a classical "
                "fallback; required mode fails closed."
            )

    st.subheader("Evidence boundary")
    st.info(
        "The console reports stored experiment outputs and in-process simulations. "
        "It does not establish production readiness, road-safety compliance, hardware "
        "root-of-trust protection, or resistance to field attacks."
    )
    st.caption(
        "Local paths, raw identifiers, key material, envelope bytes, and exact "
        "coordinates are intentionally excluded."
    )


def policy_lab() -> None:
    _view_header(
        "Decision analysis",
        "Policy Lab",
        "Evaluate the configured risk policy against a bounded operational context. "
        "Inputs are non-identifying and exact coordinates are never requested.",
    )
    with st.form("policy-form"):
        context_col, resource_col = st.columns(2, gap="large")
        with context_col:
            st.subheader("Threat and context")
            threat = st.slider("Threat probability", 0.0, 1.0, 0.42, 0.01)
            data_class = st.selectbox(
                "Data class",
                [item.value for item in DataClass],
                index=1,
            )
            zone = st.selectbox(
                "Zone category",
                [item.value for item in GeoZone],
                index=2,
            )
            interface = st.selectbox(
                "Interface",
                [item.value for item in Interface],
                index=4,
            )
            assurance = st.selectbox(
                "Location assurance",
                [item.value for item in LocationAssurance],
                index=1,
            )
        with resource_col:
            st.subheader("Resource state")
            cpu = st.slider("CPU utilization (%)", 0.0, 100.0, 35.0, 1.0)
            memory = st.slider("Memory utilization (%)", 0.0, 100.0, 42.0, 1.0)
            latency = st.number_input(
                "Observed latency (ms)",
                0.0,
                1_000.0,
                8.0,
                1.0,
            )
            density = st.slider("Traffic density", 0.0, 1.0, 0.35, 0.01)
        submitted = st.form_submit_button("Evaluate security policy", type="primary")

    st.caption(
        "Method note: location assurance is retained in context, while the current "
        "RiskEngine scores zone and interface without a separate assurance weight."
    )
    if submitted:
        result, error = services.safe_call(
            lambda: services.evaluate_policy(
                threat_probability=threat,
                data_class=data_class,
                zone=zone,
                interface=interface,
                assurance=assurance,
                cpu_percent=cpu,
                memory_percent=memory,
                latency_ms=latency,
                traffic_density=density,
            )
        )
        if error:
            st.error(f"Policy evaluation stopped safely — {error}")
            return
        assert isinstance(result, dict)
        st.subheader("Decision summary")
        first = st.columns(3)
        first[0].metric("Risk score", _fmt(result.get("risk_score"), 3))
        first[1].metric("Selected profile", result.get("profile_id", "unknown"))
        first[2].metric("Edge action", result.get("action", "unknown"))
        second = st.columns(2)
        second[0].metric("Security floor", result.get("security_floor", "unknown"))
        second[1].metric("PQC mode", result.get("pqc_mode", "unknown"))
        reasons = result.get("reasons", [])
        st.dataframe(
            pd.DataFrame(
                [
                    {"Order": index, "Decision rationale": reason}
                    for index, reason in enumerate(reasons, start=1)
                ]
            ),
            width="stretch",
            hide_index=True,
        )


def secure_demo() -> None:
    _view_header(
        "Protocol test bench",
        "Secure V2X",
        "Establish an in-process peer session, protect one canonical message, and "
        "verify the authenticated envelope at the receiver.",
    )
    pqc = services.pqc_availability()
    provider_rows = [
        {"Test-bench capability": "AEAD suites", "State": "AES-256-GCM / ChaCha20-Poly1305"},
        {
            "Test-bench capability": "PQC provider",
            "State": "liboqs available" if pqc.get("available") else "Unavailable",
        },
        {"Test-bench capability": "Failure behavior", "State": "Fail closed"},
    ]
    st.dataframe(pd.DataFrame(provider_rows), width="stretch", hide_index=True)
    if not pqc.get("available"):
        st.warning(
            "PQC preferred can record a classical fallback. PQC required will stop "
            "session establishment when the provider is unavailable."
        )

    with st.form("secure-message-form"):
        left, right = st.columns(2, gap="large")
        with left:
            st.subheader("Message fixture")
            signal_type = st.selectbox(
                "Signal type",
                ("vehicle_status", "hazard_alert", "sensor_telemetry", "cooperative_awareness"),
            )
            event_reference = st.text_input(
                "Event reference",
                "demo-event-001",
                max_chars=48,
                help="Use a non-sensitive test alias.",
            )
            speed = st.number_input("Speed (km/h)", 0.0, 300.0, 48.0, 1.0)
            alert = st.text_area(
                "Message note",
                "Simulated road condition update",
                max_chars=280,
            )
        with right:
            st.subheader("Protocol configuration")
            aead_label = st.selectbox(
                "Authenticated encryption",
                ("AES-256-GCM", "ChaCha20-Poly1305"),
            )
            mode = st.selectbox(
                "Security mode",
                [item.value for item in PQCMode],
                index=1,
                format_func=lambda value: value.replace("_", " ").title(),
            )
            ttl_ms = st.slider("Envelope lifetime (ms)", 500, 30_000, 5_000, 500)
            data_class = st.selectbox(
                "Payload data class",
                [item.value for item in DataClass],
                index=2,
            )
        submitted = st.form_submit_button("Execute protocol test", type="primary")

    if submitted:
        aead = AES_256_GCM if aead_label == "AES-256-GCM" else CHACHA20_POLY1305
        payload = {
            "event_reference": event_reference,
            "signal_type": signal_type,
            "data_class": data_class,
            "speed_kmh": speed,
            "note": alert,
            "location": {"category": "withheld", "exact_coordinates": False},
        }
        with st.spinner("Establishing and verifying a real session…"):
            result, error = services.safe_call(
                lambda: services.secure_round_trip(
                    payload=payload,
                    aead=aead,
                    pqc_mode=mode,
                    ttl_ms=ttl_ms,
                )
            )
        if error:
            st.error(f"FAIL CLOSED — message was not transmitted or accepted. {error}")
            return
        assert isinstance(result, dict)
        if result.get("verified"):
            st.success("PASS — receiver recovered and verified the original canonical payload.")
        else:
            st.error("FAIL CLOSED — receiver output did not match the transmitted payload.")
        cols = st.columns(2)
        cols[0].metric("Envelope size", _human_bytes(result.get("envelope_bytes")))
        cols[1].metric("Envelope overhead", _human_bytes(result.get("overhead_bytes")))
        cols = st.columns(2)
        cols[0].metric("Protect latency", _fmt(result.get("protect_ms"), 3, " ms"))
        cols[1].metric("Open latency", _fmt(result.get("open_ms"), 3, " ms"))
        stage_rows = [
            {
                "Stage": "Session establishment",
                "Result": result.get("pqc_status", "unknown"),
                "Measurement": _fmt(result.get("session_establishment_ms"), 3, " ms"),
            },
            {
                "Stage": "Envelope protection",
                "Result": result.get("aead", "unknown"),
                "Measurement": _fmt(result.get("protect_ms"), 3, " ms"),
            },
            {
                "Stage": "Peer verification",
                "Result": "pass" if result.get("verified") else "fail closed",
                "Measurement": _fmt(result.get("open_ms"), 3, " ms"),
            },
        ]
        st.dataframe(
            pd.DataFrame(stage_rows),
            width="stretch",
            hide_index=True,
        )
        if result.get("audit"):
            detail = str(result["audit"][0].get("detail", "Negotiation event recorded"))
            st.warning("Negotiation audit: " + detail)
        st.caption(
            "Requested mode: "
            + str(result.get("pqc_mode", "unknown"))
            + ". Key material, exact envelope bytes, and peer identifiers are not displayed."
        )


def _training_panel(train: dict[str, Any]) -> None:
    st.subheader("Model evaluation")
    if not train:
        _missing("training")
        return
    held = train.get("held_out_test_metrics", {})
    validation = train.get("validation_metrics", {})
    metric_frame = pd.DataFrame(
        {
            "Validation": {
                "F1": validation.get("f1"),
                "Recall": validation.get("recall"),
                "PR AUC": validation.get("pr_auc"),
            },
            "Held-out test": {
                "F1": held.get("f1"),
                "Recall": held.get("recall"),
                "PR AUC": held.get("pr_auc"),
            },
        }
    )
    st.bar_chart(metric_frame, color=["#2FB8AD", "#6C7A88"])
    table = metric_frame.reset_index().rename(columns={"index": "Metric"})
    st.dataframe(table, width="stretch", hide_index=True)
    rows = train.get("rows", {})
    st.caption(
        f"Model {train.get('model_version', 'unknown')} · "
        f"{rows.get('train', 0):,} training rows · "
        f"{rows.get('test', 0):,} held-out rows · calibrated: "
        f"{'yes' if train.get('calibrated') else 'no'}"
    )


def _demo_panel(demo: dict[str, Any]) -> None:
    st.subheader("Adaptive replay evidence")
    if not demo:
        _missing("demo")
        return
    left, right = st.columns(2)
    profiles = pd.Series(demo.get("profiles", {}), name="Messages")
    actions = pd.Series(demo.get("actions", {}), name="Messages")
    with left:
        st.caption("Protection profiles")
        st.bar_chart(profiles, color="#2FB8AD")
    with right:
        st.caption("Edge actions")
        st.bar_chart(actions, color="#2FB8AD")
    reduction = demo.get("adaptive_vs_send_all", {}).get("reduction", {})
    cols = st.columns(3)
    cols[0].metric("Records replayed", demo.get("records_replayed", "—"))
    cols[1].metric("Message reduction", _pct(reduction.get("messages")))
    cols[2].metric("Byte reduction", _pct(reduction.get("bytes")))
    failures = demo.get("fail_closed", {})
    if failures.get("count"):
        st.warning(f"{failures['count']} event(s) failed closed; no synthetic PQC was substituted.")


def _benchmark_panel(benchmark: dict[str, Any]) -> None:
    st.subheader("Latency distribution")
    if not benchmark:
        _missing("benchmark")
        return
    latency = benchmark.get("latency", {})
    rows = []
    for name, item in (
        ("Inference", latency.get("inference_ms", {})),
        ("Policy", latency.get("policy_ms", {})),
        ("Protect", latency.get("security_classical", {}).get("protect_ms", {})),
        ("Open", latency.get("security_classical", {}).get("open_ms", {})),
    ):
        rows.append(
            {
                "Stage": name,
                "Median": item.get("median"),
                "P95": item.get("p95"),
                "P99": item.get("p99"),
            }
        )
    frame = pd.DataFrame(rows).set_index("Stage")
    st.bar_chart(frame, color=["#2FB8AD", "#73808D", "#4D5A67"])
    st.dataframe(frame.reset_index(), width="stretch", hide_index=True)


def _ota_panel(ota: dict[str, Any]) -> None:
    st.subheader("Firmware lifecycle summary")
    if not ota:
        _missing("OTA")
        return
    boot = ota.get("secure_boot", {})
    update = ota.get("ab_update", {})
    successful = update.get("successful_update", {})
    rollback = update.get("rollback_scenario", {})
    cols = st.columns(2)
    cols[0].metric("Boot decision", "Allowed" if boot.get("allowed") else "Denied")
    cols[1].metric("Update activated", "Yes" if successful.get("activated") else "No")
    cols = st.columns(2)
    cols[0].metric("Rollback exercised", "Yes" if rollback.get("rolled_back") else "No")
    cols[1].metric("Active slot", update.get("active_slot_after_scenarios", "—"))


def experiments() -> None:
    _view_header(
        "Evaluation workspace",
        "Experiments",
        "Inspect stored evaluation outputs and launch bounded in-process workflows. "
        "Result panels and execution controls are intentionally separated.",
    )
    _flash()
    results = services.load_results()
    _section_label("Stored results")
    tabs = st.tabs(("Model", "Replay", "Latency", "Firmware"))
    with tabs[0]:
        _training_panel(results["train"])
    with tabs[1]:
        _demo_panel(results["demo"])
    with tabs[2]:
        _benchmark_panel(results["benchmark"])
    with tabs[3]:
        _ota_panel(results["ota"])

    st.divider()
    st.subheader("Run controls")
    st.caption(
        "Operations can take several minutes. Dataset locations remain in trusted project "
        "configuration and are not rendered. Training replaces the active UI model artifact."
    )
    runner = st.segmented_control(
        "Workflow",
        ("Data audit", "Model training", "Secure replay", "Benchmark"),
        default="Data audit",
        selection_mode="single",
    )
    if runner == "Data audit":
        with st.form("audit-run"):
            left, right = st.columns(2)
            dataset = left.selectbox("Dataset", ("edge-iiot", "veremi"), key="audit-dataset")
            task = right.selectbox("Task", ("binary", "multiclass"), key="audit-task")
            rows = left.number_input("Sample rows", 100, 10_000, 2_000, 100)
            seed = right.number_input("Random state", 0, 1_000_000, 42)
            submit = st.form_submit_button("Run bounded audit")
        if submit:
            _run_with_feedback(
                "Bounded data audit",
                lambda: services.run_experiment(
                    "audit", dataset=dataset, task=task, max_rows=rows, random_state=seed
                ),
            )
    elif runner == "Model training":
        with st.form("train-run"):
            left, right = st.columns(2)
            dataset = left.selectbox("Dataset", ("edge-iiot", "veremi"), key="train-dataset")
            task = right.selectbox("Task", ("binary", "multiclass"), key="train-task")
            rows = left.number_input(
                "Training sample bound",
                1_000,
                25_000,
                5_000,
                1_000,
            )
            seed = right.number_input(
                "Random state",
                0,
                1_000_000,
                42,
                key="train-seed",
            )
            calibrate = st.checkbox("Calibrate probabilities", value=True)
            submit = st.form_submit_button("Train bounded model")
        if submit:
            _run_with_feedback(
                "Bounded model training",
                lambda: services.run_experiment(
                    "train",
                    dataset=dataset,
                    task=task,
                    max_rows=rows,
                    calibrate=calibrate,
                    random_state=seed,
                ),
            )
    elif runner == "Secure replay":
        with st.form("demo-run"):
            left, right = st.columns(2)
            records = left.slider("Records to replay", 4, 100, 20)
            seed = right.number_input(
                "Random state",
                0,
                1_000_000,
                42,
                key="demo-seed",
            )
            submit = st.form_submit_button("Run secure replay demo")
        if submit:
            _run_with_feedback(
                "Secure replay demo",
                lambda: services.run_experiment(
                    "demo", max_records=records, random_state=seed
                ),
            )
    else:
        with st.form("benchmark-run"):
            left, right = st.columns(2)
            records = left.number_input("Records loaded", 10, 200, 50, 10)
            iterations = right.number_input("Iterations", 1, 100, 20)
            payload_bytes = left.number_input("Payload bytes", 16, 4_096, 256, 16)
            seed = right.number_input("Random state", 0, 1_000_000, 42, key="bench-seed")
            submit = st.form_submit_button("Run bounded benchmark")
        if submit:
            _run_with_feedback(
                "Bounded benchmark",
                lambda: services.run_experiment(
                    "benchmark",
                    max_records=records,
                    iterations=iterations,
                    payload_bytes=payload_bytes,
                    random_state=seed,
                ),
            )


def secure_boot_ota() -> None:
    _view_header(
        "Firmware assurance",
        "Secure Boot / OTA",
        "Review signed-manifest decisions, anti-rollback behavior, A/B activation, "
        "and lifecycle events from the software assurance model.",
    )
    _flash()
    ota = services.load_results()["ota"]
    if not ota:
        _missing("OTA")
    else:
        boot = ota.get("secure_boot", {})
        update = ota.get("ab_update", {})
        successful = update.get("successful_update", {})
        rollback = update.get("rollback_scenario", {})
        pqc = ota.get("pqc", {})
        _section_label("Assurance state")
        cols = st.columns(2)
        cols[0].metric("Signed boot", "Allowed" if boot.get("allowed") else "Denied")
        cols[1].metric("Verified components", len(boot.get("verified_components", [])))
        cols = st.columns(2)
        cols[0].metric("Installed version", successful.get("version", "—"))
        cols[1].metric("Active A/B slot", update.get("active_slot_after_scenarios", "—"))
        left, right = st.columns(2, gap="large")
        with left:
            st.subheader("Manifest verification")
            algorithms = (
                ota.get("manifests", {})
                .get("firmware", {})
                .get("signature_algorithms", [])
            )
            boot_rows = [
                {
                    "Control": "Boot authorization",
                    "State": "Allowed" if boot.get("allowed") else "Denied",
                },
                {
                    "Control": "Verified components",
                    "State": ", ".join(boot.get("verified_components", [])) or "None",
                },
                {
                    "Control": "Manifest signatures",
                    "State": ", ".join(algorithms) or "Not available",
                },
                {
                    "Control": "PQC signatures",
                    "State": "Available" if pqc.get("available") else "Unavailable",
                },
            ]
            st.dataframe(pd.DataFrame(boot_rows), width="stretch", hide_index=True)
            if not boot.get("allowed"):
                st.error("Boot denied: " + "; ".join(boot.get("errors", ["unknown error"])))
            if not pqc.get("available"):
                st.warning("PQC manifest signatures were not used because liboqs is unavailable.")
        with right:
            st.subheader("Update lifecycle")
            if successful.get("activated"):
                st.success("Signed candidate passed activation checks.")
            if rollback.get("rolled_back"):
                st.info(
                    "The unhealthy candidate was rolled back and the prior healthy "
                    "version was retained."
                )
            audit = update.get("audit_log", [])
            lifecycle_rows = [
                {"Sequence": index, "Lifecycle event": str(item)}
                for index, item in enumerate(audit, start=1)
            ]
            st.dataframe(
                pd.DataFrame(lifecycle_rows),
                width="stretch",
                hide_index=True,
            )

    st.divider()
    st.subheader("Lifecycle run control")
    with st.form("ota-run"):
        target = st.text_input(
            "Logical target alias",
            "ecu-gateway",
            max_chars=64,
            help="Use a non-sensitive logical alias, not a VIN or hardware identifier.",
        )
        submit = st.form_submit_button("Rerun secure boot & OTA", type="primary")
    if submit:
        _run_with_feedback(
            "Secure boot and OTA simulation",
            lambda: services.run_ota(target),
        )
    st.info(
        "Simulation boundary: generated firmware bytes, software-managed keys, slots, "
        "and health checks do not provide TPM, HSM, ROM, physical ECU, or road-safety "
        "assurance."
    )


_application_header()
selected_view = st.segmented_control(
    "Primary navigation",
    VIEWS,
    default=VIEWS[0],
    selection_mode="single",
    label_visibility="collapsed",
) or VIEWS[0]
availability = services.pqc_availability()
st.caption(
    "Runtime status: "
    + ("PQC provider available" if availability.get("available") else "PQC provider unavailable")
    + " · simulated ECUs · no production or safety certification"
)


if selected_view == "Overview":
    overview()
elif selected_view == "Policy Lab":
    policy_lab()
elif selected_view == "Secure V2X":
    secure_demo()
elif selected_view == "Experiments":
    experiments()
else:
    secure_boot_ota()
