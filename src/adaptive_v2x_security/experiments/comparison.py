from __future__ import annotations

from typing import Any, Iterable

from adaptive_v2x_security.simulation import WorkloadComparison


def adaptive_vs_send_all(
    comparison: WorkloadComparison | dict[str, Any],
) -> dict[str, Any]:
    """Return a stable adaptive-versus-send-all result shape."""
    values = (
        comparison.as_dict()
        if isinstance(comparison, WorkloadComparison)
        else dict(comparison)
    )
    return {
        "send_all": {
            "messages": int(values.get("baseline_messages", 0)),
            "bytes": int(values.get("baseline_bytes", 0)),
        },
        "adaptive": {
            "messages": int(values.get("adaptive_messages", 0)),
            "bytes": int(values.get("adaptive_bytes", 0)),
            "alerts": int(values.get("alert_messages", 0)),
            "summaries": int(values.get("summary_messages", 0)),
            "unavailable": int(values.get("unavailable_messages", 0)),
        },
        "reduction": {
            "messages": float(values.get("message_reduction", 0.0)),
            "bytes": float(values.get("byte_reduction", 0.0)),
        },
    }


def aggregate_adaptive_comparisons(
    comparisons: Iterable[WorkloadComparison | dict[str, Any]],
) -> dict[str, Any]:
    totals = {
        "baseline_messages": 0,
        "baseline_bytes": 0,
        "adaptive_messages": 0,
        "adaptive_bytes": 0,
        "alert_messages": 0,
        "summary_messages": 0,
        "unavailable_messages": 0,
    }
    for comparison in comparisons:
        values = (
            comparison.as_dict()
            if isinstance(comparison, WorkloadComparison)
            else comparison
        )
        for key in totals:
            totals[key] += int(values.get(key, 0))
    totals["message_reduction"] = (
        1.0 - totals["adaptive_messages"] / totals["baseline_messages"]
        if totals["baseline_messages"]
        else 0.0
    )
    totals["byte_reduction"] = (
        1.0 - totals["adaptive_bytes"] / totals["baseline_bytes"]
        if totals["baseline_bytes"]
        else 0.0
    )
    return adaptive_vs_send_all(totals)
