from __future__ import annotations

from typing import Sequence

import pandas as pd

from .base import DatasetAdapter


_BENIGN_LABELS = {"0", "benign", "normal", "normaltraffic", "noattack", "false"}


class EdgeIIoTAdapter(DatasetAdapter):
    """Memory-bounded adapter for the Edge-IIoTset ML/DNN CSV files."""

    BINARY_TARGETS = ("Attack_label", "attack_label", "label", "class")
    MULTICLASS_TARGETS = ("Attack_type", "attack_type", "attack", "category")
    KNOWN_TARGET_COLUMNS = frozenset((*BINARY_TARGETS, *MULTICLASS_TARGETS))
    OFFICIAL_DROP_COLUMNS = (
        "frame.time",
        "ip.src_host",
        "ip.dst_host",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "http.file_data",
        "http.request.full_uri",
        "icmp.transmit_timestamp",
        "http.request.uri.query",
        "tcp.options",
        "tcp.payload",
        "tcp.srcport",
        "tcp.dstport",
        "udp.port",
        "mqtt.msg",
    )

    def __init__(
        self,
        *args,
        drop_columns: Sequence[str] = OFFICIAL_DROP_COLUMNS,
        **kwargs,
    ) -> None:
        # The dataset authors identify these high-cardinality identifiers,
        # payloads, and ports as unsuitable for the selected ML/DL pipeline.
        # Removing them also reduces memorization of capture-specific hosts.
        super().__init__(*args, drop_columns=drop_columns, **kwargs)

    def resolve_target_column(self, columns: Sequence[str]) -> str:
        if self.target_column:
            matched = self._match_column(columns, (self.target_column,))
            if matched is None:
                raise ValueError(
                    f"Configured target column {self.target_column!r} was not found"
                )
            return matched
        candidates = (
            self.BINARY_TARGETS if self.task == "binary" else self.MULTICLASS_TARGETS
        )
        matched = self._match_column(columns, candidates)
        if matched is None:
            raise ValueError(
                f"Could not find a {self.task} Edge-IIoT target; tried {candidates}"
            )
        return matched

    def transform_target(self, target: pd.Series) -> pd.Series:
        if self.task == "multiclass":
            result = target.astype("string").str.strip()
            return result.mask(result.eq("") | result.str.lower().eq("nan"))

        numeric = pd.to_numeric(target, errors="coerce")
        normalized = (
            target.astype("string")
            .str.strip()
            .str.lower()
            .str.replace(r"[^a-z0-9]+", "", regex=True)
        )
        result = pd.Series(pd.NA, index=target.index, dtype="Int8")
        numeric_rows = numeric.notna()
        result.loc[numeric_rows] = numeric.loc[numeric_rows].ne(0).astype("int8")
        text_rows = target.notna() & ~numeric_rows
        result.loc[text_rows] = (
            ~normalized.loc[text_rows].isin(_BENIGN_LABELS)
        ).astype("int8")
        return result
