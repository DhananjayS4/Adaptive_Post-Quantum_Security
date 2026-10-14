from __future__ import annotations

from typing import Sequence

import pandas as pd

from .base import DatasetAdapter


_BENIGN_LABELS = {
    "0",
    "benign",
    "genuine",
    "legitimate",
    "normal",
    "noattack",
    "false",
}


class VeReMiAdapter(DatasetAdapter):
    """Memory-bounded adapter for common flattened VeReMi CSV exports."""

    BINARY_TARGETS = (
        "attack_label",
        "Attack_label",
        "is_attack",
        "isAttacker",
        "label",
        "class",
    )
    MULTICLASS_TARGETS = (
        "attack_type",
        "Attack_type",
        "attackType",
        "attackerType",
        "type_attack",
        "label",
        "class",
    )
    # Include aliases from both tasks: the unused representation can reveal
    # the selected label just as directly as the selected target itself.
    KNOWN_TARGET_COLUMNS = frozenset((*BINARY_TARGETS, *MULTICLASS_TARGETS))

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
                "VeReMi exports use several label names; pass target_column explicitly "
                f"if none of {candidates} is present"
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
