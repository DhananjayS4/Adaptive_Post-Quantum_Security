from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture
def policy_path() -> Path:
    return ROOT / "config" / "security_policy.yaml"


@pytest.fixture
def future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)
