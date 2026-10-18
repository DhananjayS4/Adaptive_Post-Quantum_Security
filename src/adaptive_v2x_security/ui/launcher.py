"""Installed-package launcher for the Streamlit application."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Start Streamlit in-process without invoking a shell."""
    try:
        from streamlit.web import cli as streamlit_cli
    except ImportError as exc:
        raise RuntimeError(
            "Streamlit is required for the UI. Install streamlit, then retry."
        ) from exc

    app = Path(__file__).with_name("app.py")
    forwarded = list(argv) if argv is not None else sys.argv[1:]
    sys.argv = ["streamlit", "run", str(app), *forwarded]
    return int(streamlit_cli.main() or 0)


if __name__ == "__main__":
    raise SystemExit(main())
