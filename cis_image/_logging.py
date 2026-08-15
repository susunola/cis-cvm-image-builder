from __future__ import annotations

import logging
import os
import sys

VERSION = "0.16.25"

logger = logging.getLogger("cis-image")

def _setup_logging(*, verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    if logger.handlers:
        logger.setLevel(level)
        for h in logger.handlers:
            h.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)

def _color(text: str, code: int) -> str:
    if os.environ.get("NO_COLOR") or not sys.stderr.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

def ok(msg: str) -> None:
    logger.info("  %s %s", _color("\u2713", 32), msg)

def warn(msg: str) -> None:
    logger.warning("  %s %s", _color("!", 33), msg)

def fail(msg: str) -> None:
    logger.error("  %s %s", _color("\u2717", 31), msg)

def info(msg: str) -> None:
    logger.info("  %s %s", _color("\u2022", 36), msg)

def banner(title: str) -> None:
    logger.info(_color(f"\n== {title} ==", 1))

class ConfigError(Exception):
    """Raised when the TOML configuration is invalid or missing required fields."""
