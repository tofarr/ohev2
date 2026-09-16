"""JSON logging configuration ported from OpenHands Enterprise.

Configures structured (JSON) logging for the application and all third-party
libraries so logs are machine-parseable in cloud environments. The OpenHands
SDK logger is heavily customized on its own, so it is reconfigured here to emit
JSON as well. Chatty library loggers are quieted to WARNING.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from pythonjsonlogger.json import JsonFormatter

# The OpenHands logger is heavily customized by the SDK; configure it to emit
# JSON as well. Newer SDK releases expose it via openhands.sdk.logger while the
# legacy app_server path named the root "openhands" logger directly. Resolve
# whichever is available so this works across dependency versions.
try:
    from openhands.app_server.utils.logger import (  # type: ignore[import-untyped]
        openhands_logger,
    )
except ImportError:
    openhands_logger = logging.getLogger("openhands")

LOG_JSON = os.getenv("LOG_JSON", "1") == "1"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DEBUG = os.getenv("DEBUG", "False").lower() in ["true", "1", "yes"]
if DEBUG:
    LOG_LEVEL = "DEBUG"

FILE_PREFIX = 'File "'
CWD_PREFIX = FILE_PREFIX + str(Path(os.getcwd()).parent) + "/"
SITE_PACKAGES_PREFIX = (
    CWD_PREFIX + f".venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/"
)
# Make the JSON easy to read in the console - useful for non cloud environments
LOG_JSON_FOR_CONSOLE = int(os.getenv("LOG_JSON_FOR_CONSOLE", "0"))


def format_stack(stack: str) -> list[str]:
    return (
        stack.replace(SITE_PACKAGES_PREFIX, FILE_PREFIX)
        .replace(CWD_PREFIX, FILE_PREFIX)
        .replace('"', "'")
        .split("\n")
    )


def custom_json_serializer(obj: Any, **kwargs: Any) -> str:
    if LOG_JSON_FOR_CONSOLE:
        kwargs["indent"] = 2
        obj = {"ts": datetime.now().isoformat(), **obj}

        if isinstance(obj, dict):
            exc_info = obj.get("exc_info")
            if isinstance(exc_info, str):
                obj["exc_info"] = format_stack(exc_info)
            stack_info = obj.get("stack_info")
            if isinstance(stack_info, str):
                obj["stack_info"] = format_stack(stack_info)

    result = json.dumps(obj, **kwargs)

    # Swap out newlines to make things easier to read. This will produce
    # invalid json but means we can have similar logs in local development
    # to production, making things easier to correlate. Obviously,
    # LOG_JSON_FOR_CONSOLE should not be used in production environments.
    if LOG_JSON_FOR_CONSOLE:
        result = result.replace("\\n", "\n")

    return result


def setup_json_logger(
    logger: logging.Logger,
    level: str = LOG_LEVEL,
    _out: TextIO = sys.stdout,
) -> None:
    """Configure *logger* to output JSON for Google Cloud.

    Existing filters are preserved so sensitive content stays redacted.
    """
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    handler = logging.StreamHandler(_out)
    handler.setLevel(level)

    formatter = JsonFormatter(
        "%(message)s%(levelname)s%(module)s%(funcName)s%(lineno)d",
        rename_fields={"levelname": "severity"},
        json_serializer=custom_json_serializer,
        # Use 'ts' for consistency with LOG_JSON_FOR_CONSOLE mode
        # (skip when console mode to avoid duplicates)
        timestamp="ts" if not LOG_JSON_FOR_CONSOLE else False,
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)


def setup_all_loggers() -> None:
    """Set up JSON logging for all libraries that may be logging.

    The OpenHands logger is left alone here since it is reconfigured
    separately below.
    """
    if LOG_JSON:
        setup_json_logger(logging.getLogger())

        for name in logging.root.manager.loggerDict:
            child = logging.getLogger(name)
            setup_json_logger(child)
            child.propagate = False

    # Quiet down some of the loggers that talk too much!
    loquacious_loggers = {
        "engineio",
        "engineio.server",
        "fastmcp",
        "FastMCP",
        "httpx",
        "mcp.client.sse",
        "socketio",
        "socketio.client",
        "socketio.server",
        "sqlalchemy.engine.Engine",
        "sqlalchemy.orm.mapper.Mapper",
    }
    for logger_name in loquacious_loggers:
        logging.getLogger(logger_name).setLevel("WARNING")


logger = logging.getLogger("saas")
setup_all_loggers()
# OpenHands logger is heavily customized, so make sure it logs JSON too.
setup_json_logger(openhands_logger)
