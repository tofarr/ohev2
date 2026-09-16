"""Tests for the ported JSON logging configuration."""

from __future__ import annotations

import io
import json
import logging

import pytest

from openhands.ev2.util.logger import (
    LOG_JSON_FOR_CONSOLE,
    custom_json_serializer,
    format_stack,
    setup_json_logger,
)


def test_format_stack_strips_site_packages_and_cwd() -> None:
    """``format_stack`` rewrites absolute paths to ``File "`` prefixes."""
    from openhands.ev2.util.logger import CWD_PREFIX, SITE_PACKAGES_PREFIX

    # A site-packages path should be shortened to the package-relative path.
    # ``format_stack`` also swaps double quotes to single quotes.
    stack = SITE_PACKAGES_PREFIX + 'foo/bar.py", line 1, in x'
    result = format_stack(stack)
    assert isinstance(result, list)
    assert any("File 'foo/bar.py'" in line for line in result)

    # A CWD-parent path should be shortened too.
    stack2 = CWD_PREFIX + 'src/baz.py", line 2'
    result2 = format_stack(stack2)
    assert any("File 'src/baz.py'" in line for line in result2)


def test_custom_json_serializer_plain() -> None:
    """Without console mode the serializer is plain JSON."""
    payload = {"message": "hi", "severity": "INFO"}
    out = custom_json_serializer(dict(payload))
    parsed = json.loads(out)
    assert parsed == payload


def test_custom_json_serializer_console_mode_indents() -> None:
    """Console mode adds a ``ts`` and indents the output."""
    payload = {"message": "hi", "severity": "INFO"}
    out = custom_json_serializer(dict(payload), indent=None) if LOG_JSON_FOR_CONSOLE else None
    if LOG_JSON_FOR_CONSOLE:
        assert out is not None
        parsed = json.loads(out)
        assert parsed["message"] == "hi"
        assert "ts" in parsed
    else:
        assert out is None


def test_setup_json_logger_emits_json_to_stream() -> None:
    """``setup_json_logger`` wires a JSON handler that writes structured records."""
    stream = io.StringIO()
    log = logging.getLogger("test_json_logger")
    log.propagate = False
    setup_json_logger(log, level="INFO", _out=stream)
    log.info("hello %s", "world", extra={"event": "smoke"})

    line = stream.getvalue().strip()
    assert line, "expected at least one log line"
    parsed = json.loads(line)
    assert parsed["message"] == "hello world"
    assert parsed["severity"] == "INFO"
    assert parsed["event"] == "smoke"
    assert "ts" in parsed
    assert "module" in parsed


def test_setup_json_logger_replaces_existing_handlers() -> None:
    """Re-configuring a logger must not accumulate duplicate handlers."""
    log = logging.getLogger("test_json_logger_dedup")
    log.propagate = False
    stream_a = io.StringIO()
    setup_json_logger(log, level="INFO", _out=stream_a)
    before = len(log.handlers)

    stream_b = io.StringIO()
    setup_json_logger(log, level="INFO", _out=stream_b)
    after = len(log.handlers)

    assert before == 1
    assert after == 1
    # New handler points at stream_b
    log.info("second")
    assert "second" in stream_b.getvalue()
    assert stream_a.getvalue() == ""


def test_quiet_lib_loggers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing the module quiets the loquacious library loggers to WARNING."""
    import importlib

    from openhands.ev2.util import logger as logger_mod

    importlib.reload(logger_mod)

    for name in ("sqlalchemy.engine.Engine", "httpx", "socketio.server"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING


def test_app_import_does_not_flood_stdout_with_mapper_logs() -> None:
    """Importing the app configures logging before ORM models load.

    SQLAlchemy emits one INFO line per mapped column when mappers configure
    (triggered by the router/model imports in ``app.py``). The JSON logging
    setup must run *before* those imports so the flood does not stream to
    stdout on every process that imports the app (workers, tests, the
    server). Verified in a fresh subprocess so in-process import side
    effects do not mask the result.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c", "import openhands.ev2.app"],
        capture_output=True,
        text=True,
        check=True,
    )
    # The JSON log handler may be attached to stdout or stderr depending on
    # the environment; check both.
    output = result.stdout + result.stderr
    mapper_flood = sum(
        1
        for line in output.splitlines()
        if "sqlalchemy.orm.mapper.Mapper" in line and '"INFO"' in line
    )
    assert mapper_flood == 0, (
        f"Importing openhands.ev2.app emitted {mapper_flood} SQLAlchemy mapper "
        "INFO log lines — logging is not configured before ORM imports. "
        "Ensure the util/logger import precedes model/router imports in app.py."
    )
