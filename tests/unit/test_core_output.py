"""Unit tests for the shared output renderer."""

import json

from olympus.core.output import OutputFormat, render, render_table


def test_render_json() -> None:
    out = render([{"a": 1, "b": "x"}], ["a", "b"], OutputFormat.JSON)
    assert '"a": 1' in out


def test_render_table_contains_headers_and_values() -> None:
    out = render([{"severity": "high", "title": "SQLi"}], ["severity", "title"], OutputFormat.TABLE)
    assert "severity" in out
    assert "SQLi" in out


def test_render_table_direct() -> None:
    out = render_table(["x"], [["1"], ["2"]], title="nums")
    assert "nums" in out
    assert "1" in out and "2" in out


def test_render_table_neutralizes_untrusted_terminal_and_rich_markup() -> None:
    hostile = (
        "[link=https://evil.invalid/?token=secret]open\x1b[2J\nforged"
        "[/link] https://target.invalid/?api_key=private"
    )
    rendered = render_table(["finding"], [[hostile]], title=hostile)

    assert "\x1b" not in rendered
    assert "\nforged" not in rendered
    assert "secret" not in rendered
    assert "[link=https://evil.invalid" in rendered
    assert "[REDACTED]" in rendered
    assert "[/link]" in rendered

    machine = render([{"finding": hostile}], ["finding"], OutputFormat.JSON)
    assert json.loads(machine)[0]["finding"] == hostile
