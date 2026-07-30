"""Tests for the top-level ModelFuzz command-line interface."""

from typer.testing import CliRunner

from modelfuzz import __version__
from modelfuzz.cli import app

runner = CliRunner()


def test_bare_invocation_shows_help() -> None:
    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Runtime guardrails for AI agents." in result.output
    assert "scan" in result.output
    assert "version" in result.output


def test_version_option_prints_installed_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_version_subcommand_remains_supported() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__
