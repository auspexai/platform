"""Tests for the `auspexai-coordinator token` CLI subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from auspexai_platform.cli import main


def test_token_init_writes_file_and_prints_token(state_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    assert result.exit_code == 0, result.output
    assert (state_dir / "maintainer.token").exists()
    assert "Token:" in result.output


def test_token_init_refuses_overwrite_without_force(state_dir: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    result = runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_token_init_force_overwrites(state_dir: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    result = runner.invoke(main, ["token", "init", "--state-dir", str(state_dir), "--force"])
    assert result.exit_code == 0, result.output


def test_token_rotate_creates_new_token(state_dir: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    result = runner.invoke(main, ["token", "rotate", "--state-dir", str(state_dir)])
    assert result.exit_code == 0, result.output
    assert "Rotated" in result.output


def test_token_rotate_without_init_errors(state_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["token", "rotate", "--state-dir", str(state_dir)])
    assert result.exit_code != 0
    assert "no maintainer token" in result.output.lower()


def test_token_show_lists_active(state_dir: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    result = runner.invoke(main, ["token", "show", "--state-dir", str(state_dir)])
    assert result.exit_code == 0, result.output
    assert "[1]" in result.output


def test_token_show_lists_two_after_rotate(state_dir: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["token", "init", "--state-dir", str(state_dir)])
    runner.invoke(
        main, ["token", "rotate", "--state-dir", str(state_dir), "--overlap-minutes", "5"]
    )
    result = runner.invoke(main, ["token", "show", "--state-dir", str(state_dir)])
    assert result.exit_code == 0, result.output
    assert "[1]" in result.output
    assert "[2]" in result.output
