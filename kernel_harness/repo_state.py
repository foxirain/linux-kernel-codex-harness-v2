from __future__ import annotations

import subprocess
from pathlib import Path


def collect_repo_state(repo_root: Path, *, focus_paths: list[str] | None = None) -> dict:
    repo_root = repo_root.expanduser().resolve()
    state = {
        "repo_root": str(repo_root),
        "is_git": False,
        "branch": "",
        "head": "",
        "dirty": False,
        "dirty_files": [],
        "dirty_focus_paths": [],
    }

    if not repo_root.exists():
        return state

    inside = _run_git(repo_root, ["rev-parse", "--is-inside-work-tree"])
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return state

    state["is_git"] = True
    state["branch"] = _git_text(repo_root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    if not state["branch"]:
        state["branch"] = "DETACHED"
    state["head"] = _git_text(repo_root, ["rev-parse", "HEAD"])

    status_proc = _run_git(repo_root, ["status", "--porcelain"])
    dirty_files = _parse_porcelain(status_proc.stdout)
    state["dirty_files"] = dirty_files
    state["dirty"] = bool(dirty_files)

    focus_paths = focus_paths or []
    normalized_focus = [p for p in (_normalize_focus_path(item) for item in focus_paths) if p]
    state["dirty_focus_paths"] = [path for path in normalized_focus if path in dirty_files]
    return state


def commit_present(repo_root: Path, commit_hash: str) -> bool:
    proc = _run_git(repo_root, ["merge-base", "--is-ancestor", commit_hash, "HEAD"])
    return proc.returncode == 0


def _run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def _git_text(repo_root: Path, args: list[str]) -> str:
    proc = _run_git(repo_root, args)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _parse_porcelain(output: str) -> list[str]:
    files: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        path_part = line[3:] if len(line) > 3 else ""
        if " -> " in path_part:
            path_part = path_part.split(" -> ", 1)[1]
        if path_part:
            files.append(path_part)
    return files


def _normalize_focus_path(value: str) -> str:
    stripped = value.strip().strip("`")
    for token in stripped.replace("(", " ").replace(")", " ").split():
        if token.endswith((".c", ".h")) and "/" in token:
            return token
    if stripped.endswith((".c", ".h")):
        return stripped
    if ":" in stripped:
        maybe_path = stripped.split(":", 1)[0]
        if maybe_path.endswith((".c", ".h")):
            return maybe_path
    return ""
