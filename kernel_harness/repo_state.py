from __future__ import annotations

import subprocess
from pathlib import Path


def collect_repo_state(repo_root: Path, *, focus_paths: list[str] | None = None) -> dict:
    repo_root = repo_root.expanduser().resolve()
    state = {
        "repo_root": str(repo_root),
        "is_git": False,
        "status_ok": False,
        "error": "",
        "branch": "",
        "head": "",
        "dirty": False,
        "dirty_files": [],
        "dirty_focus_paths": [],
    }

    if not repo_root.exists():
        state["error"] = "repo_root_missing"
        return state
    if not repo_root.is_dir():
        state["error"] = "repo_root_not_directory"
        return state

    inside = _run_git(repo_root, ["rev-parse", "--is-inside-work-tree"])
    if inside.returncode != 0:
        detail = _process_error(inside)
        if "not a git repository" in detail.lower():
            state["error"] = "not_git_repository"
        else:
            state["error"] = _error_with_detail("git_probe_failed", detail)
        return state
    if inside.stdout.strip() != "true":
        state["error"] = "not_git_work_tree"
        return state

    state["is_git"] = True
    branch_proc = _run_git(repo_root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    state["branch"] = branch_proc.stdout.strip() if branch_proc.returncode == 0 else "DETACHED"

    head_proc = _run_git(repo_root, ["rev-parse", "--verify", "HEAD"])
    if head_proc.returncode == 0:
        state["head"] = head_proc.stdout.strip()
    else:
        state["error"] = _error_with_detail("git_head_unavailable", _process_error(head_proc))

    status_proc = _run_git(
        repo_root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    if status_proc.returncode != 0:
        state["error"] = _error_with_detail("git_status_failed", _process_error(status_proc))
        return state

    dirty_files = _parse_porcelain(status_proc.stdout)
    state["status_ok"] = True
    state["dirty_files"] = dirty_files
    state["dirty"] = bool(dirty_files)

    normalized_focus = [
        path
        for path in (_normalize_focus_path(item) for item in (focus_paths or []))
        if path
    ]
    dirty_file_set = set(dirty_files)
    state["dirty_focus_paths"] = [path for path in normalized_focus if path in dirty_file_set]
    return state


def commit_present(repo_root: Path, commit_hash: str) -> bool:
    proc = _run_git(repo_root, ["merge-base", "--is-ancestor", commit_hash, "HEAD"])
    return proc.returncode == 0


def _run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = ["git", "-C", str(repo_root), *args]
    try:
        return subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def _parse_porcelain(output: str) -> list[str]:
    if "\0" not in output:
        return _parse_porcelain_lines(output)

    records = output.split("\0")
    files: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record or len(record) < 3:
            continue

        status = record[:2]
        path = record[3:] if record[2:3] == " " else record[2:].lstrip()
        if path:
            files.append(path)

        # In porcelain v1 -z output a rename/copy record stores the destination
        # in this record and the source path in the immediately following field.
        if "R" in status or "C" in status:
            index += 1

    return _deduplicate(files)


def _parse_porcelain_lines(output: str) -> list[str]:
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
    return _deduplicate(files)


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _normalize_focus_path(value: str) -> str:
    stripped = value.strip().strip("`")
    for token in stripped.replace("(", " ").replace(")", " ").split():
        if token.endswith((".c", ".h")) and "/" in token:
            return token.removeprefix("./")
    if stripped.endswith((".c", ".h")):
        return stripped.removeprefix("./")
    if ":" in stripped:
        maybe_path = stripped.split(":", 1)[0]
        if maybe_path.endswith((".c", ".h")):
            return maybe_path.removeprefix("./")
    return ""


def _process_error(proc: subprocess.CompletedProcess[str]) -> str:
    return " ".join((proc.stderr or proc.stdout or "").split())


def _error_with_detail(code: str, detail: str) -> str:
    return f"{code}: {detail}" if detail else code
