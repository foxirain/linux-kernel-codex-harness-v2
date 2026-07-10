from __future__ import annotations

import json
import os
from pathlib import Path

STATE_FILENAME = "review_state.json"
DEFAULT_RESPONSE_FILENAME = "codex_response.txt"
DEFAULT_RESPONSE_ARCHIVE_DIRNAME = "responses"


def state_path(session_dir: Path) -> Path:
    return session_dir / STATE_FILENAME


def response_path(session_dir: Path) -> Path:
    return session_dir / DEFAULT_RESPONSE_FILENAME


def response_archive_dir(session_dir: Path) -> Path:
    return session_dir / DEFAULT_RESPONSE_ARCHIVE_DIRNAME


def _tail_followup_depth(history: list[dict]) -> int:
    depth = 0
    for item in reversed(history):
        if item.get("rank") is None and item.get("next_target"):
            depth += 1
            continue
        if item.get("rank") is None:
            depth += 1
            continue
        break
    return depth


def _normalize_state(session_dir: Path, state: dict) -> dict:
    normalized = {
        "current_rank": int(state.get("current_rank", 1) or 1),
        "history": list(state.get("history", [])),
        "manual_next_target": state.get("manual_next_target", "") or "",
        "manual_next_prompt": state.get("manual_next_prompt", "") or "",
        "manual_followup_depth": state.get("manual_followup_depth"),
        "pending_rank": state.get("pending_rank"),
        "pending_target": state.get("pending_target", "") or "",
        "pending_prompt_source": state.get("pending_prompt_source", "") or "",
        "pending_response_file": state.get("pending_response_file") or str(response_path(session_dir)),
    }
    if normalized["manual_followup_depth"] is None:
        normalized["manual_followup_depth"] = _tail_followup_depth(normalized["history"])
    else:
        normalized["manual_followup_depth"] = int(normalized["manual_followup_depth"] or 0)
    return normalized


def initialize_state(session_dir: Path) -> dict:
    state = _normalize_state(session_dir, {})
    save_state(session_dir, state)
    return state


def load_state(session_dir: Path) -> dict:
    path = state_path(session_dir)
    if not path.exists():
        return initialize_state(session_dir)
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    state = _normalize_state(session_dir, raw)
    if state != raw:
        save_state(session_dir, state)
    return state


def save_state(session_dir: Path, state: dict) -> None:
    path = state_path(session_dir)
    normalized = _normalize_state(session_dir, state)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temp_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)


def set_pending_review(session_dir: Path, rank: int | None, target: str, prompt_source: str) -> dict:
    state = load_state(session_dir)
    state["pending_rank"] = rank
    state["pending_target"] = target
    state["pending_prompt_source"] = prompt_source
    state["pending_response_file"] = str(response_path(session_dir))
    save_state(session_dir, state)
    return state


def clear_pending_review(session_dir: Path) -> dict:
    state = load_state(session_dir)
    state["pending_rank"] = None
    state["pending_target"] = ""
    state["pending_prompt_source"] = ""
    state["pending_response_file"] = str(response_path(session_dir))
    save_state(session_dir, state)
    return state


def record_review(
    session_dir: Path,
    rank: int | None,
    target: str,
    verdict: str,
    notes: str,
    next_target: str,
    next_prompt: str,
    auto_advance: bool,
    classification: dict | None = None,
) -> dict:
    state = load_state(session_dir)
    history_entry = {
        "rank": rank,
        "target": target,
        "verdict": verdict,
        "notes": notes,
        "next_target": next_target,
        "next_prompt": next_prompt,
    }
    if classification:
        history_entry["classification"] = classification
    state["history"].append(history_entry)
    if next_target:
        state["manual_next_target"] = next_target
        state["manual_next_prompt"] = next_prompt
        state["manual_followup_depth"] = int(state.get("manual_followup_depth", 0)) + 1
    elif auto_advance and rank is not None:
        state["manual_next_target"] = ""
        state["manual_next_prompt"] = ""
        state["manual_followup_depth"] = 0
    else:
        state["manual_next_target"] = ""
        state["manual_next_prompt"] = ""
        state["manual_followup_depth"] = 0
    if auto_advance:
        done = completed_ranks(state)
        next_rank = 1
        while next_rank in done:
            next_rank += 1
        state["current_rank"] = next_rank
    state["pending_rank"] = None
    state["pending_target"] = ""
    state["pending_prompt_source"] = ""
    state["pending_response_file"] = str(response_path(session_dir))
    save_state(session_dir, state)
    return state


def completed_ranks(state: dict) -> set[int]:
    return {int(item.get("rank", 0)) for item in state.get("history", []) if item.get("rank") is not None}
