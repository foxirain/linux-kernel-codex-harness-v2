from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from kernel_harness.autopilot import _candidate_to_prompt_assets, run_autopilot
from kernel_harness.repo_state import collect_repo_state
from kernel_harness.bundle import write_session_bundle
from kernel_harness.ingest import load_response, parse_response
from kernel_harness.session import (
    clear_pending_review,
    completed_ranks,
    load_state,
    record_review,
    response_archive_dir,
    response_path,
    save_state,
    set_pending_review,
)
from kernel_harness.syzbot import fetch_dashboard, load_index, summarize_index
from kernel_harness.targeting import discover_candidates, load_config


PACKAGE_ROOT = Path(__file__).resolve().parent.parent
PROFILE_CONFIGS = {
    "default": PACKAGE_ROOT / "configs" / "linux-kernel-default.json",
    "bpf": PACKAGE_ROOT / "configs" / "profiles" / "bpf.json",
    "drivers": PACKAGE_ROOT / "configs" / "profiles" / "drivers.json",
    "fs": PACKAGE_ROOT / "configs" / "profiles" / "fs.json",
    "io_uring": PACKAGE_ROOT / "configs" / "profiles" / "io_uring.json",
    "net": PACKAGE_ROOT / "configs" / "profiles" / "net.json",
}
VERDICTS = ["cve_candidate", "plausible_security_bug", "latent_bug", "not_cve_candidate", "needs_more_context"]
SUBCOMMANDS = {"scan", "inspect", "codex", "next", "record", "ingest", "loop", "status", "doctor", "autopilot", "syzbot-fetch", "syzbot-stats"}
MAX_MANUAL_FOLLOWUPS = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kernel-harness",
        description="Prepare kernel vulnerability hunting bundles for Codex.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Score files and generate a review session.")
    _add_scan_arguments(scan_parser)

    inspect_parser = subparsers.add_parser("inspect", help="Print a ranked summary from a generated session.")
    inspect_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    inspect_parser.add_argument("--top", type=int, default=10, help="Number of ranked entries to print.")

    codex_parser = subparsers.add_parser("codex", help="Print a ready-to-paste Codex prompt for a ranked target.")
    codex_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    codex_parser.add_argument("--rank", type=int, default=1, help="Rank number from SESSION.md / targets.json.")
    codex_parser.add_argument("--include-snippet", action="store_true", help="Append the generated code snippet.")
    codex_parser.add_argument("--extra-instruction", default="", help="Extra instruction appended to the prompt.")

    next_parser = subparsers.add_parser("next", help="Print the next prompt based on session state.")
    next_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    next_parser.add_argument("--include-snippet", action="store_true", help="Append the generated code snippet.")

    record_parser = subparsers.add_parser("record", help="Record a review verdict and prepare the next step.")
    record_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    record_parser.add_argument("--rank", type=int, required=True, help="Rank that was just reviewed.")
    record_parser.add_argument("--target", required=True, help="Target path or function that was reviewed.")
    record_parser.add_argument("--verdict", choices=VERDICTS, required=True, help="Strict verdict for the review.")
    record_parser.add_argument("--notes", default="", help="Short review notes or summary.")
    record_parser.add_argument("--next-target", default="", help="Optional manual next file/function if Codex suggested one.")
    record_parser.add_argument("--next-prompt", default="", help="Optional focused follow-up instruction for the manual next target.")
    record_parser.add_argument("--no-auto-advance", action="store_true", help="Do not advance to the next ranked target automatically.")

    ingest_parser = subparsers.add_parser("ingest", help="Parse a Codex response and update session state automatically.")
    ingest_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    ingest_parser.add_argument("--rank", type=int, required=True, help="Rank that was just reviewed.")
    ingest_parser.add_argument("--target", required=True, help="Target path or function that was reviewed.")
    ingest_parser.add_argument("--response-file", type=Path, help="Path to a text file containing the Codex response. If omitted, stdin is used.")
    ingest_parser.add_argument("--next-prompt", default="", help="Optional focused prompt to pair with the parsed next target.")
    ingest_parser.add_argument("--no-auto-advance", action="store_true", help="Do not advance to the next ranked target automatically.")

    loop_parser = subparsers.add_parser("loop", help="One command loop: ingest fixed response file if present, then print next prompt.")
    loop_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    loop_parser.add_argument("--include-snippet", action="store_true", help="Append the generated code snippet.")
    loop_parser.add_argument("--next-prompt", default="", help="Optional focused prompt to pair with the parsed next target.")

    status_parser = subparsers.add_parser("status", help="Show session review progress.")
    status_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")

    doctor_parser = subparsers.add_parser("doctor", help="Inspect repository cleanliness and git context for a kernel tree.")
    doctor_parser.add_argument("repo_root", type=Path, help="Path to the Linux kernel source tree to inspect.")

    autopilot_parser = subparsers.add_parser("autopilot", help="Run Codex non-interactively for a fixed time budget.")
    autopilot_parser.add_argument("session_dir", type=Path, help="Path to a generated session directory.")
    autopilot_parser.add_argument("--duration", default="1h", help="Total autopilot budget. Example: 30m, 1h.")
    autopilot_parser.add_argument("--per-run-timeout", default="20m", help="Maximum time per Codex execution. Example: 10m.")
    autopilot_parser.add_argument("--include-snippet", action="store_true", help="Append generated code snippets to prompts.")
    autopilot_parser.add_argument("--model", default="", help="Optional Codex model override.")
    autopilot_parser.add_argument("--sandbox", choices=["read-only", "workspace-write", "danger-full-access"], default="workspace-write", help="Sandbox mode for codex exec when not bypassing safeguards.")
    autopilot_parser.add_argument("--no-full-auto", action="store_true", help="Do not pass --full-auto to codex exec.")
    autopilot_parser.add_argument("--dangerously-bypass-approvals-and-sandbox", action="store_true", help="Pass through Codex's unsafe bypass flag.")
    autopilot_parser.add_argument("--stop-on-finding", action="store_true", help="Stop as soon as a strong candidate is found.")
    autopilot_parser.add_argument("--require-clean-tree", action="store_true", help="Refuse to start if the kernel tree has local modifications.")

    fetch_parser = subparsers.add_parser("syzbot-fetch", help="Fetch syzbot dashboard data into local JSON.")
    fetch_parser.add_argument("source", help="syzbot dashboard URL, for example https://syzkaller.appspot.com/upstream")
    fetch_parser.add_argument("--out", type=Path, required=True, help="Output JSON path.")
    fetch_parser.add_argument("--limit", type=int, default=50, help="Maximum number of bug pages to ingest.")

    stats_parser = subparsers.add_parser("syzbot-stats", help="Print a summary of a saved syzbot JSON file.")
    stats_parser.add_argument("syzbot_json", type=Path, help="Path to a JSON file created by syzbot-fetch.")
    stats_parser.add_argument("--top", type=int, default=10, help="Top N subsystems/files to print.")
    return parser


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("kernel_tree", help="Path to the Linux kernel source tree to analyze.")
    parser.add_argument("--config", type=Path, help="Optional JSON config overriding include directories and scoring patterns.")
    parser.add_argument("--profile", choices=sorted(PROFILE_CONFIGS), default="default", help="Built-in subsystem profile when --config is not set.")
    parser.add_argument("--syzbot-json", type=Path, help="Optional syzbot JSON created by syzbot-fetch.")
    parser.add_argument("--out", type=Path, default=Path("artifacts"), help="Directory where session artifacts will be written.")
    parser.add_argument("--limit", type=int, default=80, help="Maximum number of candidates to score before truncation.")
    parser.add_argument("--top", type=int, default=20, help="How many high-priority prompt bundles to generate.")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    normalized_argv = _normalize_argv(raw_argv)

    parser = build_parser()
    args = parser.parse_args(normalized_argv)

    if args.command == "scan":
        return _run_scan(parser, args)
    if args.command == "inspect":
        return _run_inspect(args)
    if args.command == "codex":
        return _run_codex(args)
    if args.command == "next":
        return _run_next(args)
    if args.command == "record":
        return _run_record(args)
    if args.command == "ingest":
        return _run_ingest(args)
    if args.command == "loop":
        return _run_loop(args)
    if args.command == "status":
        return _run_status(args)
    if args.command == "doctor":
        return _run_doctor(args)
    if args.command == "autopilot":
        return _run_autopilot(args)
    if args.command == "syzbot-fetch":
        return _run_syzbot_fetch(args)
    if args.command == "syzbot-stats":
        return _run_syzbot_stats(args)

    parser.error(f"unknown command: {args.command}")
    return 2


def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ["scan", "--help"]
    if argv[0] in SUBCOMMANDS:
        return argv
    if argv[0] in {"-h", "--help"}:
        return argv
    return ["scan", *argv]


def _run_scan(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    repo_root = Path(args.kernel_tree).expanduser().resolve()
    if not repo_root.exists():
        parser.error(f"kernel tree does not exist: {repo_root}")
    if not repo_root.is_dir():
        parser.error(f"kernel tree is not a directory: {repo_root}")

    config_path = args.config or PROFILE_CONFIGS[args.profile]
    config = load_config(config_path)
    syzbot_index = load_index(args.syzbot_json) if args.syzbot_json else None
    candidates = discover_candidates(repo_root, config=config, limit=args.limit, syzbot_index=syzbot_index)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    session_dir = args.out / f"session-{timestamp}"
    write_session_bundle(repo_root=repo_root, out_dir=session_dir, candidates=candidates, top_n=args.top)

    print(f"session={session_dir}")
    print(f"repo_root={repo_root}")
    print(f"config={config_path}")
    print(f"profile={args.profile}")
    print(f"syzbot_json={args.syzbot_json or ''}")
    print(f"candidates={len(candidates)}")
    print(f"top_prompts={min(args.top, len(candidates))}")
    print(f"fixed_response_file={response_path(session_dir)}")
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    manifest = _load_manifest(args.session_dir)
    candidates = manifest.get("candidates", [])

    print(f"session={Path(args.session_dir).resolve()}")
    print(f"repo_root={manifest.get('repo_root', '')}")
    print(f"candidate_count={manifest.get('candidate_count', 0)}")

    for rank, candidate in enumerate(candidates[: args.top], start=1):
        ext_count = len(candidate.get("external_signals", []))
        print(f"{rank:02d} score={candidate['score']:>3} ext={ext_count:<2} subsystem={candidate['subsystem']:<10} entry={candidate['entrypoint']:<18} path={candidate['path']}")
    return 0


def _run_codex(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    prompt, prompt_path, snippet_path, target = _load_rank_prompt(session_dir, manifest, args.rank)
    if args.extra_instruction:
        prompt = prompt.rstrip() + "\n\n" + args.extra_instruction.strip() + "\n"
    set_pending_review(session_dir, args.rank, target, str(prompt_path))
    _print_codex_runbook(manifest["repo_root"], prompt, prompt_path, snippet_path, args.include_snippet, response_path(session_dir))
    return 0


def _run_next(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    _print_next_prompt(session_dir, include_snippet=args.include_snippet)
    return 0


def _run_record(args: argparse.Namespace) -> int:
    state = record_review(
        session_dir=Path(args.session_dir).expanduser().resolve(),
        rank=args.rank,
        target=args.target,
        verdict=args.verdict,
        notes=args.notes,
        next_target=args.next_target,
        next_prompt=args.next_prompt,
        auto_advance=not args.no_auto_advance,
    )
    _print_record_result(args.rank, args.verdict, state)
    return 0


def _run_ingest(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    text = load_response(args.response_file, sys.stdin.read())
    state = _ingest_text(session_dir, text, rank=args.rank, target=args.target, next_prompt=args.next_prompt, auto_advance=not args.no_auto_advance)
    _print_record_result(args.rank, state["history"][-1]["verdict"], state)
    print(f"parsed_next_target={state['history'][-1].get('next_target', '')}")
    return 0


def _run_loop(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    state = load_state(session_dir)
    fixed_response = Path(state.get("pending_response_file", response_path(session_dir)))

    if fixed_response.exists() and fixed_response.stat().st_size > 0:
        pending_rank = state.get("pending_rank")
        pending_target = state.get("pending_target", "").strip()
        if pending_target:
            text = fixed_response.read_text(encoding="utf-8")
            state = _ingest_text(
                session_dir,
                text,
                rank=pending_rank,
                target=pending_target,
                next_prompt=args.next_prompt,
                auto_advance=True,
            )
            archive_dir = response_archive_dir(session_dir)
            archive_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            shutil.move(str(fixed_response), str(archive_dir / f"response-{stamp}.txt"))
            print(f"ingested_verdict={state['history'][-1]['verdict']}")
            print(f"ingested_next_target={state['history'][-1].get('next_target', '')}")
        else:
            print("response_file_present_but_no_pending_target=1")
    _print_next_prompt(session_dir, include_snippet=args.include_snippet)
    return 0


def _run_autopilot(args: argparse.Namespace) -> int:
    return run_autopilot(
        Path(args.session_dir),
        include_snippet=args.include_snippet,
        duration_spec=args.duration,
        per_run_timeout_spec=args.per_run_timeout,
        model=args.model,
        sandbox=args.sandbox,
        full_auto=not args.no_full_auto,
        unsafe_bypass=args.dangerously_bypass_approvals_and_sandbox,
        stop_on_finding=args.stop_on_finding,
        require_clean_tree=args.require_clean_tree,
    )


def _run_doctor(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).expanduser().resolve()
    state = collect_repo_state(repo_root)
    print(f"repo_root={repo_root}")
    print(f"is_git={int(bool(state.get('is_git')))}")
    print(f"branch={state.get('branch', '')}")
    print(f"head={state.get('head', '')}")
    print(f"dirty={int(bool(state.get('dirty')))}")
    for item in state.get("dirty_files", []):
        print(f"dirty_file={item}")
    return 0


def _run_status(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    done = completed_ranks(state)
    print(f"session={session_dir}")
    print(f"repo_root={manifest.get('repo_root', '')}")
    print(f"candidate_count={manifest.get('candidate_count', 0)}")
    print(f"completed={sorted(done)}")
    print(f"current_rank={state.get('current_rank', 1)}")
    print(f"manual_next_target={state.get('manual_next_target', '')}")
    print(f"pending_rank={state.get('pending_rank')}")
    print(f"pending_target={state.get('pending_target', '')}")
    print(f"fixed_response_file={state.get('pending_response_file', response_path(session_dir))}")
    for item in state.get("history", [])[-5:]:
        print(f"history rank={item.get('rank')} verdict={item.get('verdict')} target={item.get('target')}")
    return 0


def _run_syzbot_fetch(args: argparse.Namespace) -> int:
    out_path = fetch_dashboard(args.source, args.out, limit=args.limit)
    print(f"source={args.source}")
    print(f"out={out_path}")
    index = load_index(out_path)
    print(f"bug_count={index.get('bug_count', 0)}")
    return 0


def _run_syzbot_stats(args: argparse.Namespace) -> int:
    index = load_index(args.syzbot_json)
    summary = summarize_index(index, top=args.top)
    print(f"source={index.get('source', '')}")
    print(f"bug_count={summary['bug_count']}")
    print("top_bug_types=")
    for name, count in summary["top_bug_types"]:
        print(f"  {name}: {count}")
    print("top_subsystems=")
    for name, count in summary["top_subsystems"]:
        print(f"  {name}: {count}")
    print("top_files=")
    for name, count in summary["top_files"]:
        print(f"  {name}: {count}")
    return 0


def _load_manifest(session_dir: Path) -> dict:
    manifest_path = session_dir / "targets.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing session manifest: {manifest_path}")
    with manifest_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_rank_prompt(session_dir: Path, manifest: dict, rank: int) -> tuple[str, Path, Path | None, str]:
    candidates = manifest.get("candidates", [])
    if not candidates:
        raise SystemExit("no candidates found in session")
    if rank < 1 or rank > len(candidates):
        raise SystemExit(f"rank out of range: {rank} (1-{len(candidates)})")
    candidate = candidates[rank - 1]
    repo_root = Path(manifest["repo_root"])
    prompt, prompt_path, snippet_path = _candidate_to_prompt_assets(session_dir, repo_root, rank, candidate)
    return prompt, prompt_path, snippet_path, candidate["path"]


def _print_next_prompt(session_dir: Path, include_snippet: bool) -> None:
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    manual_target = state.get("manual_next_target", "").strip()
    manual_prompt = state.get("manual_next_prompt", "").strip()
    depth = int(state.get("manual_followup_depth", 0))
    if manual_target and depth >= MAX_MANUAL_FOLLOWUPS:
        state["manual_next_target"] = ""
        state["manual_next_prompt"] = ""
        state["manual_followup_depth"] = 0
        state["pending_target"] = ""
        state["pending_rank"] = None
        state["pending_prompt_source"] = ""
        save_state(session_dir, state)
        manual_target = ""
        manual_prompt = ""
    if manual_target:
        prompt = _manual_followup_prompt(state, manual_target, manual_prompt)
        set_pending_review(session_dir, None, manual_target, str(session_dir / "review_state.json"))
        _print_codex_runbook(manifest["repo_root"], prompt, session_dir / "review_state.json", None, False, response_path(session_dir))
        return

    rank = _next_pending_rank(state, manifest)
    prompt, prompt_path, snippet_path, target = _load_rank_prompt(session_dir, manifest, rank)
    set_pending_review(session_dir, rank, target, str(prompt_path))
    _print_codex_runbook(manifest["repo_root"], prompt, prompt_path, snippet_path, include_snippet, response_path(session_dir))


def _ingest_text(session_dir: Path, text: str, rank: int | None, target: str, next_prompt: str, auto_advance: bool) -> dict:
    parsed = parse_response(text)
    state = load_state(session_dir)
    depth = int(state.get("manual_followup_depth", 0))
    next_target = parsed["next_target"] if parsed["should_continue"] else ""
    if next_target and depth >= MAX_MANUAL_FOLLOWUPS:
        next_target = ""
        next_prompt = ""
    return record_review(
        session_dir=session_dir,
        rank=rank,
        target=target,
        verdict=parsed["verdict"],
        notes=parsed["notes"],
        next_target=next_target,
        next_prompt=next_prompt,
        auto_advance=auto_advance,
    )


def _print_codex_runbook(repo_root: str, prompt: str, prompt_path: Path, snippet_path: Path | None, include_snippet: bool, fixed_response_file: Path) -> None:
    print("# Codex CLI Runbook")
    print()
    print("1. Start Codex in the kernel tree you scanned.")
    print(f"   cd {repo_root}")
    print("   codex")
    print()
    print("2. Paste the prompt below into Codex.")
    print()
    print("```text")
    print(prompt.rstrip())
    print()
    print(f"Write your final answer to this fixed file before you return it:")
    print(f"{fixed_response_file}")
    if include_snippet and snippet_path and snippet_path.exists():
        print()
        print("Supplemental snippet from the harness:")
        print(snippet_path.read_text(encoding="utf-8").rstrip())
    print("```")
    print()
    print(f"Source prompt: {prompt_path}")
    print(f"Fixed response file: {fixed_response_file}")
    if include_snippet and snippet_path:
        print(f"Snippet file: {snippet_path}")


def _next_pending_rank(state: dict, manifest: dict) -> int:
    done = completed_ranks(state)
    candidates = manifest.get("candidates", [])
    start = max(1, int(state.get("current_rank", 1)))
    for rank in range(start, len(candidates) + 1):
        if rank in done:
            continue
        candidate = candidates[rank - 1]
        if _is_actionable_candidate(candidate.get("path", "")):
            return rank
    raise SystemExit("all ranked targets in this session have already been reviewed")


def _is_actionable_candidate(path: str) -> bool:
    lowered = path.lower()
    if lowered.startswith(("tools/", "samples/", "selftests/", "scripts/")):
        return False
    if "/test/" in lowered or "/tests/" in lowered:
        return False
    if lowered.startswith("lib/test_") or lowered.endswith("_test.c") or lowered.endswith("_test.h"):
        return False
    return True


def _manual_followup_prompt(state: dict, manual_target: str, manual_prompt: str) -> str:
    history = state.get("history", [])
    previous = history[-1] if history else {}
    lines = [
        "Continue from the previous audit.",
        "Do not restart broad review.",
        "",
        f"Previous verdict: {previous.get('verdict', '')}",
        f"Previous target: {previous.get('target', '')}",
    ]
    notes = previous.get("notes", "").strip()
    if notes:
        lines.append(f"Previous notes: {notes}")
    lines.extend(["", f"Now focus only on: {manual_target}"])
    if manual_prompt:
        lines.extend(["", manual_prompt.strip()])
    else:
        lines.extend([
            "",
            "Requirements:",
            "1. Confirm the exact userspace-reachable entrypoint or caller path into this target.",
            "2. Validate concrete attacker control, object/length/state transition, and security impact.",
            "3. If nothing concrete exists, give a strict verdict and the single best next target.",
        ])
    return "\n".join(lines) + "\n"


def _print_record_result(rank: int | None, verdict: str, state: dict) -> None:
    print(f"recorded_rank={rank}")
    print(f"verdict={verdict}")
    print(f"current_rank={state.get('current_rank', 1)}")
    print(f"manual_next_target={state.get('manual_next_target', '')}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
