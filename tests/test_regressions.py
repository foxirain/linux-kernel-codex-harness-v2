from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kernel_harness import autopilot, cli
from kernel_harness.bundle import write_session_bundle
from kernel_harness.finding_triage import classify_finding
from kernel_harness.ingest import parse_response
from kernel_harness.models import Candidate, Signal
from kernel_harness.repo_state import collect_repo_state
from kernel_harness.session import (
    completed_ranks,
    load_state,
    record_review,
    response_path,
    set_pending_review,
)
from kernel_harness.targeting import discover_candidates, load_config


def _response(verdict: str, next_target: str = "none") -> str:
    return (
        "Strict verdict:\n"
        f"- {verdict}\n\n"
        "Single best next target:\n"
        f"- {next_target}\n\n"
        "Summary:\n"
        "- concrete regression fixture\n"
    )


def _git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return proc.stdout.strip()


def _initialize_git_repo(repo_root: Path) -> str:
    subprocess.run(["git", "init", "-q", str(repo_root)], check=True, capture_output=True)
    _git(repo_root, "config", "user.email", "tests@example.invalid")
    _git(repo_root, "config", "user.name", "Harness Tests")
    _git(repo_root, "add", ".")
    _git(repo_root, "commit", "-q", "-m", "fixture")
    return _git(repo_root, "rev-parse", "HEAD")


def _make_session(root: Path, *, count: int = 3, git_repo: bool = False) -> tuple[Path, Path, str]:
    repo_root = root / "linux"
    source_dir = repo_root / "kernel"
    source_dir.mkdir(parents=True)
    candidates: list[Candidate] = []
    for index in range(1, count + 1):
        source_path = source_dir / f"target{index}.c"
        line = f"long target{index}_ioctl(void) {{ return {index}; }}"
        source_path.write_text(line + "\n", encoding="utf-8")
        candidates.append(
            Candidate(
                path=source_path,
                subsystem="kernel",
                entrypoint="ioctl",
                score=20 - index,
                signals=[Signal("ioctl_surface", 10, 1, line, "test signal")],
            )
        )

    head = _initialize_git_repo(repo_root) if git_repo else ""
    session_dir = root / "session"
    write_session_bundle(repo_root, session_dir, candidates, top_n=count)
    return session_dir, repo_root, head


def _ingest_paths(session_dir: Path, repo_root: Path) -> dict[str, Path]:
    autopilot_dir = session_dir / "autopilot"
    findings_dir = autopilot_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    return {
        "session_dir": session_dir,
        "repo_root": repo_root,
        "findings_dir": findings_dir,
        "findings_path": autopilot_dir / "AUTOPILOT_FINDINGS.txt",
        "findings_new_path": autopilot_dir / "AUTOPILOT_FINDINGS_NEW.txt",
        "known_issues_path": autopilot_dir / "AUTOPILOT_KNOWN_ISSUES.txt",
        "suspects_path": autopilot_dir / "AUTOPILOT_SUSPECTS.txt",
        "provenance_unknown_path": autopilot_dir / "AUTOPILOT_PROVENANCE_UNKNOWN.txt",
        "findings_jsonl_path": autopilot_dir / "AUTOPILOT_FINDINGS.jsonl",
        "progress_path": autopilot_dir / "AUTOPILOT_PROGRESS.txt",
    }


class V1RegressionContractTests(unittest.TestCase):
    def test_allocator_detects_kmalloc_and_kvmalloc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            source_dir = repo_root / "kernel"
            source_dir.mkdir()
            (source_dir / "alloc.c").write_text(
                "void *small(size_t n) { return kmalloc(n, GFP_KERNEL); }\n"
                "void *large(size_t n) { return kvmalloc(n, GFP_KERNEL); }\n",
                encoding="utf-8",
            )

            candidates = discover_candidates(
                repo_root,
                config=load_config(cli.PROFILE_CONFIGS["default"]),
                limit=10,
            )

            self.assertEqual(len(candidates), 1)
            allocator_lines = [
                signal.line for signal in candidates[0].signals if signal.name == "allocator"
            ]
            self.assertEqual(len(allocator_lines), 2)
            self.assertTrue(any("kmalloc(" in line for line in allocator_lines))
            self.assertTrue(any("kvmalloc(" in line for line in allocator_lines))

    def test_all_builtin_profiles_are_package_resources_and_load(self) -> None:
        self.assertEqual(
            set(cli.PROFILE_CONFIGS),
            {"default", "bpf", "drivers", "fs", "io_uring", "net"},
        )
        package_root = Path(cli.__file__).resolve().parent
        for profile, profile_path in cli.PROFILE_CONFIGS.items():
            with self.subTest(profile=profile):
                self.assertTrue(profile_path.is_relative_to(package_root), profile_path)
                self.assertTrue(profile_path.is_file(), profile_path)
                config = load_config(profile_path)
                self.assertIsInstance(config.get("include_dirs"), list)
                self.assertIsInstance(config.get("patterns"), list)
                for item in config["patterns"]:
                    re.compile(item["pattern"])

    def test_not_cve_verdict_is_matched_exactly(self) -> None:
        for spelling in ("not_cve_candidate", "not_a_cve_candidate"):
            with self.subTest(spelling=spelling):
                parsed = parse_response(_response(spelling))
                self.assertEqual(parsed["verdict"], "not_cve_candidate")
                self.assertFalse(parsed["should_continue"])

    def test_cve_phrase_in_prose_is_not_treated_as_a_verdict(self) -> None:
        with self.assertRaises(ValueError):
            parse_response("There is insufficient evidence to consider this a CVE candidate.")

        positive = parse_response(_response("cve_candidate"))
        self.assertEqual(positive["verdict"], "cve_candidate")

    def test_two_manual_followups_run_before_third_is_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, _, _ = _make_session(Path(temp_dir))

            cli._ingest_text(
                session_dir,
                _response("needs_more_context", "kernel/first.c"),
                rank=1,
                target="kernel/target1.c",
                next_prompt="",
                auto_advance=True,
            )
            first = autopilot._render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual((first["rank"], first["target"]), (None, "kernel/first.c"))

            cli._ingest_text(
                session_dir,
                _response("needs_more_context", "kernel/second.c"),
                rank=None,
                target=first["target"],
                next_prompt="",
                auto_advance=True,
            )
            second = autopilot._render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual((second["rank"], second["target"]), (None, "kernel/second.c"))

            final_state = cli._ingest_text(
                session_dir,
                _response("needs_more_context", "kernel/third.c"),
                rank=None,
                target=second["target"],
                next_prompt="",
                auto_advance=True,
            )
            self.assertEqual(final_state["manual_next_target"], "")
            fallback = autopilot._render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual((fallback["rank"], fallback["target"]), (2, "kernel/target2.c"))

    def test_manual_loop_archives_stale_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, _, _ = _make_session(Path(temp_dir), count=1)
            fixed_response = response_path(session_dir)
            fixed_response.write_text("stale response\n", encoding="utf-8")
            args = argparse.Namespace(session_dir=session_dir, include_snippet=False, next_prompt="")

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli._run_loop(args), 0)

            self.assertFalse(fixed_response.exists())
            archives = list((session_dir / "responses").glob("stale-response-*.txt"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_text(encoding="utf-8"), "stale response\n")
            self.assertEqual(load_state(session_dir)["pending_target"], "kernel/target1.c")

    def test_autopilot_archives_stale_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, repo_root, _ = _make_session(Path(temp_dir), count=1)
            fixed_response = response_path(session_dir)
            fixed_response.write_text("orphaned response\n", encoding="utf-8")
            paths = _ingest_paths(session_dir, repo_root)

            result = autopilot._ingest_pending_response(**paths)

            self.assertIsNone(result)
            self.assertFalse(fixed_response.exists())
            archives = list((session_dir / "responses").glob("stale-response-*.txt"))
            self.assertEqual(len(archives), 1)
            progress = paths["progress_path"].read_text(encoding="utf-8")
            self.assertIn("stale_response_without_pending_target=1", progress)

    def test_autopilot_defaults_to_read_only(self) -> None:
        args = cli.build_parser().parse_args(["autopilot", "/tmp/session"])
        self.assertEqual(args.sandbox, "read-only")

    def test_scan_rejects_non_positive_limit(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                cli.build_parser().parse_args(["scan", "/tmp/linux", "--limit", "0"])
        self.assertEqual(raised.exception.code, 2)


class V2ProvenanceContractTests(unittest.TestCase):
    def test_require_clean_tree_blocks_non_git_before_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, _, _ = _make_session(Path(temp_dir), count=1, git_repo=False)

            with mock.patch("kernel_harness.autopilot._run_codex_exec") as codex_exec:
                result = autopilot.run_autopilot(
                    session_dir,
                    include_snippet=False,
                    duration_spec="1s",
                    per_run_timeout_spec="1s",
                    model="",
                    sandbox="read-only",
                    full_auto=False,
                    unsafe_bypass=False,
                    stop_on_finding=False,
                    require_clean_tree=True,
                )

            self.assertEqual(result, 2)
            codex_exec.assert_not_called()
            autopilot_dir = session_dir / "autopilot"
            progress = (autopilot_dir / "AUTOPILOT_PROGRESS.txt").read_text(encoding="utf-8")
            status = (autopilot_dir / "AUTOPILOT_STATUS.txt").read_text(encoding="utf-8")
            self.assertIn("stop_reason=blocked_unverified_tree", progress)
            self.assertIn("stage=blocked_unverified_tree", status)

    def test_unknown_provenance_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            non_git = root / "not-git"
            non_git.mkdir()
            non_git_state = collect_repo_state(non_git)

            no_head = root / "no-head"
            subprocess.run(["git", "init", "-q", str(no_head)], check=True, capture_output=True)
            no_head_state = collect_repo_state(no_head)

            def failing_status(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
                if args == ["rev-parse", "--is-inside-work-tree"]:
                    return subprocess.CompletedProcess(args, 0, "true\n", "")
                if args == ["symbolic-ref", "--quiet", "--short", "HEAD"]:
                    return subprocess.CompletedProcess(args, 0, "main\n", "")
                if args == ["rev-parse", "--verify", "HEAD"]:
                    return subprocess.CompletedProcess(args, 0, "a" * 40 + "\n", "")
                if args == ["status", "--porcelain=v1", "-z", "--untracked-files=all"]:
                    return subprocess.CompletedProcess(args, 1, "", "status failed")
                return subprocess.CompletedProcess(args, 1, "", "unexpected git command")

            with mock.patch("kernel_harness.repo_state._run_git", side_effect=failing_status):
                failed_status_state = collect_repo_state(root)

            for name, repo_root, state in (
                ("non_git", non_git, non_git_state),
                ("missing_head", no_head, no_head_state),
                ("status_failed", root, failed_status_state),
            ):
                with self.subTest(case=name):
                    classification = classify_finding(
                        repo_root=repo_root,
                        repo_state=state,
                        target="kernel/target.c",
                        verdict="cve_candidate",
                        response_text="Concrete memory corruption candidate.",
                    )
                    self.assertEqual(classification["bucket"], "provenance_unknown")
                    self.assertFalse(classification["novelty_proven"])
                    if name in {"non_git", "status_failed"}:
                        self.assertFalse(classification["repo_status_ok"])
                    if name == "missing_head":
                        self.assertEqual(classification["repo_head"], "")

    def test_negated_marker_and_unrelated_cve_are_not_known_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, repo_root, _ = _make_session(root, count=1, git_repo=True)
            repo_state = collect_repo_state(repo_root, focus_paths=["kernel/target1.c"])

            responses = (
                "This is not a known issue; no matching upstream fix was found.",
                "This behavior is unrelated to CVE-2025-12345 in another subsystem.",
            )
            for response_text in responses:
                with self.subTest(response=response_text):
                    classification = classify_finding(
                        repo_root=repo_root,
                        repo_state=repo_state,
                        target="kernel/target1.c",
                        verdict="cve_candidate",
                        response_text=response_text,
                    )
                    self.assertEqual(classification["bucket"], "new_candidate")
                    self.assertFalse(classification["novelty_proven"])

            for response_text in (
                "This is a known issue confirmed upstream.",
                "The same defect is tracked as CVE-2025-54321.",
            ):
                with self.subTest(positive_control=response_text):
                    classification = classify_finding(
                        repo_root=repo_root,
                        repo_state=repo_state,
                        target="kernel/target1.c",
                        verdict="cve_candidate",
                        response_text=response_text,
                    )
                    self.assertEqual(classification["bucket"], "known_issue")

    def test_clean_and_dirty_repositories_use_distinct_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, repo_root, _ = _make_session(root, count=1, git_repo=True)
            target = repo_root / "kernel" / "target1.c"

            clean_state = collect_repo_state(repo_root, focus_paths=["kernel/target1.c"])
            clean = classify_finding(
                repo_root=repo_root,
                repo_state=clean_state,
                target="kernel/target1.c",
                verdict="cve_candidate",
                response_text="Concrete memory corruption candidate.",
            )
            self.assertEqual(clean["bucket"], "new_candidate")
            self.assertTrue(clean["repo_status_ok"])
            self.assertFalse(clean["novelty_proven"])

            target.write_text("long changed(void) { return -1; }\n", encoding="utf-8")
            dirty_state = collect_repo_state(repo_root, focus_paths=["kernel/target1.c"])
            dirty = classify_finding(
                repo_root=repo_root,
                repo_state=dirty_state,
                target="kernel/target1.c",
                verdict="cve_candidate",
                response_text="Concrete memory corruption candidate.",
            )
            self.assertEqual(dirty["bucket"], "dirty_tree_suspect")
            self.assertTrue(dirty["dirty_repo"])
            self.assertTrue(dirty["dirty_target"])


class V2StateContractTests(unittest.TestCase):
    def test_parse_error_does_not_complete_or_advance_rank(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, repo_root, _ = _make_session(Path(temp_dir), count=2)
            set_pending_review(session_dir, 1, "kernel/target1.c", "test prompt")
            response_path(session_dir).write_text("unparseable model output\n", encoding="utf-8")
            paths = _ingest_paths(session_dir, repo_root)

            result = autopilot._ingest_pending_response(**paths)
            state = load_state(session_dir)

            self.assertTrue(result["retryable"])
            self.assertEqual(completed_ranks(state), set())
            self.assertEqual(state["current_rank"], 1)
            self.assertEqual(state["history"], [])
            retry = autopilot._render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual((retry["rank"], retry["target"]), (1, "kernel/target1.c"))

    def test_out_of_order_rank_does_not_skip_lower_incomplete_rank(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, _, _ = _make_session(Path(temp_dir), count=3)
            state = record_review(
                session_dir,
                rank=3,
                target="kernel/target3.c",
                verdict="not_cve_candidate",
                notes="reviewed out of order",
                next_target="",
                next_prompt="",
                auto_advance=True,
            )

            self.assertEqual(completed_ranks(state), {3})
            self.assertEqual(state["current_rank"], 1)
            rendered = autopilot._render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual((rendered["rank"], rendered["target"]), (1, "kernel/target1.c"))

    def test_classification_and_repo_head_are_preserved_in_history_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir, repo_root, head = _make_session(Path(temp_dir), count=1, git_repo=True)
            set_pending_review(session_dir, 1, "kernel/target1.c", "test prompt")
            response_path(session_dir).write_text(_response("cve_candidate"), encoding="utf-8")
            paths = _ingest_paths(session_dir, repo_root)

            result = autopilot._ingest_pending_response(**paths)

            self.assertEqual(result["bucket"], "new_candidate")
            history_entry = load_state(session_dir)["history"][-1]
            classification = history_entry["classification"]
            self.assertEqual(classification["bucket"], "new_candidate")
            self.assertEqual(classification["repo_head"], head)
            self.assertFalse(classification["novelty_proven"])

            records = [
                json.loads(line)
                for line in paths["findings_jsonl_path"].read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["bucket"], classification["bucket"])
            self.assertEqual(records[0]["repo_head"], head)
            self.assertFalse(records[0]["novelty_proven"])


if __name__ == "__main__":
    unittest.main()
