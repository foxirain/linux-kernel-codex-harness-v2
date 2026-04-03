from __future__ import annotations

import re
from pathlib import Path

from kernel_harness.repo_state import commit_present

STRONG_FINDING_VERDICTS = {"cve_candidate", "plausible_security_bug"}
NOVELTY_BUCKETS = {"new_candidate", "known_issue", "dirty_tree_suspect", "non_finding"}
KNOWN_MARKERS = [
    "upstream confirmed",
    "already assigned cve",
    "assigned cve",
    "later assigned cve",
    "fixed in commit",
    "known issue",
    "backported",
    "merged upstream",
]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
COMMIT_RE = re.compile(r"\b[0-9a-f]{12,40}\b")
PATH_RE = re.compile(r"([A-Za-z0-9_./-]+\.(?:c|h))")


def classify_finding(*, repo_root: Path, repo_state: dict, target: str, verdict: str, response_text: str) -> dict:
    target_file = guess_target_file(target, response_text)
    referenced_cves = sorted({value.upper() for value in CVE_RE.findall(response_text)})
    referenced_commits = sorted({value.lower() for value in COMMIT_RE.findall(response_text)})
    present_commits = [commit for commit in referenced_commits if len(commit) >= 12 and commit_present(repo_root, commit)]
    lowered = response_text.lower()
    matched_markers = [marker for marker in KNOWN_MARKERS if marker in lowered]

    dirty_repo = bool(repo_state.get("dirty"))
    dirty_focus_paths = set(repo_state.get("dirty_focus_paths", []))
    dirty_target = bool(target_file and target_file in dirty_focus_paths)

    if verdict not in STRONG_FINDING_VERDICTS:
        bucket = "non_finding"
        reason = "verdict_not_strong"
    elif dirty_target:
        bucket = "dirty_tree_suspect"
        reason = "target_file_dirty"
    elif dirty_repo:
        bucket = "dirty_tree_suspect"
        reason = "repo_dirty"
    elif referenced_cves or present_commits or matched_markers:
        bucket = "known_issue"
        if referenced_cves:
            reason = "response_references_cve"
        elif present_commits:
            reason = "referenced_fix_commit_present_in_head"
        else:
            reason = "response_contains_known_issue_marker"
    else:
        bucket = "new_candidate"
        reason = "no_known_issue_markers_detected"

    return {
        "bucket": bucket,
        "reason": reason,
        "target_file": target_file,
        "dirty_repo": dirty_repo,
        "dirty_target": dirty_target,
        "referenced_cves": referenced_cves,
        "referenced_commits": referenced_commits,
        "present_commits": present_commits,
        "matched_markers": matched_markers,
    }


def guess_target_file(target: str, response_text: str = "") -> str:
    direct = _extract_file_from_text(target)
    if direct:
        return direct
    return _extract_file_from_text(response_text)


def _extract_file_from_text(text: str) -> str:
    for match in PATH_RE.finditer(text):
        path = match.group(1)
        if "/" in path:
            return path.strip().strip("`")
    return ""
