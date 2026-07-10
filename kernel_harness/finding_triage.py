from __future__ import annotations

import re
from pathlib import Path

from kernel_harness.repo_state import commit_present

STRONG_FINDING_VERDICTS = {"cve_candidate", "plausible_security_bug"}
TRIAGE_BUCKETS = {
    "new_candidate",
    "known_issue",
    "dirty_tree_suspect",
    "provenance_unknown",
    "non_finding",
}
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
COMMIT_RE = re.compile(r"\b[0-9a-f]{12,40}\b", re.IGNORECASE)
RELATED_COMMIT_RE = re.compile(
    r"\b(?:fix(?:ed)?\s+(?:by|in)\s+(?:commit\s+)?|upstream\s+commit\s+)"
    r"(?P<commit>[0-9a-f]{12,40})\b",
    re.IGNORECASE,
)
PATH_RE = re.compile(r"([A-Za-z0-9_./-]+\.(?:c|h))")
NEGATED_CVE_PREFIX_RE = re.compile(
    r"(?:unrelated\s+to|not\s+related\s+to|unlike|distinct\s+from|different\s+from)"
    r"\b[^.;:\n]{0,48}$",
    re.IGNORECASE,
)
NEGATED_CVE_SUFFIX_RE = re.compile(
    r"^[^.;:\n]{0,24}\b(?:is|was|appears)\s+(?:entirely\s+)?"
    r"(?:unrelated|distinct|different)\b",
    re.IGNORECASE,
)
NEGATION_PREFIX_RE = re.compile(
    r"\b(?:not|no|never|without)\b(?:[\s_-]+[A-Za-z0-9_'-]+){0,4}[\s:,-]*$",
    re.IGNORECASE,
)


def classify_finding(*, repo_root: Path, repo_state: dict, target: str, verdict: str, response_text: str) -> dict:
    target_file = guess_target_file(target, response_text)
    referenced_cves, related_cves = _extract_cves(response_text)
    referenced_commits = sorted({value.lower() for value in COMMIT_RE.findall(response_text)})
    related_commits = sorted(
        {match.group("commit").lower() for match in RELATED_COMMIT_RE.finditer(response_text)}
    )
    matched_markers = _extract_known_markers(response_text)

    repo_is_git = repo_state.get("is_git") is True
    repo_status_ok = repo_state.get("status_ok") is True
    repo_branch = str(repo_state.get("branch") or "")
    repo_head = str(repo_state.get("head") or "")
    repo_error = str(repo_state.get("error") or "")
    dirty_repo = bool(repo_state.get("dirty"))
    dirty_focus_paths = set(repo_state.get("dirty_focus_paths", []))
    dirty_target = bool(target_file and target_file in dirty_focus_paths)

    provenance_ok = repo_is_git and repo_status_ok and bool(repo_head)
    present_commits = (
        [commit for commit in related_commits if commit_present(repo_root, commit)]
        if provenance_ok
        else []
    )

    if verdict not in STRONG_FINDING_VERDICTS:
        bucket = "non_finding"
        reason = "verdict_not_strong"
    elif not repo_is_git:
        bucket = "provenance_unknown"
        reason = "repo_not_git"
    elif not repo_status_ok:
        bucket = "provenance_unknown"
        reason = "repo_status_unavailable"
    elif not repo_head:
        bucket = "provenance_unknown"
        reason = "repo_head_missing"
    elif dirty_target:
        bucket = "dirty_tree_suspect"
        reason = "target_file_dirty"
    elif dirty_repo:
        bucket = "dirty_tree_suspect"
        reason = "repo_dirty"
    elif related_cves or present_commits or matched_markers:
        bucket = "known_issue"
        if related_cves:
            reason = "response_references_cve"
        elif present_commits:
            reason = "referenced_fix_commit_present_in_head"
        else:
            reason = "response_contains_known_issue_marker"
    else:
        bucket = "new_candidate"
        reason = "no_known_reference_detected"

    return {
        "bucket": bucket,
        "reason": reason,
        "target_file": target_file,
        "dirty_repo": dirty_repo,
        "dirty_target": dirty_target,
        "referenced_cves": referenced_cves,
        "related_cves": related_cves,
        "referenced_commits": referenced_commits,
        "related_commits": related_commits,
        "present_commits": present_commits,
        "matched_markers": matched_markers,
        "repo_is_git": repo_is_git,
        "repo_status_ok": repo_status_ok,
        "repo_branch": repo_branch,
        "repo_head": repo_head,
        "repo_error": repo_error,
        "novelty_proven": False,
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


def _extract_cves(text: str) -> tuple[list[str], list[str]]:
    referenced: set[str] = set()
    related: set[str] = set()
    for match in CVE_RE.finditer(text):
        value = match.group(0).upper()
        referenced.add(value)
        if not _cve_reference_is_unrelated(text, match.start(), match.end()):
            related.add(value)
    return sorted(referenced), sorted(related)


def _cve_reference_is_unrelated(text: str, start: int, end: int) -> bool:
    prefix = text[max(0, start - 96):start]
    suffix = text[end:min(len(text), end + 64)]
    return bool(NEGATED_CVE_PREFIX_RE.search(prefix) or NEGATED_CVE_SUFFIX_RE.search(suffix))


def _extract_known_markers(text: str) -> list[str]:
    lowered = text.lower()
    matched: list[str] = []
    for marker in KNOWN_MARKERS:
        start = 0
        while True:
            index = lowered.find(marker, start)
            if index < 0:
                break
            if not _marker_is_negated(lowered, index):
                matched.append(marker)
                break
            start = index + len(marker)
    return matched


def _marker_is_negated(text: str, marker_start: int) -> bool:
    prefix = text[max(0, marker_start - 80):marker_start]
    if re.search(r"\bnot\s+only\s+$", prefix, re.IGNORECASE):
        return False
    return bool(NEGATION_PREFIX_RE.search(prefix))
