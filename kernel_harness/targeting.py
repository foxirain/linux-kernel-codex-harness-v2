from __future__ import annotations

import json
import re
from pathlib import Path

from kernel_harness.models import Candidate, ExternalSignal, Signal


DEFAULT_INCLUDE_DIRS = [
    "kernel",
    "mm",
    "net",
    "fs",
    "security",
    "io_uring",
    "lib",
    "drivers",
]

DEFAULT_PATTERNS = [
    {
        "name": "ioctl_surface",
        "pattern": r"\b(?:unlocked_)?ioctl\b|\bcompat_ioctl\b",
        "weight": 10,
        "rationale": "ioctl handlers often expose complex user-controlled state transitions.",
    },
    {
        "name": "copy_from_user",
        "pattern": r"\bcopy_from_user\b|\b__copy_from_user\b|\bget_user\b",
        "weight": 9,
        "rationale": "user-to-kernel data movement is a frequent memory corruption entrypoint.",
    },
    {
        "name": "copy_to_user",
        "pattern": r"\bcopy_to_user\b|\b__copy_to_user\b|\bput_user\b",
        "weight": 6,
        "rationale": "kernel-to-user transfers are a strong info-leak signal.",
    },
    {
        "name": "user_pointer",
        "pattern": r"\b__user\b",
        "weight": 6,
        "rationale": "explicit user pointer handling usually marks trust boundaries.",
    },
    {
        "name": "allocator",
        "pattern": r"\b(?:k[mz]alloc|kv[mz]alloc|vmalloc|kmem_cache_alloc)\b",
        "weight": 5,
        "rationale": "allocation around user input often couples to lifetime and bounds bugs.",
    },
    {
        "name": "free_path",
        "pattern": r"\b(?:kfree|kvfree|kmem_cache_free)\b",
        "weight": 5,
        "rationale": "free paths near user-triggerable flows increase UAF and double-free risk.",
    },
    {
        "name": "refcount",
        "pattern": r"\b(?:refcount_|atomic_(?:inc|dec|add|sub)|kref_)\w*",
        "weight": 7,
        "rationale": "reference counting mistakes are common kernel CVE material.",
    },
    {
        "name": "size_math",
        "pattern": r"\b(?:size_t|u\d+|unsigned)\b.*(?:len|size|count)|\b(?:array_size|struct_size|flex_array_size)\b",
        "weight": 6,
        "rationale": "length arithmetic and struct sizing are strong overflow indicators.",
    },
    {
        "name": "memcpy_family",
        "pattern": r"\b(?:memcpy|memmove|strscpy|strncpy|snprintf)\b",
        "weight": 4,
        "rationale": "buffer movement around user-derived lengths can lead to overwrite or leak.",
    },
    {
        "name": "lockless_or_racy",
        "pattern": r"\b(?:spin_lock|mutex_lock|rcu_read_lock|lockdep_assert_held)\b",
        "weight": 3,
        "rationale": "locking primitives help surface race windows when paired with frees or refs.",
    },
    {
        "name": "bpf_surface",
        "pattern": r"\b(?:BPF_PROG|bpf_|sk_buff|xdp)\w*",
        "weight": 8,
        "rationale": "BPF and packet processing frequently expose rich attacker-controlled state.",
    },
    {
        "name": "capability_gate",
        "pattern": r"\b(?:capable|ns_capable|security_)\w*",
        "weight": 4,
        "rationale": "authorization checks nearby can indicate privilege-boundary mistakes.",
    },
    {
        "name": "warning_marker",
        "pattern": r"\b(?:WARN_ON|BUG_ON|KASAN|UBSAN|__must_check)\b",
        "weight": 3,
        "rationale": "existing invariant checks often cluster around historically fragile code.",
    },
]

PATH_RULES = [
    ("drivers/", 2, "driver attack surface"),
    ("net/", 8, "network reachable subsystem"),
    ("fs/", 7, "filesystem syscall boundary"),
    ("mm/", 7, "memory management primitives"),
    ("kernel/bpf", 9, "BPF verifier and helpers are high-value surfaces"),
    ("io_uring/", 10, "io_uring has deep async lifetime complexity"),
    ("security/", 5, "security modules gate privilege transitions"),
    ("kernel/sys.c", 8, "syscall core file"),
    ("proc", 5, "procfs often exposes low-friction interfaces"),
    ("seq_file", 4, "seq_file patterns can leak kernel memory or refs"),
]


def load_config(config_path: Path | None) -> dict:
    if config_path is None:
        return {
            "include_dirs": DEFAULT_INCLUDE_DIRS,
            "patterns": DEFAULT_PATTERNS,
            "max_signals_per_file": 12,
        }

    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def discover_candidates(
    repo_root: Path,
    config: dict,
    limit: int,
    extensions: tuple[str, ...] = (".c", ".h"),
    syzbot_index: dict | None = None,
) -> list[Candidate]:
    include_dirs = config.get("include_dirs", DEFAULT_INCLUDE_DIRS)
    pattern_defs = config.get("patterns", DEFAULT_PATTERNS)
    max_signals_per_file = int(config.get("max_signals_per_file", 12))

    compiled = [
        (
            entry["name"],
            re.compile(entry["pattern"]),
            int(entry["weight"]),
            entry["rationale"],
        )
        for entry in pattern_defs
    ]

    candidates: list[Candidate] = []

    for rel_dir in include_dirs:
        scan_root = repo_root / rel_dir
        if not scan_root.exists():
            continue

        for file_path in scan_root.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in extensions:
                continue

            candidate = _score_file(repo_root, file_path, compiled, max_signals_per_file)
            if candidate is not None:
                candidates.append(candidate)

    if syzbot_index:
        _apply_syzbot_signals(repo_root, candidates, syzbot_index)

    candidates.sort(key=lambda item: (-item.score, str(item.path)))
    return candidates[:limit]


def _score_file(
    repo_root: Path,
    file_path: Path,
    compiled_patterns: list[tuple[str, re.Pattern[str], int, str]],
    max_signals_per_file: int,
) -> Candidate | None:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    rel_path = str(file_path.relative_to(repo_root))
    signals: list[Signal] = []
    score = 0
    reasons: list[str] = []
    path_signals: list[str] = []

    for needle, weight, rationale in _path_hits(rel_path):
        score += weight
        path_signals.append(needle)
        reasons.append(f"path:{needle} (+{weight}) {rationale}")

    lines = content.splitlines()
    for index, line in enumerate(lines, start=1):
        for name, pattern, weight, rationale in compiled_patterns:
            if not pattern.search(line):
                continue
            signal = Signal(
                name=name,
                weight=weight,
                line_no=index,
                line=line.strip(),
                rationale=rationale,
            )
            signals.append(signal)
            score += weight

    if not signals and score < 8:
        return None

    signals.sort(key=lambda item: (-item.weight, item.line_no))
    signals = signals[:max_signals_per_file]
    for signal in signals:
        reasons.append(f"line {signal.line_no}: {signal.name} (+{signal.weight})")

    subsystem = rel_path.split("/", 1)[0]
    entrypoint = _infer_entrypoint(rel_path, lines, signals)
    return Candidate(
        path=file_path,
        subsystem=subsystem,
        entrypoint=entrypoint,
        score=score,
        signals=signals,
        path_signals=path_signals,
        reasons=reasons,
    )


def _path_hits(rel_path: str) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for needle, weight, rationale in PATH_RULES:
        if needle in rel_path:
            hits.append((needle, weight, rationale))
    return hits


def _infer_entrypoint(rel_path: str, lines: list[str], signals: list[Signal]) -> str:
    stem = Path(rel_path).stem
    if "ioctl" in rel_path:
        return "ioctl"
    if "sys_" in stem or "/sys" in rel_path:
        return "syscall-ish"
    if "netlink" in rel_path:
        return "netlink"
    if "proc" in rel_path:
        return "procfs"
    if "bpf" in rel_path:
        return "bpf"
    if signals:
        top = signals[0].name
        if top in {"copy_from_user", "copy_to_user", "user_pointer"}:
            return "usercopy boundary"
    for line in lines[:200]:
        if "file_operations" in line or "proc_ops" in line:
            return "file operation hook"
    return stem


def _apply_syzbot_signals(repo_root: Path, candidates: list[Candidate], syzbot_index: dict) -> None:
    bugs = syzbot_index.get("bugs", [])

    for candidate in candidates:
        rel_path = str(candidate.path.relative_to(repo_root))
        rel_path_lower = rel_path.lower()
        subsystem = candidate.subsystem.lower()
        applied = 0

        for bug in bugs:
            if applied >= 6:
                break

            file_hits = bug.get("file_hits", [])
            matched_files = [
                hit for hit in file_hits
                if rel_path_lower.endswith(str(hit.get("path", "")).lower())
                or str(hit.get("path", "")).lower().endswith(rel_path_lower)
            ]
            subsystem_match = subsystem in [item.lower() for item in bug.get("subsystems", [])]
            title = bug.get("title", "")
            bug_type = bug.get("bug_type", "unknown")
            url = bug.get("url", "")

            if matched_files:
                weight = 18
                if bug_type in {"use-after-free", "slab-use-after-free", "slab-out-of-bounds", "out-of-bounds"}:
                    weight += 4
                summary = f"syzbot exact file overlap: {title}"
                candidate.external_signals.append(
                    ExternalSignal(
                        source="syzbot",
                        weight=weight,
                        summary=summary,
                        url=url,
                        metadata={
                            "bug_type": bug_type,
                            "matched_path": matched_files[0].get("path", ""),
                        },
                    )
                )
                candidate.score += weight
                candidate.reasons.append(f"external:syzbot (+{weight}) {summary}")
                applied += 1
                continue

            if subsystem_match:
                weight = 5
                summary = f"syzbot subsystem overlap: {title}"
                candidate.external_signals.append(
                    ExternalSignal(
                        source="syzbot",
                        weight=weight,
                        summary=summary,
                        url=url,
                        metadata={"bug_type": bug_type},
                    )
                )
                candidate.score += weight
                candidate.reasons.append(f"external:syzbot (+{weight}) {summary}")
                applied += 1
