from __future__ import annotations

import json
from pathlib import Path

from kernel_harness.models import Candidate
from kernel_harness.prompting import render_bundle_prompt
from kernel_harness.session import initialize_state


def write_session_bundle(repo_root: Path, out_dir: Path, candidates: list[Candidate], top_n: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = out_dir / "bundles"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "repo_root": str(repo_root),
        "candidate_count": len(candidates),
        "top_n": top_n,
        "candidates": [candidate.to_dict(repo_root) for candidate in candidates],
    }
    (out_dir / "targets.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    report_template = {
        "title": "",
        "bug_class": "",
        "impact": "",
        "entrypoint": "",
        "attacker_control": "",
        "affected_files": [],
        "evidence": [],
        "exploit_sketch": "",
        "confidence": 0,
        "next_steps": [],
    }
    (out_dir / "finding_template.json").write_text(
        json.dumps(report_template, indent=2),
        encoding="utf-8",
    )
    initialize_state(out_dir)

    index_lines = [
        "# Kernel Codex Harness Session",
        "",
        f"- Repository root: `{repo_root}`",
        f"- Candidate count: `{len(candidates)}`",
        f"- Pre-generated prompt bundles: top `{top_n}` files",
        "",
        "## Priority Targets",
        "",
    ]

    for rank, candidate in enumerate(candidates[:top_n], start=1):
        rel_path = candidate.path.relative_to(repo_root)
        slug = f"{rank:02d}-{str(rel_path).replace('/', '__')}.md"
        prompt_path = bundle_dir / slug
        prompt_path.write_text(render_bundle_prompt(repo_root, candidate), encoding="utf-8")

        snippet_path = bundle_dir / slug.replace(".md", ".snippet.txt")
        snippet_path.write_text(_extract_snippet(candidate), encoding="utf-8")

        index_lines.append(
            f"{rank}. `{rel_path}` | score `{candidate.score}` | entry `{candidate.entrypoint}` | prompt `{prompt_path.name}`"
        )

    index_lines.extend(
        [
            "",
            "## Codex Usage Pattern",
            "",
            "1. Start with the highest-score prompt file in `bundles/` or use `kernel-harness next <session_dir>`.",
            "   Ranks beyond the pre-generated set remain available and are generated on demand.",
            "2. Ask Codex to inspect the target file and the neighboring teardown/caller paths named in the prompt.",
            "3. Record verdicts with `kernel-harness record ...` so the harness can prepare the next prompt automatically.",
            "4. Persist confirmed issues into `finding_template.json` copies per bug.",
        ]
    )
    (out_dir / "SESSION.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    return out_dir


def _extract_snippet(candidate: Candidate, radius: int = 4) -> str:
    try:
        lines = candidate.path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""

    seen: set[tuple[int, int]] = set()
    blocks: list[str] = []
    for signal in candidate.signals[:6]:
        start = max(1, signal.line_no - radius)
        end = min(len(lines), signal.line_no + radius)
        if (start, end) in seen:
            continue
        seen.add((start, end))
        header = f"## lines {start}-{end} [{signal.name}]"
        body = "\n".join(f"{line_no:>6} {lines[line_no - 1]}" for line_no in range(start, end + 1))
        blocks.append(f"{header}\n{body}")
    return "\n\n".join(blocks) + ("\n" if blocks else "")
