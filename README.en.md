# Kernel Codex Harness v2

[한국어](README.md) | [English](README.en.md)

[![CI](https://github.com/foxirain/linux-kernel-codex-harness-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/foxirain/linux-kernel-codex-harness-v2/actions/workflows/ci.yml)

<p align="center"><strong>Research Tool · Original Import: 3 April 2026 · v2 Documentation Revision: 11 July 2026</strong></p>

<p align="center"><strong>External Signal: From Attention Allocation to Provenance-Aware Triage</strong><br>Use reproducible observations to guide model attention, then use repository provenance to organize review queues—never to claim proof.</p>

> **Project Lineage—** [Kernel Codex Harness v1](https://github.com/foxirain/linux-kernel-codex-harness) · *Attention Allocation* → **Kernel Codex Harness v2** · *Provenance-Aware Triage*

> **Project status.** This repository preserves an LLM-assisted research harness that evolved v1's attention-allocation workflow into provenance-aware triage for real Linux kernel vulnerability research. This version was used in the investigation that discovered the vulnerability published as [CVE-2026-53075](https://nvd.nist.gov/vuln/detail/CVE-2026-53075). It is not an automatic vulnerability detector, novelty classifier, exploit verifier, or kernel security assurance tool; final validation and reporting remain human responsibilities.

## Abstract

**Abstract—** When an LLM is asked to explore a codebase as large as the Linux kernel without structure, context disperses and the presence of dangerous APIs is easily confused with actual exploitability. `Kernel Codex Harness v2` defines this problem as two stages of **External Signal** processing. Before model invocation, path weights, lexical hits, and cached syzbot overlap rank candidate files and allocate attention. After the model responds, Git branch, HEAD, and dirty-state facts are combined with CVE, commit, and known markers extracted from the response to classify strong findings into provenance-aware review buckets. The harness was used in a real Linux kernel investigation that discovered a missing authorization check against the target network namespace in PPP, later published as [CVE-2026-53075](https://nvd.nist.gov/vuln/detail/CVE-2026-53075). Triage is a heuristic for organizing investigation queues; in particular, `new_candidate` means only that no known clue or provenance problem was detected, not that novelty has been proved. Every finding requires human revalidation of userspace reachability, the invariant break, and concrete impact.

**Index Terms—** Linux kernel, vulnerability research, external signal, provenance, heuristic triage, LLM orchestration, syzbot, Codex.

## I. Introduction

Kernel security review contains two distinct kinds of uncertainty.

1. **Where should the review look first?** The full source tree is too large for a single model context.
2. **How should a strong model finding be handled?** Local modifications, existing fixes, known CVEs, or incomplete repository state can contaminate the conclusion.

The central problem in v1 was the first one: attention allocation. v2 preserves that principle and extends it to the second problem through provenance-aware triage. Both versions were used in real investigations: a v1-assisted investigation led to CVE-2026-31720, and a v2-assisted investigation led to CVE-2026-53075.

> Narrow the investigation with observations outside the model, then attach verifiable repository provenance after the model responds. Signals at neither stage prove vulnerability or novelty.

## II. External Signal and Design Principles

### A. Stage 1 — Attention Allocation Before Inference

Pre-inference External Signal is not an LLM judgment, but an observation computed before model execution.

- kernel paths and subsystem weights
- lexical hits such as usercopy, allocator, refcount, size, and lock operations
- file and subsystem overlap from stored syzbot JSON

Candidate ranks can be recomputed from the same source tree, profile, and cached syzbot JSON. The score is not a probability or exploitability measure, but **a relative order for deciding where to look first**.

### B. Stage 2 — Provenance-Aware Triage After Inference

The post-inference stage combines a strong model verdict with the following information:

- whether the target is a Git repository and whether status collection succeeded
- branch and HEAD
- dirty state of the repository and target file
- CVEs, commit hashes, and known-issue markers extracted from the response
- negation or unrelated-reference language in the response

In this document, **post-inference External Signal** refers only to provenance collected independently of the model, such as Git repository/status facts, branch, HEAD, dirty state, and local commit ancestry. CVE, commit, and known markers extracted from the model response are **model-derived references**, not External Signal or authoritative facts. Triage combines both kinds of input while recording their provenance separately.

### C. Heuristic Buckets, Not Novelty Proof

A strong finding is operationally assigned to one of the following review buckets.

| Bucket | Meaning |
| --- | --- |
| `new_candidate` | Provenance was verified and no dirty or known blocking signal was found |
| `known_issue` | A non-negated known reference was found, or a commit identified by the response as a fix/upstream relation is confirmed in the current HEAD |
| `dirty_tree_suspect` | The influence of a dirty repository or dirty target cannot be excluded |
| `provenance_unknown` | The Git repository, status, or HEAD could not be verified reliably |

Every classification sets `novelty_proven` to `false`. `new_candidate` does not mean a new vulnerability; it means **a queue in which a human should continue the novelty investigation first**.

### D. Reachability Before Bug Class

The audit first identifies boundaries that originate in userspace, such as a `syscall`, `ioctl`, `netlink`, `procfs`, filesystem, BPF, or driver hook. Only then does it evaluate bug classes such as UAF, OOB access, refcount errors, races, information leaks, or capability-check failures.

### E. One Investigation Branch at a Time

An investigation unit is limited to one file and its nearby caller, teardown, and free paths. Model-proposed manual follow-ups are capped at two, preserving a short, verifiable path instead of broad exploration.

### F. Evidence Over Confidence

A strong finding must explain at least the following:

1. attacker-reachable entrypoint,
2. an attacker-controlled field or lifetime transition,
3. the object, length, or state invariant that breaks,
4. a concrete impact such as corruption, leakage, or privilege escalation,
5. why existing checks do not block the attack.

The parser normalizes the verdict and next target; it does not automatically prove the completeness of this evidence.

### G. Design Lineage

The initial flow drew inspiration from the file-level analysis, bounded context expansion, and structured outputs used by Protect AI's `vulnhuntr` [1]. This project redesigned those ideas around userspace-reachable kernel surfaces, kernel object lifetimes, teardown paths, and syzbot overlap. v2's additional contribution is **a finding-triage stage that uses repository provenance after attention allocation**.

## III. System Architecture

<p align="center">
  <img src="docs/assets/kernel-harness-v2-architecture.svg" alt="Two-stage External Signal architecture for Kernel Codex Harness v2" width="960">
</p>

<p align="center"><strong>Fig. 1.</strong> Pre-inference External Signal ranks reproducible review units. Post-inference triage combines model-independent Git provenance with model-derived response references, without treating the latter as External Signal or authoritative fact. Human validation remains outside both automated stages.</p>

**TABLE I — MAJOR MODULE RESPONSIBILITIES**

| Module | Responsibility |
| --- | --- |
| `targeting.py` | Kernel file discovery and scoring of path, lexical, and syzbot signals |
| `models.py` | `Candidate`, `Signal`, syzbot-derived `ExternalSignal` |
| `bundle.py` | Manifest, session index, and prompt/snippet bundle generation |
| `prompting.py` | Kernel audit prompts centered on reachability and invariants |
| `session.py` | State for pending reviews, history, and follow-up depth |
| `ingest.py` | Normalization of strict verdicts and a single next target |
| `repo_state.py` | Collection of Git branch, HEAD, status, dirty paths, and ancestry |
| `finding_triage.py` | Heuristic bucket classification based on provenance and known references |
| `autopilot.py` | Time-budgeted Codex execution, ingestion, archiving, and finding records |
| `syzbot.py` | Public syzbot HTML collection and local JSON cache generation |
| `cli.py` | Command routing for scan, review, doctor, and autopilot |

## IV. Methodology

### A. Candidate Discovery and Scoring

The scanner walks `.c` and `.h` files under the profile's include directories.

```text
Score(f) = Σ path_weight(f)
         + Σ line_signal_weight(f)
         + Σ syzbot_overlap_weight(f)
```

The current implementation sums line-level matches and limits only the number of top signals displayed in the prompt. The score determines the model's investigation order, but it is not a statistically calibrated vulnerability likelihood.

The main static signals are:

- ioctl, compat handler, file operation hook
- copy_from/to_user and `__user`
- kmalloc/kzalloc/kvmalloc, cache allocation, and free paths
- refcount, atomic, kref
- size and length calculations and the memcpy family
- lock, RCU, async lifetime
- BPF, skb, XDP, netlink
- capability and namespace checks

### B. Profile-Driven Scope

| Profile | Focus |
| --- | --- |
| `default` | Starting points in kernel/mm/net/fs/security/io_uring/lib/drivers |
| `net` | netlink, socket, skb, XDP |
| `fs` | ioctl, procfs, seq_file, debugfs |
| `io_uring` | Asynchronous request lifetimes and teardown |
| `bpf` | verifier, map/program lifetime, BTF |
| `drivers` | ioctl, DMA, MMIO, and driver teardown |

### C. Crash Intelligence

`syzbot-fetch` extracts titles, subsystems, bug types, and file:line information from public syzbot bug pages and stores them as JSON. Exact file overlap is used as a strong ranking signal, while subsystem overlap is weaker. Because the live dashboard can change, the reproducibility unit is the JSON captured at fetch time. Crash overlap is a hint for variant hunting, not vulnerability evidence.

### D. Session and Review Contract

`scan` creates the full ranked candidate manifest and prompt bundles for the highest-ranked targets. `--limit` is the number of candidates retained in the manifest, while `--top` is the number of bundles generated in advance. Later ranks can also be generated on demand.

Model responses are normalized to one of the following verdicts:

- `cve_candidate`
- `plausible_security_bug`
- `latent_bug`
- `not_cve_candidate`
- `needs_more_context`

Manual review and the autopilot use the same `review_state.json`, fixed response path, and verdict parser.

### E. Provenance Collection and Triage

`doctor` and the autopilot check whether the target is a Git repository, whether status collection succeeded, and the branch, HEAD, and dirty paths. A state whose provenance cannot be established is not treated as clean; it is preserved as `provenance_unknown`.

Triage of a strong verdict follows roughly this precedence:

1. `provenance_unknown` when provenance cannot be trusted,
2. `dirty_tree_suspect` when the repository or target is dirty,
3. `known_issue` when there is a related CVE or non-negated marker, or when a commit identified by the response as a fix/upstream relation is an ancestor of the current HEAD,
4. otherwise, `new_candidate`.

Negative or unrelated language such as “not a known issue” or “unrelated to CVE-...” is not used as known-issue evidence. The final classification records the original verdict together with the branch, HEAD, status, dirty state, matched references, and rationale.

The provenance-aware bucket classifier and JSONL writer currently apply to the autopilot ingestion path. Manual `loop` and `ingest` commands use the same base session state and verdict parser, but do not create bucket artifacts.

## V. Implementation and Usage

### A. Requirements

- Python 3.11 or later
- Linux kernel source tree
- Git when using provenance, doctor, or autopilot features
- Codex CLI and authentication when using the autopilot [3]
- Network access when collecting remote syzbot data

The Python runtime depends only on the standard library.

### B. Installation

```bash
git clone https://github.com/foxirain/linux-kernel-codex-harness-v2.git
cd linux-kernel-codex-harness-v2

python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
kernel-harness --help
```

The built-in profile JSON files are included in the wheel. Custom rules can be supplied with `--config /path/to/profile.json`.

### C. Minimal Workflow

```bash
# 1. Verify repository provenance.
kernel-harness doctor /path/to/linux

# 2. Create a ranked session.
kernel-harness scan /path/to/linux \
  --profile net \
  --limit 80 \
  --top 20 \
  --out artifacts

# 3. Inspect and render one focused review.
kernel-harness inspect artifacts/session-YYYYMMDDTHHMMSSZ --top 10
kernel-harness codex artifacts/session-YYYYMMDDTHHMMSSZ \
  --rank 1 \
  --include-snippet
```

Manual Codex responses can be saved to the `codex_response.txt` specified by the runbook and then ingested with the following commands.

```bash
kernel-harness loop artifacts/session-YYYYMMDDTHHMMSSZ --include-snippet
kernel-harness status artifacts/session-YYYYMMDDTHHMMSSZ
```

### D. Time-Budgeted Autopilot

```bash
kernel-harness autopilot artifacts/session-YYYYMMDDTHHMMSSZ \
  --duration 30m \
  --per-run-timeout 10m \
  --include-snippet \
  --require-clean-tree \
  --stop-on-finding
```

The Codex sandbox defaults to `read-only`. `--require-clean-tree` permits execution only when the Git repository, status, and HEAD can be verified and the working tree is clean. `--stop-on-finding` stops only when heuristic triage produces `new_candidate`.

### E. Optional syzbot Feed

```bash
kernel-harness syzbot-fetch https://syzkaller.appspot.com/upstream \
  --out artifacts/syzbot/upstream.json \
  --limit 50

kernel-harness syzbot-stats artifacts/syzbot/upstream.json --top 15

kernel-harness scan /path/to/linux \
  --profile fs \
  --syzbot-json artifacts/syzbot/upstream.json \
  --out artifacts
```

### F. Session Artifacts

```text
artifacts/session-<timestamp>/
├── SESSION.md
├── targets.json
├── finding_template.json
├── review_state.json
├── codex_response.txt              # present while a response is pending
├── bundles/
├── responses/
└── autopilot/
    ├── AUTOPILOT_STATUS.txt
    ├── AUTOPILOT_PROGRESS.txt
    ├── AUTOPILOT_BASELINE.json
    ├── AUTOPILOT_FINDINGS.txt
    ├── AUTOPILOT_FINDINGS_NEW.txt
    ├── AUTOPILOT_KNOWN_ISSUES.txt
    ├── AUTOPILOT_SUSPECTS.txt
    ├── AUTOPILOT_PROVENANCE_UNKNOWN.txt
    ├── AUTOPILOT_FINDINGS.jsonl
    ├── prompts/
    ├── exec/
    ├── parse_errors/
    └── findings/
        ├── new/
        ├── known/
        ├── suspects/
        └── unknown/
```

`AUTOPILOT_FINDINGS.jsonl` preserves the verdict, bucket, reason, branch, HEAD, provenance status, matched reference, and finding/archive paths in a form suitable for post-processing.

## VI. Operational Outcome and Verification

v2 applied the extended architecture to real Linux kernel vulnerability research.

**TABLE II — DISCLOSED VULNERABILITY OUTCOME**

| Public outcome | Affected area | Vulnerability | Investigation model |
| --- | --- | --- | --- |
| [CVE-2026-53075](https://nvd.nist.gov/vuln/detail/CVE-2026-53075) | PPP · `drivers/net/ppp/ppp_generic.c` | Unattached administrative ioctls lacked a `CAP_NET_ADMIN` check against the user namespace owning the target network namespace | Finding surfaced during a v2-assisted investigation; validation and disclosure remained human-led |

The 16 regression tests focus on software contracts and distributability, not a security-detection accuracy benchmark.

- allocator and built-in profile resource regressions
- ensuring negative verdicts and CVE references in ordinary prose do not become strong findings
- manual follow-up bounds and rank ordering
- stale response archival when no target is pending
- the read-only sandbox default and positive CLI arguments
- fail-closed provenance for missing repositories, non-Git directories, and status failures
- dirty target, known reference, negation, unrelated CVE triage
- preservation of classification metadata in session history and JSONL
- parse-error and finding-artifact contracts
- profile-scan smoke testing from the installed wheel

```bash
python -m unittest discover -s tests -v
python -m pip wheel . --no-deps --wheel-dir dist
python -m pip install --force-reinstall dist/*.whl
```

GitHub Actions runs the regression tests on Python 3.11 and 3.12, installs the wheel, and smoke-tests the 6 packaged profiles and the default scan. The public case above is an operational outcome from real research, not a benchmark of precision, recall, exploitability, or CVE discovery rate measured on a representative corpus of Linux trees.

## VII. Safety Considerations

- The Codex sandbox defaults to `read-only`, and retaining that default is recommended.
- When clean provenance matters, run `doctor` and then use `--require-clean-tree`.
- Do not interpret a non-Git directory or a status/HEAD verification failure as clean.
- Do not use `--dangerously-bypass-approvals-and-sandbox` outside an isolated experimental environment.
- Treat source comments and identifiers as model input and account for prompt injection.
- CVE and commit strings in a response are references, not authoritative confirmation.
- Before publishing or reporting a finding, a human must revalidate reachability, the invariant, impact, and affected versions.

## VIII. Limitations and Threats to Validity

1. **Lexical analysis.** The harness does not construct a true C AST, call graph, or interprocedural data flow.
2. **Score bias.** Comments, macros, repeated tokens, and large files can have an outsized effect on scores.
3. **Reachability gap.** Kernel configuration, privileges, namespaces, and device availability are not modeled automatically.
4. **External data fragility.** The syzbot integration is affected by changes to the public HTML structure.
5. **Local provenance only.** Git ancestry is evaluated from the current checkout's HEAD and does not represent every upstream or vendor history.
6. **Response-derived references.** CVEs and known markers are extracted from model responses and may be omitted, hallucinated, or misunderstood in context.
7. **Heuristic triage.** Neither `new_candidate` nor `known_issue` is a final novelty determination.
8. **Model dependence.** Result quality depends on the model, prompt interpretation, and available repository context.
9. **Evaluation scope.** The current tests verify software regressions. The disclosed CVE case is a real-use outcome, but it does not replace a statistical evaluation of security-detection performance.

## IX. Evolution and Retrospective

v1 ([repository](https://github.com/foxirain/linux-kernel-codex-harness)) focused on **allocating LLM attention with External Signal** and was used in a real v1-assisted investigation that found [CVE-2026-31720](https://nvd.nist.gov/vuln/detail/CVE-2026-31720). v2 continues the same research philosophy and extends it by recording repository state and response-derived references even after the model produces a strong finding. A later investigation using this architecture found [CVE-2026-53075](https://nvd.nist.gov/vuln/detail/CVE-2026-53075).

```text
v1: source observations → rank → focused review
v2: source observations → rank → focused review → provenance-aware triage
```

Two principles must be preserved through this evolution.

1. Do not mistake a pre-inference score for vulnerability proof.
2. Do not mistake a post-inference bucket for novelty proof.

If extending the system again today, the priorities would be Clang/tree-sitter call graphs, score normalization, versioned manifests and inter-process state locking, an authoritative CVE/fix database adapter, and separation of the runner, triage, and artifact writer. Current state writes already use temporary files and atomic replacement.

## X. Conclusion

`Kernel Codex Harness v2` does not replace vulnerability detection. Before model invocation, External Signal allocates the investigation budget to explainable candidates; after model invocation, provenance signals organize strong findings into a reviewable queue. This architecture was used in a real investigation that found CVE-2026-53075. The project's central result is not an algorithm that automatically determines novelty, but a **practical LLM security-review workflow that explicitly separates attention allocation from provenance-aware triage**.

## Appendix A. Repository Layout

```text
.
├── .github/workflows/ci.yml
├── docs/
│   ├── assets/kernel-harness-v2-architecture.svg
│   ├── AUTOPILOT.md
│   ├── CODEX_CLI.md
│   ├── CODEX_WORKFLOW.md
│   └── SYZBOT.md
├── kernel_harness/
│   ├── resources/
│   │   ├── linux-kernel-default.json
│   │   └── profiles/
│   │       ├── bpf.json
│   │       ├── drivers.json
│   │       ├── fs.json
│   │       ├── io_uring.json
│   │       └── net.json
│   ├── __init__.py
│   ├── __main__.py
│   ├── autopilot.py
│   ├── bundle.py
│   ├── cli.py
│   ├── finding_triage.py
│   ├── ingest.py
│   ├── models.py
│   ├── prompting.py
│   ├── repo_state.py
│   ├── session.py
│   ├── syzbot.py
│   └── targeting.py
├── tests/test_regressions.py
├── .gitignore
├── README.md
└── pyproject.toml
```

For detailed manual operation, see the [Codex CLI guide](docs/CODEX_CLI.md); for automated execution and triage, see the [Autopilot guide](docs/AUTOPILOT.md); and for crash intelligence, see the [syzbot guide](docs/SYZBOT.md).

## References

[1] Protect AI, “vulnhuntr,” GitHub repository. <https://github.com/protectai/vulnhuntr>

[2] Google, “syzkaller and syzbot,” GitHub repository. <https://github.com/google/syzkaller>

[3] OpenAI, “Codex CLI.” <https://developers.openai.com/codex/cli/>

## License

Licensed under the [Apache License 2.0](LICENSE).
