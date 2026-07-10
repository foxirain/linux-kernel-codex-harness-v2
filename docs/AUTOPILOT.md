# Autopilot v2: Provenance-Aware Triage

`autopilot`은 ranked session을 시간 예산 동안 비대화식으로 검토한다. 다음 prompt를 만들고 `codex exec`를 실행한 뒤, 응답을 ingest하고 strong finding에 repository provenance를 결합해 review bucket을 기록한다.

이 기능의 목적은 신규 취약점을 자동 판정하는 것이 아니다. 반복 실행을 재현 가능한 로그로 남기고, 사람이 먼저 확인할 finding queue를 정리하는 것이다.

## 1. Two-Stage External Signal

Autopilot은 두 종류의 signal을 서로 다른 시점에 사용한다.

### Pre-inference: attention allocation

- path와 subsystem weight
- usercopy, allocator, refcount, size, lock 등 lexical hit
- cached syzbot file/subsystem overlap

이 signal은 모델에게 전달할 target을 정한다. 높은 rank는 취약점 증명이 아니다.

### Post-inference: provenance-aware triage

- Git repository 여부와 status 수집 성공 여부
- branch와 HEAD
- repository 및 target dirty state
- 응답의 CVE, commit hash, known marker
- negated 또는 unrelated reference

이 문서에서 post-inference External Signal은 Git repository/status, branch, HEAD, dirty state, local ancestry처럼 모델과 독립적으로 수집한 provenance만 가리킨다. CVE·commit·known marker는 모델 응답에서 추출한 model-derived reference이며 External Signal이나 authoritative fact가 아니다. Triage는 두 입력을 결합해 strong finding을 review bucket으로 정리한다. 어떤 bucket도 novelty proof가 아니다.

## 2. Requirements

- `kernel-harness scan`으로 생성한 session
- session manifest가 가리키는 Linux kernel source tree
- Git executable
- Codex CLI와 인증

Codex sandbox 기본값은 `read-only`다.

## 3. Repository Doctor

먼저 provenance를 확인한다.

```bash
kernel-harness doctor /path/to/linux
```

출력 예시:

```text
repo_root=/path/to/linux
is_git=1
branch=master
head=<full-commit-hash>
dirty=0
status_ok=1
```

Dirty path가 있으면 `dirty_file=<path>`가 반복 출력된다. Missing path, non-Git directory, HEAD/status 실패에서는 `status_ok=0`과 `error=<reason>`이 출력되고 종료 코드 2를 반환한다.

`doctor` 성공은 취약점 분석 성공을 뜻하지 않는다. 단지 local repository provenance를 읽을 수 있다는 뜻이다.

## 4. Recommended Run

```bash
kernel-harness autopilot artifacts/session-YYYYMMDDTHHMMSSZ \
  --duration 30m \
  --per-run-timeout 10m \
  --include-snippet \
  --require-clean-tree \
  --stop-on-finding
```

`--require-clean-tree`를 사용하면 다음 조건을 모두 만족해야 시작한다.

1. 유효한 Git work tree,
2. status 수집 성공,
3. HEAD 확인 성공,
4. dirty file 없음.

Dirty tree는 `blocked_dirty_tree`, 검증할 수 없는 tree는 `blocked_unverified_tree`로 종료되며 반환 코드는 2다.

## 5. Execution Lifecycle

한 iteration은 다음 순서로 진행된다.

1. stale response가 있으면 새 target에 연결하지 않고 archive한다.
2. session state에서 다음 rank 또는 최대 두 번의 bounded follow-up을 선택한다.
3. prompt와 선택적 snippet을 고정된 run artifact로 저장한다.
4. kernel tree를 working directory로 `codex exec`를 실행한다.
5. strict verdict와 single next target을 parse한다.
6. parse 실패는 retryable error로 archive하며 rank를 완료 처리하지 않는다.
7. strong verdict이면 현재 repository state를 다시 수집한다.
8. provenance-aware heuristic triage를 실행한다.
9. session history, text index, finding 원문, JSONL을 기록한다.

`--stop-on-finding`은 triage bucket이 `new_candidate`일 때만 중단한다. `known_issue`, `dirty_tree_suspect`, `provenance_unknown`은 기록한 뒤 다음 target으로 진행한다.

## 6. Triage Contract

Strong verdict는 `cve_candidate` 또는 `plausible_security_bug`다. 나머지는 `non_finding`으로 취급하며 bucket별 finding 파일을 만들지 않는다.

Triage 우선순위는 다음과 같다.

| Priority | Condition | Bucket |
| --- | --- | --- |
| 1 | Git/status/HEAD provenance 확인 실패 | `provenance_unknown` |
| 2 | target 또는 repository dirty | `dirty_tree_suspect` |
| 3 | related CVE, non-negated marker 또는 HEAD에 존재하는 related fix/upstream commit | `known_issue` |
| 4 | 위 blocking signal 없음 | `new_candidate` |

### Reference handling

- 모든 CVE 문자열은 `referenced_cves`에 보존한다.
- “unrelated to CVE-…”, “distinct from CVE-…” 같은 표현은 `related_cves`에서 제외한다.
- “not a known issue”처럼 negated marker는 known 근거로 사용하지 않는다.
- 모든 commit hash는 audit metadata로 보존하지만, 응답이 `fixed by/in commit` 또는 `upstream commit` 관계로 지목한 hash만 HEAD ancestor 여부를 known 근거로 확인한다.
- 응답 reference는 외부 CVE database confirmation이 아니다.

모든 classification은 `novelty_proven=false`를 기록한다.

## 7. Finding Artifacts

```text
autopilot/
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

각 finding 원문에는 다음이 포함된다.

- target, rank, verdict, bucket, reason
- target file과 dirty 상태
- Git repository/status 여부, branch, HEAD, error
- `novelty_proven`
- referenced/related CVE와 commit
- 현재 HEAD에 존재하는 related fix/upstream commit
- matched known marker
- archived Codex response

`AUTOPILOT_FINDINGS.jsonl`은 동일한 핵심 metadata와 artifact path를 machine-readable record로 누적한다. Classification은 `review_state.json` history에도 저장되어 session state와 finding artifact가 같은 결과를 가리킨다.

`AUTOPILOT_BASELINE.json`은 run 시작 시점의 repository path, branch, HEAD, status, dirty file을 고정해 이후 finding provenance를 비교할 기준을 남긴다.

## 8. Options

| Option | Meaning |
| --- | --- |
| `--duration 30m` | 전체 실행 시간. `s`, `m`, `h` 지원 |
| `--per-run-timeout 10m` | Codex 한 번의 최대 실행 시간 |
| `--include-snippet` | signal 주변 code snippet을 prompt에 추가 |
| `--model MODEL` | Codex model override |
| `--sandbox MODE` | `read-only`, `workspace-write`, `danger-full-access` |
| `--no-full-auto` | Codex CLI의 `--full-auto` 전달 생략 |
| `--require-clean-tree` | Git/status/HEAD가 확인된 clean tree만 허용 |
| `--stop-on-finding` | `new_candidate`에서 중단 |
| `--dangerously-bypass-approvals-and-sandbox` | Codex의 보호 우회 flag 전달 |

마지막 option은 격리된 실험 환경이 아니면 사용하지 않는다.

## 9. Status and Resume

```bash
kernel-harness status artifacts/session-YYYYMMDDTHHMMSSZ
cat artifacts/session-YYYYMMDDTHHMMSSZ/autopilot/AUTOPILOT_STATUS.txt
```

Run prompt와 stdout/stderr는 번호가 붙어 누적된다. 완료된 rank는 session history로 계산하며, pre-generated `--top` 범위를 넘는 bundle도 필요할 때 생성한다.

## 10. Interpretation Boundary

- `new_candidate`는 “known/dirty/provenance blocking signal이 없었다”는 heuristic이다.
- `known_issue`는 authoritative CVE matching 결과가 아니다.
- `dirty_tree_suspect`는 local change의 인과관계를 증명하지 않는다.
- `provenance_unknown`은 finding의 참·거짓이 아니라 repository context를 확인할 수 없음을 뜻한다.
- 최종 판단은 clean checkout에서 reachability, invariant, impact, affected version을 사람이 재검증해야 한다.
