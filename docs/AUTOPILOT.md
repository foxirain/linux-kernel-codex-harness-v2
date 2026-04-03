# Autopilot v2

## 목적

`autopilot`은 세션 상태를 읽어 다음 프롬프트를 만들고, `codex exec`를 비대화식으로 실행한 뒤, 응답을 ingest하고 다시 다음 타깃으로 넘어가는 루프를 시간 예산 동안 반복한다.

## 기본 실행

```bash
cd /linux_harness
python3 -m kernel_harness autopilot /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ \
  --duration 1h \
  --per-run-timeout 20m \
  --include-snippet \
  --require-clean-tree
```

## clean tree 확인

```bash
python3 -m kernel_harness doctor /linux
```

출력 예시:

```text
repo_root=/linux
is_git=1
branch=master
head=<commit>
dirty=1
dirty_file=kernel/bpf/btf.c
```

`--require-clean-tree`를 주면 dirty tree에서는 오토파일럿이 바로 종료한다. 이때 진행 로그에는 `stop_reason=blocked_dirty_tree`가 남는다.

## finding 분류

strong finding verdict는 추가 분류를 거친다.

- `new_candidate`: 신규 후보로 보이는 finding
- `known_issue`: 기존 CVE, fix commit, known marker가 응답에 포함된 finding
- `dirty_tree_suspect`: dirty tree 또는 dirty target 위에서 나온 finding

## 산출물

세션의 `autopilot/` 아래에 다음이 쌓인다.

- `AUTOPILOT_STATUS.txt`
- `AUTOPILOT_PROGRESS.txt`
- `AUTOPILOT_FINDINGS.txt`
- `AUTOPILOT_FINDINGS_NEW.txt`
- `AUTOPILOT_KNOWN_ISSUES.txt`
- `AUTOPILOT_SUSPECTS.txt`
- `AUTOPILOT_FINDINGS.jsonl`
- `findings/new/`
- `findings/known/`
- `findings/suspects/`

## 운영 기준

- dirty kernel tree에서는 `doctor`로 확인하고 새 clean checkout으로 돌리는 편이 맞다.
- `--stop-on-finding`은 `new_candidate`에만 반응한다.
- `known_issue`나 `dirty_tree_suspect`는 기록은 남기되 세션을 자동 종료시키지 않는다.
