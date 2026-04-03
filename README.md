# Kernel Codex Harness

`Kernel Codex Harness`는 Linux 커널 소스 트리에서 취약점 후보가 될 만한 고위험 파일을 먼저 좁히고, Codex가 바로 조사에 들어갈 수 있도록 분석 번들과 프롬프트를 생성하는 하네스다.

핵심 목표는 두 가지다.

- Codex 토큰과 조사 시간을 `고위험 엔트리포인트`에 집중시킨다.
- `실제 CVE 후보`가 될 가능성이 높은 커널 버그 패턴에 맞춰 조사 흐름을 표준화한다.

## 왜 이런 구조인가

Protect AI의 `vulnhuntr`는 `엔트리 파일 분석 → 추가 컨텍스트 요청 → 취약점별 2차 분석 → 구조화된 결과물` 흐름을 사용한다. 이 하네스는 그 아이디어를 커널에 맞게 옮겼다.

- 원본 레퍼런스: https://github.com/protectai/vulnhuntr?tab=readme-ov-file
- 참고한 포인트
  - 초기 파일 단위 분석 후 추가 컨텍스트 확장
  - 취약점 클래스별 재평가
  - confidence와 PoC 중심의 산출물
- 커널 버전으로 바꾼 포인트
  - `remote input` 대신 `userspace reachable kernel surface`에 집중
  - Python call-chain 대신 `syscall/ioctl/netlink/procfs/bpf/fs/driver` 경계를 우선 선별
  - 커널답게 `UAF/refcount/race/usercopy/size truncation/infoleak/capability check`를 기본 감사 축으로 둠
  - `syzbot` 공개 크래시 데이터를 붙여 실제 퍼징 힌트를 점수에 반영할 수 있게 함

## 지금 된 상태

이 레포는 이제 단순 스캐너가 아니라 `실행 가능한 Codex 운영 하네스`다.

v2에서 강화된 점은 다음과 같다.

- `autopilot`이 strong finding을 `new_candidate`, `known_issue`, `dirty_tree_suspect`로 분류
- dirty kernel tree를 자동 감지하고 `--require-clean-tree`로 실행 전 차단 가능
- top-N 번들을 넘어가는 rank도 즉석 프롬프트 생성으로 계속 탐색 가능
- `doctor` 명령으로 현재 커널 트리의 git 상태와 dirty 파일을 바로 확인 가능
- finding을 text index와 JSONL 둘 다로 누적해서 후처리하기 쉬움

- `scan`: 커널 트리 스캔 후 세션 생성
- `inspect`: 생성된 세션 우선순위 요약 출력
- `codex`: Codex CLI에 바로 붙여 넣을 조사 프롬프트 출력
- `syzbot-fetch`: syzbot 대시보드에서 버그 데이터를 가져와 JSON 캐시 생성
- `syzbot-stats`: 저장한 syzbot JSON 요약
- built-in profile: `default`, `net`, `fs`, `io_uring`, `bpf`, `drivers`

## 빠른 시작

기본 스캔:

```bash
cd /linux_harness
python -m kernel_harness scan /path/to/linux --profile default --out /linux_harness/artifacts
```

syzbot까지 붙여서 스캔:

```bash
python -m kernel_harness syzbot-fetch https://syzkaller.appspot.com/upstream --out /linux_harness/artifacts/syzbot/upstream.json --limit 50
python -m kernel_harness scan /path/to/linux --profile net --syzbot-json /linux_harness/artifacts/syzbot/upstream.json --out /linux_harness/artifacts
```

상위 후보 확인:

```bash
python -m kernel_harness inspect /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ --top 10
```

Codex CLI용 프롬프트 출력:

```bash
python -m kernel_harness codex /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ --rank 1 --include-snippet
```

시간 예산 기반 완전 자동 실행:

```bash
python3 -m kernel_harness autopilot /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ \
  --duration 1h \
  --per-run-timeout 20m \
  --include-snippet \
  --require-clean-tree
```

커널 트리가 깨끗한지 먼저 확인하려면:

```bash
python3 -m kernel_harness doctor /linux
```

예전 방식도 유지된다.

```bash
python -m kernel_harness /path/to/linux
```

## 생성 산출물

실행 결과는 `artifacts/session-<timestamp>/` 아래에 생성된다.

- `targets.json`: 점수화된 후보 목록
- `SESSION.md`: 우선순위 인덱스와 운영 순서
- `finding_template.json`: CVE 후보 보고서 템플릿
- `bundles/*.md`: Codex에 바로 넣을 타깃별 감사 프롬프트
- `bundles/*.snippet.txt`: 신호 주변 코드 일부

## syzbot 연동이 하는 일

`syzbot`은 퍼징으로 실제 커널 크래시를 수집하는 시스템이다. 이 하네스는 공개 버그 페이지에서 다음 정보를 긁어와 로컬 JSON으로 저장한다.

- bug title
- subsystem
- bug type
- file:line 히트
- bug URL

그 다음 `scan --syzbot-json ...`을 쓰면:

- exact file overlap이 있는 파일 점수를 크게 올리고
- 같은 subsystem에서 최근 많이 깨진 코드도 약하게 올리고
- Codex prompt 안에 `syzbot context`를 넣어 준다

즉 `정적 냄새`와 `실제 크래시 힌트`를 합치는 방식이다.

## 프로필 추천

- `default`: 전체 훑기용 시작점
- `net`: netlink, socket ops, skb, XDP 계열 집중
- `fs`: ioctl, procfs, seq_file, debugfs 계열 집중
- `io_uring`: async lifetime, request teardown 집중
- `bpf`: verifier, map/program lifetime, BTF 경계 집중
- `drivers`: ioctl, DMA, MMIO 기반 드라이버 공격면 집중

## 추천 운영 방식

가장 점수가 높은 번들부터 순서대로 Codex에 투입한다. 한 번에 너무 넓게 보지 말고, 각 세션에서 다음 순서로 좁혀가는 게 효율적이다.

1. 타깃 파일 하나를 열어 userspace entrypoint를 확정한다.
2. allocation, refcount, error unwind, free path를 우선 추적한다.
3. syzbot context가 있으면 같은 invariant인지, nearby variant인지 따진다.
4. 확실한 invariant break가 나오면 finding 템플릿으로 고정한다.
5. 애매하면 인접 파일 2~3개만 추가로 본다.
6. 서브시스템별로 profile이나 pattern weight를 조정해서 다시 돌린다.

## Codex CLI에서 쓰는 법

자세한 절차는 아래 문서에 정리했다.

- `/linux_harness/docs/CODEX_CLI.md`
- `/linux_harness/docs/CODEX_WORKFLOW.md`
- `/linux_harness/docs/SYZBOT.md`

핵심만 요약하면:

1. `syzbot-fetch`로 퍼징 힌트를 가져온다.
2. `scan --syzbot-json ...`으로 세션을 만든다.
3. `inspect`로 상위 타깃을 고른다.
4. `codex --rank N`으로 프롬프트를 출력한다.
5. 커널 트리에서 `codex`를 실행하고 그 프롬프트를 그대로 붙여 넣는다.

## 커널에서 특히 잘 나오는 감사 축

- `ioctl` 핸들러의 크기 검증 누락
- compat/native 경로 불일치
- refcount 증가/감소 불균형
- async teardown 중 UAF
- usercopy 길이 검증 실패
- `size_t`, `u32`, `unsigned long` 사이 truncation
- `copy_to_user` 전 초기화되지 않은 데이터 노출
- capability/ns boundary check 위치 오류
- procfs/debugfs/sysfs에서의 느슨한 권한 처리
- BPF verifier/helper 경계의 타입 혼동

## 디렉터리 구조

```text
/linux_harness
├── configs/
│   ├── linux-kernel-default.json
│   └── profiles/
│       ├── bpf.json
│       ├── drivers.json
│       ├── fs.json
│       ├── io_uring.json
│       └── net.json
├── docs/
│   ├── CODEX_CLI.md
│   ├── CODEX_WORKFLOW.md
│   └── SYZBOT.md
├── kernel_harness/
│   ├── __init__.py
│   ├── __main__.py
│   ├── bundle.py
│   ├── cli.py
│   ├── models.py
│   ├── prompting.py
│   ├── syzbot.py
│   └── targeting.py
└── README.md
```

## 다음 단계 제안

이 하네스는 `정적 신호 기반 우선순위화 + Codex 조사 오케스트레이션 + syzbot 힌트 결합` 버전이다. 다음 단계로 붙이면 더 강해진다.

- 최근 커널 수정 이력에서 `Fixes:`, `Cc: stable`, `KASAN`, `UBSAN` 태그를 반영하는 Git 히스토리 스코어링
- `syzbot` 크래시와 실제 커밋 수정 이력 자동 매핑
- 서브시스템별 맞춤 규칙 세트
- 조사 결과를 누적해서 같은 패턴의 N-day를 자동 재탐색하는 회귀 모드

## 한계

- 아직 실제 call graph나 C AST를 만들지는 않는다.
- syzbot 연동은 공개 HTML 페이지 파싱에 의존한다.
- false positive를 줄이려면 사람이 teardown path와 reachability를 검증해야 한다.
- 커널 소스 트리 크기가 크므로 첫 버전은 `정밀 분석`보다 `좋은 시작점 선별`에 초점을 둔다.

## Autopilot v2 산출물

`autopilot/` 아래에 다음 파일들이 생긴다.

- `AUTOPILOT_STATUS.txt`: 현재 상태 스냅샷
- `AUTOPILOT_PROGRESS.txt`: 실행 로그
- `AUTOPILOT_FINDINGS.txt`: 모든 strong finding 인덱스
- `AUTOPILOT_FINDINGS_NEW.txt`: 신규 후보로 분류된 finding만 누적
- `AUTOPILOT_KNOWN_ISSUES.txt`: 이미 알려진 이슈로 분류된 finding
- `AUTOPILOT_SUSPECTS.txt`: dirty tree나 repro 코드 영향이 의심되는 finding
- `AUTOPILOT_FINDINGS.jsonl`: 후처리용 구조화 로그
- `findings/new/`, `findings/known/`, `findings/suspects/`: 각 finding 원문

분류 규칙은 간단하다.

- `new_candidate`: 강한 finding이며 known marker와 dirty-tree 문제가 없음
- `known_issue`: 응답 안에 CVE, fix commit, known marker가 잡힘
- `dirty_tree_suspect`: 현재 커널 트리나 타깃 파일이 dirty 상태

실전에서는 `/linux`처럼 실험 코드가 섞인 트리 대신 clean checkout을 두고 `--require-clean-tree`를 켜는 편이 맞다.
