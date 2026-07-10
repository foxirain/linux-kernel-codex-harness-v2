# Codex CLI Usage

이 문서는 생성한 하네스를 Codex CLI에서 바로 사용하는 절차다.

## 1. 세션 생성

전체 기본 프로필:

```bash
kernel-harness scan /path/to/linux --profile default --out artifacts
```

서브시스템 집중 프로필 예시:

```bash
kernel-harness scan /path/to/linux --profile net --top 15 --out artifacts
kernel-harness scan /path/to/linux --profile io_uring --top 10 --out artifacts
kernel-harness scan /path/to/linux --profile bpf --top 10 --out artifacts
```

## 2. syzbot까지 붙여서 세션 생성

```bash
kernel-harness syzbot-fetch https://syzkaller.appspot.com/upstream --out artifacts/syzbot/upstream.json --limit 50
kernel-harness scan /path/to/linux --profile fs --syzbot-json artifacts/syzbot/upstream.json --out artifacts
```

구버전 호환으로 아래도 된다.

```bash
kernel-harness /path/to/linux
```

## 3. 세션 요약 보기

```bash
kernel-harness inspect artifacts/session-YYYYMMDDTHHMMSSZ --top 10
```

## 4. Codex에 넣을 프롬프트 출력

1위 타깃 프롬프트:

```bash
kernel-harness codex artifacts/session-YYYYMMDDTHHMMSSZ --rank 1
```

신호 주변 스니펫까지 포함:

```bash
kernel-harness codex artifacts/session-YYYYMMDDTHHMMSSZ --rank 1 --include-snippet
```

## 5. 실제 Codex CLI 루프

```bash
cd /path/to/linux
codex
```

그 다음 `kernel-harness codex ...` 출력 내용을 그대로 붙여 넣는다.

추천 루프는 다음과 같다.

1. `inspect`로 상위 5개만 본다.
2. `codex --rank N`으로 하나씩 투입한다.
3. Codex가 추가 파일을 2~3개 이상 요구하면 그 세션은 중지한다.
4. finding이 concrete해지면 별도 파일로 저장한다.
5. 같은 서브시스템은 전용 profile로 다시 스캔한다.

## 6. 추천 프롬프트 운용법

- 한 번에 한 타깃만 본다.
- Codex에게 먼저 reachability를 확정시키고 그 다음 bug class를 판단시킨다.
- 막연한 "취약점 있을까" 대신 invariant break를 강제한다.
- confidence가 높아도 free path와 error unwind가 확인되지 않으면 확정하지 않는다.
- syzbot context가 붙었더라도 실제 취약점 입증은 별도로 해야 한다.

수동 `codex`/`loop` 경로는 verdict와 next target을 session state에 기록한다. v2의 provenance-aware finding bucket과 JSONL artifact는 `autopilot` ingest 경로에서 생성되며, 자세한 내용은 [`AUTOPILOT.md`](AUTOPILOT.md)를 참고한다.
