# Codex Workflow

이 문서는 생성된 하네스를 실제 Codex 조사 루프로 연결하는 운영 가이드다.

## 1. 세션 생성

```bash
kernel-harness scan /path/to/linux --profile default --out artifacts
```

## 2. 가장 먼저 볼 파일

`SESSION.md`에서 점수가 가장 높은 번들을 고른다. 번들 하나당 조사 범위는 다음처럼 제한한다.

- 타깃 파일 1개
- 직접 호출자 또는 ops table 1~2개
- teardown/free path 1~2개

이렇게 해야 Codex 컨텍스트가 넓게 새지 않는다.

## 3. Codex에 넣을 기본 지시문

```text
Open the target bundle and the referenced kernel file. Confirm the true userspace-reachable entrypoint first. Then audit only the shortest path to a realistic CVE candidate, prioritizing UAF, refcount, usercopy, integer truncation, infoleak, and missing capability checks. Do not give generic advice. Either produce a concrete bug hypothesis with evidence, or name the single best next file/function to inspect.
```

## 4. 한 세션의 종료 조건

다음 셋 중 하나가 나오면 그 세션은 종료하는 편이 효율적이다.

- invariant break가 명확하고 exploit impact까지 설명 가능함
- false positive로 판정했고 근거가 명확함
- 추가로 봐야 할 파일이 3개를 넘어서며 범위가 번들 밖으로 퍼짐

세 번째 상황이면 하네스를 다시 돌려 새로운 타깃 세션으로 쪼개는 게 낫다.

## 5. CVE 후보 최소 기준

아래를 짧게라도 채우지 못하면 아직 CVE 후보로 올리기 이르다.

- reachable entrypoint
- attacker-controlled field or lifetime transition
- broken invariant
- concrete impact
- why existing checks do not stop it

## 6. 반복 탐색 팁

- `drivers/`는 넓으니 서브시스템별로 config를 복사해 include_dirs를 더 줄여라.
- `net/`, `io_uring/`, `fs/`, `kernel/bpf/`는 별도 세션으로 돌리는 게 보통 효율적이다.
- 한 번 찾은 버그 클래스는 비슷한 ops table과 compat path에 재적용해 N-day를 찾아라.
