# syzbot Integration

이 하네스의 syzbot 연동은 `실제 퍼징에서 깨진 버그 정보`를 로컬 JSON으로 가져와서, 스캔 점수와 Codex 프롬프트에 반영하는 기능이다.

## 흐름

1. syzbot 대시보드에서 공개 버그 페이지를 가져온다.
2. 각 버그 페이지에서 `title`, `subsystems`, `bug type`, `file:line` 히트를 추출한다.
3. JSON 캐시로 저장한다.
4. `scan --syzbot-json ...`으로 후보 파일 스코어에 반영한다.
5. 생성된 prompt에는 `syzbot context` 섹션이 추가된다.

이 cache는 모델 호출 전에 계산되는 pre-inference External Signal이다. 동일한 결과를 재계산하려면 live dashboard가 아니라 fetch 시점에 저장한 같은 JSON을 사용해야 하며, overlap은 review priority일 뿐 vulnerability proof가 아니다.

## 1. syzbot 데이터 가져오기

가장 일반적인 upstream 대시보드 예시는 아래다.

```bash
kernel-harness syzbot-fetch https://syzkaller.appspot.com/upstream --out artifacts/syzbot/upstream.json --limit 50
```

다른 대시보드 URL도 가능하다. 예를 들면 특정 브랜치나 상태 페이지를 넣을 수 있다.

## 2. 가져온 데이터 요약 보기

```bash
kernel-harness syzbot-stats artifacts/syzbot/upstream.json --top 15
```

이 명령은 많이 나오는 bug type, subsystem, file path를 요약해서 보여준다.

## 3. 스캔에 반영하기

```bash
kernel-harness scan /path/to/linux --profile fs --syzbot-json artifacts/syzbot/upstream.json --out artifacts
```

이제 `inspect` 출력의 `ext=` 값은 외부 crash intelligence가 몇 개 붙었는지 뜻한다.

```bash
kernel-harness inspect artifacts/session-YYYYMMDDTHHMMSSZ --top 10
```

## 4. Codex에 넣기

```bash
kernel-harness codex artifacts/session-YYYYMMDDTHHMMSSZ --rank 1 --include-snippet
```

prompt 안에 `syzbot context:` 블록이 추가된다. 이건 증거가 아니라 힌트다. Codex는 여기서:

- 같은 invariant가 깨지는지
- incomplete fix 가능성이 있는지
- nearby variant인지
- 다른 entrypoint에서 재도달 가능한지

를 확인해야 한다.

## 5. 추천 운용 방식

- `syzbot-fetch`는 주기적으로 다시 돌려 JSON을 갱신한다.
- `default`보다 `fs`, `net`, `bpf`, `io_uring` 같은 좁은 profile과 같이 쓰는 편이 효율적이다.
- syzbot이 같은 subsystem에서 많이 뜨는 시기에는 그 subsystem 전용 세션을 따로 만든다.
- syzbot exact file overlap은 강한 힌트지만, 그대로 CVE 후보라고 보면 안 된다.

## 6. 주의점

- 이 연동은 공개 HTML 페이지를 파싱하는 방식이라 대시보드 구조가 크게 바뀌면 조정이 필요할 수 있다.
- 네트워크가 막힌 환경이라면 `syzbot-fetch`는 동작하지 않는다. 그런 경우 미리 만든 JSON 파일을 옮겨와서 `--syzbot-json`만 써도 된다.
- syzbot은 `실제 크래시 힌트`를 주지만 reachability와 exploitability는 직접 검증해야 한다.
