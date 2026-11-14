# OCS 입력 회귀검사

실제 환자·운영 자료는 사용하지 않는다. 테스트의 품목과 원장은 가상 fixture다.

## 외부 의존성 없이 실행

```
node --test .github/tests/ocs-input.test.cjs
```

실제 모듈의 이벤트를 간단한 DOM 대역으로 실행한다. 미해석 원문 저장 차단, 해석 실패 시 기존 수량 보존, 재확인 후 저장 진입, 정상 재읽기를 검증한다. DOM 레이아웃·실제 브라우저 동작 검증을 대신하지 않는다.

## 브라우저 검사

Playwright가 설치된 환경에서:

```
CHROMIUM_PATH=/usr/bin/chromium node .github/tests/ocs-input.browser.cjs
```

`CHROMIUM_PATH`를 생략하면 Playwright 기본 Chromium을 사용한다. 외부 네트워크 요청은 전부 차단하고 실제 OCS 모듈만 주입한다. Firebase 저장은 테스트 대역을 사용한다.

이 테스트는 변경한 입력 흐름에 대한 검사다. 전체 앱의 로그인, 입고, 장부, 동시성 및 운영 권한 검증은 별도로 필요하다.
