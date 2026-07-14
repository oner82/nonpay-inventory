// 웹앱 버전 정보 (단일 소스)
// - 로그인 화면과 앱 화면이 모두 이 파일을 읽어 버전을 표시한다.
// - 기능을 추가/변경해 배포할 때마다 아래 VERSION과 RELEASE_DATE를 함께 올린다.
//   예) 기능 추가 → 1.9.0 → 1.10.0, 큰 전환 → 2.0.0
// - 화면에 표시하려면 요소에 data-app-version 속성을 준다.
//     data-app-version="date"  → "v1.9.0 · 2026-07-07" (로그인 화면용)
//     data-app-version="short" → "v1.9.0"              (앱 헤더용)
(function () {
  const VERSION = "2.3.0";
  const RELEASE_DATE = "2026-07-14";

  window.OR_APP_VERSION = VERSION;
  window.OR_APP_VERSION_DATE = RELEASE_DATE;

  const applyVersionLabels = () => {
    document.querySelectorAll("[data-app-version]").forEach((el) => {
      const mode = el.getAttribute("data-app-version");
      el.textContent = mode === "date" ? `v${VERSION} · ${RELEASE_DATE}` : `v${VERSION}`;
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", applyVersionLabels);
  } else {
    applyVersionLabels();
  }
})();
