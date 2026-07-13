# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 언어 규칙

**모든 답변과 코드 주석 설명은 한국어로 작성한다.**

## What this is

A hospital operating-room inventory web app (수술실 비급여·재고관리) for tracking non-reimbursable supplies (비급여), human tissue / 인체조직 (historically called "DBM" — always call it **인체조직** now), treatment materials (치료재료), and implants. The primary users are OR nurses on tablets/phones. The UI is entirely in Korean. There is **no build step, no framework, no package.json** — it is plain ES-era JavaScript loaded via `<script>` tags and served as static files. Firebase (Firestore + Storage) is the backend, accessed directly from the browser via CDN ES module imports.

There is a detailed domain/workflow skill at `.codex/skills/or-nonpay-inventory/SKILL.md` — read it before non-trivial changes. Key rules from it: **do not change Firebase config, collection names, storage/delete/edit logic, deployment config, auth, or the working stock formula** unless explicitly asked; explain impact before touching data logic; prioritize mobile/tablet usability and fast, error-resistant input.

Stock formula: `현재고 = 기존재고 + 입고수량 - 사용수량` (current = prior + received − used).

## Commands

- **Run locally:** `python3 -m http.server 5177` then open `http://localhost:5177/auth_shell.html` (VS Code task "local server: auth_shell" + launch config "Open auth_shell in Chrome" do this). `index.html` just redirects to `auth_shell.html`.
- **Syntax check (the only "test"):** `node --check <file.js>`. There is no test suite, linter, or type checker. Verify by running the app and exercising the flow — see the SKILL.md test checklist (입고 save, 사용 save, delete, refresh persistence, stock math, mobile header/tabs).
- **Deploy:** push to `main` → GitHub Actions (`.github/workflows/firebase-hosting.yml`) runs `firebase deploy --only hosting --project nonpay-inventory`. **Pushing to main deploys to the live production site.** Hosting serves the repo root as-is (`firebase.json` `public: "."`).

## 배포 전 필수 점검 (Pre-deploy checklist — 반드시 순서대로)

**`main` 푸시는 곧 라이브 배포다. 스크럽(간호사)이 실사용 중이므로, 아래를 모두 통과하기 전에는 절대 푸시하지 않는다.** (이 절차는 2026-07-08, `index_new.html`에서 `</script>` 닫는 태그 하나가 누락된 채 배포돼 `index_usage_rules.js`가 로드되지 않아 임시저장 불러오기·최종저장이 라이브에서 깨진 사고 이후 추가됨.)

1. **HTML 태그 정합성** — `index_new.html`의 여는/닫는 스크립트 태그 개수가 일치하는지 확인한다:
   `grep -c '<script' index_new.html` == `grep -c '</script>' index_new.html`. 불일치면 태그 누락이다.
2. **캐시버스터는 국소 치환** — 버전 쿼리(`?v=…`)를 바꿀 때 `<script>`/`<link>` 태그 전체를 다시 쓰지 말고, **버전 문자열 부분만** 바꾼다. 태그를 통째로 재작성하면 닫는 태그를 빠뜨리기 쉽다.
3. **문법 검사** — 바꾼 JS마다 `node --check <file.js>`. (node가 없는 환경이면 4번 로드 프로브로 대체.)
4. **전 모듈 로드 프로브** — 헤드리스로 앱을 실제 부팅해 모든 `create<Feature>Module` 전역이 정의됐는지 확인한다. 세션을 위조(`localStorage.orInventoryUser = {id,loginId,name,role}`)해 로그인 리다이렉트를 피하고, 로드 후 `typeof window.createUsageRulesModule` 등이 전부 `"function"`인지 검사. 하나라도 `undefined`면 스크립트 태그/파싱 문제다. (조용한 실패라 눈으로는 안 보인다.)
5. **바꾼 기능을 실제로 눌러본다** — 특히 스크럽 필수 흐름(입고 저장, **임시저장→최종저장**, 삭제, 새로고침 지속성, 재고 계산)을 로컬(`python3 -m http.server 5177`)에서 로그인해 직접 실행. SKILL.md 테스트 체크리스트 참고.
6. **버전 반영** — `version.js`의 `VERSION`/`RELEASE_DATE`를 올리고, 바꾼 파일의 캐시버스터도 갱신했는지 확인.
7. **배포 후 검증** — 푸시 뒤 GitHub Actions가 `success`인지, 라이브(`nonpay-inventory.web.app`)의 `version.js`가 새 버전인지 확인하고, 스크럽들에게 강력 새로고침을 안내한다.

문제가 생기면 즉시 롤백: 직전 정상 커밋으로 `git revert <bad-sha>` 후 푸시(force-push 불필요).

## Architecture

### Two-layer shell + iframe

1. **`auth_shell.html` / `auth_shell.js`** — the login/session outer shell. Handles PIN auth, account requests, and account management (admin). Stores the logged-in user in `sessionStorage`+`localStorage` (`orInventoryUser`). On success it loads the actual app into an `<iframe>` pointing at `index_new.html`. PINs are stored as salted SHA-256 (`sha256(loginId::pin::salt)`), never plaintext.
2. **`index_new.html`** — the real app. Loads the CSS and, in a **fixed order**, ~13 classic (non-module) `<script>` files ending with `index_app.js` as the orchestrator.

### Module pattern (important)

These are **not ES modules** — they are plain scripts sharing the global scope, wrapped in IIFEs. Each feature file exposes a single factory on `window`:

- `window.create<Feature>Module = (context) => ({ render..., bind... })` — e.g. `createDashboardModule`, `createReceiptsModule`, `createUsageEntryModule`, `createHistoryModule`, `createProductsModule`, `createImplantsModule`, `createSettingsModule`, `createDepartmentsModule`, `createImplantVendorsModule`, `createUsageRulesModule`, `createBackupResetModule`.
- Shared helpers live on `window.ORInventoryUtils` (`index_utils.js`: `uid`, `today`, `num`, `escapeHtml`, `productCategory`, …) and `window.ORInventoryExportUtils` (`index_export_utils.js`: Excel/report export).

`index_app.js` (the big ~5500-line orchestrator) owns the Firebase connection and the app `state`, then lazily instantiates each module by calling its factory with a **`context` object of injected dependencies** (`getState`, `render`, `saveState`, helper fns, etc.). Modules never import each other and never touch Firebase directly — they read/write through the injected context and call back into `index_app.js`. When adding a module method that needs new data or a helper, thread it through the `context` object in `index_app.js`, don't reach for globals.

Version query strings on every script/link (`?v=20260707-...`) are manual cache-busters — bump them when you change a file so the live site picks it up.

### Firestore data model

Firebase is initialized in both `auth_shell.js` and `index_app.js` via dynamic `import()` from `https://www.gstatic.com/firebasejs/10.12.5/...` (config is just `{ projectId: "nonpay-inventory" }`).

- **`app/main`** — a single document holding the entire core inventory `state` (products, doctors, surgeries, receipts, usages, usageRules, backupVersions, …). Loaded with `getDoc`, kept live with `onSnapshot`, saved by rewriting the whole doc via `setDoc`/`runTransaction`. `blankState()` and `normalizeState()` in `index_app.js` define/repair its shape.
- **`app/users`** — accounts + roles (managed by `auth_shell.js`).
- **`implantRecords`**, **`implantVendors`**, **`pendingUsages`** — per-document collections (each item is its own doc), streamed with `onSnapshot`.

Because `app/main` is one big document mutated by whole-doc writes, the `onSnapshot` handler guards against clobbering in-flight edits (`saving` flag, `renderOrDeferForUseEntry` protects active 사용입력 forms). Preserve that guarding when touching save/subscribe logic.

### Roles

`admin` (관리자, all + account mgmt), `manager` (책임사용자, all except accounts), `receiver` (입고담당자, receipts/implants only), `staff` (일반사용자, use/edit/history, no delete). `roleAllowedViews` gates nav in **both** `auth_shell.js` and `index_app.js` — keep them in sync.

### Exports & vendored libs

Excel/PDF report generation runs client-side. `vendor/jspdf.umd.min.js` and `vendor/html2canvas.min.js` are lazy-loaded on demand (`loadExternalScriptOnce`) and used from `index_export_utils.js` / `index_implants.js`. `vendor/` is the only third-party code (no npm).

## Domain rules (beyond the stock formula)

- **업체관리 인체조직 (vendor-managed tissue):** products with `vendorManaged: true` (only valid for category 인체조직; see `isVendorManagedProduct` in `index_app.js`). They are selectable in 사용입력 like any 인체조직, but are **excluded from stock deduction, low-stock warnings, and stock checks** — the vendor keeps the ledger. Every place that mutates or checks `product.stock` must keep the `isVendorManagedProduct` guard. In UI copy about these items, never phrase photo requirements as "사진 첨부 필수" in a way that implies other items don't need photos.
- **사용입력 two-step save:** 임시저장 writes to the `pendingUsages` collection ("스크럽 확인 대기") and does **not** deduct stock or create a 사용내역 entry; only 최종저장 does both. Don't collapse or reorder these steps.
- **NO PATIENT DATA (v2.0.0, 2026-07-13):** 병원 전산팀 방침으로 환자 식별정보(이름·등록번호)는 Firebase 어디에도 저장하지 않는다. Records are keyed by a non-identifying **케이스 번호** — `caseRoom` (수술실 1~`CASE_ROOM_COUNT`(10)) + `caseOrder` (그날 순서), displayed as `1-1` via `caseLabel()` in `index_app.js`. `patientDisplayName`/`patientIdText` are compat aliases that now return the case label. The 환자↔케이스 mapping lives only in hospital paper/EMR records. Never reintroduce `patientName`/`patientId` fields or free-text patient inputs; ledger photos must not include patient labels (운영 규칙). `implantRecords.patientNo` is an app-assigned ledger closing number (장부번호), not a hospital patient ID.
- **Duplicate-case warning:** saving a usage checks same-day same-case records (`sameDayPatientUsageWarning`) and asks for confirmation — duplicates warn first. Pending drafts also match on date+case number to resume instead of duplicating.

## Repo notes

- `output/` and `tmp/` are local scratch/backup dumps (JSON snapshots, generated PDFs) and are untracked — not part of the app.
- `index_backup_reset.js` provides in-app backup/restore of `app/main`; treat as destructive.
- Indentation is 2 spaces; final newline + trimmed trailing whitespace enforced by `.vscode/settings.json`.
- **App version:** `version.js` is the single source of truth for the displayed version (`window.OR_APP_VERSION`), loaded by both `auth_shell.html` (login screen, shows `v… · date`) and `index_new.html` (app header, shows `v…` only) via `data-app-version` attributes. Bump `VERSION`/`RELEASE_DATE` there when shipping a feature. Current: **v2.0.0** (v1.9.0 was retroactively estimated from the project's ~9 feature epochs since its 2026-05-03 launch — the "Claude era" starting point).
