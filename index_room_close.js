(() => {
  window.createRoomCloseModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const {
      escapeHtml,
      num,
      today,
      productById,
      formatDateTime,
      auditUserText,
      downloadExcel
    } = context;

    // 방 마감(방 단위 보충) 운영은 2026-07-27 종료 — 비급여는 다시 사용입력(케이스 단위)에서 기록한다.
    // 운영 기간(2026-07-14~)에 쌓인 roomRefills 이력을 사용내역 화면 하단의 접힌 카드로 제공한다
    // (조회·엑셀 전용, 관리자·책임사용자만). 과거 기록은 재고 집계에 계속 사용량으로 반영된다.

    const monthStart = () => `${today().slice(0, 8)}01`;

    const refillsInRange = (start, end) => (state.roomRefills || [])
      .filter((refill) => (!start || (refill.date || "") >= start) && (!end || (refill.date || "") <= end))
      .slice()
      .sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")) || (num(a.room) - num(b.room)));

    const refillHistoryHtml = (start, end) => {
      const refills = refillsInRange(start, end);
      if (!refills.length) return `<div class="empty">조회 기간에 방 마감 기록이 없습니다.</div>`;
      return refills.map((refill) => {
        const itemText = (refill.items || []).map((item) =>
          `${escapeHtml(productById(item.productId)?.name || "삭제된 제품")} ${Math.max(0, num(item.qty))}개`).join(", ");
        const total = (refill.items || []).reduce((sum, item) => sum + Math.max(0, num(item.qty)), 0);
        return `
          <div class="item">
            <div class="item-title">
              <span>${escapeHtml(refill.date || "-")} · ${escapeHtml(String(refill.room || "-"))}번방</span>
              <span class="pill">${total}개</span>
            </div>
            <div class="meta">
              <span>${itemText || "-"}</span>
              <span>입력: ${escapeHtml(auditUserText(refill) || "-")} · ${escapeHtml(formatDateTime(refill.updatedAt || refill.createdAt || ""))}</span>
            </div>
          </div>
        `;
      }).join("");
    };

    const exportRefillHistory = (start, end) => {
      const refills = refillsInRange(start, end);
      if (!refills.length) {
        alert("조회 기간에 방 마감 기록이 없습니다.");
        return;
      }
      const rows = refills.flatMap((refill) => (refill.items || []).map((item) => {
        const product = productById(item.productId);
        return [
          refill.date || "",
          `${refill.room || ""}번방`,
          product?.name || "삭제된 제품",
          product?.company || "",
          product?.subcategory || "",
          Math.max(0, num(item.qty)),
          auditUserText(refill) || "",
          formatDateTime(refill.updatedAt || refill.createdAt || "")
        ];
      }));
      downloadExcel(
        `방마감_비급여사용_${start || "all"}_${end || "all"}.xlsx`,
        ["날짜", "수술실", "제품명", "업체", "세부분류", "수량", "입력자", "입력시각"],
        rows
      );
    };

    // 기록이 하나도 없으면 카드 자체를 숨긴다(새 병원/초기화 상태에서 불필요한 과거 메뉴 노출 방지).
    const renderRoomCloseHistoryCard = () => {
      if (!(state.roomRefills || []).length) return "";
      return `
        <section class="grid">
          <details class="card">
            <summary class="use-draft-head">
              <div>
                <h3 style="margin:0;">방 마감 이력 (과거 기록)</h3>
                <div class="muted">방 단위 보충으로 운영했던 2026-07-14~07-27 기록입니다. 조회·엑셀 전용이며 집계에는 이미 포함되어 있습니다.</div>
              </div>
            </summary>
            <div class="row three">
              <div>
                <label for="roomHistoryStart">시작일</label>
                <input id="roomHistoryStart" type="date" value="${monthStart()}">
              </div>
              <div>
                <label for="roomHistoryEnd">종료일</label>
                <input id="roomHistoryEnd" type="date" value="${today()}">
              </div>
              <div>
                <label>&nbsp;</label>
                <button class="secondary" type="button" id="exportRoomHistory">엑셀로 저장</button>
              </div>
            </div>
            <div id="roomHistoryList">${refillHistoryHtml(monthStart(), today())}</div>
          </details>
        </section>
      `;
    };

    const bindRoomCloseHistory = () => {
      const historyStart = document.getElementById("roomHistoryStart");
      const historyEnd = document.getElementById("roomHistoryEnd");
      const historyList = document.getElementById("roomHistoryList");
      const refreshHistory = () => {
        if (historyList) historyList.innerHTML = refillHistoryHtml(historyStart?.value || "", historyEnd?.value || "");
      };
      [historyStart, historyEnd].forEach((input) => input?.addEventListener("change", refreshHistory));
      document.getElementById("exportRoomHistory")?.addEventListener("click", () =>
        exportRefillHistory(historyStart?.value || "", historyEnd?.value || ""));
    };

    return {
      renderRoomCloseHistoryCard,
      bindRoomCloseHistory
    };
  };
})();
