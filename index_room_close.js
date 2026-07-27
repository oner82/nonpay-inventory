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
      downloadExcel,
      setRoomCloseDirty
    } = context;

    // 방 마감(방 단위 보충) 운영은 2026-07-27 종료 — 비급여는 다시 사용입력(케이스 단위)에서 기록한다.
    // 이 화면은 운영 기간(2026-07-14~)에 쌓인 roomRefills 이력 조회·엑셀 저장 전용이다.
    // 과거 기록은 productMovementCounts 등 재고 집계에 계속 사용량으로 반영된다.

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

    const renderRoomClose = () => `
      <section class="grid">
        <div class="card">
          <h2>방 마감 (운영 종료)</h2>
          <p class="helper">비급여는 다시 <strong>사용입력(케이스 단위)</strong>에서 기록합니다. 이 화면은 방 마감 방식으로 운영했던 기간(2026-07-14 ~ 2026-07-27)의 이력 조회 전용이며, 새 마감 입력은 받지 않습니다. 과거 마감 수량은 재고·사용 집계에 계속 반영됩니다.</p>
        </div>
        <div class="card">
          <h2>방 마감 이력</h2>
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
        </div>
      </section>
    `;

    const bindRoomClose = () => {
      // 입력이 없는 조회 전용 화면 — 원격 재렌더 보호가 필요 없다.
      setRoomCloseDirty?.(false);
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
      renderRoomClose,
      bindRoomClose
    };
  };
})();
