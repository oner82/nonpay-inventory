(() => {
  window.createRoomCloseModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const app = context.getApp();
    const {
      escapeHtml,
      num,
      today,
      uid,
      sameId,
      productCategory,
      productDisplaySort,
      productById,
      formatDateTime,
      auditCreateFields,
      auditUpdateFields,
      auditUserText,
      saveState,
      render,
      setButtonBusy,
      saveDoneToast,
      CASE_ROOM_COUNT
    } = context;

    // 방 마감 원리: 방 상자는 항상 정수(par)로 채우므로, 채운 수량 = 그날 그 방의 사용량.
    // 저장된 items가 재고 집계(productMovementCounts)에서 사용량으로 차감된다.
    let selectedRoom = "";

    // 0부터 시작하는 수량 스테퍼 (기본 qtyStepper는 최소 1이라 별도 정의)
    const zeroStepper = (inputAttrs, value) => `
      <div class="qty-stepper">
        <button type="button" onclick="event.preventDefault();event.stopPropagation();adjustQtyButton(this,-1)" aria-label="수량 줄이기">−</button>
        <input type="number" min="0" max="99" value="${Math.max(0, num(value))}" ${inputAttrs} readonly>
        <button type="button" onclick="event.preventDefault();event.stopPropagation();adjustQtyButton(this,1)" aria-label="수량 늘리기">+</button>
      </div>
    `;

    const nonpayProducts = () => state.products
      .filter((item) => productCategory(item.category) === "비급여")
      .slice()
      .sort(productDisplaySort("비급여"));

    const refillFor = (date, room) => (state.roomRefills || []).find((refill) =>
      (refill.date || "") === date && String(refill.room || "") === String(room || ""));

    const selectedDate = () => document.getElementById("roomCloseDate")?.value || today();

    const roomStatusHtml = (date) => {
      const rooms = Array.from({ length: CASE_ROOM_COUNT }, (_, i) => String(i + 1));
      return `
        <div class="room-close-status">
          ${rooms.map((room) => {
            const refill = refillFor(date, room);
            const total = (refill?.items || []).reduce((sum, item) => sum + Math.max(0, num(item.qty)), 0);
            return `
              <button type="button" class="room-close-room ${refill ? "done" : ""} ${selectedRoom === room ? "active" : ""}" data-room-close-room="${room}">
                <strong>${room}번방</strong>
                <span>${refill ? `마감 · ${total}개` : "미마감"}</span>
              </button>
            `;
          }).join("")}
        </div>
      `;
    };

    const refillItemsHtml = (date, room) => {
      const products = nonpayProducts();
      if (!products.length) return `<div class="empty">비급여 제품이 없습니다. 설정에서 제품을 등록해 주세요.</div>`;
      const existing = refillFor(date, room);
      const qtyById = new Map((existing?.items || []).map((item) => [String(item.productId), Math.max(0, num(item.qty))]));
      return `
        ${existing ? `<div class="helper">이미 마감된 방입니다 (${escapeHtml(auditUserText(existing) || "-")} · ${escapeHtml(formatDateTime(existing.updatedAt || existing.createdAt || ""))}). 수량을 고쳐 저장하면 덮어씁니다.</div>` : `<div class="helper">방 상자를 채운 수량만 입력하세요. 채운 수량이 그날 이 방의 사용량으로 기록되고 재고에서 차감됩니다.</div>`}
        <div class="room-close-items">
          ${products.map((product) => `
            <label class="check-card use-card room-close-item">
              <span>${escapeHtml(product.name)}<br><span class="muted">${escapeHtml(product.company || "")}${product.subcategory ? ` · ${escapeHtml(product.subcategory)}` : ""} · 현재고 ${num(product.stock)}</span></span>
              ${zeroStepper(`data-room-close-qty="${product.id}" aria-label="${escapeHtml(product.name)} 보충 수량"`, qtyById.get(String(product.id)) || 0)}
            </label>
          `).join("")}
        </div>
        <div class="actions">
          <button type="button" id="saveRoomClose">${existing ? "마감 수정 저장" : "방 마감 저장"}</button>
        </div>
      `;
    };

    const renderRoomClose = () => `
      <section class="grid">
        <div class="card">
          <h2>방 마감 (비급여 보충 입력)</h2>
          <p class="helper">마감 정리하며 방 상자를 채운 비급여 수량을 입력합니다. 채운 수량 = 그 방의 오늘 사용량입니다.</p>
          <div class="row two">
            <div>
              <label for="roomCloseDate">마감 날짜</label>
              <input id="roomCloseDate" type="date" value="${today()}">
            </div>
          </div>
          <div id="roomCloseStatus">${roomStatusHtml(today())}</div>
          <div id="roomCloseItems">${selectedRoom ? refillItemsHtml(today(), selectedRoom) : `<div class="empty">마감할 방을 선택해 주세요.</div>`}</div>
        </div>
      </section>
    `;

    const bindRoomClose = () => {
      const dateInput = document.getElementById("roomCloseDate");
      const statusWrap = document.getElementById("roomCloseStatus");
      const itemsWrap = document.getElementById("roomCloseItems");
      if (!dateInput || !statusWrap || !itemsWrap) return;
      const refresh = () => {
        statusWrap.innerHTML = roomStatusHtml(selectedDate());
        itemsWrap.innerHTML = selectedRoom
          ? refillItemsHtml(selectedDate(), selectedRoom)
          : `<div class="empty">마감할 방을 선택해 주세요.</div>`;
        bindControls();
      };
      const collectItems = () => Array.from(itemsWrap.querySelectorAll("[data-room-close-qty]"))
        .map((input) => ({ productId: input.dataset.roomCloseQty, qty: Math.max(0, num(input.value)) }))
        .filter((item) => item.qty > 0);
      const saveRoomClose = async () => {
        const date = selectedDate();
        if (!selectedRoom) return;
        const items = collectItems();
        if (!items.length && !refillFor(date, selectedRoom)) {
          alert("채운 수량이 없습니다. 보충한 제품의 수량을 입력해 주세요.");
          return;
        }
        const button = document.getElementById("saveRoomClose");
        setButtonBusy(button, true, "저장 중...");
        const existing = refillFor(date, selectedRoom);
        const record = {
          id: existing?.id || uid(),
          date,
          room: selectedRoom,
          items,
          createdAt: existing?.createdAt || new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          ...(existing ? auditUpdateFields() : auditCreateFields())
        };
        state.roomRefills = [
          ...(state.roomRefills || []).filter((refill) => !sameId(refill.id, record.id)),
          record
        ];
        render();
        await saveState(`${selectedRoom}번방 마감 저장 완료`, {
          savingMessage: "방 마감 저장 중입니다...",
          doneMessage: `${selectedRoom}번방 마감 저장 완료`
        });
      };
      const bindControls = () => {
        statusWrap.querySelectorAll("[data-room-close-room]").forEach((button) => {
          button.addEventListener("click", () => {
            selectedRoom = button.dataset.roomCloseRoom;
            refresh();
          });
        });
        document.getElementById("saveRoomClose")?.addEventListener("click", saveRoomClose);
      };
      dateInput.addEventListener("change", refresh);
      bindControls();
    };

    return {
      renderRoomClose,
      bindRoomClose
    };
  };
})();
