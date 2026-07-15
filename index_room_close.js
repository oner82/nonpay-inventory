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
      downloadExcel,
      setRoomCloseDirty,
      CASE_ROOM_COUNT
    } = context;

    // 방 마감 원리: 방 상자는 항상 정수(par)로 채우므로, 채운 수량 = 그날 그 방의 사용량.
    // 저장된 items가 재고 집계(productMovementCounts)에서 사용량으로 차감된다.
    let selectedRoom = "";
    // 사용자가 고른 마감 날짜. 렌더마다 today()로 리셋되면 과거 날짜 연속 마감(백필) 시
    // 두 번째 방부터 조용히 오늘 날짜로 저장되므로, 선택값을 모듈 변수로 보존한다.
    let closeDate = "";
    const effectiveDate = () => closeDate || today();
    // 제품별 입력 방식: 기본은 채운 수량(=사용량) 직접 입력.
    // remainIds에 든 제품만 남은 개수 입력(사용량 = 기본수량 − 남은 개수)으로 전환된다.
    // 보관소 부족으로 특정 제품만 못 채운 날, 그 제품의 사용량이 누락되지 않게 하기 위한 장치.
    let remainIds = new Set();
    // 기본수량 미설정(구버전 등록) 품목은 운영 기준값 10개로 계산한다.
    const parFor = (product) => num(product?.roomParQty) || 10;

    // 0부터 시작하는 수량 스테퍼 (기본 qtyStepper는 최소 1이라 별도 정의)
    // 최대값은 방 기본 수량(par) — 하루 보충량이 기본 수량을 넘을 수 없다.
    const zeroStepper = (inputAttrs, value, max = 99) => `
      <div class="qty-stepper">
        <button type="button" onclick="event.preventDefault();event.stopPropagation();adjustQtyButton(this,-1)" aria-label="수량 줄이기">−</button>
        <input type="number" min="0" max="${Math.max(1, num(max))}" value="${Math.max(0, num(value))}" ${inputAttrs} readonly>
        <button type="button" onclick="event.preventDefault();event.stopPropagation();adjustQtyButton(this,1)" aria-label="수량 늘리기">+</button>
      </div>
    `;

    const nonpayProducts = () => state.products
      .filter((item) => productCategory(item.category) === "비급여")
      .slice()
      .sort(productDisplaySort("비급여"));

    // 방 상자에는 비급여 일부 품목만 들어간다 — 기본은 '방 배치 품목'만 표시.
    let showAllNonpay = false;
    const roomBoxProducts = () => {
      const all = nonpayProducts();
      const stocked = all.filter((item) => item.roomStocked);
      // 방 배치 품목이 아직 지정되지 않았으면 전체를 보여준다(설정 안내 겸용).
      if (!stocked.length) return { products: all, usingAll: true, hasStockedConfig: false };
      return showAllNonpay
        ? { products: all, usingAll: true, hasStockedConfig: true }
        : { products: stocked, usingAll: false, hasStockedConfig: true };
    };

    const refillFor = (date, room) => (state.roomRefills || []).find((refill) =>
      (refill.date || "") === date && String(refill.room || "") === String(room || ""));

    const selectedDate = () => document.getElementById("roomCloseDate")?.value || effectiveDate();

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
      const { products, usingAll, hasStockedConfig } = roomBoxProducts();
      if (!products.length) return `<div class="empty">비급여 제품이 없습니다. 설정에서 제품을 등록해 주세요.</div>`;
      const existing = refillFor(date, room);
      const qtyById = new Map((existing?.items || []).map((item) => [String(item.productId), Math.max(0, num(item.qty))]));
      // 기존 마감에 들어있는 품목은 필터와 무관하게 항상 표시한다(수정 저장 시 소실 방지).
      const visibleIds = new Set(products.map((item) => String(item.id)));
      const extraFromExisting = nonpayProducts().filter((item) =>
        qtyById.has(String(item.id)) && !visibleIds.has(String(item.id)));
      const listProducts = [...products, ...extraFromExisting];
      const dateWarning = date !== today()
        ? `<div class="helper" style="color:#c2410c;font-weight:900;">⚠️ 오늘(${escapeHtml(today())})이 아닌 ${escapeHtml(date)} 날짜로 저장됩니다. 날짜를 확인해 주세요.</div>`
        : "";
      const scopeNote = hasStockedConfig
        ? `<label class="toggle-line" style="margin-top:8px;"><input id="roomCloseShowAll" type="checkbox" ${showAllNonpay ? "checked" : ""}> 전체 비급여 품목 보기</label>`
        : `<div class="helper">설정 > 제품관리에서 비급여 제품에 "방 배치 품목"을 체크하면 이 목록이 방 상자 품목만으로 줄어듭니다.</div>`;
      // 남은 개수 모드 스테퍼 초기값: 기존 기록이 있으면 남은 개수(기본수량 − 사용량), 없으면 가득(par) = 사용량 0.
      const stepperValue = (product) => {
        const savedQty = qtyById.get(String(product.id)) || 0;
        if (remainIds.has(String(product.id))) return Math.min(parFor(product), Math.max(0, parFor(product) - savedQty));
        return savedQty;
      };
      const stepperMax = (product) => remainIds.has(String(product.id)) ? parFor(product) : (num(product.roomParQty) || 99);
      const itemRow = (product) => {
        const isRemain = remainIds.has(String(product.id));
        return `
          <label class="check-card use-card room-close-item">
            <span>${escapeHtml(product.name)}<br><span class="muted">${escapeHtml(product.company || "")}${product.subcategory ? ` · ${escapeHtml(product.subcategory)}` : ""}${num(product.roomParQty) ? ` · 기본 ${num(product.roomParQty)}개` : ""} · 총재고 ${num(product.stock)}</span>
            ${isRemain ? `<br><span style="color:#c2410c;font-weight:700;">남은 개수 입력 중 · 사용량 = 기본수량 − 남은 개수</span>` : ""}
            <br><button type="button" class="secondary" data-room-close-remain="${product.id}" style="margin-top:4px;padding:2px 10px;font-size:12px;">${isRemain ? "채운 수량으로 되돌리기" : "남은 개수로 입력"}</button></span>
            ${zeroStepper(`data-room-close-qty="${product.id}" aria-label="${escapeHtml(product.name)} ${isRemain ? "남은 수량" : "보충 수량"}"`, stepperValue(product), stepperMax(product))}
          </label>
        `;
      };
      return `
        ${dateWarning}
        ${existing ? `<div class="helper">이미 마감된 방입니다 (${escapeHtml(auditUserText(existing) || "-")} · ${escapeHtml(formatDateTime(existing.updatedAt || existing.createdAt || ""))}). 수량을 고쳐 저장하면 덮어씁니다.</div>` : ""}
        <div class="helper">방 상자를 채운 수량만 입력하세요. 채운 수량이 그날 이 방의 사용량으로 기록되고 재고에서 차감됩니다. 보관소가 부족해 못 채운 제품만 <strong>남은 개수로 입력</strong>을 눌러 상자에 남은 개수를 적으면 사용량이 자동 계산됩니다.</div>
        ${scopeNote}
        <div class="room-close-items">
          ${listProducts.map(itemRow).join("")}
        </div>
        <div class="actions">
          <button type="button" id="saveRoomClose">${existing ? "마감 수정 저장" : "방 마감 저장"}</button>
        </div>
      `;
    };

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
          <h2>방 마감 (비급여 보충 입력)</h2>
          <p class="helper">마감 정리하며 방 상자를 채운 비급여 수량을 입력합니다. 채운 수량 = 그 방의 오늘 사용량입니다.</p>
          <div class="row two">
            <div>
              <label for="roomCloseDate">마감 날짜</label>
              <input id="roomCloseDate" type="date" value="${effectiveDate()}">
            </div>
          </div>
          <div id="roomCloseStatus">${roomStatusHtml(effectiveDate())}</div>
          <div id="roomCloseItems">${selectedRoom ? refillItemsHtml(effectiveDate(), selectedRoom) : `<div class="empty">마감할 방을 선택해 주세요.</div>`}</div>
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
      const dateInput = document.getElementById("roomCloseDate");
      const statusWrap = document.getElementById("roomCloseStatus");
      const itemsWrap = document.getElementById("roomCloseItems");
      if (!dateInput || !statusWrap || !itemsWrap) return;
      // 전체 렌더 직후에는 화면이 저장된 상태와 일치하므로 보호를 해제한다.
      setRoomCloseDirty?.(false);
      const refresh = () => {
        // 화면을 저장된 상태 기준으로 다시 그리므로 입력 중 보호를 해제한다.
        setRoomCloseDirty?.(false);
        statusWrap.innerHTML = roomStatusHtml(selectedDate());
        itemsWrap.innerHTML = selectedRoom
          ? refillItemsHtml(selectedDate(), selectedRoom)
          : `<div class="empty">마감할 방을 선택해 주세요.</div>`;
        bindControls();
      };
      // 스테퍼(+/−)로 수량을 만지는 순간부터 원격 onSnapshot 재렌더로부터 입력을 보호한다.
      itemsWrap.addEventListener("input", (event) => {
        if (event.target.matches?.("[data-room-close-qty]")) setRoomCloseDirty?.(true);
      });
      const collectItems = () => Array.from(itemsWrap.querySelectorAll("[data-room-close-qty]"))
        .map((input) => {
          const productId = input.dataset.roomCloseQty;
          const value = Math.max(0, num(input.value));
          // 남은 개수 모드 제품: 입력값은 남은 개수 → 사용량 = 기본수량 − 남은 개수.
          const qty = remainIds.has(String(productId))
            ? Math.max(0, parFor(productById(productId)) - value)
            : value;
          return { productId, qty };
        })
        .filter((item) => item.qty > 0);
      const saveRoomClose = async () => {
        const date = selectedDate();
        if (!selectedRoom) return;
        if (date !== today() && !confirm(`오늘이 아닌 ${date} 날짜로 마감을 저장합니다. 계속할까요?`)) return;
        const items = collectItems();
        if (!items.length && !refillFor(date, selectedRoom)) {
          alert("채운 수량이 없습니다. 보충한 제품의 수량을 입력해 주세요.");
          return;
        }
        const remainItems = items.filter((item) => remainIds.has(String(item.productId)));
        if (remainItems.length) {
          const summary = remainItems.map((item) => `${productById(item.productId)?.name || "삭제된 제품"} ${item.qty}개`).join(", ");
          if (!confirm(`남은 개수 기준으로 계산된 사용량입니다:\n${summary}\n이대로 저장할까요?`)) return;
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
        setRoomCloseDirty?.(false);
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
            remainIds = new Set();
            refresh();
          });
        });
        document.getElementById("saveRoomClose")?.addEventListener("click", saveRoomClose);
        document.getElementById("roomCloseShowAll")?.addEventListener("change", (event) => {
          showAllNonpay = Boolean(event.target.checked);
          refresh();
        });
        itemsWrap.querySelectorAll("[data-room-close-remain]").forEach((button) => {
          button.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            const id = String(button.dataset.roomCloseRemain);
            // 전환한 제품 외에는 입력 중이던 수량을 보존한다.
            const keep = new Map(Array.from(itemsWrap.querySelectorAll("[data-room-close-qty]"))
              .map((input) => [String(input.dataset.roomCloseQty), Math.max(0, num(input.value))]));
            if (remainIds.has(id)) remainIds.delete(id); else remainIds.add(id);
            refresh();
            itemsWrap.querySelectorAll("[data-room-close-qty]").forEach((input) => {
              const pid = String(input.dataset.roomCloseQty);
              if (pid !== id && keep.has(pid)) {
                input.value = Math.min(keep.get(pid), num(input.max) || 99);
              }
            });
            // 입력 중이던 수량을 복원했으므로 다시 보호 상태로 표시한다.
            setRoomCloseDirty?.(true);
          });
        });
      };
      dateInput.addEventListener("change", () => {
        closeDate = dateInput.value || "";
        remainIds = new Set();
        refresh();
      });
      bindControls();
      // 방 마감 이력 조회/엑셀
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
