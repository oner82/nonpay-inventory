(() => {
  window.createReceiptsModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const app = context.getApp();
    const {
      canRegisterNonpayReceipts,
      canManageLandingReceipts,
      canManageReceipts,
      currentUserRole,
      productCategory,
      productCategoryLabel,
      productDisplaySort,
      escapeHtml,
      num,
      renderLandingBoard,
      receiptHistoryFiltersHtml,
      renderReceiptHistory,
      renderReceiptHistoryList,
      receiptProduct,
      receiptProductName,
      receiptDateValue,
      receiptStockDelta,
      captureLandingBoardOpenState,
      sameId,
      today,
      auditUpdateFields,
      auditCreateFields,
      reconcileProductStocks,
      render,
      saveState,
      normalizedName,
      byName,
      exportReceiptHistory,
      productById,
      uid,
      landingUsageLines
    } = context;
    let morningCheckDate = today();
    let receiptHistoryType = "nonpay";

const landingCarryoverProducts = () => state.products
  .filter((item) => productCategory(item.category) !== "비급여")
  .slice()
  .sort((a, b) => productDisplaySort(productCategory(a.category))(a, b) || byName(a, b));

const nonpayReceiptProducts = () => state.products
  .filter((item) => productCategory(item.category) === "비급여")
  .slice()
  .sort(productDisplaySort("비급여"));

const morningCheckProducts = () => state.products
  .filter((product) => product?.name)
  .slice()
  .sort((a, b) => productDisplaySort(productCategory(a.category))(a, b) || byName(a, b));

const productUsageCountBefore = (productId, date) => state.usages.reduce((sum, usage) => {
  if (!usage?.date || usage.date >= date) return sum;
  return sum + (usage.productIds || []).filter((id) => sameId(id, productId)).length;
}, 0);

const productReceiptDeltaBefore = (productId, date) => state.receipts.reduce((sum, receipt) => {
  if (!sameId(receipt.productId, productId)) return sum;
  const receiptDate = receiptDateValue(receipt);
  if (!receiptDate || receiptDate >= date) return sum;
  return sum + receiptStockDelta(receipt);
}, 0);

const productReceiptDeltaAll = (productId) => state.receipts.reduce((sum, receipt) => (
  sameId(receipt.productId, productId) ? sum + receiptStockDelta(receipt) : sum
), 0);

const productUsageCountAll = (productId) => state.usages.reduce((sum, usage) => (
  sum + (usage.productIds || []).filter((id) => sameId(id, productId)).length
), 0);

const productBaseStockForCheck = (product) => Number.isFinite(Number(product.baseStock))
  ? num(product.baseStock)
  : num(product.stock) - productReceiptDeltaAll(product.id) + productUsageCountAll(product.id);

const morningExpectedStock = (product, date) => Math.max(
  0,
  productBaseStockForCheck(product) + productReceiptDeltaBefore(product.id, date) - productUsageCountBefore(product.id, date)
);

const morningCheckStatus = (product, stock) => {
  const warning = num(product.warningStock);
  if (stock <= 0) return { className: "danger", label: "0 이하" };
  if (warning > 0 && stock <= warning) return { className: "warn", label: "경고 이하" };
  return { className: "ok", label: "정상" };
};

const morningStockCheckHtml = () => {
  const products = morningCheckProducts();
  const checkDate = morningCheckDate || today();
  const categories = [...new Set(products.map((product) => productCategory(product.category)))].filter(Boolean);
  const stockRows = products.map((product) => {
    const expectedStock = morningExpectedStock(product, checkDate);
    return { product, expectedStock, status: morningCheckStatus(product, expectedStock) };
  });
  const attention = stockRows.filter((row) => row.status.className !== "ok").length;
  const zero = stockRows.filter((row) => row.expectedStock <= 0).length;
  const low = stockRows.filter((row) => row.expectedStock > 0 && row.status.className === "warn").length;
  const groupedRows = categories.map((category) => {
    const rows = stockRows.filter((row) => productCategory(row.product.category) === category);
    return {
      category,
      rows,
      attention: rows.filter((row) => row.status.className !== "ok").length
    };
  });
  return `
    <div class="morning-check-panel" id="receiptMorningCheckPanel">
      <div class="morning-check-summary">
        <div class="morning-check-metric">
          <strong>${products.length}</strong>
          <span>전체 품목</span>
        </div>
        <div class="morning-check-metric ${attention ? "warn" : "ok"}">
          <strong>${attention}</strong>
          <span>확인 필요</span>
        </div>
        <div class="morning-check-metric danger">
          <strong>${zero}</strong>
          <span>0 이하</span>
        </div>
        <div class="morning-check-metric warn">
          <strong>${low}</strong>
          <span>경고 이하</span>
        </div>
      </div>
      <div class="row three morning-check-controls">
        <div>
          <label for="receiptMorningDate">점검 기준일</label>
          <input id="receiptMorningDate" type="date" value="${escapeHtml(checkDate)}">
        </div>
        <div>
          <label for="receiptMorningSearch">제품 검색</label>
          <input id="receiptMorningSearch" autocomplete="off" placeholder="제품명, 업체, 분류">
        </div>
        <div>
          <label for="receiptMorningCategory">분류</label>
          <select id="receiptMorningCategory">
            <option value="">전체 분류</option>
            ${categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(productCategoryLabel(category))}</option>`).join("")}
          </select>
        </div>
      </div>
      <p class="helper">선택한 날짜의 아침 시작 기준 프로그램 재고입니다. 당일 사용·입고는 제외하고 전날까지의 기록으로 계산합니다. 이 화면은 확인용이며 재고 수량을 저장하지 않습니다.</p>
      <div class="morning-check-list" id="receiptMorningCheckList">
        ${groupedRows.map(({ category, rows, attention: groupAttention }) => `
          <details class="morning-check-group" data-morning-group open>
            <summary>
              <span>${escapeHtml(productCategoryLabel(category))}</span>
              <span class="pill ${groupAttention ? "low" : ""}">${rows.length}품목${groupAttention ? ` · 확인 ${groupAttention}` : ""}</span>
            </summary>
            <div class="morning-check-group-body">
              ${rows.map(({ product, expectedStock, status }) => {
        const searchText = normalizedName([
          product.name,
          productCategoryLabel(product.category),
          product.company,
          product.subcategory
        ].filter(Boolean).join(" "));
        return `
                <div class="morning-check-row ${status.className}" data-morning-row data-category="${escapeHtml(productCategory(product.category))}" data-search="${escapeHtml(searchText)}">
                  <div>
                    <div class="morning-check-title">
                      <span>${escapeHtml(product.name)}</span>
                      <span class="pill ${status.className === "danger" || status.className === "warn" ? "low" : ""}">${escapeHtml(status.label)}</span>
                    </div>
                    <div class="morning-check-meta">
                      <span>${escapeHtml(productCategoryLabel(product.category))}</span>
                      ${product.company ? `<span>${escapeHtml(product.company)}</span>` : ""}
                      ${product.subcategory ? `<span>${escapeHtml(product.subcategory)}</span>` : ""}
                      <span>경고 ${num(product.warningStock)}</span>
                    </div>
                  </div>
                  <div class="morning-check-stock">
                    <span>프로그램</span>
                    <strong>${expectedStock}</strong>
                  </div>
                  <label class="morning-check-actual">
                    <span>실사</span>
                    <input type="number" inputmode="numeric" min="0" step="1" data-morning-actual data-stock="${expectedStock}" aria-label="${escapeHtml(product.name)} 실사 수량">
                  </label>
                  <div class="morning-check-diff" data-morning-diff>미확인</div>
                </div>
              `;
      }).join("")}
            </div>
          </details>
        `).join("")}
      </div>
    </div>
  `;
};

const renderReceipts = () => {
  const canEnterReceipts = canRegisterNonpayReceipts();
  const canEnterLanding = canManageLandingReceipts();
  const canViewReceiptHistory = canManageReceipts();
  const canCheckMorningStock = canEnterReceipts || canEnterLanding || canViewReceiptHistory;
  const allowedReceiptViews = [
    ...(canEnterReceipts ? ["nonpay"] : []),
    ...(canCheckMorningStock ? ["morning"] : []),
    ...(canEnterLanding ? ["landing"] : []),
    ...(canViewReceiptHistory ? ["history"] : []),
    ...(canEnterReceipts ? ["loan"] : [])
  ];
  const activeReceiptView = context.getCurrentReceiptView();
  const receiptView = allowedReceiptViews.includes(activeReceiptView) ? activeReceiptView : allowedReceiptViews[0];
  return `
  <section class="grid">
    <div class="receipt-tabs">
      ${canEnterReceipts ? `<button class="receipt-tab ${receiptView === "nonpay" ? "active" : ""}" data-receipt-view="nonpay" type="button">비급여 입고관리</button>` : ""}
      ${canCheckMorningStock ? `<button class="receipt-tab ${receiptView === "morning" ? "active" : ""}" data-receipt-view="morning" type="button">아침 점검</button>` : ""}
      ${canEnterLanding ? `<button class="receipt-tab ${receiptView === "landing" ? "active" : ""}" data-receipt-view="landing" type="button">랜딩 입고관리</button>` : ""}
      ${canViewReceiptHistory ? `<button class="receipt-tab ${receiptView === "history" ? "active" : ""}" data-receipt-view="history" type="button">입고내역</button>` : ""}
      ${canEnterReceipts ? `<button class="receipt-tab ${receiptView === "loan" ? "active" : ""}" data-receipt-view="loan" type="button">타부서 대여</button>` : ""}
    </div>
    ${receiptView === "nonpay" ? `
      <form class="card receipt-wide" id="nonpayReceiptForm">
        <h2>비급여 입고 등록</h2>
        ${currentUserRole() === "receiver" ? `<p class="receipt-safety-note">입고담당자 권한입니다. 비급여 입고 수량만 저장할 수 있고, 랜딩 입고·입고내역 수정·삭제는 책임사용자 이상에게 요청해 주세요.</p>` : ""}
        <label for="nonpayReceiptProduct">제품 선택</label>
        <select id="nonpayReceiptProduct" required>
          <option value="">비급여 제품을 선택하세요</option>
          ${nonpayReceiptProducts().map((item) => `<option value="${item.id}">${escapeHtml(item.name)} / 현재고 ${num(item.stock)}</option>`).join("")}
        </select>
        <label for="nonpayReceiptDate">입고일</label>
        <input id="nonpayReceiptDate" type="date" value="${today()}" required>
        <label for="nonpayReceiptQty">입고 수량</label>
        <input id="nonpayReceiptQty" type="number" min="1" value="1" required>
        <label for="nonpayReceiptMemo">메모</label>
        <textarea id="nonpayReceiptMemo" class="memo-input" placeholder="메모 입력(선택)"></textarea>
        <div class="actions"><button type="submit">비급여 입고 저장</button></div>
      </form>
    ` : ""}
    ${receiptView === "morning" ? `
      <div class="card receipt-wide">
        <h2>아침 재고 점검</h2>
        ${morningStockCheckHtml()}
      </div>
    ` : ""}
    ${receiptView === "loan" ? `
      <form class="card receipt-wide" id="departmentLoanForm">
        <h2>타부서 대여 등록</h2>
        <p class="helper">응급실·병동 등에 비급여 제품을 빌려준 경우 사용합니다. 저장하면 현재고에서 차감되고, 다음날 대시보드에 전날 대여 수량으로 표시됩니다.</p>
        <label for="loanProduct">제품 선택</label>
        <select id="loanProduct" required>
          <option value="">비급여 제품을 선택하세요</option>
          ${nonpayReceiptProducts().map((item) => `<option value="${item.id}">${escapeHtml(item.name)} / 현재고 ${num(item.stock)}</option>`).join("")}
        </select>
        <div class="row two">
          <div>
            <label for="loanQty">대여 수량</label>
            <input id="loanQty" type="number" min="1" value="1" required>
          </div>
          <div>
            <label for="loanDate">대여일</label>
            <input id="loanDate" type="date" value="${today()}" required>
          </div>
        </div>
        <label for="loanDepartment">대여 부서</label>
        <input id="loanDepartment" placeholder="예: 응급실, 병동, 외래">
        <label for="loanMemo">메모</label>
        <textarea id="loanMemo" class="memo-input" placeholder="예: 응급 처방 예정, 병동 요청자명 등"></textarea>
        <div class="actions"><button type="submit">대여 저장</button></div>
      </form>
    ` : ""}
    ${receiptView === "landing" ? `
      <form class="card receipt-wide" id="landingCarryoverReceiptForm">
        <h2>이월 랜딩 입고 등록</h2>
        <p class="helper">프로그램 사용 시작 전 이미 사용했지만 아직 받지 못했던 랜딩 제품을 받았을 때 사용합니다. 환자 사용내역과 연결하지 않고 현재고와 입고내역에만 반영됩니다.</p>
        <label for="landingCarryoverProduct">제품 선택</label>
        <select id="landingCarryoverProduct" required>
          <option value="">랜딩 제품을 선택하세요</option>
          ${landingCarryoverProducts().map((item) => `<option value="${item.id}">${escapeHtml(item.name)}${item.company ? ` / ${escapeHtml(item.company)}` : ""}${item.subcategory ? ` / ${escapeHtml(item.subcategory)}` : ""} / 현재고 ${num(item.stock)}</option>`).join("")}
        </select>
        <label for="landingCarryoverQty">입고 수량</label>
        <input id="landingCarryoverQty" type="number" min="1" value="1" required>
        <label for="landingCarryoverMemo">메모</label>
        <textarea id="landingCarryoverMemo" class="memo-input" placeholder="예: 프로그램 시작 전 사용분 보충"></textarea>
        <div class="actions"><button type="submit">이월 랜딩 입고 저장</button></div>
      </form>
      <div class="card receipt-wide">
        <h2>랜딩 입고 확인</h2>
        ${renderLandingBoard()}
      </div>
    ` : ""}
    ${receiptView === "history" ? `
      <div class="card receipt-wide">
        <h2>입고내역</h2>
        <div class="receipt-history-tabs">
          <button class="receipt-history-tab ${receiptHistoryType === "nonpay" ? "active" : ""}" type="button" data-receipt-history-type="nonpay">비급여</button>
          <button class="receipt-history-tab ${receiptHistoryType === "landing" ? "active" : ""}" type="button" data-receipt-history-type="landing">랜딩</button>
          <button class="receipt-history-tab ${receiptHistoryType === "loan" ? "active" : ""}" type="button" data-receipt-history-type="loan">타부서 대여</button>
        </div>
        ${receiptHistoryFiltersHtml("receiptTabHistory")}
        <div id="receiptTabHistoryList">${renderReceiptHistoryList("", "", "", receiptHistoryType)}</div>
      </div>
    ` : ""}
  </section>
`;
};

const setReceiptQuickRange = (prefix, days) => {
  const end = new Date();
  const start = new Date();
  start.setDate(end.getDate() - (Number(days) - 1));
  const toInputDate = (date) => {
    const next = new Date(date);
    next.setMinutes(next.getMinutes() - next.getTimezoneOffset());
    return next.toISOString().slice(0, 10);
  };
  document.getElementById(`${prefix}Start`).value = toInputDate(start);
  document.getElementById(`${prefix}End`).value = toInputDate(end);
};

const updateReceiptRecord = async (receiptId, values) => {
  if (!canManageReceipts()) {
    alert("입고이력 수정은 관리자와 책임사용자만 가능합니다.");
    return false;
  }
  const receipt = state.receipts.find((item) => sameId(item.id, receiptId));
  if (!receipt) return false;
  const product = receiptProduct(receipt);
  Object.assign(receipt, {
    qty: Math.max(1, num(values.qty)),
    date: values.date || receiptDateValue(receipt) || today(),
    productName: product?.name || receipt.productName || "",
    memo: values.memo || "",
    updatedAt: new Date().toISOString(),
    ...auditUpdateFields()
  });
  reconcileProductStocks();
  render();
  await saveState("입고이력 수정 완료", { authoritative: true });
  return true;
};

const deleteReceiptRecord = async (receiptId) => {
  if (!canManageReceipts()) {
    alert("입고이력 삭제는 관리자와 책임사용자만 가능합니다.");
    return false;
  }
  const receipt = state.receipts.find((item) => sameId(item.id, receiptId));
  if (!receipt || !confirm("입고이력을 삭제하고 현재고를 다시 계산할까요?")) return false;
  state.receipts = state.receipts.filter((item) => !sameId(item.id, receiptId));
  reconcileProductStocks();
  render();
  await saveState("입고이력 삭제 완료", { authoritative: true });
  return true;
};

const bindReceiptHistoryControls = (prefix, listId) => {
  const startInput = document.getElementById(`${prefix}Start`);
  const endInput = document.getElementById(`${prefix}End`);
  const searchInput = document.getElementById(`${prefix}Search`);
  const productMenu = document.getElementById(`${prefix}ProductMenu`);
  const list = document.getElementById(listId);
  if (!startInput || !endInput || !searchInput || !list) return;
  const updateList = () => {
    list.innerHTML = renderReceiptHistoryList(startInput.value, endInput.value, searchInput.value, receiptHistoryType);
  };
  const closeProductMenu = () => {
    if (productMenu) productMenu.hidden = true;
  };
  const renderProductMenu = () => {
    if (!productMenu) return;
    const query = normalizedName(searchInput.value);
    const products = state.products
      .slice()
      .sort(byName)
      .filter((product) => !query || normalizedName(product.name).includes(query))
      .slice(0, 20);
    if (!products.length) {
      closeProductMenu();
      return;
    }
    productMenu.innerHTML = products.map((product) => `
      <button class="receipt-search-option" type="button" data-receipt-product-suggestion="${escapeHtml(product.name)}">
        ${escapeHtml(product.name)}
      </button>
    `).join("");
    productMenu.hidden = false;
  };
  [startInput, endInput, searchInput].forEach((input) => {
    input.addEventListener("input", updateList);
    input.addEventListener("change", updateList);
  });
  searchInput.addEventListener("focus", renderProductMenu);
  searchInput.addEventListener("input", renderProductMenu);
  searchInput.addEventListener("blur", () => setTimeout(closeProductMenu, 120));
  productMenu?.addEventListener("mousedown", (event) => event.preventDefault());
  productMenu?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-receipt-product-suggestion]");
    if (!button) return;
    searchInput.value = button.dataset.receiptProductSuggestion || "";
    closeProductMenu();
    updateList();
  });
  app.querySelectorAll(`[data-receipt-prefix="${prefix}"][data-receipt-quick]`).forEach((button) => {
    button.addEventListener("click", () => {
      setReceiptQuickRange(prefix, button.dataset.receiptQuick);
      updateList();
    });
  });
  app.querySelector(`[data-receipt-prefix="${prefix}"][data-receipt-reset]`)?.addEventListener("click", () => {
    startInput.value = "";
    endInput.value = "";
    searchInput.value = "";
    updateList();
  });
  app.querySelectorAll("[data-export-receipt-history]").forEach((button) => {
    button.addEventListener("click", () => exportReceiptHistory(startInput.value, endInput.value, searchInput.value, receiptHistoryType));
  });
  app.querySelectorAll("[data-receipt-history-type]").forEach((button) => {
    button.addEventListener("click", () => {
      receiptHistoryType = button.dataset.receiptHistoryType || "nonpay";
      app.querySelectorAll("[data-receipt-history-type]").forEach((item) => {
        item.classList.toggle("active", item.dataset.receiptHistoryType === receiptHistoryType);
      });
      updateList();
    });
  });
  list.addEventListener("click", async (event) => {
    const editButton = event.target.closest("[data-edit-receipt]");
    if (editButton) {
      list.querySelector(`[data-edit-receipt-form="${CSS.escape(editButton.dataset.editReceipt)}"]`)?.toggleAttribute("hidden");
      return;
    }
    const cancelButton = event.target.closest("[data-cancel-edit-receipt]");
    if (cancelButton) {
      list.querySelector(`[data-edit-receipt-form="${CSS.escape(cancelButton.dataset.cancelEditReceipt)}"]`)?.setAttribute("hidden", "");
      return;
    }
    const deleteButton = event.target.closest("[data-delete-receipt]");
    if (deleteButton) await deleteReceiptRecord(deleteButton.dataset.deleteReceipt);
  });
  list.addEventListener("submit", async (event) => {
    const form = event.target.closest("[data-edit-receipt-form]");
    if (!form) return;
    event.preventDefault();
    await updateReceiptRecord(form.dataset.editReceiptForm, {
      date: form.querySelector("[data-receipt-edit-date]")?.value || "",
      qty: form.querySelector("[data-receipt-edit-qty]")?.value || "1",
      memo: form.querySelector("[data-receipt-edit-memo]")?.value.trim() || ""
    });
  });
};

const bindReceipts = () => {
  const morningPanel = document.getElementById("receiptMorningCheckPanel");
  const updateMorningDiff = (input) => {
    const row = input.closest("[data-morning-row]");
    const diff = row?.querySelector("[data-morning-diff]");
    if (!row || !diff) return;
    const rawValue = String(input.value || "").trim();
    row.classList.remove("matched", "short", "over");
    if (!rawValue) {
      diff.textContent = "미확인";
      return;
    }
    const actual = num(rawValue);
    const stock = num(input.dataset.stock);
    const delta = actual - stock;
    if (delta === 0) {
      row.classList.add("matched");
      diff.textContent = "맞음";
      return;
    }
    row.classList.add(delta < 0 ? "short" : "over");
    diff.textContent = delta < 0 ? `${Math.abs(delta)} 부족` : `${delta} 초과`;
  };
  const filterMorningRows = () => {
    const search = normalizedName(document.getElementById("receiptMorningSearch")?.value || "");
    const category = document.getElementById("receiptMorningCategory")?.value || "";
    morningPanel?.querySelectorAll("[data-morning-row]").forEach((row) => {
      const matchesSearch = !search || String(row.dataset.search || "").includes(search);
      const matchesCategory = !category || row.dataset.category === category;
      row.hidden = !(matchesSearch && matchesCategory);
    });
    morningPanel?.querySelectorAll("[data-morning-group]").forEach((group) => {
      const hasVisibleRows = Array.from(group.querySelectorAll("[data-morning-row]")).some((row) => !row.hidden);
      group.hidden = !hasVisibleRows;
    });
  };
  app.querySelectorAll("[data-receipt-view]").forEach((button) => {
    button.addEventListener("click", () => {
      context.setCurrentReceiptView(button.dataset.receiptView);
      render();
    });
  });
  morningPanel?.addEventListener("input", (event) => {
    const actualInput = event.target.closest("[data-morning-actual]");
    if (actualInput) {
      updateMorningDiff(actualInput);
      return;
    }
    const dateInput = event.target.closest("#receiptMorningDate");
    if (dateInput) {
      morningCheckDate = dateInput.value || today();
      render();
      return;
    }
    if (event.target.closest("#receiptMorningSearch")) filterMorningRows();
  });
  morningPanel?.addEventListener("change", (event) => {
    if (event.target.closest("#receiptMorningCategory")) filterMorningRows();
  });
  document.getElementById("nonpayReceiptForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!canRegisterNonpayReceipts()) {
      alert("비급여 입고 등록은 관리자, 책임사용자, 입고담당자만 가능합니다.");
      return;
    }
    const productId = document.getElementById("nonpayReceiptProduct").value;
    const date = document.getElementById("nonpayReceiptDate")?.value || today();
    const qty = Math.max(1, num(document.getElementById("nonpayReceiptQty").value));
    const memo = document.getElementById("nonpayReceiptMemo")?.value.trim() || "";
    const product = productById(productId);
    if (!product) return;
    product.stock = num(product.stock) + qty;
    state.receipts.push({ id: uid(), type: "nonpay", productId, productName: product.name, qty, date, memo, createdAt: new Date().toISOString(), ...auditCreateFields() });
    render();
    await saveState();
  });
  document.getElementById("departmentLoanForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!canRegisterNonpayReceipts()) {
      alert("타부서 대여 등록은 관리자, 책임사용자, 입고담당자만 가능합니다.");
      return;
    }
    const productId = document.getElementById("loanProduct").value;
    const qty = Math.max(1, num(document.getElementById("loanQty").value));
    const date = document.getElementById("loanDate").value || today();
    const loanDepartment = document.getElementById("loanDepartment")?.value.trim() || "";
    const memo = document.getElementById("loanMemo")?.value.trim() || "";
    const product = productById(productId);
    if (!product) return;
    if (num(product.stock) < qty && !confirm(`현재고가 ${num(product.stock)}개입니다. 그래도 ${qty}개 대여로 저장할까요?`)) return;
    product.stock = Math.max(0, num(product.stock) - qty);
    state.receipts.push({
      id: uid(),
      type: "loan",
      productId,
      productName: product.name,
      qty,
      date,
      loanDepartment,
      memo,
      createdAt: new Date().toISOString(),
      ...auditCreateFields()
    });
    reconcileProductStocks();
    render();
    await saveState("타부서 대여 저장 완료", { authoritative: true });
  });
  document.getElementById("landingCarryoverReceiptForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!canManageLandingReceipts()) {
      alert("이월 랜딩 입고 등록은 관리자와 책임사용자만 가능합니다.");
      return;
    }
    const productId = document.getElementById("landingCarryoverProduct").value;
    const qty = Math.max(1, num(document.getElementById("landingCarryoverQty").value));
    const memo = document.getElementById("landingCarryoverMemo")?.value.trim() || "프로그램 시작 전 사용분 보충";
    const product = productById(productId);
    if (!product) return;
    product.stock = num(product.stock) + qty;
    state.receipts.push({
      id: uid(),
      type: "landingCarryover",
      productId,
      productName: product.name,
      qty,
      date: today(),
      memo,
      company: product.company || "",
      subcategory: product.subcategory || "",
      category: product.category || "",
      createdAt: new Date().toISOString(),
      ...auditCreateFields()
    });
    render();
    await saveState("이월 랜딩 입고 저장 완료");
  });
  const receiveLandingLine = async (usageId, productId) => {
    if (!canManageLandingReceipts()) {
      alert("랜딩 입고 확인은 관리자와 책임사용자만 가능합니다.");
      return;
    }
    const usage = state.usages.find((item) => item.id === usageId);
    const product = productById(productId);
    if (!usage || !product) return;
    const exists = state.receipts.some((item) => item.type === "landing" && item.usageId === usageId && item.productId === productId);
    if (exists) return;
    const line = landingUsageLines(true).find((item) => item.usage.id === usageId && item.product.id === productId);
    const qty = Math.max(1, num(line?.qty));
    product.stock = num(product.stock) + qty;
    state.receipts.push({
      id: uid(),
      type: "landing",
      usageId,
      productId,
      productName: product.name,
      qty,
      date: today(),
      usageDate: usage.date,
      patientName: usage.patientName,
      company: product.company || "",
      subcategory: product.subcategory || "",
      createdAt: new Date().toISOString(),
      ...auditCreateFields()
    });
  };
  app.querySelectorAll("[data-receive-landing]").forEach((button) => {
    button.addEventListener("click", async () => {
      const [usageId, productId] = button.dataset.receiveLanding.split("::");
      captureLandingBoardOpenState?.();
      await receiveLandingLine(usageId, productId);
      render();
      await saveState();
    });
  });
  app.querySelectorAll("[data-receive-company]").forEach((button) => {
    button.addEventListener("click", async () => {
      const company = button.dataset.receiveCompany;
      captureLandingBoardOpenState?.();
      const lines = landingUsageLines(false).filter((line) => (line.product.company || "업체 없음") === company);
      lines.forEach((line) => {
        const product = line.product;
        const qty = Math.max(1, num(line.qty));
        product.stock = num(product.stock) + qty;
        state.receipts.push({
          id: uid(),
          type: "landing",
          usageId: line.usage.id,
          productId: product.id,
          productName: product.name,
          qty,
          date: today(),
          usageDate: line.usage.date,
          patientName: line.usage.patientName,
          company: product.company || "",
          subcategory: product.subcategory || "",
          createdAt: new Date().toISOString(),
          ...auditCreateFields()
        });
      });
      render();
      await saveState();
    });
  });
  bindReceiptHistoryControls("receiptTabHistory", "receiptTabHistoryList");
};



    return {
      renderReceipts,
      bindReceipts
    };
  };
})();
