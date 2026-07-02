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
      productDisplaySort,
      escapeHtml,
      num,
      renderLandingBoard,
      receiptHistoryFiltersHtml,
      renderReceiptHistory,
      renderReceiptHistoryList,
      receiptProduct,
      receiptProductName,
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

const landingCarryoverProducts = () => state.products
  .filter((item) => productCategory(item.category) !== "비급여")
  .slice()
  .sort((a, b) => productDisplaySort(productCategory(a.category))(a, b) || byName(a, b));

const renderReceipts = () => {
  const canEnterReceipts = canRegisterNonpayReceipts();
  const canEnterLanding = canManageLandingReceipts();
  const canViewReceiptHistory = canManageReceipts();
  const allowedReceiptViews = [
    ...(canEnterReceipts ? ["nonpay"] : []),
    ...(canEnterLanding ? ["landing"] : []),
    ...(canViewReceiptHistory ? ["history"] : [])
  ];
  const activeReceiptView = context.getCurrentReceiptView();
  const receiptView = allowedReceiptViews.includes(activeReceiptView) ? activeReceiptView : allowedReceiptViews[0];
  return `
  <section class="grid">
    <div class="receipt-tabs">
      ${canEnterReceipts ? `<button class="receipt-tab ${receiptView === "nonpay" ? "active" : ""}" data-receipt-view="nonpay" type="button">비급여 입고관리</button>` : ""}
      ${canEnterLanding ? `<button class="receipt-tab ${receiptView === "landing" ? "active" : ""}" data-receipt-view="landing" type="button">랜딩 입고관리</button>` : ""}
      ${canViewReceiptHistory ? `<button class="receipt-tab ${receiptView === "history" ? "active" : ""}" data-receipt-view="history" type="button">입고내역</button>` : ""}
    </div>
    ${receiptView === "nonpay" ? `
      <form class="card receipt-wide" id="nonpayReceiptForm">
        <h2>비급여 입고 등록</h2>
        ${currentUserRole() === "receiver" ? `<p class="receipt-safety-note">입고담당자 권한입니다. 비급여 입고 수량만 저장할 수 있고, 랜딩 입고·입고내역 수정·삭제는 책임사용자 이상에게 요청해 주세요.</p>` : ""}
        <label for="nonpayReceiptProduct">제품 선택</label>
        <select id="nonpayReceiptProduct" required>
          <option value="">비급여 제품을 선택하세요</option>
          ${state.products.filter((item) => productCategory(item.category) === "비급여").sort(productDisplaySort("비급여")).map((item) => `<option value="${item.id}">${escapeHtml(item.name)} / 현재고 ${num(item.stock)}</option>`).join("")}
        </select>
        <label for="nonpayReceiptQty">입고 수량</label>
        <input id="nonpayReceiptQty" type="number" min="1" value="1" required>
        <label for="nonpayReceiptMemo">메모</label>
        <textarea id="nonpayReceiptMemo" class="memo-input" placeholder="메모 입력(선택)"></textarea>
        <div class="actions"><button type="submit">비급여 입고 저장</button></div>
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
        ${receiptHistoryFiltersHtml("receiptTabHistory")}
        <div id="receiptTabHistoryList">${renderReceiptHistory()}</div>
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
    list.innerHTML = renderReceiptHistoryList(startInput.value, endInput.value, searchInput.value);
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
    button.addEventListener("click", () => exportReceiptHistory(startInput.value, endInput.value, searchInput.value));
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
  app.querySelectorAll("[data-receipt-view]").forEach((button) => {
    button.addEventListener("click", () => {
      context.setCurrentReceiptView(button.dataset.receiptView);
      render();
    });
  });
  document.getElementById("nonpayReceiptForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!canRegisterNonpayReceipts()) {
      alert("비급여 입고 등록은 관리자, 책임사용자, 입고담당자만 가능합니다.");
      return;
    }
    const productId = document.getElementById("nonpayReceiptProduct").value;
    const qty = Math.max(1, num(document.getElementById("nonpayReceiptQty").value));
    const memo = document.getElementById("nonpayReceiptMemo")?.value.trim() || "";
    const product = productById(productId);
    if (!product) return;
    product.stock = num(product.stock) + qty;
    state.receipts.push({ id: uid(), type: "nonpay", productId, productName: product.name, qty, date: today(), memo, createdAt: new Date().toISOString(), ...auditCreateFields() });
    render();
    await saveState();
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
      await receiveLandingLine(usageId, productId);
      render();
      await saveState();
    });
  });
  app.querySelectorAll("[data-receive-company]").forEach((button) => {
    button.addEventListener("click", async () => {
      const company = button.dataset.receiveCompany;
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
