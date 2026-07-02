(() => {
  window.createProductsModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const implantVendors = () => context.getImplantVendors();
    const {
      canManageSettings,
      renderGroupedProducts,
      productCompanyOptions,
      implantVendorById,
      productById,
      productSortOrderValue,
      nextNonpaySortOrder,
      productMovementCounts,
      reconcileProductStocks,
      today,
      receiptDateValue,
      render,
      saveState,
      uid,
      num
    } = context;

const renderProducts = () => `
  ${canManageSettings() ? "" : `<div class="empty">관리자와 책임사용자만 제품관리를 사용할 수 있습니다.</div>`}
  ${canManageSettings() ? `
  <section class="grid two">
    <form class="card" id="productForm">
      <h2 id="productFormTitle">제품 추가</h2>
      <input type="hidden" id="productId">
      <label for="productCategory">분류</label>
      <select id="productCategory" required>
        <option>비급여</option>
        <option>인체조직</option>
        <option value="ANCHOR">ANCHOR&etc</option>
        <option value="URO_LANDING">URO 랜딩</option>
        <option value="GS_LANDING">GS 랜딩</option>
        <option value="IMPLANT">IMPLANT</option>
      </select>
      <label for="productName">제품명</label>
      <input id="productName" required autocomplete="off">
      <div id="productCompanyWrap">
        <label for="productCompany">업체명</label>
        <select id="productCompany">
          ${productCompanyOptions()}
        </select>
        <div class="helper" id="productCompanyHelp">비급여 외 제품은 설정의 임플란트 업체를 먼저 등록한 뒤 선택합니다.</div>
      </div>
      <div id="productSubcategoryWrap">
        <label for="productSubcategory">세부 분류</label>
        <select id="productSubcategory">
          <option value="">선택</option>
          <option>ANCHOR</option>
          <option>Cannula</option>
          <option>etc</option>
          <option>small joint</option>
        </select>
      </div>
      <div class="row two">
        <div>
          <label for="productStock">현재고(지금 기준)</label>
          <input id="productStock" type="number" min="0" value="0" required>
        </div>
        <div>
          <label for="productWarning">경고수량</label>
          <input id="productWarning" type="number" min="0" value="1" required>
        </div>
      </div>
      <div>
        <label for="productOpeningStockToday">오늘 시작 전 현재고</label>
        <input id="productOpeningStockToday" type="number" min="0" placeholder="오늘 이미 사용한 뒤 시작 전 재고를 맞출 때만 입력">
        <div class="helper">입력하면 오늘 사용/입고는 그대로 두고, 오늘 시작 시점 재고가 이 수량이 되도록 기준재고를 보정합니다.</div>
      </div>
      <div id="productLandingWrap">
        <label for="productLanding">랜딩수량</label>
        <input id="productLanding" type="number" min="0" value="0">
      </div>
      <div class="actions">
        <button type="submit">제품 저장</button>
        <button class="secondary" type="button" id="productReset">새로 입력</button>
      </div>
    </form>
    <div class="card">
      <h2>제품 목록</h2>
      ${renderGroupedProducts(true)}
    </div>
  </section>
` : ""}
`;


const bindProducts = () => {
  const form = document.getElementById("productForm");
  const syncProductFields = () => {
    const category = document.getElementById("productCategory").value;
    const companySelect = document.getElementById("productCompany");
    const companyHelp = document.getElementById("productCompanyHelp");
    document.getElementById("productCompanyWrap").style.display = category === "비급여" ? "none" : "block";
    document.getElementById("productSubcategoryWrap").style.display = category === "ANCHOR" ? "block" : "none";
    document.getElementById("productLandingWrap").style.display = category === "비급여" ? "none" : "block";
    if (category === "비급여") {
      companySelect.value = "";
      document.getElementById("productSubcategory").value = "";
      document.getElementById("productLanding").value = "0";
    }
    companySelect.required = category !== "비급여";
    companySelect.disabled = category !== "비급여" && !implantVendors().length;
    if (companyHelp) companyHelp.textContent = implantVendors().length
      ? "비급여 외 제품은 등록된 임플란트 업체 중에서 선택합니다."
      : "비급여 외 제품을 등록하려면 먼저 설정 > 임플란트 업체에서 업체를 등록해 주세요.";
  };
  context.setSyncProductFields(syncProductFields);
  document.getElementById("productCategory").addEventListener("change", syncProductFields);
  document.getElementById("productReset").addEventListener("click", () => {
    form.reset();
    document.getElementById("productId").value = "";
    document.getElementById("productFormTitle").textContent = "제품 추가";
    document.getElementById("productCompany").innerHTML = productCompanyOptions();
    syncProductFields();
  });
  const productMovementBeforeDate = (productId, date) => {
    const used = state.usages.reduce((sum, usage) => {
      if (!usage.date || usage.date >= date) return sum;
      return sum + (usage.productIds || []).filter((id) => String(id) === String(productId)).length;
    }, 0);
    const received = state.receipts.reduce((sum, receipt) => {
      const receiptDate = receiptDateValue(receipt);
      if (!receiptDate || receiptDate >= date || String(receipt.productId) !== String(productId)) return sum;
      return sum + num(receipt.qty);
    }, 0);
    return { used, received };
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById("productId").value || uid();
    const category = document.getElementById("productCategory").value;
    if (category !== "비급여" && !implantVendors().length) {
      alert("비급여 외 제품은 임플란트 업체를 먼저 등록해야 제품등록 할 수 있습니다.");
      return;
    }
    if (category !== "비급여" && !document.getElementById("productCompany").value.trim()) {
      alert("비급여 외 제품은 임플란트 업체를 선택해 주세요.");
      return;
    }
    const selectedCompanyValue = document.getElementById("productCompany").value.trim();
    const selectedCompanyVendor = category === "비급여" ? null : implantVendorById(selectedCompanyValue);
    const existingProduct = productById(id);
    const next = {
      id,
      category,
      name: document.getElementById("productName").value.trim(),
      company: category === "비급여" ? "" : (selectedCompanyVendor?.name || selectedCompanyValue),
      companyVendorId: category === "비급여" ? "" : (selectedCompanyVendor?.id || ""),
      subcategory: category === "ANCHOR" ? document.getElementById("productSubcategory").value : "",
      stock: num(document.getElementById("productStock").value),
      warningStock: num(document.getElementById("productWarning").value),
      landingQty: category === "비급여" ? 0 : num(document.getElementById("productLanding").value),
      sortOrder: category === "비급여" ? (productSortOrderValue(existingProduct) || nextNonpaySortOrder(id)) : 0
    };
    if (!next.name) return;
    const { used, received } = productMovementCounts();
    const openingStockTodayInput = document.getElementById("productOpeningStockToday").value;
    if (openingStockTodayInput !== "") {
      const beforeToday = productMovementBeforeDate(id, today());
      next.baseStock = num(openingStockTodayInput) - beforeToday.received + beforeToday.used;
    } else {
      next.baseStock = num(next.stock) - (received.get(id) || 0) + (used.get(id) || 0);
    }
    state.products = [...state.products.filter((item) => item.id !== id), next];
    reconcileProductStocks();
    render();
    await saveState("제품 저장 완료", {
      savingMessage: "제품 저장 중입니다...",
      doneMessage: "제품 저장 완료"
    });
  });
  syncProductFields();
};



    return {
      renderProducts,
      bindProducts
    };
  };
})();
