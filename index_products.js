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
      isVendorManagedProduct,
      today,
      receiptDateValue,
      receiptStockDelta,
      setProductFormDirty,
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
        <option value="PURCHASE">구매재료</option>
        <option>인체조직</option>
        <option value="ANCHOR">ANCHOR&etc</option>
        <option value="URO_LANDING">URO 랜딩</option>
        <option value="GS_LANDING">GS 랜딩</option>
        <option value="IMPLANT">IMPLANT</option>
      </select>
      <label for="productName">제품명</label>
      <input id="productName" required autocomplete="off">
      <p class="helper">새 제품은 여기서 직접 등록할 수 있습니다. 이미 있는 비급여는 새로 만들지 말고 기존 제품에 구매코드를 입력하세요. 엑셀 목록 연결·실사 확정은 구매주문에서 합니다.</p>
      <div id="productOrderCodeWrap">
        <label for="productOrderCode">구매팀 품목코드</label>
        <input id="productOrderCode" maxlength="80" placeholder="구매팀 코드 직접 입력 가능">
        <div class="helper">주문 목록에 제품명과 함께 표시됩니다. 구매재료는 코드 등록을 권장합니다.</div>
      </div>
      <div class="row three">
        <label>재고·사용 단위<input id="productStockUnit" value="EA" required maxlength="20"></label>
        <label>구매 신청·입고 단위<input id="productOrderUnit" value="EA" required maxlength="20"></label>
        <label>신청 1단위당 수량<input id="productUnitsPerOrder" type="number" min="1" step="1" value="1" required></label>
      </div>
      <label class="toggle-line"><input id="productUnconfirmed" type="checkbox" checked>실사 전: 재고 미확정으로 사용량 기록</label>
      <p class="helper">예: EA / BOX / 100. 기록이 있는 제품의 재고 단위는 변경하지 마세요. 미확정 해제는 구매주문 화면에서 실제 수량을 확인한 뒤 진행합니다.</p>
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
        <div class="helper">입력하면 오늘 사용/입고는 그대로 두고, 오늘 시작 시점 재고가 이 수량이 되도록 기준재고를 보정합니다. <strong>비급여는 보관실과 각 방 상자에 있는 수량을 합한 총량</strong> 기준으로 세어 입력하세요.</div>
      </div>
      <div id="productLandingWrap">
        <label for="productLanding">랜딩수량</label>
        <input id="productLanding" type="number" min="0" value="0">
      </div>
      <div id="productVendorManagedWrap">
        <label class="toggle-line"><input id="productVendorManaged" type="checkbox"> 업체관리품</label>
        <div class="helper">병원은 보관만 하고 업체가 재고를 관리하는 인체조직입니다. 사용입력에는 표시되지만 재고 차감과 재고확인에서는 제외됩니다.</div>
      </div>
      <div id="productRoomStockedWrap">
        <label class="toggle-line"><input id="productRoomStocked" type="checkbox"> 방 배치 품목</label>
        <div class="helper">각 수술실 비급여 상자에 들어가는 품목입니다. 체크하면 방 마감 입력 목록에 기본으로 표시됩니다.</div>
        <div id="productRoomParWrap" style="display:none;margin-top:8px;">
          <label for="productRoomPar">방 기본 수량 (상자당 채워두는 개수)</label>
          <input id="productRoomPar" type="number" min="1" max="99" value="10">
          <div class="helper">방 마감 입력에서 이 수량이 하루 최대 보충량이 됩니다 (기본 10).</div>
        </div>
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
  const markProductFormDirty = () => setProductFormDirty?.(true);
  const syncProductFields = () => {
    const category = document.getElementById("productCategory").value;
    const purchaseMaterial = category === "PURCHASE";
    const companySelect = document.getElementById("productCompany");
    const companyHelp = document.getElementById("productCompanyHelp");
    document.getElementById("productCompanyWrap").style.display = category === "비급여" || purchaseMaterial ? "none" : "block";
    document.getElementById("productOrderCodeWrap").style.display = "block";
    document.getElementById("productSubcategoryWrap").style.display = category === "ANCHOR" ? "block" : "none";
    document.getElementById("productLandingWrap").style.display = category === "비급여" || purchaseMaterial ? "none" : "block";
    document.getElementById("productVendorManagedWrap").style.display = category === "인체조직" ? "block" : "none";
    document.getElementById("productRoomStockedWrap").style.display = category === "비급여" ? "block" : "none";
    document.getElementById("productRoomParWrap").style.display =
      category === "비급여" && document.getElementById("productRoomStocked").checked ? "block" : "none";
    if (category === "비급여" || purchaseMaterial) {
      companySelect.value = "";
      document.getElementById("productSubcategory").value = "";
      document.getElementById("productLanding").value = "0";
    }
    if (category !== "인체조직") document.getElementById("productVendorManaged").checked = false;
    if (category !== "비급여") document.getElementById("productRoomStocked").checked = false;
    companySelect.required = category !== "비급여" && !purchaseMaterial;
    document.getElementById("productOrderCode").required = false;
    companySelect.disabled = category !== "비급여" && !purchaseMaterial && !implantVendors().length;
    if (companyHelp) companyHelp.textContent = implantVendors().length
      ? "비급여 외 제품은 등록된 임플란트 업체 중에서 선택합니다."
      : "비급여 외 제품을 등록하려면 먼저 설정 > 임플란트 업체에서 업체를 등록해 주세요.";
  };
  context.setSyncProductFields(syncProductFields);
  document.getElementById("productCategory").addEventListener("change", syncProductFields);
  document.getElementById("productRoomStocked").addEventListener("change", syncProductFields);
  form.addEventListener("input", markProductFormDirty);
  form.addEventListener("change", markProductFormDirty);
  document.getElementById("productReset").addEventListener("click", () => {
    setProductFormDirty?.(false);
    form.reset();
    document.getElementById("productId").value = "";
    document.getElementById("productStockUnit").readOnly = false;
    document.getElementById("productFormTitle").textContent = "제품 추가";
    document.getElementById("productCompany").innerHTML = productCompanyOptions();
    syncProductFields();
  });
  const productMovementBeforeDate = (productId, date) => {
    const received = state.receipts.reduce((sum, receipt) => {
      const receiptDate = receiptDateValue(receipt);
      if (!receiptDate || receiptDate >= date || String(receipt.productId) !== String(productId)) return sum;
      return sum + receiptStockDelta(receipt);
    }, 0);
    // 업체관리품은 재고 수식 전체(productMovementCounts)에서 사용량을 세지 않으므로 여기서도 제외
    if (isVendorManagedProduct?.(productById(productId))) return { used: 0, received };
    const fromUsages = state.usages.reduce((sum, usage) => {
      if (!usage.date || usage.date >= date) return sum;
      return sum + (usage.productIds || []).filter((id) => String(id) === String(productId)).length;
    }, 0);
    // 방 마감 보충 기록(비급여)도 사용량으로 계산 — productMovementCounts와 동일 기준
    const fromRefills = (state.roomRefills || []).reduce((sum, refill) => {
      if (!refill?.date || refill.date >= date) return sum;
      return sum + (refill.items || [])
        .filter((item) => String(item.productId) === String(productId))
        .reduce((qty, item) => qty + Math.max(0, num(item.qty)), 0);
    }, 0);
    return { used: fromUsages + fromRefills, received };
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById("productId").value || uid();
    const category = document.getElementById("productCategory").value;
    if (category !== "비급여" && category !== "PURCHASE" && !implantVendors().length) {
      alert("비급여 외 제품은 임플란트 업체를 먼저 등록해야 제품등록 할 수 있습니다.");
      return;
    }
    if (category !== "비급여" && category !== "PURCHASE" && !document.getElementById("productCompany").value.trim()) {
      alert("비급여 외 제품은 임플란트 업체를 선택해 주세요.");
      return;
    }
    const selectedCompanyValue = document.getElementById("productCompany").value.trim();
    const selectedCompanyVendor = category === "비급여" || category === "PURCHASE" ? null : implantVendorById(selectedCompanyValue);
    const existingProduct = productById(id);
    const orderCode = document.getElementById("productOrderCode").value.trim();
    const stockUnit = document.getElementById("productStockUnit").value.trim();
    const orderUnit = document.getElementById("productOrderUnit").value.trim();
    const unitsPerOrder = Number(document.getElementById("productUnitsPerOrder").value);
    const stockConfirmed = existingProduct?.stockConfirmed === false ? false : !document.getElementById("productUnconfirmed").checked;
    if (!stockUnit || !orderUnit || !Number.isSafeInteger(unitsPerOrder) || unitsPerOrder < 1) return alert("단위와 포장당 수량을 확인해 주세요.");
    if (existingProduct?.stockUnit && stockUnit !== existingProduct.stockUnit) return alert("기존 재고 단위는 변경할 수 없습니다.");
    if (category === "PURCHASE" && !orderCode) return alert("구매팀 품목코드를 입력해 주세요.");
    if (orderCode && state.products.some((item) => item.id !== id && String(item.orderCode || "").trim().toLowerCase() === orderCode.toLowerCase())) {
      alert("이미 등록된 구매팀 품목코드입니다.");
      document.getElementById("productOrderCode").focus();
      return;
    }
    const next = {
      ...existingProduct,
      id,
      category,
      name: document.getElementById("productName").value.trim(),
      orderCode, stockUnit, orderUnit, unitsPerOrder, stockConfirmed,
      purchaseName: existingProduct?.orderCode ? document.getElementById("productName").value.trim() : (orderCode ? document.getElementById("productName").value.trim() : ""),
      company: category === "비급여" || category === "PURCHASE" ? "" : (selectedCompanyVendor?.name || selectedCompanyValue),
      companyVendorId: category === "비급여" || category === "PURCHASE" ? "" : (selectedCompanyVendor?.id || ""),
      subcategory: category === "ANCHOR" ? document.getElementById("productSubcategory").value : "",
      stock: num(document.getElementById("productStock").value),
      warningStock: num(document.getElementById("productWarning").value),
      landingQty: category === "비급여" || category === "PURCHASE" ? 0 : num(document.getElementById("productLanding").value),
      vendorManaged: category === "인체조직" && document.getElementById("productVendorManaged").checked,
      roomStocked: category === "비급여" && document.getElementById("productRoomStocked").checked,
      roomParQty: category === "비급여" && document.getElementById("productRoomStocked").checked
        ? Math.max(1, num(document.getElementById("productRoomPar").value) || 10)
        : 0,
      sortOrder: category === "비급여" ? (productSortOrderValue(existingProduct) || nextNonpaySortOrder(id)) : 0
    };
    if (!next.name) return;
    if (existingProduct?.stockConfirmed === false) next.stock = existingProduct.stock;
    const { used, received } = productMovementCounts();
    const openingStockTodayInput = document.getElementById("productOpeningStockToday").value;
    if (openingStockTodayInput !== "") {
      const beforeToday = productMovementBeforeDate(id, today());
      next.baseStock = num(openingStockTodayInput) - beforeToday.received + beforeToday.used;
    } else {
      next.baseStock = num(next.stock) - (received.get(id) || 0) + (used.get(id) || 0);
    }
    const auditTime = new Date().toISOString();
    const stockChanged = !existingProduct || next.stock !== existingProduct.stock || openingStockTodayInput !== "";
    const button = event.submitter; button.disabled = true;
    try {
      const ok = await saveState("제품 저장 완료", {
        apply: s => {
          if (orderCode && s.products.some(p => p.id !== id && String(p.orderCode || "").toLowerCase() === orderCode.toLowerCase())) throw new Error("이미 등록된 구매코드입니다.");
          const latest = s.products.find(p => p.id === id);
          if (existingProduct && !latest) throw new Error("제품이 삭제되었습니다. 새로고침 후 확인해 주세요.");
          const merged = {...latest, ...next, updatedAt:auditTime};
          // 이름·코드만 고칠 때 다른 기기의 최신 재고를 덮어쓰지 않는다.
          if (latest && !stockChanged) { merged.baseStock = latest.baseStock; merged.stock = latest.stock; }
          else if (openingStockTodayInput === "" && stockConfirmed) {
            const movement = window.ORPurchase.movement(s,id);
            merged.baseStock = next.stock - movement.received + movement.used;
          }
          s.products = [...s.products.filter(p => p.id !== id), merged];
        },
        savingMessage: "제품 저장 중입니다...", doneMessage: "제품 저장 완료"
      });
      if (ok) { setProductFormDirty?.(false); render(); }
    } finally { button.disabled = false; }
  });
  syncProductFields();
};



    return {
      renderProducts,
      bindProducts
    };
  };
})();
