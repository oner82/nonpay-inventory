(() => {
  window.createUsageEntryModule = (context) => {
    const pendingUsageSummary = (item) => {
      const productCount = (item.productItems || []).reduce((sum, product) => sum + Math.max(1, context.num(product.qty)), 0);
      const implantCount = (item.implantDrafts || []).length;
      const photoCount = (item.implantDrafts || []).reduce((sum, implant) => sum + (implant.photos || []).length, 0);
      return { productCount, implantCount, photoCount };
    };

    const renderPendingUsageList = () => {
      const items = context.pendingUsagesOpen();
      if (!items.length) return "";
      return `
        <div class="card">
          <div class="use-draft-head">
            <div>
              <h3 style="margin:0;">스크럽 확인 대기</h3>
              <div class="muted">임시저장된 기록은 새로고침 후에도 남아 있습니다. 확인할 환자를 불러와 최종저장하세요.</div>
            </div>
            <span class="use-draft-status">${items.length}건</span>
          </div>
          <div class="pending-usage-list">
            ${items.map((item) => {
              const summary = pendingUsageSummary(item);
              const doctor = context.departmentById(item.doctorId);
              const surgery = context.surgeryById(item.surgeryId);
              return `
                <div class="pending-usage-card">
                  <div class="pending-usage-head">
                    <strong>${context.escapeHtml(context.patientDisplayName(item) || "환자 정보 없음")}</strong>
                    <span class="pill">${context.escapeHtml(item.date || context.today())}</span>
                  </div>
                  <div class="pending-usage-meta">
                    <span>${context.escapeHtml(doctor?.name || "-")}</span>
                    <span>${context.escapeHtml(surgery?.name || "-")}</span>
                    <span>제품 ${summary.productCount}개</span>
                    <span>임플란트 ${summary.implantCount}업체 · 사진 ${summary.photoCount}장</span>
                    <span>입력 ${context.escapeHtml(item.enteredBy?.name || item.enteredBy?.loginId || item.draftSavedBy || "-")}</span>
                    <span>${context.escapeHtml(context.formatDateTime(item.updatedAt || item.createdAt || ""))}</span>
                  </div>
                  <div class="actions">
                    <button type="button" data-load-pending-usage="${context.escapeHtml(item.id)}">불러오기</button>
                    <button class="danger" type="button" data-delete-pending-usage="${context.escapeHtml(item.id)}">대기삭제</button>
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    };

    const renderUseItemsList = (items, target) => {
      if (!items.length) {
        target.innerHTML = `<span>선택된 제품이 없습니다.</span>`;
        return;
      }
      const chipClass = (category) => {
        const key = context.productCategory(category);
        if (key === "비급여") return "nonpay";
        if (key === "인체조직") return "tissue";
        if (["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(key)) return "anchor";
        return "";
      };
      const safeItems = items
        .map((item) => ({ ...item, product: context.productById(item.productId) }))
        .filter((item) => item.product && context.num(item.qty) > 0);
      if (!safeItems.length) {
        target.innerHTML = `<span>선택된 제품이 없습니다.</span>`;
        return;
      }
      target.innerHTML = `
        <div class="selected-use-buttons">
          ${safeItems.map((item) => {
            const product = item.product;
            const linkedQty = context.getApp().querySelector(`[data-use-qty="${item.productId}"]`);
            const maxQty = Math.max(1, context.num(linkedQty?.max || product.stock || 999));
            const meta = [context.productCategoryLabel(product.category), product.company, product.subcategory].filter(Boolean).join(" · ");
            return `
              <div class="selected-use-chip ${chipClass(product.category)}">
                <div class="selected-use-name" title="${context.escapeHtml(product.name)}">
                  ${context.escapeHtml(product.name)}<span>${context.escapeHtml(meta)}</span>
                </div>
                <div class="selected-use-controls">
                  <button type="button" class="secondary" data-edit-selected-dec="${item.productId}" aria-label="수량 줄이기">−</button>
                  <input type="number" min="0" max="${maxQty}" value="${Math.max(1, context.num(item.qty))}" data-edit-selected-qty="${item.productId}" aria-label="${context.escapeHtml(product.name)} 수량" readonly>
                  <button type="button" class="secondary" data-edit-selected-inc="${item.productId}" aria-label="수량 늘리기">+</button>
                  <button type="button" class="remove-selected" data-edit-selected-remove="${item.productId}">삭제</button>
                </div>
              </div>
            `;
          }).join("")}
        </div>
      `;
      const syncProductQty = (productId, nextQty) => {
        const scope = target.closest("form") || context.getApp();
        const checkbox = scope.querySelector(`[data-use-product="${productId}"]`);
        const qtyInput = scope.querySelector(`[data-use-qty="${productId}"]`);
        const maxQty = Math.max(1, context.num(qtyInput?.max || 999));
        const safeQty = Math.min(maxQty, Math.max(0, context.num(nextQty)));
        if (safeQty <= 0) {
          if (checkbox) checkbox.checked = false;
          if (qtyInput) qtyInput.value = 1;
        } else {
          if (checkbox) checkbox.checked = true;
          if (qtyInput) qtyInput.value = safeQty;
        }
        renderUseItemsList(Array.from(scope.querySelectorAll("[data-use-product]:checked")).map((input) => ({
          productId: input.value,
          qty: Math.max(1, context.num(scope.querySelector(`[data-use-qty="${input.value}"]`)?.value))
        })), target);
      };
      target.querySelectorAll("[data-edit-selected-remove]").forEach((button) => {
        button.addEventListener("click", () => syncProductQty(button.dataset.editSelectedRemove, 0));
      });
      target.querySelectorAll("[data-edit-selected-dec], [data-edit-selected-inc]").forEach((button) => {
        button.addEventListener("click", () => {
          const productId = button.dataset.editSelectedDec || button.dataset.editSelectedInc;
          const linked = context.getApp().querySelector(`[data-use-qty="${productId}"]`);
          const currentQty = Math.max(1, context.num(linked?.value || 1));
          const nextQty = button.dataset.editSelectedDec ? currentQty - 1 : currentQty + 1;
          syncProductQty(productId, nextQty);
        });
      });
    };

    const editUsagePatientsForDate = (date) => context.getState().usages
      .filter((usage) => (usage.date || "") === date)
      .slice()
      .sort((a, b) => context.alphaFirstCompare(a.patientName, b.patientName) || context.alphaFirstCompare(context.patientIdText(a), context.patientIdText(b)));

    const editUsagePatientCardHtml = (usage, selectedId = "") => {
      const doctor = context.departmentById(usage.doctorId);
      const surgery = context.surgeryById(usage.surgeryId);
      const surgeryDepartment = surgery ? (surgery.department || context.inferSurgeryDepartment(surgery.name)) : "-";
      const productItems = context.usageProductItems(usage);
      const productSummary = productItems
        .slice(0, 3)
        .map((item) => `${context.productById(item.productId)?.name || "삭제된 제품"}${item.qty > 1 ? ` ${item.qty}개` : ""}`)
        .join(", ");
      const extraCount = Math.max(0, productItems.length - 3);
      const locked = !context.canModifyUsageRecord(usage);
      return `
        <button class="edit-patient-card ${selectedId === usage.id ? "active" : ""} ${locked ? "locked" : ""}" type="button" data-edit-usage-card="${context.escapeHtml(usage.id)}">
          <div class="edit-patient-card-head">
            <span>${context.escapeHtml(context.patientDisplayName(usage) || "이름 없음")}</span>
            <span class="pill ${locked ? "low" : ""}">${locked ? "관리자 전용" : "수정 가능"}</span>
          </div>
          <div class="edit-patient-card-meta">
            <span>원장: ${context.escapeHtml(doctor?.name || "-")}</span>
            <span>수술: ${context.escapeHtml(surgeryDepartment)} - ${context.escapeHtml(surgery?.name || "-")}</span>
            <span>제품: ${productItems.reduce((sum, item) => sum + item.qty, 0)}개${productSummary ? ` · ${context.escapeHtml(productSummary)}${extraCount ? ` 외 ${extraCount}종` : ""}` : ""}</span>
          </div>
        </button>
      `;
    };

    const editUsagePatientListHtml = (date, selectedId = "") => {
      const patients = editUsagePatientsForDate(date);
      if (!patients.length) return `<div class="empty">선택한 날짜에 사용내역이 없습니다.</div>`;
      return patients.map((usage) => editUsagePatientCardHtml(usage, selectedId)).join("");
    };

    const renderUseProductSearchModal = () => `
      <div class="modal-backdrop" id="useProductSearchModal" hidden role="dialog" aria-modal="true" aria-labelledby="useProductSearchTitle">
        <div class="search-modal-panel">
          <div class="search-modal-head">
            <h3 id="useProductSearchTitle">제품 검색</h3>
            <button class="search-modal-close" type="button" id="closeUseProductSearch" aria-label="제품 검색 닫기">×</button>
          </div>
          <div>
            <label for="useProductSearch">제품명 검색</label>
            <input id="useProductSearch" autocomplete="off" placeholder="제품명, 업체, 종류를 입력하세요">
          </div>
          <div id="useProductSearchResults" class="product-picker search-modal-results"></div>
        </div>
      </div>
    `;

    const renderImplantPhotoModal = () => `
      <div class="modal-backdrop" id="implantPhotoModal" hidden role="dialog" aria-modal="true" aria-label="임플란트 사진 확대">
        <div class="search-modal-panel">
          <div class="search-modal-head">
            <h3>사진 확인</h3>
            <button class="search-modal-close" type="button" id="closeImplantPhotoModal" aria-label="사진 닫기">×</button>
          </div>
          <div class="implant-crop-stage" id="implantCropStage">
            <img class="implant-modal-image" id="implantPhotoModalImage" alt="임플란트 사진 확대">
            <div class="implant-crop-frame" id="implantCropFrame" hidden>
              <span class="implant-crop-handle" data-crop-handle="nw"></span>
              <span class="implant-crop-handle" data-crop-handle="n"></span>
              <span class="implant-crop-handle" data-crop-handle="ne"></span>
              <span class="implant-crop-handle" data-crop-handle="e"></span>
              <span class="implant-crop-handle" data-crop-handle="se"></span>
              <span class="implant-crop-handle" data-crop-handle="s"></span>
              <span class="implant-crop-handle" data-crop-handle="sw"></span>
              <span class="implant-crop-handle" data-crop-handle="w"></span>
            </div>
          </div>
          <div class="actions" id="implantPhotoEditTools" hidden>
            <button class="secondary" type="button" id="implantModalRotate">회전</button>
            <button class="secondary" type="button" id="implantModalCrop">자르기</button>
            <button type="button" id="implantModalDone">완료</button>
          </div>
        </div>
      </div>
    `;

    return {
      pendingUsageSummary,
      renderPendingUsageList,
      renderUseItemsList,
      editUsagePatientsForDate,
      editUsagePatientCardHtml,
      editUsagePatientListHtml,
      renderUseProductSearchModal,
      renderImplantPhotoModal
    };
  };
})();
