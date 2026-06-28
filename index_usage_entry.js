(() => {
  window.createUsageEntryModule = (context) => {
    const pendingUsageSummary = (item) => {
      const productCount = (item.productItems || []).reduce((sum, product) => sum + Math.max(1, context.num(product.qty)), 0);
      const implantCount = (item.implantDrafts || []).length;
      const photoCount = (item.implantDrafts || []).reduce((sum, implant) => sum + (implant.photos || []).length, 0);
      return { productCount, implantCount, photoCount };
    };

    const useDraftSummaryHtml = (snapshot) => {
      const useItems = snapshot.useItems || [];
      const implantDrafts = snapshot.implantDraftPayload || [];
      const productLines = useItems.map((item) => {
        const product = context.productById(item.productId);
        return `${product?.name || "삭제된 제품"} ${context.num(item.qty)}개`;
      });
      const implantPhotoCount = implantDrafts.reduce((sum, draft) => sum + (draft.photos || []).length, 0);
      return `
        <div><span>환자</span> ${context.escapeHtml(snapshot.patientName || "-")} ${snapshot.patientId ? `(${context.escapeHtml(snapshot.patientId)})` : ""}</div>
        <div><span>사용일</span> ${context.escapeHtml(snapshot.date || context.today())}</div>
        <div><span>수술</span> ${context.escapeHtml(snapshot.doctorText)} · ${context.escapeHtml(snapshot.surgeryText)}</div>
        <div><span>사용제품</span> ${context.escapeHtml(productLines.join(", ") || "-")}</div>
        <div><span>임플란트</span> ${implantDrafts.length ? `${implantDrafts.length}개 업체 · 사진 ${implantPhotoCount}장` : "기록 없음"}</div>
        <div><span>임시저장</span> ${context.escapeHtml(snapshot.enteredBy)} · ${context.escapeHtml(context.formatDateTime(snapshot.enteredAt))}</div>
      `;
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

    const selectedUseItemsFromScope = (scope) => Array.from(scope.querySelectorAll("[data-use-product]:checked")).map((input) => ({
      productId: input.value,
      qty: Math.max(1, context.num(scope.querySelector(`[data-use-qty="${input.value}"]`)?.value))
    }));

    const syncRecommendControl = (productId, checked, qty = "") => {
      const recommend = context.getApp().querySelector(`[data-recommend-product="${productId}"]`);
      const recommendQty = context.getApp().querySelector(`[data-recommend-qty="${productId}"]`);
      if (recommend) recommend.checked = checked;
      if (recommendQty && qty !== "") recommendQty.value = Math.max(1, context.num(qty));
    };

    const setRestrictButtonState = (button, value) => {
      if (!button) return;
      button.dataset.restrict = value ? "true" : "false";
      button.textContent = value ? "비급여 제한 켜짐" : "비급여 제한 꺼짐";
      button.classList.toggle("danger", Boolean(value));
      button.classList.toggle("secondary", !value);
    };

    const setUseDraftPanelState = ({ status, finalSaveButton, saveButton, dirty, hasSnapshot }) => {
      if (status) {
        status.textContent = dirty ? "수정 중 · 임시저장 갱신 필요" : "임시저장 완료";
        status.classList.toggle("dirty", Boolean(dirty));
      }
      if (finalSaveButton) finalSaveButton.disabled = Boolean(dirty);
      if (saveButton) saveButton.textContent = hasSnapshot ? "임시저장 갱신" : "임시저장";
    };

    const draftUserText = () => context.currentAuditUser()?.name || context.currentAuditUser()?.loginId || "현재 사용자";

    const selectedUseListHtml = (items) => {
      if (!items.length) return `<span>선택된 제품이 없습니다.</span>`;
      const chipClass = (category) => {
        const key = context.productCategory(category);
        if (key === "비급여") return "nonpay";
        if (key === "인체조직") return "tissue";
        if (["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(key)) return "anchor";
        return "";
      };
      return `
        <div class="selected-use-buttons">
          ${items.map((item) => {
            const product = context.productById(item.productId);
            if (!product) return "";
            const meta = [context.productCategoryLabel(product.category), product.company, product.subcategory].filter(Boolean).join(" · ");
            return `
              <div class="selected-use-chip ${chipClass(product.category)}">
                <div class="selected-use-name" title="${context.escapeHtml(product.name)}">
                  ${context.escapeHtml(product.name)}<span>${context.escapeHtml(meta)}</span>
                </div>
                <div class="selected-use-controls">
                  <button type="button" class="secondary" data-selected-dec="${item.productId}" aria-label="수량 줄이기">−</button>
                  <input type="number" min="1" max="${Math.max(1, context.num(product.stock) + item.qty)}" value="${item.qty}" data-selected-qty="${item.productId}" aria-label="${context.escapeHtml(product.name)} 수량" readonly>
                  <button type="button" class="secondary" data-selected-inc="${item.productId}" aria-label="수량 늘리기">+</button>
                  <button type="button" class="remove-selected" data-selected-remove="${item.productId}">삭제</button>
                </div>
              </div>
            `;
          }).join("")}
        </div>
      `;
    };

    const productSearchResultsHtml = (results, selectedItems = []) => {
      if (!results.length) return `<div class="empty">검색 결과가 없습니다.</div>`;
      const selectedQtyById = new Map(selectedItems.map((item) => [item.productId, Math.max(1, context.num(item.qty))]));
      return results.map((item) => {
        const selectedQty = selectedQtyById.get(item.id);
        return `
          <label class="check-card use-card">
            <input type="checkbox" value="${item.id}" data-search-product="${item.id}" ${selectedQty ? "checked" : ""}>
            <span>${context.escapeHtml(item.name)}<br><span class="muted">${context.escapeHtml(context.productCategoryLabel(item.category))}${item.company ? ` · ${context.escapeHtml(item.company)}` : ""}${item.subcategory ? ` · ${context.escapeHtml(item.subcategory)}` : ""} · 현재고 ${context.num(item.stock)}</span></span>
            ${context.qtyStepper(`data-search-qty="${item.id}" aria-label="${context.escapeHtml(item.name)} 검색 사용 수량"`, selectedQty || 1, Math.max(1, context.num(item.stock)))}
          </label>
        `;
      }).join("");
    };

    const productSearchEmptyQueryHtml = () => `<div class="empty">제품명을 입력해 주세요.</div>`;

    const useProductSearchResults = (products = [], query = "") => {
      const normalizedQuery = context.normalizedName(query);
      if (!normalizedQuery) return [];
      return products
        .filter((item) => context.normalizedName(`${item.name} ${item.company || ""} ${item.subcategory || ""} ${context.productCategoryLabel(item.category)}`).includes(normalizedQuery))
        .sort((a, b) => context.alphaFirstCompare(a.name, b.name))
        .slice(0, 12);
    };

    const noRecommendationHtml = (hasSurgerySelection) => hasSurgerySelection
      ? `<div class="empty">추천 비급여가 등록되지 않은 수술입니다. 수술은 저장할 수 있으며, 필요한 제품은 아래에서 직접 선택해 주세요.</div>`
      : "";

    const useRecommendedItemsWithProducts = (items = []) => items
      .map((item) => ({ ...item, product: context.productById(item.productId) }))
      .filter((item) => item.product);

    const shouldHideUseProductForRestriction = (product, productId, recommendedItems = [], restrictActive = false) =>
      Boolean(product) &&
      context.productCategory(product.category) === "비급여" &&
      Boolean(restrictActive) &&
      recommendedItems.some((item) => item.productId === productId);

    const syncRecommendProductToUseForm = (input, form) => {
      const linked = form?.querySelector(`[data-use-product="${input.value}"]`);
      const qtyInput = form?.querySelector(`[data-use-qty="${input.value}"]`);
      const recommendQty = context.getApp().querySelector(`[data-recommend-qty="${input.value}"]`);
      if (linked) linked.checked = input.checked;
      if (qtyInput && recommendQty) qtyInput.value = Math.max(1, context.num(recommendQty.value));
    };

    const syncRecommendQtyToUseForm = (input) => {
      const linked = context.getApp().querySelector(`[data-use-product="${input.dataset.recommendQty}"]`);
      const qtyInput = context.getApp().querySelector(`[data-use-qty="${input.dataset.recommendQty}"]`);
      if (linked) linked.checked = true;
      if (qtyInput) qtyInput.value = Math.max(1, context.num(input.value));
    };

    const searchProductQtyValue = (container, productId) =>
      container?.querySelector(`[data-search-qty="${productId}"]`)?.value;

    const clearSearchProductFromUseForm = (productId, form) => {
      const linked = form?.querySelector(`[data-use-product="${productId}"]`);
      const qtyInput = form?.querySelector(`[data-use-qty="${productId}"]`);
      if (linked) linked.checked = false;
      if (qtyInput) qtyInput.value = 1;
      syncRecommendControl(productId, false);
    };

    const resetUseProductControls = (form) => {
      form?.querySelectorAll("[data-use-product]").forEach((input) => { input.checked = false; });
      form?.querySelectorAll("[data-use-qty]").forEach((input) => { input.value = 1; });
    };

    const applyPendingProductItemsToForm = (form, productItems = []) => {
      resetUseProductControls(form);
      productItems.forEach((item) => {
        const checkbox = form?.querySelector(`[data-use-product="${item.productId}"]`);
        const qtyInput = form?.querySelector(`[data-use-qty="${item.productId}"]`);
        if (checkbox) checkbox.checked = true;
        if (qtyInput) qtyInput.value = Math.max(1, context.num(item.qty));
        syncRecommendControl(item.productId, true, item.qty);
      });
    };

    const useRecommendationHtml = (recommended, restrictActive, selectedItems = []) => {
      const selectedQtyById = new Map(selectedItems.map((item) => [item.productId, Math.max(1, context.num(item.qty))]));
      const visibleItems = recommended.filter((item) => !(restrictActive && context.productCategory(item.product.category) === "비급여"));
      return `
        <div class="item ${restrictActive ? "landing-line pending" : ""}">
          <div class="item-title">
            <span>${restrictActive ? "비급여 제한" : "추천 항목"}</span>
            <span class="pill ${restrictActive ? "low" : ""}">${recommended.length}</span>
          </div>
          <div class="meta"><span>${context.escapeHtml(restrictActive ? "이 환자는 비급여 제한으로 선택되어 있습니다. 추천 비급여만 숨겨지고, 인체조직/ANCHOR 추천은 선택할 수 있습니다." : "추천 항목을 선택하고 수량을 조절해 사용내용에 넣을 수 있습니다.")}</span></div>
          ${visibleItems.map((item) => {
            const selectedQty = selectedQtyById.get(item.productId);
            const qty = selectedQty || Math.max(1, context.num(item.qty));
            return `
              <label class="check-card use-card">
                <input type="checkbox" value="${item.productId}" data-recommend-product="${item.productId}" ${selectedQty ? "checked" : ""}>
                <span>${context.escapeHtml(item.product.name)}<br><span class="muted">추천 ${Math.max(1, context.num(item.qty))}개 · 현재고 ${context.num(item.product.stock)}</span></span>
                ${context.qtyStepper(`data-recommend-qty="${item.productId}" aria-label="${context.escapeHtml(item.product.name)} 추천 사용 수량"`, qty, Math.max(1, context.num(item.product.stock)))}
              </label>
            `;
          }).join("")}
        </div>
      `;
    };

    const commonImplantPhotosHtml = (photos = []) => photos.map((photo, index) => {
      const src = context.implantPhotoViewSrc(photo);
      return `
        <div class="implant-common-photo" data-common-implant-photo="${context.escapeHtml(photo.id)}">
          ${src ? `<img src="${context.escapeHtml(src)}" alt="공용 임플란트 사진 ${index + 1}" data-preview-common-implant-photo="${context.escapeHtml(photo.id)}">` : ""}
          <div class="implant-photo-actions">
            <button class="secondary" type="button" data-preview-common-implant-photo="${context.escapeHtml(photo.id)}">확대</button>
            <button class="danger" type="button" data-remove-common-implant-photo="${context.escapeHtml(photo.id)}">삭제</button>
          </div>
        </div>
      `;
    }).join("") || `<div class="empty">공용 사진을 먼저 촬영하거나 선택해 주세요.</div>`;

    const emptyImplantDraft = () => ({ id: context.uid(), vendorId: "", customVendor: "", description: "", photos: [] });

    const commonImplantPhotoFromFile = (file) => ({
      id: context.uid(),
      file,
      preview: URL.createObjectURL(file),
      name: file.name || "implant.jpg",
      size: file.size,
      contentType: file.type || "image/jpeg",
      rotation: 0,
      cropped: false
    });

    const implantDraftPhotoFromFile = (file) => ({
      id: context.uid(),
      file,
      preview: URL.createObjectURL(file),
      rotation: 0,
      cropped: false
    });

    const addCommonImplantPhotosFromFiles = (photos = [], files = []) => {
      files
        .filter((file) => file.type.startsWith("image/"))
        .forEach((file) => photos.push(commonImplantPhotoFromFile(file)));
      return photos;
    };

    const cloneCommonImplantPhoto = (photo) => ({
      id: context.uid(),
      file: photo.file || null,
      preview: photo.file ? URL.createObjectURL(photo.file) : (photo.preview || ""),
      url: photo.url || "",
      dataUrl: photo.dataUrl || "",
      name: photo.name || photo.file?.name || "",
      size: context.num(photo.size || photo.file?.size),
      contentType: photo.contentType || photo.file?.type || "image/jpeg",
      rotation: 0,
      cropped: false,
      cropRect: null,
      sourceCommonPhotoId: photo.id
    });

    const commonImplantPhotoById = (photos = [], id = "") => photos.find((photo) => photo.id === id);

    const removeCommonImplantPhotoById = (photos = [], id = "") => {
      const index = photos.findIndex((photo) => photo.id === id);
      if (index < 0) return false;
      URL.revokeObjectURL(photos[index].preview);
      photos.splice(index, 1);
      return true;
    };

    const implantDraftById = (drafts = [], id = "") => drafts.find((draft) => draft.id === id);

    const addImplantDraftPhotosFromFiles = (draft, files = []) => {
      if (!draft) return draft;
      files
        .filter((file) => file.type.startsWith("image/"))
        .forEach((file) => draft.photos.push(implantDraftPhotoFromFile(file)));
      return draft;
    };

    const removeImplantDraftById = (drafts = [], id = "") => {
      const index = drafts.findIndex((item) => item.id === id);
      if (index < 0) return false;
      (drafts[index].photos || []).forEach((photo) => URL.revokeObjectURL(photo.preview));
      drafts.splice(index, 1);
      return true;
    };

    const mergeDuplicateImplantDrafts = (drafts = []) => {
      const kept = [];
      let changed = false;
      for (let index = 0; index < drafts.length; index += 1) {
        const draft = drafts[index];
        const existing = kept.find((item) => context.implantVendorEntriesMatch(item, draft));
        if (!existing) {
          kept.push(draft);
          continue;
        }
        existing.vendorId = existing.vendorId || draft.vendorId || "";
        existing.customVendor = existing.customVendor || draft.customVendor || "";
        existing.vendor = existing.vendor || draft.vendor || "";
        existing.autoSource = existing.autoSource || draft.autoSource;
        existing.autoCompanyKey = existing.autoCompanyKey || draft.autoCompanyKey || "";
        existing.description = context.mergeImplantDescriptionLines(existing.description, draft.description);
        existing.autoDescription = context.mergeImplantDescriptionLines(existing.autoDescription, draft.autoDescription);
        const existingPhotoIds = new Set((existing.photos || []).map((photo) => photo.id));
        (draft.photos || []).forEach((photo) => {
          if (!existingPhotoIds.has(photo.id)) {
            existing.photos = existing.photos || [];
            existing.photos.push(photo);
            existingPhotoIds.add(photo.id);
          }
        });
        drafts.splice(index, 1);
        index -= 1;
        changed = true;
      }
      return changed;
    };

    const implantDraftVendorText = (draft = {}) => {
      if (draft.vendorId === "__custom__") return draft.customVendor;
      return context.implantVendorById(draft.vendorId)?.name;
    };

    const implantDraftPayloadFromList = (drafts = [], enabled = false) => enabled ? drafts.map((draft) => ({
      ...draft,
      vendorId: draft.vendorId || "",
      customVendor: String(draft.customVendor || "").trim(),
      description: String(draft.description || "").trim()
    })).filter((draft) =>
      String(implantDraftVendorText(draft) || "").trim() || draft.description || (draft.photos || []).length
    ) : [];

    const invalidImplantDraft = (payload = []) => payload.find((draft) =>
      !String(implantDraftVendorText(draft) || "").trim() || (!draft.description && !(draft.photos || []).length)
    );

    const useDraftValidationMessage = (useItems = [], implantDraftPayload = []) => {
      if (!useItems.length && !implantDraftPayload.length) return "제품을 선택하거나 임플란트 장부를 작성해 주세요.";
      const unavailable = useItems.find((item) => context.num(context.productById(item.productId)?.stock) < item.qty);
      if (unavailable) return "재고가 부족한 제품이 있습니다.";
      if (invalidImplantDraft(implantDraftPayload)) return "임플란트 장부가 작성되지 않았습니다. 업체명과 사용내용 또는 사진을 확인해 주세요.";
      return "";
    };

    const buildUseDraftSnapshot = ({
      date = context.today(),
      patientName = "",
      patientId = "",
      doctorText = "-",
      surgeryText = "-",
      enteredBy = "",
      useItems = [],
      implantDraftPayload = []
    } = {}) => ({
      date,
      patientName,
      patientId,
      doctorText,
      surgeryText,
      enteredBy,
      enteredAt: new Date().toISOString(),
      useItems,
      implantDraftPayload
    });

    const pendingUsagePhotoCount = (implantDraftPayload = []) =>
      implantDraftPayload.reduce((sum, draft) =>
        sum + (draft.photos || []).filter((photo) => !(photo.url || photo.dataUrl)).length
      , 0);

    const pendingUsagePhotoProgressMessage = (done = 0, total = 0, failed = 0) => {
      const failText = failed ? ` · 실패 ${failed}장` : "";
      return `임시저장 사진 처리 중 ${done}/${total}${failText}`;
    };

    const pendingImplantDraftsFromRecord = (pending = {}) => (pending.implantDrafts || []).map((draft) => ({
      id: draft.id || context.uid(),
      vendorId: draft.vendorId || "",
      customVendor: draft.customVendor || "",
      vendor: draft.vendor || "",
      description: draft.description || "",
      autoSource: draft.autoSource || "",
      autoDescription: draft.autoDescription || "",
      autoCompanyKey: draft.autoCompanyKey || "",
      photos: (draft.photos || []).map(context.cleanImplantPhotoPayload)
    }));

    const implantDraftPhotoPair = (drafts = [], value = "") => {
      const [draftId, photoId] = String(value || "").split("::");
      const draft = implantDraftById(drafts, draftId);
      const photo = draft?.photos?.find((item) => item.id === photoId);
      return { draft, photo };
    };

    const implantDraftsHtml = (drafts = [], commonPhotoCount = 0) => drafts.map((draft, index) => `
      <div class="implant-vendor-card" data-implant-draft="${context.escapeHtml(draft.id)}">
        <div class="implant-vendor-head">
          <strong>업체 ${index + 1}</strong>
          <button class="danger" type="button" data-remove-implant-draft="${context.escapeHtml(draft.id)}">업체 삭제</button>
        </div>
        <div class="row two">
          <div>
            <label for="implantVendorSelect-${context.escapeHtml(draft.id)}">업체명</label>
            <select id="implantVendorSelect-${context.escapeHtml(draft.id)}" data-implant-vendor-select="${context.escapeHtml(draft.id)}">
              ${context.implantVendorOptions(draft.vendorId)}
            </select>
          </div>
          <div ${draft.vendorId === "__custom__" ? "" : "hidden"}>
            <label for="implantVendorCustom-${context.escapeHtml(draft.id)}">직접 입력</label>
            <input id="implantVendorCustom-${context.escapeHtml(draft.id)}" data-implant-vendor-custom="${context.escapeHtml(draft.id)}" value="${context.escapeHtml(draft.customVendor || "")}" autocomplete="off">
          </div>
        </div>
        <label for="implantDescription-${context.escapeHtml(draft.id)}">사용내용</label>
        <textarea id="implantDescription-${context.escapeHtml(draft.id)}" data-implant-description="${context.escapeHtml(draft.id)}" placeholder="Plate 255-209-L&#10;Screw 22mm 3ea">${context.escapeHtml(draft.description || "")}</textarea>
        <label for="implantPhotos-${context.escapeHtml(draft.id)}">사진첨부</label>
        <div class="implant-photo-pickers">
          <button class="secondary" type="button" data-open-implant-gallery="${context.escapeHtml(draft.id)}">파일 선택</button>
          <button type="button" data-open-implant-camera="${context.escapeHtml(draft.id)}">사진 찍기</button>
          <button class="secondary" type="button" data-use-common-implant-photo="${context.escapeHtml(draft.id)}" ${commonPhotoCount ? "" : "disabled"}>공용 사진 사용</button>
          <span class="muted">Android/iPad 카메라와 갤러리를 지원합니다.</span>
          <input id="implantGallery-${context.escapeHtml(draft.id)}" type="file" accept="image/*" multiple data-implant-photo-input="${context.escapeHtml(draft.id)}">
          <input id="implantCamera-${context.escapeHtml(draft.id)}" type="file" accept="image/*" capture="environment" data-implant-camera-input="${context.escapeHtml(draft.id)}">
        </div>
        <div class="implant-photo-grid">
          ${(draft.photos || []).map((photo, photoIndex) => `
            <div class="implant-photo" data-implant-photo="${context.escapeHtml(photo.id)}">
              <img class="${photo.cropped ? "cropped" : ""}" src="${context.escapeHtml(context.implantPhotoViewSrc(photo))}" alt="임플란트 사진 미리보기" data-preview-implant-photo="${context.escapeHtml(draft.id)}::${context.escapeHtml(photo.id)}" style="${context.implantPhotoRotationStyle(photo)} cursor:pointer;">
              <div class="implant-photo-actions">
                <button class="secondary" type="button" data-edit-implant-photo="${context.escapeHtml(draft.id)}::${context.escapeHtml(photo.id)}">편집</button>
                <button class="secondary" type="button" data-move-implant-photo-up="${context.escapeHtml(draft.id)}::${context.escapeHtml(photo.id)}" ${photoIndex === 0 ? "disabled" : ""}>앞</button>
                <button class="secondary" type="button" data-move-implant-photo-down="${context.escapeHtml(draft.id)}::${context.escapeHtml(photo.id)}" ${photoIndex === draft.photos.length - 1 ? "disabled" : ""}>뒤</button>
                <button class="danger" type="button" data-remove-implant-photo="${context.escapeHtml(draft.id)}::${context.escapeHtml(photo.id)}">삭제</button>
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    `).join("") || `<div class="empty">임플란트 업체를 추가해 주세요.</div>`;

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
      useDraftSummaryHtml,
      renderPendingUsageList,
      renderUseItemsList,
      selectedUseItemsFromScope,
      syncRecommendControl,
      setRestrictButtonState,
      setUseDraftPanelState,
      draftUserText,
      selectedUseListHtml,
      useProductSearchResults,
      productSearchResultsHtml,
      productSearchEmptyQueryHtml,
      noRecommendationHtml,
      useRecommendedItemsWithProducts,
      shouldHideUseProductForRestriction,
      syncRecommendProductToUseForm,
      syncRecommendQtyToUseForm,
      searchProductQtyValue,
      clearSearchProductFromUseForm,
      resetUseProductControls,
      applyPendingProductItemsToForm,
      useRecommendationHtml,
      commonImplantPhotosHtml,
      emptyImplantDraft,
      commonImplantPhotoFromFile,
      implantDraftPhotoFromFile,
      addCommonImplantPhotosFromFiles,
      cloneCommonImplantPhoto,
      commonImplantPhotoById,
      removeCommonImplantPhotoById,
      implantDraftById,
      addImplantDraftPhotosFromFiles,
      removeImplantDraftById,
      mergeDuplicateImplantDrafts,
      implantDraftPayloadFromList,
      invalidImplantDraft,
      useDraftValidationMessage,
      buildUseDraftSnapshot,
      pendingUsagePhotoCount,
      pendingUsagePhotoProgressMessage,
      pendingImplantDraftsFromRecord,
      implantDraftPhotoPair,
      implantDraftsHtml,
      editUsagePatientsForDate,
      editUsagePatientCardHtml,
      editUsagePatientListHtml,
      renderUseProductSearchModal,
      renderImplantPhotoModal
    };
  };
})();
