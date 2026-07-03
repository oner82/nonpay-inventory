(() => {
  window.createHistoryModule = (context) => {
    const defaultHistoryDate = () => context.today();

    const renderHistory = () => {
      const state = context.getState();
      const defaultDate = defaultHistoryDate();
      const defaultPatientCount = filteredHistoryUsages(defaultDate, defaultDate, "", "").length;
      return `
        <section class="grid">
          <div class="card">
            <h2>사용내역 검색</h2>
            <div class="row history-filter-grid">
              <div>
                <label for="historyStart">시작일</label>
                <input id="historyStart" type="date" value="${context.escapeHtml(defaultDate)}">
              </div>
              <div>
                <label for="historyEnd">종료일</label>
                <input id="historyEnd" type="date" value="${context.escapeHtml(defaultDate)}">
              </div>
              <div>
                <label for="historySearch">제품 검색</label>
                <input id="historySearch" list="historyProductList" autocomplete="off" placeholder="제품명 입력">
                <datalist id="historyProductList">
                  ${state.products.slice().sort(context.byName).map((product) => `<option value="${context.escapeHtml(product.name)}"></option>`).join("")}
                </datalist>
              </div>
              <div>
                <label for="historyPatientSearch">환자 검색</label>
                <input id="historyPatientSearch" autocomplete="off" placeholder="환자명 또는 등록번호">
              </div>
            </div>
            <div class="actions">
              <button type="button" id="historyApply">기간 적용</button>
              <button class="secondary" type="button" id="historyReset">오늘로 초기화</button>
            </div>
          </div>
          <div class="card">
            <details class="item" id="historyProductDetails">
              <summary><span>제품군별 제품 사용내역</span><span class="pill">3</span></summary>
              <div class="details-body" id="historyProductSummary">${productUsageSummaryHtml()}</div>
            </details>
          </div>
          <div class="card">
            <details class="item" id="historyPatientDetails">
              <summary><span>환자별 사용내역</span><span class="pill">${defaultPatientCount}</span></summary>
              <div class="details-body">
                <div class="actions"><button class="secondary" type="button" id="exportHistoryPatients">엑셀 저장</button></div>
                <div id="historyPatientList">${patientHistoryListHtml(defaultDate, defaultDate)}</div>
              </div>
            </details>
          </div>
        </section>
      `;
    };

    const historyFilterValues = () => ({
      start: document.getElementById("historyStart")?.value || "",
      end: document.getElementById("historyEnd")?.value || "",
      query: document.getElementById("historySearch")?.value || "",
      patientQuery: document.getElementById("historyPatientSearch")?.value || ""
    });

    const filteredHistoryUsages = (start, end, query, patientQuery = "") => {
      const normalizedQuery = context.normalizedName(query || "");
      const normalizedPatientQuery = context.normalizedName(patientQuery || "");
      const patientIdQuery = String(patientQuery || "").replace(/\D/g, "");
      return context.getState().usages.filter((usage) => {
        if (!context.inDateRange(usage.date, start, end)) return false;
        if (normalizedPatientQuery) {
          const patientText = context.normalizedName(`${usage.patientName || ""} ${context.patientIdText(usage)}`);
          const patientId = context.patientIdText(usage).replace(/\D/g, "");
          if (!patientText.includes(normalizedPatientQuery) && (!patientIdQuery || !patientId.includes(patientIdQuery))) return false;
        }
        if (!normalizedQuery) return true;
        const doctor = context.departmentById(usage.doctorId);
        const surgery = context.surgeryById(usage.surgeryId);
        const productText = usage.productIds.map((id) => {
          const product = context.productById(id);
          return `${product?.name || ""} ${product?.company || ""} ${product?.subcategory || ""}`;
        }).join(" ");
        return context.normalizedName(`${doctor?.name || ""} ${surgery?.name || ""} ${productText}`).includes(normalizedQuery);
      });
    };

    const productUsagePatientRows = (productId, start = "", end = "") => filteredHistoryUsages(start, end, "")
      .map((usage) => {
        const qty = (usage.productIds || []).filter((id) => id === productId).length;
        if (!qty) return null;
        const doctor = context.departmentById(usage.doctorId);
        const surgery = context.surgeryById(usage.surgeryId);
        return { usage, qty, doctor, surgery };
      })
      .filter(Boolean)
      .sort((a, b) => context.alphaFirstCompare(b.usage.date, a.usage.date) || context.alphaFirstCompare(a.usage.patientName, b.usage.patientName));

    const historyMovementCounts = (start = "", end = "") => {
      const usageCounts = new Map();
      filteredHistoryUsages(start, end, "").forEach((usage) => {
        usage.productIds.forEach((id) => usageCounts.set(id, (usageCounts.get(id) || 0) + 1));
      });
      const receiptCounts = new Map();
      context.getState().receipts
        .filter((receipt) => context.inDateRange(context.receiptDateValue(receipt), start, end))
        .forEach((receipt) => receiptCounts.set(receipt.productId, (receiptCounts.get(receipt.productId) || 0) + context.receiptStockDelta(receipt)));
      return { usageCounts, receiptCounts };
    };

    const productUsageSummaryRows = (category, start = "", end = "", query = "") => {
      const normalizedQuery = context.normalizedName(query || "");
      const { usageCounts, receiptCounts } = historyMovementCounts(start, end);
      return context.getState().products
        .filter((product) => context.productCategory(product.category) === category)
        .filter((product) => {
          if (!normalizedQuery) return (usageCounts.get(product.id) || 0) || (receiptCounts.get(product.id) || 0);
          return context.normalizedName(`${product.name} ${product.company || ""} ${product.subcategory || ""} ${context.productCategoryLabel(product.category)}`).includes(normalizedQuery);
        })
        .sort(context.productUsageSort(category))
        .map((product) => ({
          product,
          received: receiptCounts.get(product.id) || 0,
          used: usageCounts.get(product.id) || 0
        }));
    };

    const historyPeriodText = (start = "", end = "") => start || end
      ? `${start || "처음"} ~ ${end || "오늘"}`
      : "전체 기간";

    const reportPeriodFromFilters = (start = "", end = "") => {
      const fallback = context.today();
      const periodStart = start || end || fallback;
      const periodEnd = end || start || fallback;
      return periodStart <= periodEnd
        ? { start: periodStart, end: periodEnd }
        : { start: periodEnd, end: periodStart };
    };

    const reportPeriodLabel = (period) => period.start === period.end ? period.start : `${period.start} ~ ${period.end}`;

    const usageDateValue = (usage) => usage?.date || String(usage?.createdAt || usage?.updatedAt || "").slice(0, 10) || "";

    const productSeedFor = (product) => {
      const seeds = context.parseSeedProducts();
      const seedByKey = new Map(seeds.map((item) => [context.productKey(item), item]));
      const seedByLooseKey = new Map(seeds.map((item) => [context.productLooseKey(item), item]));
      return seedByKey.get(context.productKey(product)) || seedByLooseKey.get(context.productLooseKey(product));
    };

    const productMovementTotal = (productId, type, dateMatch = () => true) => {
      const state = context.getState();
      if (type === "receipt") {
        return state.receipts.reduce((sum, receipt) => {
          if (!context.sameId(receipt.productId, productId) || !dateMatch(context.receiptDateValue(receipt))) return sum;
          return sum + context.receiptStockDelta(receipt);
        }, 0);
      }
      return state.usages.reduce((sum, usage) => {
        if (!dateMatch(usageDateValue(usage))) return sum;
        return sum + (Array.isArray(usage.productIds) ? usage.productIds : []).filter((id) => context.sameId(id, productId)).length;
      }, 0);
    };

    const productInitialStock = (product, totalReceived, totalUsed) => {
      if (Number.isFinite(Number(product.baseStock))) return context.num(product.baseStock);
      const seed = productSeedFor(product);
      if (seed) return context.num(seed.baseStock);
      return context.num(product.stock) - totalReceived + totalUsed;
    };

    const productMatchesReportQuery = (product, query = "") => {
      const normalizedQuery = context.normalizedName(query || "");
      if (!normalizedQuery) return true;
      return context.normalizedName(`${product.name} ${product.company || ""} ${product.subcategory || ""} ${context.productCategoryLabel(product.category)}`).includes(normalizedQuery);
    };

    const latestReceiptDateForProduct = (productId) => context.getState().receipts.reduce((latest, receipt) => {
      if (!context.sameId(receipt.productId, productId)) return latest;
      const date = context.receiptDateValue(receipt);
      if (!date) return latest;
      return !latest || date > latest ? date : latest;
    }, "");

    const productStockFlowRows = (category, period, query = "") => context.getState().products
      .filter((product) => context.productCategory(product.category) === category)
      .filter((product) => productMatchesReportQuery(product, query))
      .sort(context.productUsageSort(category))
      .map((product) => {
        const totalReceived = productMovementTotal(product.id, "receipt");
        const totalUsed = productMovementTotal(product.id, "usage");
        const initialStock = productInitialStock(product, totalReceived, totalUsed);
        const basisReceived = productMovementTotal(product.id, "receipt", (date) => Boolean(date) && date < period.start);
        const basisUsed = productMovementTotal(product.id, "usage", (date) => Boolean(date) && date < period.start);
        const periodReceived = productMovementTotal(product.id, "receipt", (date) => Boolean(date) && date >= period.start && date <= period.end);
        const periodUsed = productMovementTotal(product.id, "usage", (date) => Boolean(date) && date >= period.start && date <= period.end);
        const basisStock = initialStock + basisReceived - basisUsed;
        const currentStock = basisStock + periodReceived - periodUsed;
        const systemCurrentStock = Math.max(0, initialStock + totalReceived - totalUsed);
        return {
          product,
          initialStock,
          totalReceived,
          totalUsed,
          basisStock,
          periodReceived,
          periodUsed,
          currentStock,
          systemCurrentStock,
          latestReceiptDate: latestReceiptDateForProduct(product.id)
        };
      });

    const productUsageSummaryHtml = (start = "", end = "", query = "") => {
      const defaultsToToday = !start && !end;
      const effectiveStart = defaultsToToday ? context.today() : start;
      const effectiveEnd = defaultsToToday ? context.today() : end;
      const periodText = defaultsToToday
        ? reportPeriodLabel({ start: effectiveStart, end: effectiveEnd })
        : historyPeriodText(start, end);
      const groups = context.productCategories.map((category) => {
        const productRows = productUsageSummaryRows(category, effectiveStart, effectiveEnd, query);
        const rows = productRows.map(({ product, received, used }) => {
          const isNonpay = context.productCategory(product.category) === "비급여";
          const patientRows = productUsagePatientRows(product.id, effectiveStart, effectiveEnd);
          return `
            <details class="summary-row ${isNonpay ? "nonpay" : ""}">
              <summary>
                <div class="summary-headline">
                  <span class="summary-name">${context.escapeHtml(product.name)}</span>
                  ${product.company || product.subcategory ? `<span class="summary-sub">${product.company ? `${context.escapeHtml(product.company)}` : ""}${product.subcategory ? `${product.company ? " · " : ""}${context.escapeHtml(product.subcategory)}` : ""}</span>` : ""}
                </div>
                <div class="summary-metrics">
                  <div class="metric"><span>기간입고</span> <strong>${received}</strong></div>
                  <div class="metric"><span>기간사용</span> <strong>${used}</strong></div>
                  <div class="metric ${context.stockStatusClass(product)}"><strong>${context.num(product.stock)}</strong><span>재고</span></div>
                </div>
              </summary>
              <div class="details-body">
                ${patientRows.length ? patientRows.map(({ usage, qty, doctor, surgery }) => `
                  <div class="item">
                    <div class="item-title"><span>${context.escapeHtml(context.patientDisplayName(usage))}</span><span class="pill">${qty}개</span></div>
                    <div class="meta">
                      <span>사용일: ${context.escapeHtml(usage.date)}</span>
                      ${context.auditMetaHtml(usage, "입력")}
                      <span>과/원장 코드: ${context.escapeHtml(doctor?.name || "-")} · 수술: ${context.escapeHtml(surgery?.department || context.inferSurgeryDepartment(surgery?.name || ""))} - ${context.escapeHtml(surgery?.name || "-")}</span>
                    </div>
                  </div>
                `).join("") : `<div class="empty">해당 기간 사용 환자가 없습니다.</div>`}
              </div>
            </details>
          `;
        }).join("");
        return `
          <details class="item">
            <summary><span>${context.escapeHtml(context.productCategoryLabel(category))} 제품 사용내역</span><span class="pill">${productRows.length}</span></summary>
            <div class="details-body">
              <div class="actions">
                <button class="secondary" type="button" data-export-history-category="${context.escapeHtml(category)}">보고용 엑셀</button>
                <button class="secondary" type="button" data-export-history-category-detail="${context.escapeHtml(category)}">상세 엑셀</button>
              </div>
              <div class="summary-table">${rows || `<div class="empty">해당 제품 사용내역이 없습니다.</div>`}</div>
            </div>
          </details>
        `;
      }).join("");
      return `
        <div class="meta" style="margin-bottom:10px;">
          <span>조회 기간: ${context.escapeHtml(periodText)}${query ? ` · 검색어: ${context.escapeHtml(query)}` : ""}</span>
        </div>
        ${groups}
      `;
    };

    const patientHistoryListHtml = (start = "", end = "", query = "", patientQuery = "") => {
      const usages = filteredHistoryUsages(start, end, query, patientQuery).slice().reverse();
      const openProducts = Boolean(String(query || patientQuery || "").trim());
      return usages.map((usage) => usageItem(usage, { openProducts })).join("") || `<div class="empty">사용내역이 없습니다.</div>`;
    };

    const productGroupTotal = (groupedProducts, category) => {
      const group = groupedProducts.find((item) => context.productCategory(item.category) === category);
      return group ? group.items.reduce((sum, item) => sum + item.qty, 0) : 0;
    };

    const implantLikeProductTotal = (groupedProducts) => groupedProducts
      .filter((group) => ["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(context.productCategory(group.category)))
      .reduce((sum, group) => sum + group.items.reduce((groupSum, item) => groupSum + item.qty, 0), 0);

    const implantPhotoCount = (records) => records.reduce((sum, record) => {
      const implants = Array.isArray(record.implants) ? record.implants : [];
      return sum + implants.reduce((photoSum, implant) => {
        const photos = Array.isArray(implant.photos) ? implant.photos : [];
        return photoSum + photos.filter((photo) => photo && (photo.url || photo.dataUrl || photo.preview || photo.src)).length;
      }, 0);
    }, 0);

    const implantStatusForUsage = (usage, groupedProducts) => {
      const records = (typeof context.getImplantRecords === "function" ? context.getImplantRecords() : [])
        .filter((record) => context.sameId(record.usageId, usage.id));
      const patientNos = Array.from(new Set(records.map((record) => context.implantPatientNoText?.(record) || "").filter(Boolean)));
      const hasDateMismatch = records.some((record) => {
        const recordDate = context.implantRecordDate?.(record) || "";
        return recordDate && usage.date && recordDate !== usage.date;
      });
      return {
        records,
        expectedCount: implantLikeProductTotal(groupedProducts),
        photoCount: implantPhotoCount(records),
        patientNos,
        hasDateMismatch
      };
    };

    const implantStatusBadgesHtml = (status) => {
      if (status.records.length) {
        return `
          <span class="usage-check-badge good">임플란트 장부 ${status.records.length}건</span>
          <span class="usage-check-badge ${status.photoCount ? "good" : "warn"}">사진 ${status.photoCount}장</span>
          <span class="usage-check-badge ${status.patientNos.length ? "good" : "warn"}">${status.patientNos.length ? `마감번호 #${context.escapeHtml(status.patientNos.join(", #"))}` : "미마감"}</span>
          ${status.hasDateMismatch ? `<span class="usage-check-badge danger">장부 날짜 확인</span>` : ""}
        `;
      }
      if (status.expectedCount) {
        return `<span class="usage-check-badge danger">임플란트 장부 없음</span>`;
      }
      return `<span class="usage-check-badge muted">임플란트 없음</span>`;
    };

    const usageItem = (usage, options = {}) => {
      const showDelete = options.showDelete !== false && context.canDeleteUsageRecord(usage);
      const showEdit = options.showEdit !== false && context.canEditUsage();
      const showActions = options.showDelete !== false && (showEdit || showDelete);
      const doctor = context.departmentById(usage.doctorId);
      const surgery = context.surgeryById(usage.surgeryId);
      const surgeryDepartment = surgery ? (surgery.department || context.inferSurgeryDepartment(surgery.name)) : "-";
      const productCounts = usage.productIds.reduce((map, id) => {
        map.set(id, (map.get(id) || 0) + 1);
        return map;
      }, new Map());
      const groupedProducts = context.productCategories.map((category) => {
        const items = Array.from(productCounts.entries())
          .map(([id, qty]) => ({ product: context.productById(id), id, qty }))
          .filter((item) => context.productCategory(item.product?.category) === category)
          .sort((a, b) => context.alphaFirstCompare(a.product?.name || "", b.product?.name || ""));
        return { category, items };
      }).filter((group) => group.items.length);
      const missingProducts = Array.from(productCounts.entries())
        .map(([id, qty]) => ({ id, qty, product: context.productById(id) }))
        .filter((item) => !item.product);
      const totalProductQty = Array.from(productCounts.values()).reduce((sum, qty) => sum + qty, 0);
      const nonpayTotal = productGroupTotal(groupedProducts, "비급여");
      const tissueTotal = productGroupTotal(groupedProducts, "인체조직");
      const implantStatus = implantStatusForUsage(usage, groupedProducts);
      const groupClass = (category) => {
        const key = context.productCategory(category);
        if (key === "비급여") return "nonpay";
        if (key === "인체조직") return "tissue";
        if (["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(key)) return "anchor";
        return "";
      };
      const doubleCheck = usage.doubleCheck || {};
      const doubleCheckText = doubleCheck.status === "finalSaved"
        ? `더블체크: 임시저장 ${doubleCheck.draftSavedBy || "-"}${doubleCheck.draftSavedAt ? ` (${context.formatDateTime(doubleCheck.draftSavedAt)})` : ""} · 최종저장 ${doubleCheck.finalSavedBy || "-"}${doubleCheck.finalSavedAt ? ` (${context.formatDateTime(doubleCheck.finalSavedAt)})` : ""}`
        : "";
      return `
        <div class="item">
          <div class="item-title">
            <span>${context.escapeHtml(context.patientDisplayName(usage))}</span>
            <span class="pill">${usage.date}</span>
          </div>
          <div class="meta">
            ${context.auditMetaHtml(usage, "입력")}
            ${doubleCheckText ? `<span>${context.escapeHtml(doubleCheckText)}</span>` : ""}
            <span>과/원장 코드: ${context.escapeHtml(doctor?.name || "-")} · 수술: ${context.escapeHtml(surgeryDepartment)} - ${context.escapeHtml(surgery?.name || "-")}</span>
            <div class="usage-check-badges">
              <span class="usage-check-badge ${nonpayTotal ? "warn" : "muted"}">비급여 ${nonpayTotal}개</span>
              <span class="usage-check-badge ${tissueTotal ? "info" : "muted"}">인체조직 ${tissueTotal}개</span>
              ${implantStatusBadgesHtml(implantStatus)}
            </div>
            <details class="usage-products-details" ${options.openProducts ? "open" : ""}>
              <summary>
                <span>사용제품 상세</span>
                <span class="pill">${totalProductQty}개</span>
              </summary>
              <div class="usage-products">
                ${groupedProducts.map((group) => `
                  <div class="usage-product-group ${groupClass(group.category)}">
                    <div class="usage-product-heading">
                      <span>${context.escapeHtml(context.productCategoryLabel(group.category))}</span>
                      <span class="pill ${group.category === "비급여" ? "low" : ""}">${group.items.reduce((sum, item) => sum + item.qty, 0)}개</span>
                    </div>
                    <div class="usage-product-chips">
                      ${group.items.map((item) => `<span class="usage-chip">${context.escapeHtml(item.product.name)}${item.qty > 1 ? ` · ${item.qty}개` : ""}</span>`).join("")}
                    </div>
                  </div>
                `).join("")}
                ${missingProducts.length ? `
                  <div class="usage-product-group">
                    <div class="usage-product-heading"><span>삭제된 제품</span><span class="pill">${missingProducts.reduce((sum, item) => sum + item.qty, 0)}개</span></div>
                    <div class="usage-product-chips">${missingProducts.map((item) => `<span class="usage-chip">삭제된 제품${item.qty > 1 ? ` · ${item.qty}개` : ""}</span>`).join("")}</div>
                  </div>
                ` : ""}
              </div>
            </details>
          </div>
          ${showActions ? `<div class="actions">
            ${showEdit ? `<button class="secondary" type="button" data-edit-usage="${usage.id}">${context.canModifyUsageRecord(usage) ? "사용내용 수정" : "사용내용 확인"}</button>` : ""}
            ${showDelete ? `<button class="danger" type="button" data-delete-usage="${usage.id}">사용내역 삭제</button>` : ""}
          </div>` : ""}
        </div>
      `;
    };

    const exportHistoryCategory = (category) => {
      const { start, end, query } = historyFilterValues();
      const period = reportPeriodFromFilters(start, end);
      const periodText = reportPeriodLabel(period);
      const rows = productStockFlowRows(category, period, query).map((item) => [
        item.product.name,
        context.productCategoryLabel(item.product.category),
        item.basisStock,
        periodText,
        item.periodReceived,
        item.periodUsed,
        item.currentStock
      ]);
      context.downloadExcel(
        `보고용_재고흐름_${context.productCategoryLabel(category)}_${periodText}.xlsx`,
        ["제품명", "분류", "기준재고", "조회기간", "기간입고", "기간사용", "현재고"],
        rows
      );
    };

    const exportHistoryCategoryDetail = (category) => {
      const { start, end, query } = historyFilterValues();
      const period = reportPeriodFromFilters(start, end);
      const periodText = reportPeriodLabel(period);
      const rows = productStockFlowRows(category, period, query).map((item) => [
        item.product.name,
        context.productCategoryLabel(item.product.category),
        item.basisStock,
        periodText,
        item.periodReceived,
        item.periodUsed,
        item.currentStock,
        item.product.company || "",
        item.latestReceiptDate,
        item.initialStock,
        item.totalReceived,
        item.totalUsed,
        item.systemCurrentStock
      ]);
      context.downloadExcel(
        `상세_재고흐름_${context.productCategoryLabel(category)}_${periodText}.xlsx`,
        ["제품명", "분류", "기준재고", "조회기간", "기간입고", "기간사용", "현재고", "업체명", "최근입고일", "초기재고", "누적입고", "누적사용", "시스템현재고"],
        rows
      );
    };

    const exportHistoryPatients = () => {
      const { start, end, query, patientQuery } = historyFilterValues();
      const rows = filteredHistoryUsages(start, end, query, patientQuery).slice().reverse().map((usage) => {
        const doctor = context.departmentById(usage.doctorId);
        const surgery = context.surgeryById(usage.surgeryId);
        const productText = usage.productIds.map((id) => context.productById(id)?.name || "삭제된 제품").join(", ");
        return [
          historyPeriodText(start, end),
          usage.date,
          usage.patientName,
          context.patientIdText(usage),
          context.auditUserText(usage),
          context.auditTimeText(usage),
          doctor?.name || "",
          surgery?.department || context.inferSurgeryDepartment(surgery?.name || ""),
          surgery?.name || "",
          productText
        ];
      });
      context.downloadExcel(
        `환자별_사용내역_${start || "all"}_${end || "all"}.xlsx`,
        ["조회기간", "사용일", "환자명", "환자ID", "입력자", "입력시각", "원장코드", "과", "수술", "사용제품"],
        rows
      );
    };

    const bindHistory = () => {
      const app = context.getApp();
      const startInput = document.getElementById("historyStart");
      const endInput = document.getElementById("historyEnd");
      const searchInput = document.getElementById("historySearch");
      const patientSearchInput = document.getElementById("historyPatientSearch");
      const summary = document.getElementById("historyProductSummary");
      const patientList = document.getElementById("historyPatientList");
      const bindHistoryExports = () => {
        app.querySelectorAll("[data-export-history-category]").forEach((button) => {
          button.addEventListener("click", () => exportHistoryCategory(button.dataset.exportHistoryCategory));
        });
        app.querySelectorAll("[data-export-history-category-detail]").forEach((button) => {
          button.addEventListener("click", () => exportHistoryCategoryDetail(button.dataset.exportHistoryCategoryDetail));
        });
        document.getElementById("exportHistoryPatients")?.addEventListener("click", exportHistoryPatients);
      };
      const updateHistory = () => {
        const start = startInput.value;
        const end = endInput.value;
        const query = searchInput.value;
        const patientQuery = patientSearchInput.value;
        summary.innerHTML = productUsageSummaryHtml(start, end, query);
        patientList.innerHTML = patientHistoryListHtml(start, end, query, patientQuery);
        const hasSearch = Boolean(String(query || patientQuery || "").trim());
        const patientDetails = document.getElementById("historyPatientDetails");
        const productDetails = document.getElementById("historyProductDetails");
        if (patientDetails && hasSearch) patientDetails.open = true;
        if (productDetails && query.trim()) productDetails.open = true;
        bindHistoryDeleteButtons();
        bindHistoryExports();
      };
      [startInput, endInput, searchInput, patientSearchInput].forEach((input) => {
        input.addEventListener("input", updateHistory);
        input.addEventListener("change", updateHistory);
      });
      document.getElementById("historyApply").addEventListener("click", updateHistory);
      document.getElementById("historyReset").addEventListener("click", () => {
        const defaultDate = defaultHistoryDate();
        startInput.value = defaultDate;
        endInput.value = defaultDate;
        searchInput.value = "";
        patientSearchInput.value = "";
        updateHistory();
      });
      const bindHistoryDeleteButtons = () => {
        if (patientList.dataset.boundHistoryActions === "true") return;
        patientList.dataset.boundHistoryActions = "true";
        patientList.addEventListener("click", async (event) => {
          const button = event.target.closest("button");
          if (!button) return;
          if (button.dataset.editUsage) {
            context.setPendingEditUsageId(button.dataset.editUsage);
            context.setCurrentView("edit");
            context.render();
            return;
          }
          if (!button.dataset.deleteUsage) return;
          await context.deleteUsageRecord(button.dataset.deleteUsage, { onSuccess: updateHistory });
        });
      };
      bindHistoryDeleteButtons();
      bindHistoryExports();
    };

    return {
      usageItem,
      renderHistory,
      bindHistory
    };
  };
})();
