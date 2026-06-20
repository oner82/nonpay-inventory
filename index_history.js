(() => {
  window.createHistoryModule = (context) => {
    const renderHistory = () => {
      const state = context.getState();
      return `
        <section class="grid">
          <div class="card">
            <h2>사용내역 검색</h2>
            <div class="row three history-filter-grid">
              <div>
                <label for="historyStart">시작일</label>
                <input id="historyStart" type="date">
              </div>
              <div>
                <label for="historyEnd">종료일</label>
                <input id="historyEnd" type="date">
              </div>
              <div>
                <label for="historySearch">제품 검색</label>
                <input id="historySearch" list="historyProductList" autocomplete="off" placeholder="제품명 입력">
                <datalist id="historyProductList">
                  ${state.products.slice().sort(context.byName).map((product) => `<option value="${context.escapeHtml(product.name)}"></option>`).join("")}
                </datalist>
              </div>
            </div>
            <div class="actions">
              <button type="button" id="historyApply">기간 적용</button>
              <button class="secondary" type="button" id="historyReset">초기화</button>
            </div>
          </div>
          <div class="card">
            <details class="item">
              <summary><span>제품군별 제품 사용내역</span><span class="pill">3</span></summary>
              <div class="details-body" id="historyProductSummary">${productUsageSummaryHtml()}</div>
            </details>
          </div>
          <div class="card">
            <details class="item">
              <summary><span>환자별 사용내역</span><span class="pill">${state.usages.length}</span></summary>
              <div class="details-body">
                <div class="actions"><button class="secondary" type="button" id="exportHistoryPatients">엑셀 저장</button></div>
                <div id="historyPatientList">${patientHistoryListHtml()}</div>
              </div>
            </details>
          </div>
        </section>
      `;
    };

    const historyFilterValues = () => ({
      start: document.getElementById("historyStart")?.value || "",
      end: document.getElementById("historyEnd")?.value || "",
      query: document.getElementById("historySearch")?.value || ""
    });

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

    const productUsageSummaryHtml = (start = "", end = "", query = "") => {
      const defaultsToToday = !start && !end;
      const effectiveStart = defaultsToToday ? context.today() : start;
      const effectiveEnd = defaultsToToday ? context.today() : end;
      const periodText = defaultsToToday
        ? reportPeriodLabel({ start: effectiveStart, end: effectiveEnd })
        : historyPeriodText(start, end);
      const groups = context.productCategories.map((category) => {
        const productRows = context.productUsageSummaryRows(category, effectiveStart, effectiveEnd, query);
        const rows = productRows.map(({ product, received, used }) => {
          const isNonpay = context.productCategory(product.category) === "비급여";
          const patientRows = context.productUsagePatientRows(product.id, effectiveStart, effectiveEnd);
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

    const patientHistoryListHtml = (start = "", end = "", query = "") => {
      const usages = context.filteredHistoryUsages(start, end, query).slice().reverse();
      return usages.map(context.usageItem).join("") || `<div class="empty">사용내역이 없습니다.</div>`;
    };

    const exportHistoryCategory = (category) => {
      const { start, end, query } = historyFilterValues();
      const period = reportPeriodFromFilters(start, end);
      const periodText = reportPeriodLabel(period);
      const rows = context.productStockFlowRows(category, period, query).map((item) => [
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
      const rows = context.productStockFlowRows(category, period, query).map((item) => [
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
      const { start, end, query } = historyFilterValues();
      const rows = context.filteredHistoryUsages(start, end, query).slice().reverse().map((usage) => {
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
        summary.innerHTML = productUsageSummaryHtml(start, end, query);
        patientList.innerHTML = patientHistoryListHtml(start, end, query);
        bindHistoryDeleteButtons();
        bindHistoryExports();
      };
      [startInput, endInput, searchInput].forEach((input) => {
        input.addEventListener("input", updateHistory);
        input.addEventListener("change", updateHistory);
      });
      document.getElementById("historyApply").addEventListener("click", updateHistory);
      document.getElementById("historyReset").addEventListener("click", () => {
        startInput.value = "";
        endInput.value = "";
        searchInput.value = "";
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
      historyPeriodText,
      reportPeriodFromFilters,
      reportPeriodLabel,
      productUsageSummaryHtml,
      patientHistoryListHtml,
      renderHistory,
      bindHistory,
      exportHistoryCategory,
      exportHistoryCategoryDetail,
      exportHistoryPatients
    };
  };
})();
