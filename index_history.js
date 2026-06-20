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
              <div class="details-body" id="historyProductSummary">${context.productUsageSummaryHtml()}</div>
            </details>
          </div>
          <div class="card">
            <details class="item">
              <summary><span>환자별 사용내역</span><span class="pill">${state.usages.length}</span></summary>
              <div class="details-body">
                <div class="actions"><button class="secondary" type="button" id="exportHistoryPatients">엑셀 저장</button></div>
                <div id="historyPatientList">${state.usages.slice().reverse().map(context.usageItem).join("") || `<div class="empty">사용내역이 없습니다.</div>`}</div>
              </div>
            </details>
          </div>
        </section>
      `;
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
          button.addEventListener("click", () => context.exportHistoryCategory(button.dataset.exportHistoryCategory));
        });
        app.querySelectorAll("[data-export-history-category-detail]").forEach((button) => {
          button.addEventListener("click", () => context.exportHistoryCategoryDetail(button.dataset.exportHistoryCategoryDetail));
        });
        document.getElementById("exportHistoryPatients")?.addEventListener("click", context.exportHistoryPatients);
      };
      const updateHistory = () => {
        const start = startInput.value;
        const end = endInput.value;
        const query = searchInput.value;
        summary.innerHTML = context.productUsageSummaryHtml(start, end, query);
        const usages = context.filteredHistoryUsages(start, end, query).slice().reverse();
        patientList.innerHTML = usages.map(context.usageItem).join("") || `<div class="empty">사용내역이 없습니다.</div>`;
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
      renderHistory,
      bindHistory
    };
  };
})();
