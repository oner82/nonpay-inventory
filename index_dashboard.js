(() => {
  window.createDashboardModule = (context) => {
    const statCard = (label, value, icon) => `
      <div class="card stat" data-icon="${context.escapeHtml(icon)}">
        <strong>${value}</strong>
        <span>${label}</span>
      </div>
    `;

    const renderDashboard = () => {
      const state = context.getState();
      const lowProducts = state.products
        .filter((item) => !context.isVendorManagedProduct?.(item) && context.num(item.stock) <= context.num(item.warningStock))
        .sort((a, b) => context.num(a.stock) - context.num(b.stock) || context.alphaFirstCompare(a.name, b.name));
      const hiddenLowIds = new Set(state.hiddenLowProductIds || []);
      const visibleLowProducts = lowProducts.filter((item) => !hiddenLowIds.has(item.id));
      const hiddenLowProducts = lowProducts.filter((item) => hiddenLowIds.has(item.id));

      const todayText = context.today();
      const todayDate = new Date(`${todayText}T00:00:00`);
      const dateOffsetText = (date, offset) => {
        const next = new Date(date);
        next.setDate(next.getDate() + offset);
        next.setMinutes(next.getMinutes() - next.getTimezoneOffset());
        return next.toISOString().slice(0, 10);
      };
      const dateDistance = (dateText) => {
        const date = new Date(`${dateText || ""}T00:00:00`);
        if (Number.isNaN(date.getTime())) return 9999;
        return Math.floor((todayDate - date) / 86400000);
      };

      const yesterdayText = dateOffsetText(todayDate, -1);
      const todayUsages = state.usages.filter((item) => item.date === todayText);
      const yesterdayLoanQty = state.receipts
        .filter((receipt) => receipt.type === "loan" && context.receiptDateValue(receipt) === yesterdayText)
        .reduce((sum, receipt) => sum + Math.max(1, context.num(receipt.qty)), 0);
      const recentUsages = state.usages.filter((item) => {
        const distance = dateDistance(item.date);
        return distance >= 0 && distance <= 6;
      });
      // 방 마감 보충 기록 = 비급여 사용량 (오늘/최근 7일)
      const todayRefills = (state.roomRefills || []).filter((refill) => refill.date === todayText);
      const recentRefills = (state.roomRefills || []).filter((refill) => {
        const distance = dateDistance(refill.date);
        return distance >= 0 && distance <= 6;
      });
      const refillQtySum = (refills) => refills.reduce((sum, refill) =>
        sum + (refill.items || []).reduce((qty, item) => qty + Math.max(0, context.num(item.qty)), 0), 0);
      const todayProductCount = todayUsages.reduce((sum, item) => sum + (item.productIds || []).length, 0) + refillQtySum(todayRefills);
      const pendingLandingLines = context.landingUsageLines(false);
      const openPendingUsageItems = context.pendingUsagesOpen();

      const todayCategoryCounts = context.PRODUCT_CATEGORIES.map((category) => ({
        category,
        count: todayUsages.reduce((sum, usage) => sum + (usage.productIds || []).filter((id) => context.productCategory(context.productById(id)?.category) === category).length, 0)
          + (category === "비급여" ? refillQtySum(todayRefills) : 0)
      }));

      const productUseMap = new Map();
      recentUsages.forEach((usage) => {
        (usage.productIds || []).forEach((productId) => {
          productUseMap.set(productId, (productUseMap.get(productId) || 0) + 1);
        });
      });
      recentRefills.forEach((refill) => {
        (refill.items || []).forEach((item) => {
          productUseMap.set(item.productId, (productUseMap.get(item.productId) || 0) + Math.max(0, context.num(item.qty)));
        });
      });
      const topUsedProducts = Array.from(productUseMap.entries())
        .map(([productId, count]) => ({ product: context.productById(productId), count }))
        .filter((item) => item.product)
        .sort((a, b) => b.count - a.count || context.alphaFirstCompare(a.product.name, b.product.name))
        .slice(0, 8);

      const pendingByCompany = Array.from(pendingLandingLines.reduce((map, line) => {
        const company = line.product.company || "업체 없음";
        const current = map.get(company) || { company, lines: 0, qty: 0, products: new Set() };
        current.lines += 1;
        current.qty += Math.max(1, context.num(line.qty));
        current.products.add(line.product.name);
        map.set(company, current);
        return map;
      }, new Map()).values()).sort((a, b) => b.lines - a.lines || context.alphaFirstCompare(a.company, b.company));

      const todayUsageBrief = todayUsages.slice().reverse().slice(0, 5);
      const lowPriorityProducts = visibleLowProducts.slice(0, 6);

      return `
        <section class="dashboard-shell">
          <div class="stats">
            ${statCard("오늘 사용 케이스", todayUsages.length.toLocaleString(), "P")}
            ${statCard("오늘 미마감 방", `${Math.max(0, context.CASE_ROOM_COUNT - new Set(todayRefills.map((refill) => String(refill.room || ""))).size)}`, "방")}
            ${statCard("오늘 사용 제품", todayProductCount.toLocaleString(), "✓")}
            ${statCard("전날 대여", yesterdayLoanQty.toLocaleString(), "대여")}
            ${statCard("스크럽 확인 대기", openPendingUsageItems.length.toLocaleString(), "확인")}
            ${statCard("랜딩 입고 대기", pendingLandingLines.length.toLocaleString(), "↙")}
            ${statCard("재고 부족 확인", lowProducts.length.toLocaleString(), "!")}
          </div>

          <div class="dashboard-content">
            <div class="dashboard-left">
              <div class="card">
                <h2>오늘 사용 현황</h2>
                <div class="summary-table">
                  <details class="summary-row" open>
                    <summary>
                      <div class="summary-headline">
                        <span class="summary-name">오늘 입력된 사용내역</span>
                        <span class="summary-sub">${todayUsages.length}건 · 제품 ${todayProductCount}개</span>
                      </div>
                      <div class="summary-metrics">
                        ${todayCategoryCounts.map((item) => `<div class="metric"><strong>${item.count}</strong><span>${context.escapeHtml(context.productCategoryLabel(item.category))}</span></div>`).join("")}
                      </div>
                    </summary>
                  </details>
                </div>
                ${todayUsageBrief.length ? todayUsageBrief.map((item) => context.usageItem(item, { showDelete: false })).join("") : `<div class="empty">오늘 입력된 사용내역이 없습니다.</div>`}
                <div class="actions">
                  <button type="button" data-go-view="use">사용입력 바로가기</button>
                  <button class="secondary" type="button" data-go-view="history">사용내역 확인</button>
                  <button class="secondary" type="button" data-go-view="edit">사용내용 수정</button>
                </div>
              </div>

              <div class="card">
                <h2>랜딩 입고 대기</h2>
                ${pendingByCompany.length ? pendingByCompany.slice(0, 6).map((item) => `
                  <div class="item landing-line pending">
                    <div class="compact-line">
                      <div class="compact-main">${context.escapeHtml(item.company)}</div>
                      <div class="compact-meta">대기 ${item.lines}건 · ${item.qty}개 · 품목 ${item.products.size}</div>
                      <span class="pill low">확인 필요</span>
                    </div>
                  </div>
                `).join("") : `<div class="empty">랜딩 입고 대기 항목이 없습니다.</div>`}
                <div class="actions">
                  <button type="button" data-go-view="receipts">입고관리로 이동</button>
                </div>
              </div>

              <div class="card">
                <h2>최근 7일 많이 사용한 제품</h2>
                ${topUsedProducts.length ? topUsedProducts.map((item, index) => `
                  <div class="item">
                    <div class="item-title">
                      <span>${index + 1}. ${context.escapeHtml(item.product.name)}</span>
                      <span class="pill">${item.count}개</span>
                    </div>
                    <div class="meta">
                      <span>${context.escapeHtml(context.productCategoryLabel(item.product.category))}${item.product.company ? ` · ${context.escapeHtml(item.product.company)}` : ""}${item.product.subcategory ? ` · ${context.escapeHtml(item.product.subcategory)}` : ""}</span>
                      <span>${context.isVendorManagedProduct?.(item.product) ? "업체관리 · 재고차감 제외" : `현재고 ${context.num(item.product.stock)} · 경고수량 ${context.num(item.product.warningStock)}`}</span>
                    </div>
                  </div>
                `).join("") : `<div class="empty">최근 7일 사용 데이터가 없습니다.</div>`}
              </div>
            </div>

            <div class="dashboard-right">
              <div class="card">
                <h2>재고 부족 우선 확인</h2>
                ${lowPriorityProducts.length ? lowPriorityProducts.map(context.lowProductItem).join("") : `<div class="empty">표시할 재고 부족 품목이 없습니다.</div>`}
                ${hiddenLowProducts.length ? `<details class="item"><summary><span>감춰진 경고 재고</span><span class="pill">${hiddenLowProducts.length}</span></summary><div class="details-body">${hiddenLowProducts.map((item) => context.lowProductItem(item, true)).join("")}</div></details>` : ""}
                <div class="actions">
                  <button class="secondary" type="button" data-go-view="settings">제품관리</button>
                </div>
              </div>

              <div class="card">
                <h2>분류별 현재 재고</h2>
                <div class="summary-table">
                  ${context.PRODUCT_CATEGORIES.map((category) => {
                    const items = state.products.filter((item) => context.productCategory(item.category) === category);
                    const stockItems = items.filter((item) => !context.isVendorManagedProduct?.(item));
                    const stock = stockItems.reduce((sum, item) => sum + context.num(item.stock), 0);
                    const low = stockItems.filter((item) => context.num(item.stock) <= context.num(item.warningStock)).length;
                    return `
                      <details class="summary-row ${category === "비급여" ? "nonpay" : ""}" open>
                        <summary>
                          <div class="summary-headline">
                            <span class="summary-name">${context.escapeHtml(context.productCategoryLabel(category))}</span>
                            <span class="summary-sub">${items.length}품목</span>
                          </div>
                          <div class="summary-metrics">
                            <div class="metric"><strong>${stock}</strong><span>재고</span></div>
                            <div class="metric ${low ? "stock-danger" : "stock-ok"}"><strong>${low}</strong><span>부족</span></div>
                            <div class="metric"><strong>${stockItems.reduce((sum, item) => sum + context.num(item.warningStock), 0)}</strong><span>경고합</span></div>
                          </div>
                        </summary>
                      </details>
                    `;
                  }).join("")}
                </div>
              </div>

              <div class="card">
                <h2>최근 사용 내역</h2>
                ${state.usages.slice().reverse().slice(0, 4).map((item) => context.usageItem(item, { showDelete: false })).join("") || `<div class="empty">사용내역이 없습니다.</div>`}
              </div>
            </div>
          </div>
        </section>
      `;
    };

    const bindDashboard = () => {
      const app = context.getApp();
      app.querySelectorAll("[data-go-view]").forEach((button) => {
        button.addEventListener("click", () => {
          context.setCurrentView(button.dataset.goView);
          context.render();
        });
      });
      app.querySelectorAll("[data-hide-low-product]").forEach((button) => {
        button.addEventListener("click", async () => {
          const state = context.getState();
          const id = button.dataset.hideLowProduct;
          state.hiddenLowProductIds = [...new Set([...(state.hiddenLowProductIds || []), id])];
          context.render();
          await context.saveState();
        });
      });
      app.querySelectorAll("[data-show-low-product]").forEach((button) => {
        button.addEventListener("click", async () => {
          const state = context.getState();
          const id = button.dataset.showLowProduct;
          state.hiddenLowProductIds = (state.hiddenLowProductIds || []).filter((item) => item !== id);
          context.render();
          await context.saveState();
        });
      });
    };

    return {
      renderDashboard,
      bindDashboard
    };
  };
})();
