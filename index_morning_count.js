(() => {
  window.createMorningCountModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const {
      escapeHtml,
      num,
      today,
      uid,
      sameId,
      productCategory,
      productCategoryLabel,
      productDisplaySort,
      productById,
      isVendorManagedProduct,
      formatDateTime,
      auditCreateFields,
      auditUpdateFields,
      auditUserText,
      currentAuditUser,
      saveState,
      render,
      setButtonBusy,
      downloadExcel,
      receiptDateValue,
      receiptStockDelta,
      setMorningCountDirty
    } = context;

    // 아침 실사: 실제 세어본 수량을 날짜별로 기록한다. 재고를 자동 보정하지 않는 기록 전용 화면.
    // 직전 실사값 + 그 이후 입고(±) − 오늘 실사값 = 그 사이 사용량(유추)을 계산해
    // OCS·앱 기록과 눈으로 대조하는 용도다. 저장은 입력(변경)한 품목만 병합한다.
    const CATEGORY_ORDER = ["비급여", "인체조직", "ANCHOR", "GS_LANDING", "URO_LANDING", "IMPLANT"];

    let countDate = "";
    const effectiveDate = () => countDate || today();
    // 분류 접기 상태 — 기본은 비급여만 열림(스크럽 기본 동선), 재렌더에도 유지.
    const openCategories = new Set(["비급여"]);

    const countableProducts = () => state.products
      .filter((item) => item.active !== false && !isVendorManagedProduct?.(item));

    const categoriesInUse = () => {
      const present = [...new Set(countableProducts().map((item) => productCategory(item.category)))].filter(Boolean);
      const known = CATEGORY_ORDER.filter((category) => present.includes(category));
      const unknown = present.filter((category) => !CATEGORY_ORDER.includes(category)).sort();
      return [...known, ...unknown];
    };

    const recordFor = (date) => (state.morningCounts || []).find((record) => (record.date || "") === date);

    const itemFor = (record, productId) => (record?.items || []).find((item) => sameId(item.productId, productId));

    // date 이전(< date)에 이 품목을 실사한 가장 최근 기록을 찾는다.
    const previousCount = (productId, date) => {
      const candidates = (state.morningCounts || [])
        .filter((record) => (record.date || "") < date && itemFor(record, productId))
        .sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")));
      const record = candidates[0];
      if (!record) return null;
      return { date: record.date, qty: Math.max(0, num(itemFor(record, productId).qty)) };
    };

    const dayBefore = (dateText) => {
      const date = new Date(`${dateText}T12:00:00`);
      date.setDate(date.getDate() - 1);
      return date.toISOString().slice(0, 10);
    };

    // 기준일(직전 실사일, 없으면 전일) ≤ 입고일 < 오늘 실사일 구간의 순입고(대여는 음수).
    // 기준일 아침 실사 이후 들어온 입고부터 오늘 아침 실사 전까지가 유추 구간이다.
    const receiptsNetBetween = (productId, startDate, endDate) => state.receipts.reduce((sum, receipt) => {
      if (!sameId(receipt.productId, productId)) return sum;
      const receiptDate = receiptDateValue(receipt);
      if (!receiptDate || receiptDate < startDate || receiptDate >= endDate) return sum;
      return sum + receiptStockDelta(receipt);
    }, 0);

    // 같은 구간의 앱 기록 사용량(케이스 기록 + 과거 방 마감 기록) — OCS 대조의 참고값.
    const recordedUsageBetween = (productId, startDate, endDate) => {
      const fromUsages = state.usages.reduce((sum, usage) => {
        const date = usage?.date || "";
        if (!date || date < startDate || date >= endDate) return sum;
        return sum + (usage.productIds || []).filter((id) => sameId(id, productId)).length;
      }, 0);
      const fromRefills = (state.roomRefills || []).reduce((sum, refill) => {
        const date = refill?.date || "";
        if (!date || date < startDate || date >= endDate) return sum;
        return sum + (refill.items || []).filter((item) => sameId(item.productId, productId))
          .reduce((qty, item) => qty + Math.max(0, num(item.qty)), 0);
      }, 0);
      return fromUsages + fromRefills;
    };

    const productCalc = (productId, date) => {
      const prev = previousCount(productId, date);
      const baseline = prev ? prev.date : dayBefore(date);
      return {
        prev,
        baseline,
        receiptsNet: receiptsNetBetween(productId, baseline, date),
        recordedUsage: recordedUsageBetween(productId, baseline, date)
      };
    };

    const inferredUsage = (calc, todayQty) => {
      if (!calc.prev || todayQty === "" || todayQty === null || todayQty === undefined) return null;
      return calc.prev.qty + calc.receiptsNet - Math.max(0, num(todayQty));
    };

    const inferredHtml = (calc, todayQty) => {
      const inferred = inferredUsage(calc, todayQty);
      if (inferred === null) {
        return calc.prev
          ? `<span class="muted">실사 수량을 입력하면 사용량이 계산됩니다.</span>`
          : `<span class="muted">이전 실사 기록이 없어 사용량을 계산할 수 없습니다. 오늘부터 기록됩니다.</span>`;
      }
      const overCount = inferred < 0;
      const usageText = overCount
        ? `실사가 계산보다 ${Math.abs(inferred)}개 많습니다 — 입고 누락이나 오입력을 확인해 주세요.`
        : `사용량(유추) <strong>${inferred}개</strong>`;
      return `
        <span class="${overCount ? "morning-count-over" : "morning-count-usage"}">${usageText}</span>
        <span class="muted"> · 앱 기록 사용 ${calc.recordedUsage}개</span>
      `;
    };

    const productRowHtml = (product, date) => {
      const record = recordFor(date);
      const saved = itemFor(record, product.id);
      const savedQty = saved ? Math.max(0, num(saved.qty)) : "";
      const calc = productCalc(product.id, date);
      const prevText = calc.prev
        ? `직전 실사 ${escapeHtml(calc.prev.date)} · ${calc.prev.qty}개`
        : "직전 실사 없음";
      const receiptText = `그 이후 입고 ${calc.receiptsNet > 0 ? "+" : ""}${calc.receiptsNet}개`;
      const savedByText = saved?.by ? ` · 입력 ${escapeHtml(saved.by)}` : "";
      return `
        <label class="check-card use-card morning-count-item">
          <span>${escapeHtml(product.name)}<br>
            <span class="muted">${escapeHtml(product.company || "")}${product.subcategory ? ` · ${escapeHtml(product.subcategory)}` : ""} · ${escapeHtml(window.ORPurchase.stockText(product))}${savedByText}</span><br>
            <span class="muted">${prevText} · ${receiptText}</span><br>
            <span data-morning-calc="${product.id}">${inferredHtml(calc, savedQty)}</span>
          </span>
          <input type="number" min="0" max="9999" inputmode="numeric" placeholder="수량"
            value="${savedQty === "" ? "" : savedQty}" data-morning-count-qty="${product.id}"
            aria-label="${escapeHtml(product.name)} 실사 수량">
        </label>
      `;
    };

    const categoryGroupHtml = (category, date) => {
      const products = countableProducts()
        .filter((item) => productCategory(item.category) === category)
        .sort(productDisplaySort(category));
      if (!products.length) return "";
      const record = recordFor(date);
      const entered = products.filter((product) => itemFor(record, product.id)).length;
      return `
        <details class="item" data-morning-category="${escapeHtml(category)}" ${openCategories.has(category) ? "open" : ""}>
          <summary><span>${escapeHtml(productCategoryLabel(category))}</span><span class="pill ${entered >= products.length ? "" : "low"}" data-morning-category-pill="${escapeHtml(category)}">입력 ${entered}/${products.length}</span></summary>
          <div class="details-body">
            ${products.map((product) => productRowHtml(product, date)).join("")}
          </div>
        </details>
      `;
    };

    const countItemsHtml = (date) => {
      const categories = categoriesInUse();
      if (!categories.length) return `<div class="empty">등록된 제품이 없습니다. 설정에서 제품을 등록해 주세요.</div>`;
      const dateWarning = date !== today()
        ? `<div class="helper" style="color:#c2410c;font-weight:900;">⚠️ 오늘(${escapeHtml(today())})이 아닌 ${escapeHtml(date)} 날짜의 실사를 보고 있습니다.</div>`
        : "";
      return `
        ${dateWarning}
        ${categories.map((category) => categoryGroupHtml(category, date)).join("")}
      `;
    };

    const monthStart = () => `${today().slice(0, 8)}01`;

    const countsInRange = (start, end) => (state.morningCounts || [])
      .filter((record) => (!start || (record.date || "") >= start) && (!end || (record.date || "") <= end))
      .slice()
      .sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")));

    const countHistoryHtml = (start, end) => {
      const records = countsInRange(start, end);
      if (!records.length) return `<div class="empty">조회 기간에 실사 기록이 없습니다.</div>`;
      return records.map((record) => {
        const items = record.items || [];
        const names = [...new Set(items.map((item) => item.by).filter(Boolean))];
        return `
          <div class="item">
            <div class="item-title">
              <span>${escapeHtml(record.date || "-")}</span>
              <span class="pill">${items.length}품목</span>
            </div>
            <div class="meta">
              <span>입력: ${escapeHtml(names.join(", ") || auditUserText(record) || "-")}</span>
              <span>최종 저장 ${escapeHtml(formatDateTime(record.updatedAt || record.createdAt || ""))}</span>
            </div>
          </div>
        `;
      }).join("");
    };

    const exportCountHistory = (start, end) => {
      const records = countsInRange(start, end);
      if (!records.length) {
        alert("조회 기간에 실사 기록이 없습니다.");
        return;
      }
      const rows = records.flatMap((record) => (record.items || []).map((item) => {
        const product = productById(item.productId);
        const calc = productCalc(item.productId, record.date || "");
        const inferred = inferredUsage(calc, Math.max(0, num(item.qty)));
        return [
          record.date || "",
          productCategoryLabel(product?.category || ""),
          product?.name || "삭제된 제품",
          product?.company || "",
          Math.max(0, num(item.qty)),
          calc.prev ? `${calc.prev.qty} (${calc.prev.date})` : "",
          calc.receiptsNet,
          inferred === null ? "" : inferred,
          calc.recordedUsage,
          item.by || "",
          item.at ? formatDateTime(item.at) : ""
        ];
      }));
      downloadExcel(
        `아침실사_${start || "all"}_${end || "all"}.xlsx`,
        ["날짜", "분류", "제품명", "업체", "실사수량", "직전실사", "이후입고", "사용량(유추)", "앱기록사용", "입력자", "입력시각"],
        rows
      );
    };

    const renderMorningCount = () => `
      <section class="grid">
        <div class="card">
          <h2>① 실사 기록 · 재고는 바뀌지 않음</h2>
          <p class="helper">실제 세어본 수량을 입력하고 저장하세요. <strong>입력한 품목만 저장</strong>되며, 다른 사람이 입력한 품목은 그대로 유지됩니다. 이 기록은 재고를 자동으로 고치지 않는 확인·대조용입니다.</p>
          <div class="row two">
            <div>
              <label for="morningCountDate">실사 날짜</label>
              <input id="morningCountDate" type="date" value="${effectiveDate()}">
            </div>
            <div>
              <label>&nbsp;</label>
              <button type="button" id="saveMorningCount">실사 저장</button>
            </div>
          </div>
          <div id="morningCountItems">${countItemsHtml(effectiveDate())}</div>
          <div class="actions">
            <button type="button" id="saveMorningCountBottom">실사 저장</button>
          </div>
        </div>
        <div class="card">
          <h2>실사 이력</h2>
          <div class="row three">
            <div>
              <label for="morningHistoryStart">시작일</label>
              <input id="morningHistoryStart" type="date" value="${monthStart()}">
            </div>
            <div>
              <label for="morningHistoryEnd">종료일</label>
              <input id="morningHistoryEnd" type="date" value="${today()}">
            </div>
            <div>
              <label>&nbsp;</label>
              <button class="secondary" type="button" id="exportMorningHistory">엑셀로 저장</button>
            </div>
          </div>
          <div id="morningHistoryList">${countHistoryHtml(monthStart(), today())}</div>
        </div>
      </section>
    `;

    const bindMorningCount = () => {
      const dateInput = document.getElementById("morningCountDate");
      const itemsWrap = document.getElementById("morningCountItems");
      if (!dateInput || !itemsWrap) return;
      // 전체 렌더 직후에는 화면이 저장된 상태와 일치하므로 보호를 해제한다.
      setMorningCountDirty?.(false);

      const refreshItems = () => {
        setMorningCountDirty?.(false);
        itemsWrap.innerHTML = countItemsHtml(effectiveDate());
        bindItems();
      };

      const bindItems = () => {
        // 분류 접기 상태를 기억해 재렌더 후에도 유지한다.
        itemsWrap.querySelectorAll("[data-morning-category]").forEach((details) => {
          details.addEventListener("toggle", () => {
            const category = details.dataset.morningCategory;
            if (details.open) openCategories.add(category); else openCategories.delete(category);
          });
        });
        // 값을 고치는 순간부터 원격 onSnapshot 재렌더로부터 입력을 보호하고, 사용량(유추)을 즉시 갱신한다.
        itemsWrap.querySelectorAll("[data-morning-count-qty]").forEach((input) => {
          input.addEventListener("input", () => {
            input.dataset.dirty = "1";
            setMorningCountDirty?.(true);
            const productId = input.dataset.morningCountQty;
            const calcTarget = itemsWrap.querySelector(`[data-morning-calc="${productId}"]`);
            if (calcTarget) {
              const calc = productCalc(productId, effectiveDate());
              calcTarget.innerHTML = inferredHtml(calc, input.value === "" ? "" : Math.max(0, num(input.value)));
            }
          });
        });
      };

      const collectDirtyItems = () => Array.from(itemsWrap.querySelectorAll("[data-morning-count-qty]"))
        .filter((input) => input.dataset.dirty === "1" && String(input.value).trim() !== "")
        .map((input) => ({
          productId: input.dataset.morningCountQty,
          qty: Math.max(0, num(input.value))
        }));

      const saveMorningCount = async (button) => {
        const date = effectiveDate();
        const entries = collectDirtyItems();
        if (!entries.length) {
          alert("입력하거나 고친 실사 수량이 없습니다.");
          return;
        }
        if (date !== today() && !confirm(`오늘이 아닌 ${date} 날짜의 실사로 저장합니다. 계속할까요?`)) return;
        const user = currentAuditUser();
        const byText = user?.name || user?.loginId || "";
        const at = new Date().toISOString();
        const stamped = entries.map((entry) => ({ ...entry, by: byText, at }));
        // 저장 충돌 시 재적용될 수 있도록 병합을 함수로 만든다(제품 삭제와 같은 패턴).
        const applyCountMerge = (s) => {
          const list = Array.isArray(s.morningCounts) ? s.morningCounts : [];
          const existing = list.find((record) => (record.date || "") === date);
          const record = existing || { id: uid(), date, items: [], ...auditCreateFields() };
          const kept = (record.items || []).filter((item) =>
            !stamped.some((entry) => sameId(entry.productId, item.productId)));
          record.items = [...kept, ...stamped];
          record.updatedAt = at;
          Object.assign(record, auditUpdateFields());
          s.morningCounts = existing ? list.map((item) => (item === existing ? record : item)) : [...list, record];
        };
        setButtonBusy(button, true, "저장 중...");
        applyCountMerge(context.getState());
        setMorningCountDirty?.(false);
        render();
        await saveState(`아침 실사 저장 완료 (${stamped.length}품목)`, {
          apply: applyCountMerge,
          savingMessage: "아침 실사 저장 중입니다...",
          doneMessage: `아침 실사 저장 완료 (${stamped.length}품목)`
        });
      };

      document.getElementById("saveMorningCount")?.addEventListener("click", (event) => saveMorningCount(event.currentTarget));
      document.getElementById("saveMorningCountBottom")?.addEventListener("click", (event) => saveMorningCount(event.currentTarget));
      dateInput.addEventListener("change", () => {
        countDate = dateInput.value || "";
        refreshItems();
      });
      bindItems();

      // 실사 이력 조회/엑셀
      const historyStart = document.getElementById("morningHistoryStart");
      const historyEnd = document.getElementById("morningHistoryEnd");
      const historyList = document.getElementById("morningHistoryList");
      const refreshHistory = () => {
        if (historyList) historyList.innerHTML = countHistoryHtml(historyStart?.value || "", historyEnd?.value || "");
      };
      [historyStart, historyEnd].forEach((input) => input?.addEventListener("change", refreshHistory));
      document.getElementById("exportMorningHistory")?.addEventListener("click", () =>
        exportCountHistory(historyStart?.value || "", historyEnd?.value || ""));
    };

    return {
      renderMorningCount,
      bindMorningCount
    };
  };
})();
