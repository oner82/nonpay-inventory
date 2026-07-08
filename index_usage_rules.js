(() => {
  window.createUsageRulesModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const app = context.getApp();
    const {
      departmentNames,
      departmentCompare,
      departmentCode,
      departmentById,
      surgeryById,
      inferSurgeryDepartment,
      isCommonSurgery,
      visibleSurgeriesFor,
      productById,
      productCategory,
      productCategoryLabel,
      productDisplaySort,
      isVendorManagedProduct,
      qtyStepper,
      PRODUCT_CATEGORIES,
      alphaFirstCompare,
      normalizedName,
      byName,
      escapeHtml,
      sameId,
      uid,
      num,
      render,
      saveState
    } = context;
    let filterRuleOptions = null;
    let usageRuleListFilterFromForm = null;

const renderUsageRules = () => {
  const rules = sortedUsageRules();
  const departmentCount = new Set(rules.map((rule) => rule.department || "미분류")).size;
  const productCount = rules.reduce((sum, rule) => sum + ruleItems(rule).reduce((innerSum, item) => innerSum + Math.max(1, num(item.qty)), 0), 0);
  return `
  <section class="grid two">
    <form class="card" id="usageRuleForm">
      <h2 id="usageRuleFormTitle">수술별 사용관리 추가</h2>
      <input type="hidden" id="usageRuleId">
      <label for="ruleDepartment">과</label>
      <select id="ruleDepartment" required>
        <option value="">과 선택</option>
        ${departmentNames().map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}
      </select>
      <label for="ruleDoctor">원장코드</label>
      <select id="ruleDoctor" required>
        <option value="">과를 먼저 선택하세요</option>
      </select>
      <div class="muted">과를 먼저 선택하면 해당 과 원장코드만 표시되고, 원장코드 선택 후 등록 가능한 수술이 표시됩니다.</div>
      <label for="ruleSurgery">수술</label>
      <select id="ruleSurgery" required>
        <option value="">수술 선택</option>
        ${state.surgeries.slice().sort((a, b) => alphaFirstCompare(a.department || inferSurgeryDepartment(a.name), b.department || inferSurgeryDepartment(b.name)) || alphaFirstCompare(a.name, b.name)).map((item) => `<option value="${item.id}" data-department="${escapeHtml(item.department || inferSurgeryDepartment(item.name))}">${escapeHtml(item.department || inferSurgeryDepartment(item.name))} - ${escapeHtml(item.name)}</option>`).join("")}
      </select>
      <label>추천 항목</label>
      <div class="product-picker">
        ${renderRuleProductSelector()}
      </div>
      <div class="actions">
        <button type="submit">설정 저장</button>
        <button class="secondary" type="button" id="usageRuleReset">새로 입력</button>
      </div>
    </form>
    <div class="card">
      <h2>수술별 사용관리 목록</h2>
      <div class="usage-rule-tools" aria-label="수술별 사용관리 목록 찾기">
        <div class="usage-rule-summary">
          <span><strong>${rules.length}</strong>등록 규칙</span>
          <span><strong>${departmentCount}</strong>과 분류</span>
          <span><strong>${productCount}</strong>추천 수량 합계</span>
        </div>
        <div class="usage-rule-filter-row">
          <select id="usageRuleDepartmentFilter" aria-label="과별 목록 검색">
            <option value="">전체 과</option>
            ${[...new Set(rules.map((rule) => rule.department || "미분류"))].sort(departmentCompare).map((department) => `<option value="${escapeHtml(department)}">${escapeHtml(department)}</option>`).join("")}
          </select>
          <select id="usageRuleDoctorFilter" aria-label="선택 과의 원장코드별 목록 검색">
            <option value="">과를 먼저 선택하세요</option>
          </select>
          <select id="usageRuleSurgeryFilter" aria-label="선택 원장코드의 수술별 목록 검색">
            <option value="">원장코드를 선택하면 수술이 표시됩니다</option>
          </select>
          <button class="secondary" type="button" id="usageRuleClearFilter">초기화</button>
        </div>
      </div>
      <p class="usage-rule-help">목록은 과별로 접어서 정리했고, 과를 먼저 고른 뒤 해당 과 원장코드와 원장에게 등록된 수술만 순서대로 표시됩니다. 왼쪽 추가 폼에서 과/원장코드를 선택해도 오른쪽 관련 카드가 즉시 필터링됩니다.</p>
      <div id="usageRuleFilterEmpty" class="empty" hidden>검색 조건에 맞는 규칙이 없습니다.</div>
      <div id="usageRuleList" class="usage-rule-list">
        ${renderUsageRuleGroups(rules)}
      </div>
    </div>
  </section>
`;
};

const ruleItems = (rule) => Array.isArray(rule.items)
  ? rule.items
  : Array.isArray(rule.nonpayItems)
  ? rule.nonpayItems
  : (rule.nonpayProductIds || []).map((productId) => ({ productId, qty: 1 }));

const renderRuleProductSelector = () => {
  if (!state.products.length) return `<div class="empty">제품이 없습니다.</div>`;
  const categories = PRODUCT_CATEGORIES;
  return categories.map((category) => {
    const items = state.products.filter((item) => productCategory(item.category) === category).sort(productDisplaySort(category));
    if (!items.length) return "";
    return `
      <details class="item">
        <summary><span>${escapeHtml(productCategoryLabel(category))}</span><span class="pill">${items.length}</span></summary>
        <div class="details-body">
          ${items.map(ruleProductItem).join("")}
        </div>
      </details>
    `;
  }).join("");
};

const ruleProductItem = (item) => {
  // 업체관리품은 병원이 재고를 관리하지 않으므로 재고량을 표시하지 않는다.
  const vendorManaged = isVendorManagedProduct?.(item);
  const stockText = vendorManaged ? "업체관리 · 재고차감 제외" : `현재고 ${num(item.stock)}`;
  return `
  <label class="check-card rule-card">
    <input type="checkbox" value="${item.id}" data-rule-product>
    <span>${escapeHtml(item.name)}<br><span class="muted">${escapeHtml(productCategoryLabel(item.category))}${item.company ? ` · ${escapeHtml(item.company)}` : ""}${item.subcategory ? ` · ${escapeHtml(item.subcategory)}` : ""} · ${stockText}</span></span>
    ${qtyStepper(`data-rule-product-qty="${item.id}" aria-label="${escapeHtml(item.name)} 추천 수량"`, 1, vendorManaged ? 999 : Math.max(1, num(item.stock)))}
  </label>
`;
};

const sortedUsageRules = () => state.usageRules.slice().sort((a, b) =>
  departmentCompare(a.department || "", b.department || "") ||
  alphaFirstCompare(departmentById(a.doctorId)?.name, departmentById(b.doctorId)?.name) ||
  alphaFirstCompare(surgeryById(a.surgeryId)?.name, surgeryById(b.surgeryId)?.name)
);

const usageRuleSearchText = (rule) => {
  const doctor = departmentById(rule.doctorId);
  const surgery = surgeryById(rule.surgeryId);
  const itemText = ruleItems(rule).map((item) => {
    const product = productById(item.productId);
    return [product?.name, productCategoryLabel(product?.category), product?.company, product?.subcategory, item.qty].filter(Boolean).join(" ");
  }).join(" ");
  return normalizedName([rule.department, doctor?.name, surgery?.department, surgery?.name, itemText].filter(Boolean).join(" "));
};

const usageRuleDoctorOptions = (department = "", rules = state.usageRules) => {
  const allowedDoctorIds = department
    ? new Set(rules.filter((rule) => (rule.department || "미분류") === department).map((rule) => String(rule.doctorId || "")))
    : null;
  return state.doctors
    .slice()
    .sort(byName)
    .filter((doctor) => (!department || departmentCode(doctor.name) === department) && (!allowedDoctorIds || allowedDoctorIds.has(String(doctor.id))))
    .map((doctor) => `<option value="${escapeHtml(doctor.id)}">${escapeHtml(doctor.name)}</option>`)
    .join("");
};

const usageRuleSurgeryOptions = (rules, doctorId = "", department = "") => {
  if (!doctorId) return "";
  const surgeries = new Map();
  rules
    .filter((rule) => sameId(rule.doctorId, doctorId) && (!department || (rule.department || "미분류") === department))
    .forEach((rule) => {
      const surgery = surgeryById(rule.surgeryId);
      if (!surgery?.name || surgeries.has(String(rule.surgeryId))) return;
      const surgeryDepartment = surgery.department || inferSurgeryDepartment(surgery.name) || rule.department || "미분류";
      surgeries.set(String(rule.surgeryId), `${surgeryDepartment} - ${surgery.name}`);
    });
  return [...surgeries.entries()]
    .sort((a, b) => alphaFirstCompare(a[1], b[1]))
    .map(([id, name]) => `<option value="${escapeHtml(id)}">${escapeHtml(name)}</option>`)
    .join("");
};

const renderUsageRuleGroups = (rules) => {
  if (!rules.length) return `<div class="empty">등록된 규칙이 없습니다.</div>`;
  const grouped = rules.reduce((map, rule) => {
    const department = rule.department || "미분류";
    if (!map.has(department)) map.set(department, []);
    map.get(department).push(rule);
    return map;
  }, new Map());
  return [...grouped.entries()].map(([department, items]) => `
    <details class="item usage-rule-group" data-rule-group="${escapeHtml(department)}" open>
      <summary><span>${escapeHtml(department)} 수술별 사용관리</span><span class="pill" data-rule-group-count>${items.length}</span></summary>
      <div class="usage-rule-group-body">
        ${items.map(ruleItem).join("")}
      </div>
    </details>
  `).join("");
};

const ruleItem = (rule) => {
  const doctor = departmentById(rule.doctorId);
  const surgery = surgeryById(rule.surgeryId);
  const items = ruleItems(rule);
  const productChips = items.map((item) => {
    const product = productById(item.productId);
    return `<span class="usage-rule-product-chip">${escapeHtml(product?.name || "삭제된 제품")} · ${Math.max(1, num(item.qty))}개</span>`;
  }).join("");
  const totalQty = items.reduce((sum, item) => sum + Math.max(1, num(item.qty)), 0);
  return `
    <div class="item usage-rule-card" data-rule-card data-rule-department="${escapeHtml(rule.department || "미분류")}" data-rule-doctor="${escapeHtml(rule.doctorId || "")}" data-rule-surgery="${escapeHtml(rule.surgeryId || "")}" data-rule-search="${escapeHtml(usageRuleSearchText(rule))}">
      <div class="item-title">
        <span>${escapeHtml(doctor?.name || "-")} · ${escapeHtml(surgery?.name || "-")}</span>
        <span class="pill">${items.length}종 / ${totalQty}개</span>
      </div>
      <div class="meta">
        <span>수술: ${escapeHtml(surgery?.name || "-")}</span>
        <span>원장코드: ${escapeHtml(doctor?.name || "-")}</span>
      </div>
      <div class="usage-rule-products">${productChips || `<span class="usage-rule-product-chip">추천 항목 없음</span>`}</div>
      <div class="actions">
        <button class="secondary" type="button" data-edit-rule="${rule.id}">수정</button>
        <button class="danger" type="button" data-delete-rule="${rule.id}">삭제</button>
      </div>
    </div>
  `;
};

const bindUsageRuleListFilters = () => {
  const doctorFilter = document.getElementById("usageRuleDoctorFilter");
  const surgeryFilter = document.getElementById("usageRuleSurgeryFilter");
  const departmentFilter = document.getElementById("usageRuleDepartmentFilter");
  const clear = document.getElementById("usageRuleClearFilter");
  const empty = document.getElementById("usageRuleFilterEmpty");
  if (!doctorFilter || !surgeryFilter || !departmentFilter) return;
  const rules = sortedUsageRules();
  const syncDoctorFilter = () => {
    const department = departmentFilter.value;
    const currentDoctor = doctorFilter.value;
    const options = department ? usageRuleDoctorOptions(department, rules) : "";
    doctorFilter.innerHTML = `<option value="">${department ? "전체 원장코드" : "과를 먼저 선택하세요"}</option>${options}`;
    if (currentDoctor && Array.from(doctorFilter.options).some((option) => option.value === currentDoctor)) {
      doctorFilter.value = currentDoctor;
    }
    doctorFilter.disabled = !department;
  };
  const syncSurgeryFilter = () => {
    const currentSurgery = surgeryFilter.value;
    const department = departmentFilter.value;
    const doctorId = doctorFilter.value;
    const options = usageRuleSurgeryOptions(rules, doctorId, department);
    surgeryFilter.innerHTML = `<option value="">${doctorId ? "전체 수술" : "원장코드를 선택하면 수술이 표시됩니다"}</option>${options}`;
    if (currentSurgery && Array.from(surgeryFilter.options).some((option) => option.value === currentSurgery)) {
      surgeryFilter.value = currentSurgery;
    }
    surgeryFilter.disabled = !doctorId;
  };
  const apply = () => {
    const doctorId = doctorFilter.value;
    const surgeryId = surgeryFilter.value;
    const department = departmentFilter.value;
    let visibleTotal = 0;
    app.querySelectorAll("[data-rule-group]").forEach((group) => {
      let groupVisible = 0;
      group.querySelectorAll("[data-rule-card]").forEach((card) => {
        const matchesDepartment = !department || card.dataset.ruleDepartment === department;
        const matchesDoctor = !doctorId || sameId(card.dataset.ruleDoctor, doctorId);
        const matchesSurgery = !surgeryId || sameId(card.dataset.ruleSurgery, surgeryId);
        const visible = matchesDepartment && matchesDoctor && matchesSurgery;
        card.hidden = !visible;
        if (visible) groupVisible += 1;
      });
      group.hidden = groupVisible === 0;
      const count = group.querySelector("[data-rule-group-count]");
      if (count) count.textContent = groupVisible;
      if (groupVisible > 0 && (doctorId || surgeryId || department)) group.open = true;
      visibleTotal += groupVisible;
    });
    if (empty) empty.hidden = visibleTotal > 0 || !state.usageRules.length;
  };
  const applyExternalSelection = (department = "", doctorId = "", surgeryId = "") => {
    departmentFilter.value = Array.from(departmentFilter.options).some((option) => option.value === String(department)) ? String(department) : "";
    syncDoctorFilter();
    doctorFilter.value = doctorId && Array.from(doctorFilter.options).some((option) => option.value === String(doctorId)) ? String(doctorId) : "";
    syncSurgeryFilter();
    surgeryFilter.value = surgeryId && Array.from(surgeryFilter.options).some((option) => option.value === String(surgeryId)) ? String(surgeryId) : "";
    apply();
  };
  usageRuleListFilterFromForm = applyExternalSelection;
  context.setUsageRuleListFilterFromForm(usageRuleListFilterFromForm);
  doctorFilter.addEventListener("change", () => {
    syncSurgeryFilter();
    apply();
  });
  surgeryFilter.addEventListener("change", apply);
  departmentFilter.addEventListener("change", () => {
    syncDoctorFilter();
    syncSurgeryFilter();
    apply();
  });
  clear?.addEventListener("click", () => {
    departmentFilter.value = "";
    syncDoctorFilter();
    syncSurgeryFilter();
    apply();
    departmentFilter.focus();
  });
  syncDoctorFilter();
  syncSurgeryFilter();
  apply();
};

const bindUsageRules = () => {
  const form = document.getElementById("usageRuleForm");
  filterRuleOptions = (source = "") => {
    const departmentSelect = document.getElementById("ruleDepartment");
    const doctorSelect = document.getElementById("ruleDoctor");
    const surgerySelect = document.getElementById("ruleSurgery");
    let department = departmentSelect.value;
    let currentDoctor = doctorSelect.value;
    const currentSurgery = surgerySelect.value;
    const selectedDoctor = state.doctors.find((item) => item.id === currentDoctor);
    const inferredDepartment = selectedDoctor ? departmentCode(selectedDoctor.name) : "";
    if (currentDoctor && inferredDepartment !== department) {
      currentDoctor = "";
    }
    const doctors = department
      ? state.doctors.slice().sort(byName).filter((item) => departmentCode(item.name) === department)
      : [];
    doctorSelect.innerHTML = `<option value="">${department ? "원장코드 선택" : "과를 먼저 선택하세요"}</option>` + doctors
      .map((item) => `<option value="${item.id}" data-department="${escapeHtml(departmentCode(item.name))}">${escapeHtml(item.name)}</option>`)
      .join("");
    doctorSelect.disabled = !department;
    if (doctors.some((item) => item.id === currentDoctor)) {
      doctorSelect.value = currentDoctor;
    } else {
      currentDoctor = "";
    }
    const surgeries = department && currentDoctor
      ? visibleSurgeriesFor(department, currentDoctor)
      : [];
    surgerySelect.innerHTML = `<option value="">${department && currentDoctor ? "수술 선택" : "원장코드를 먼저 선택하세요"}</option>` + surgeries
      .map((item) => `<option value="${item.id}">${escapeHtml(item.name)}${isCommonSurgery(item) ? "" : " · 전용"}</option>`)
      .join("");
    surgerySelect.disabled = !(department && currentDoctor);
    if (surgeries.some((item) => item.id === currentSurgery)) surgerySelect.value = currentSurgery;
    usageRuleListFilterFromForm?.(department, currentDoctor, surgerySelect.value);
  };
  context.setFilterRuleOptions(filterRuleOptions);
  bindUsageRuleListFilters();
  document.getElementById("ruleDepartment").addEventListener("change", () => filterRuleOptions("department"));
  document.getElementById("ruleDoctor").addEventListener("change", () => filterRuleOptions("doctor"));
  document.getElementById("ruleSurgery").addEventListener("change", () => usageRuleListFilterFromForm?.(document.getElementById("ruleDepartment").value, document.getElementById("ruleDoctor").value, document.getElementById("ruleSurgery").value));
  document.getElementById("usageRuleReset").addEventListener("click", () => {
    form.reset();
    document.getElementById("usageRuleId").value = "";
    document.getElementById("usageRuleFormTitle").textContent = "수술별 사용관리 추가";
    filterRuleOptions();
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById("usageRuleId").value || uid();
    const items = Array.from(app.querySelectorAll("[data-rule-product]:checked")).map((input) => ({
      productId: input.value,
      qty: Math.max(1, num(app.querySelector(`[data-rule-product-qty="${input.value}"]`)?.value))
    }));
    const rule = {
      id,
      department: document.getElementById("ruleDepartment").value,
      doctorId: document.getElementById("ruleDoctor").value,
      surgeryId: document.getElementById("ruleSurgery").value,
      items,
      nonpayItems: items.filter((item) => productCategory(productById(item.productId)?.category) === "비급여"),
      nonpayProductIds: items.filter((item) => productCategory(productById(item.productId)?.category) === "비급여").map((item) => item.productId)
    };
    if (!rule.department || !rule.doctorId || !rule.surgeryId) return;
    state.usageRules = [...state.usageRules.filter((item) => !sameId(item.id, id)), rule];
    render();
    await saveState();
  });
  filterRuleOptions();
};



    return {
      renderUsageRules,
      bindUsageRules,
      ruleItems
    };
  };
})();
