(() => {
  window.createImplantVendorsModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const app = context.getApp();
    const {
      implantVendorById,
      alphaFirstCompare,
      escapeHtml,
      uid,
      auditUpdateFields,
      auditCreateFields,
      sameId,
      normalizedName,
      saveState
    } = context;
    const implantVendors = () => context.getImplantVendors();
    const dbRef = () => context.getDb();
    const docRef = (...args) => context.getDocFn()(...args);
    const setDocRef = (...args) => context.getSetDoc()(...args);

const renderImplantVendors = () => `
  <section class="grid">
    <form class="card" id="implantVendorForm">
      <h2 id="implantVendorFormTitle">임플란트 업체 연락처 추가</h2>
      <input type="hidden" id="implantVendorId">
      <div class="row two">
        <div>
          <label for="implantVendorName">업체명</label>
          <input id="implantVendorName" required autocomplete="off">
        </div>
        <div>
          <label for="implantVendorContactName">담당자</label>
          <input id="implantVendorContactName" autocomplete="off">
        </div>
      </div>
      <div class="row three">
        <div>
          <label for="implantVendorPhone">연락처</label>
          <input id="implantVendorPhone" inputmode="tel" autocomplete="off">
        </div>
        <div>
          <label for="implantVendorEmail">이메일</label>
          <input id="implantVendorEmail" type="email" autocomplete="off">
        </div>
        <div>
          <label for="implantVendorMessenger">문자/카톡 메모</label>
          <input id="implantVendorMessenger" autocomplete="off">
        </div>
      </div>
      <label for="implantVendorMemo">발송 메모</label>
      <textarea id="implantVendorMemo" placeholder="예: 매일 16시까지 사진 포함 장부 발송"></textarea>
      <div class="actions">
        <button type="submit">업체 저장</button>
        <button class="secondary" type="button" id="implantVendorReset">새로 입력</button>
      </div>
    </form>
    <div class="card">
      <h2>등록 업체</h2>
      <div class="implant-vendor-contact-list">
        ${implantVendors().length ? implantVendors().slice().sort((a, b) => alphaFirstCompare(a.name, b.name)).map((vendor) => `
          <div class="item ${vendor.active === false ? "landing-line" : ""}">
            <div class="item-title">
              <span>${escapeHtml(vendor.name || "업체명 없음")}</span>
              <span class="pill ${vendor.active === false ? "low" : ""}">${vendor.active === false ? "발송 정지" : "발송 가능"}</span>
            </div>
            <div class="meta">
              ${vendor.contactName ? `<span>담당자: ${escapeHtml(vendor.contactName)}</span>` : ""}
              ${vendor.phone ? `<span>연락처: ${escapeHtml(vendor.phone)}</span>` : ""}
              ${vendor.email ? `<span>이메일: ${escapeHtml(vendor.email)}</span>` : ""}
              ${vendor.messenger ? `<span>문자/카톡: ${escapeHtml(vendor.messenger)}</span>` : ""}
            </div>
            ${vendor.memo ? `<div class="implant-send-preview">${escapeHtml(vendor.memo)}</div>` : ""}
            <div class="actions">
              <button class="secondary" type="button" data-edit-implant-vendor="${escapeHtml(vendor.id)}">수정</button>
              <button class="${vendor.active === false ? "secondary" : "danger"}" type="button" data-toggle-implant-vendor="${escapeHtml(vendor.id)}">${vendor.active === false ? "발송 재개" : "발송 정지"}</button>
            </div>
          </div>
        `).join("") : `<div class="empty">등록된 임플란트 업체가 없습니다.</div>`}
      </div>
    </div>
  </section>
`;


const resetImplantVendorForm = () => {
  document.getElementById("implantVendorId").value = "";
  document.getElementById("implantVendorFormTitle").textContent = "임플란트 업체 연락처 추가";
  document.getElementById("implantVendorForm")?.reset();
};

const bindImplantVendors = () => {
  const form = document.getElementById("implantVendorForm");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById("implantVendorId").value || uid();
    const existingVendor = implantVendorById(id);
    const vendor = {
      id,
      name: document.getElementById("implantVendorName").value.trim(),
      contactName: document.getElementById("implantVendorContactName").value.trim(),
      phone: document.getElementById("implantVendorPhone").value.trim(),
      email: document.getElementById("implantVendorEmail").value.trim(),
      messenger: document.getElementById("implantVendorMessenger").value.trim(),
      memo: document.getElementById("implantVendorMemo").value.trim(),
      active: existingVendor?.active !== false,
      updatedAt: new Date().toISOString(),
      ...(existingVendor?.createdAt ? {} : { createdAt: new Date().toISOString() }),
      ...(existingVendor?.createdBy ? auditUpdateFields() : auditCreateFields())
    };
    if (!vendor.name) {
      alert("업체명을 입력해 주세요.");
      return;
    }
    await setDocRef(docRef(dbRef(), "implantVendors", id), vendor, { merge: true });
    const oldName = String(existingVendor?.name || "").trim();
    if (oldName && oldName !== vendor.name) {
      let changedProducts = 0;
      state.products = state.products.map((product) => {
        const linkedById = sameId(product.companyVendorId, id);
        const linkedByOldName = !product.companyVendorId && normalizedName(product.company) === normalizedName(oldName);
        if (!linkedById && !linkedByOldName) return product;
        changedProducts += 1;
        return {
          ...product,
          company: vendor.name,
          companyVendorId: id
        };
      });
      if (changedProducts) {
        await saveState("제품 업체명 동기화 완료", {
          savingMessage: "제품 업체명 동기화 중입니다...",
          doneMessage: `${changedProducts}개 제품 업체명 동기화 완료`
        });
      }
    }
    resetImplantVendorForm();
  });
  document.getElementById("implantVendorReset")?.addEventListener("click", resetImplantVendorForm);
  app.querySelectorAll("[data-edit-implant-vendor]").forEach((button) => {
    button.addEventListener("click", () => {
      const vendor = implantVendorById(button.dataset.editImplantVendor);
      if (!vendor) return;
      document.getElementById("implantVendorFormTitle").textContent = "임플란트 업체 연락처 수정";
      document.getElementById("implantVendorId").value = vendor.id;
      document.getElementById("implantVendorName").value = vendor.name || "";
      document.getElementById("implantVendorContactName").value = vendor.contactName || "";
      document.getElementById("implantVendorPhone").value = vendor.phone || "";
      document.getElementById("implantVendorEmail").value = vendor.email || "";
      document.getElementById("implantVendorMessenger").value = vendor.messenger || "";
      document.getElementById("implantVendorMemo").value = vendor.memo || "";
      form.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
  app.querySelectorAll("[data-toggle-implant-vendor]").forEach((button) => {
    button.addEventListener("click", async () => {
      const vendor = implantVendorById(button.dataset.toggleImplantVendor);
      if (!vendor) return;
      await setDocRef(docRef(dbRef(), "implantVendors", vendor.id), {
        active: vendor.active === false,
        updatedAt: new Date().toISOString(),
        ...auditUpdateFields()
      }, { merge: true });
    });
  });
};



    return {
      renderImplantVendors,
      bindImplantVendors
    };
  };
})();
