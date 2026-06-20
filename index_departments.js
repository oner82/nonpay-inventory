(() => {
  window.createDepartmentsModule = (context) => {
    const state = new Proxy({}, {
      get(_target, property) { return context.getState()[property]; },
      set(_target, property, value) { context.getState()[property] = value; return true; }
    });
    const app = context.getApp();
    const {
      departmentOptions,
      departmentNames,
      departmentCode,
      byName,
      escapeHtml,
      alphaFirstCompare,
      inferSurgeryDepartment,
      isCommonSurgery,
      surgeryDoctorIds,
      departmentById,
      surgeryById,
      uid,
      render,
      saveState,
      sameId
    } = context;

const renderDoctors = () => renderSimpleManager("doctors", "과", "doctor");

const renderSurgeryDoctorSelector = () => {
  if (!state.doctors.length) return `<div class="empty">원장코드를 먼저 추가해 주세요. 원장 미선택 시 공통 수술로 저장됩니다.</div>`;
  return `
    <div class="doctor-scope-list" id="surgeryDoctorScopeList">
      ${state.doctors.slice().sort(byName).map((doctor) => `
        <label class="doctor-scope-option" data-surgery-doctor-option data-department="${escapeHtml(departmentCode(doctor.name))}">
          <input type="checkbox" value="${escapeHtml(doctor.id)}" data-surgery-doctor>
          <span>${escapeHtml(doctor.name)}</span>
        </label>
      `).join("")}
    </div>
  `;
};

const renderSurgeries = () => `
  <section class="grid two">
    <form class="card" id="surgeryForm">
      <h2 id="surgeryFormTitle">수술 추가</h2>
      <input type="hidden" id="surgeryId">
      <label for="surgeryDepartment">수술 과</label>
      <select id="surgeryDepartment" required>
        <option value="">과 선택</option>
        ${departmentOptions()}
      </select>
      <label for="surgeryName">수술명</label>
      <input id="surgeryName" required autocomplete="off">
      <label>표시 원장코드</label>
      <div class="surgery-scope-note">아무 원장도 선택하지 않으면 같은 과 모든 원장에게 보이는 공통 수술입니다. 특정 원장을 선택하면 해당 원장 사용입력에서만 보입니다.</div>
      ${renderSurgeryDoctorSelector()}
      <div class="actions">
        <button type="submit">수술 저장</button>
        <button class="secondary" type="button" id="surgeryReset">새로 입력</button>
      </div>
    </form>
    <div class="card">
      <h2>수술 목록</h2>
      ${renderGroupedSurgeries()}
    </div>
  </section>
`;

const renderSimpleManager = (collection, label, key) => `
  <section class="grid two">
    <form class="card" id="${key}Form">
      <h2 id="${key}FormTitle">${label} 추가</h2>
      <input type="hidden" id="${key}Id">
      <input type="hidden" id="${key}OldName">
      ${key === "doctor" ? `
        <label for="${key}Department">과 선택</label>
        <select id="${key}Department">
          <option value="">과 선택</option>
          ${departmentOptions()}
        </select>
        <label for="${key}NewDepartment">새 과 추가</label>
        <input id="${key}NewDepartment" autocomplete="off" placeholder="예: ENT">
        <label for="${key}Number">의사코드</label>
        <input id="${key}Number" required autocomplete="off" inputmode="numeric" placeholder="예: 3">
      ` : `
        <label for="${key}Name">${label} 코드</label>
        <input id="${key}Name" required autocomplete="off">
      `}
      <div class="actions">
        <button type="submit">${label} 저장</button>
        <button class="secondary" type="button" id="${key}Reset">새로 입력</button>
      </div>
    </form>
    <div class="card">
      <h2>${label} 목록</h2>
      ${key === "doctor" ? renderGroupedDoctors() : state[collection].slice().sort(byName).map((item) => `
        <div class="item">
          <div class="item-title"><span>${escapeHtml(item.name)}</span></div>
          <div class="actions">
            <button class="secondary" type="button" data-edit-${key}="${item.id}">수정</button>
            <button class="danger" type="button" data-delete-${key === "doctor" ? "doctor" : "surgery"}="${item.id}">삭제</button>
          </div>
        </div>
      `).join("") || `<div class="empty">${label}을 추가해 주세요.</div>`}
    </div>
  </section>
`;


const renderGroupedDoctors = () => {
  if (!state.doctors.length) return `<div class="empty">과를 추가해 주세요.</div>`;
  return departmentNames().map((department) => {
    const items = state.doctors
      .filter((item) => departmentCode(item.name) === department)
      .sort(byName);
    return `
      <details class="item">
        <summary><span>${escapeHtml(department)}</span><span class="pill">${items.length}</span></summary>
        <div class="details-body">
        ${items.map((item) => `
          <div class="item">
            <div class="item-title"><span>${escapeHtml(item.name)}</span></div>
            <div class="actions">
              <button class="secondary" type="button" data-edit-doctor="${item.id}">수정</button>
              <button class="danger" type="button" data-delete-doctor="${item.id}">삭제</button>
            </div>
          </div>
        `).join("")}
        </div>
      </details>
    `;
  }).join("");
};


const surgeryScopeText = (surgery) => {
  const doctorIds = surgeryDoctorIds(surgery);
  if (!doctorIds.length) return "공통 수술";
  const names = doctorIds.map((id) => departmentById(id)?.name).filter(Boolean);
  const missingCount = doctorIds.length - names.length;
  return `${names.join(", ") || "지정 원장"}${missingCount ? ` 외 ${missingCount}` : ""} 전용`;
};

const renderGroupedSurgeries = () => {
  const departments = departmentNames();
  const surgeryDepartments = state.surgeries.map((item) => item.department || inferSurgeryDepartment(item.name));
  const names = [...new Set([...departments, ...surgeryDepartments])].filter(Boolean).sort(alphaFirstCompare);
  if (!state.surgeries.length) return `<div class="empty">수술을 추가해 주세요.</div>`;
  return names.map((department) => {
    const items = state.surgeries
      .filter((item) => (item.department || inferSurgeryDepartment(item.name)) === department)
      .sort(byName);
    if (!items.length) return "";
    return `
      <details class="item">
        <summary><span>${escapeHtml(department)} 수술</span><span class="pill">${items.length}</span></summary>
        <div class="details-body">
          ${items.map((item) => `
            <div class="item">
              <div class="item-title">
                <span>${escapeHtml(item.name)}</span>
                <span class="pill ${isCommonSurgery(item) ? "" : "low"}">${escapeHtml(surgeryScopeText(item))}</span>
              </div>
              <div class="meta"><span>${escapeHtml(isCommonSurgery(item) ? "같은 과 모든 원장 사용입력에 표시" : "선택한 원장코드 사용입력에만 표시")}</span></div>
              <div class="actions">
                <button class="secondary" type="button" data-edit-surgery="${item.id}">수정</button>
                <button class="danger" type="button" data-delete-surgery="${item.id}">삭제</button>
              </div>
           </div>
          `).join("")}
        </div>
      </details>
    `;
  }).join("");
};

const bindSimpleManager = (collection, label, key) => {
  const form = document.getElementById(`${key}Form`);
  document.getElementById(`${key}Reset`).addEventListener("click", () => {
    form.reset();
      document.getElementById(`${key}Id`).value = "";
      document.getElementById(`${key}OldName`).value = "";
      document.getElementById(`${key}FormTitle`).textContent = `${label} 추가`;
    });
  if (key === "doctor") {
    document.getElementById(`${key}NewDepartment`).addEventListener("input", () => {
      if (document.getElementById(`${key}NewDepartment`).value.trim()) {
        document.getElementById(`${key}Department`).value = "";
      }
    });
    document.getElementById(`${key}Department`).addEventListener("change", () => {
      if (document.getElementById(`${key}Department`).value) {
        document.getElementById(`${key}NewDepartment`).value = "";
      }
    });
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById(`${key}Id`).value || uid();
    const oldName = document.getElementById(`${key}OldName`).value;
    const name = key === "doctor"
      ? `${(document.getElementById(`${key}NewDepartment`).value.trim() || document.getElementById(`${key}Department`).value).toUpperCase()}${document.getElementById(`${key}Number`).value.trim()}`
      : document.getElementById(`${key}Name`).value.trim();
    if (key === "doctor" && (!document.getElementById(`${key}Number`).value.trim() || !(document.getElementById(`${key}NewDepartment`).value.trim() || document.getElementById(`${key}Department`).value))) {
      alert("과와 의사코드를 모두 입력해 주세요.");
      return;
    }
    if (!name) return;
    state[collection] = [...state[collection].filter((item) => item.id !== id), { id, name }];
    if (key === "doctor" && oldName && oldName !== name) {
      state.surgeries = state.surgeries.map((item) => item.department === oldName ? { ...item, department: name } : item);
    }
    render();
    await saveState(`${label} 저장 완료`, {
      savingMessage: `${label} 저장 중입니다...`,
      doneMessage: `${label} 저장 완료`
    });
  });
};

const bindDoctors = () => bindSimpleManager("doctors", "과", "doctor");
const bindSurgeries = () => {
  const form = document.getElementById("surgeryForm");
  const departmentSelect = document.getElementById("surgeryDepartment");
  const syncSurgeryDoctorScope = () => {
    const department = departmentSelect.value;
    app.querySelectorAll("[data-surgery-doctor-option]").forEach((option) => {
      const visible = !department || option.dataset.department === department;
      option.hidden = !visible;
      const input = option.querySelector("[data-surgery-doctor]");
      if (input) {
        input.disabled = !visible;
        if (!visible) input.checked = false;
      }
    });
  };
  context.setSyncSurgeryDoctorScope(syncSurgeryDoctorScope);
  departmentSelect.addEventListener("change", syncSurgeryDoctorScope);
  document.getElementById("surgeryReset").addEventListener("click", () => {
    form.reset();
    document.getElementById("surgeryId").value = "";
    document.getElementById("surgeryFormTitle").textContent = "수술 추가";
    syncSurgeryDoctorScope();
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById("surgeryId").value || uid();
    const previous = surgeryById(id) || {};
    const department = document.getElementById("surgeryDepartment").value;
    const name = document.getElementById("surgeryName").value.trim();
    const doctorIds = Array.from(form.querySelectorAll("[data-surgery-doctor]:checked:not(:disabled)")).map((input) => input.value);
    if (!department || !name) return;
    state.surgeries = [...state.surgeries.filter((item) => item.id !== id), { ...previous, id, department, name, doctorIds }];
    render();
    await saveState("수술 저장 완료", {
      savingMessage: "수술 저장 중입니다...",
      doneMessage: "수술 저장 완료"
    });
  });
  syncSurgeryDoctorScope();
};



    return {
      renderDoctors,
      renderSurgeries,
      bindDoctors,
      bindSurgeries
    };
  };
})();
