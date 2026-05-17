import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js";
import { getFirestore, doc, getDoc, setDoc, onSnapshot, runTransaction } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js";

const firebaseConfig = { projectId: "nonpay-inventory" };
const fbApp = initializeApp(firebaseConfig);
const db = getFirestore(fbApp);
const usersRef = doc(db, "app", "users");
const mainRef = doc(db, "app", "main");

const roleLabels = {
  admin: "관리자",
  manager: "책임/입고 담당",
  staff: "일반 사용자"
};

const roleAllowedViews = {
  admin: ["dashboard", "use", "edit", "history", "receipts", "settings"],
  manager: ["dashboard", "use", "edit", "history", "receipts"],
  staff: ["dashboard", "use", "history", "receipts"]
};

let accounts = [];
let setupMode = false;
let currentUser = JSON.parse(sessionStorage.getItem("orInventoryUser") || "null");
let auditTimer = null;
let unsubscribeUsers = null;
let roleInterval = null;

const $ = (id) => document.getElementById(id);
const nowIso = () => new Date().toISOString();
const uid = () => `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
const safeUser = () => currentUser ? { id: currentUser.id, loginId: currentUser.loginId, name: currentUser.name, role: currentUser.role } : null;

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
}[char]));

const setLoginStatus = (message, type = "") => {
  $("loginStatus").textContent = message;
  $("loginStatus").className = `status ${type}`;
};

const setAccountStatus = (message, type = "") => {
  $("accountStatus").textContent = message;
  $("accountStatus").className = `status ${type}`;
};

const setRequestStatus = (message, type = "") => {
  $("requestStatus").textContent = message;
  $("requestStatus").className = `status ${type}`;
};

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashPin(loginId, pin, salt) {
  return sha256(`${loginId}::${pin}::${salt}`);
}

async function loadAccounts() {
  const snap = await getDoc(usersRef);
  accounts = snap.exists() && Array.isArray(snap.data().accounts) ? snap.data().accounts : [];
  setupMode = accounts.length === 0;
  $("loginGuide").textContent = setupMode
    ? "처음 사용입니다. 여기서 입력한 아이디와 PIN이 관리자 계정으로 생성됩니다."
    : "사용자 계정으로 로그인해 주세요.";
  setLoginStatus(setupMode ? "관리자 계정 최초 생성 대기" : "계정 정보를 입력해 주세요.", setupMode ? "ok" : "");
}

async function saveAccounts(message = "계정 저장 완료") {
  await setDoc(usersRef, {
    accounts,
    updatedAt: nowIso(),
    updatedBy: safeUser()
  });
  setAccountStatus(message, "ok");
}

function accountStatusLabel(user) {
  if (user.pendingApproval && user.active === false) return "승인대기";
  return user.active === false ? "사용중지" : "사용";
}

function canDeleteAccount(user) {
  if (!user || user.id === currentUser?.id) return false;
  const adminCount = accounts.filter((item) => item.role === "admin").length;
  return user.role !== "admin" || adminCount > 1;
}

function showApp() {
  setupMode = false;
  $("loginScreen").style.display = "none";
  $("appShell").style.display = "block";
  $("currentUserText").textContent = `${currentUser.name} (${currentUser.loginId})`;
  $("roleText").textContent = roleLabels[currentUser.role] || currentUser.role;
  $("accountManageBtn").style.display = currentUser.role === "admin" ? "inline-flex" : "none";
  startAuditLoop();
  applyRoleToFrame();
}

function showLogin() {
  $("loginScreen").style.display = "grid";
  $("appShell").style.display = "none";
  stopAuditLoop();
  if (roleInterval) clearInterval(roleInterval);
  roleInterval = null;
}

async function createFirstAdmin(loginId, pin) {
  const salt = uid();
  const pinHash = await hashPin(loginId, pin, salt);
  const user = {
    id: "admin",
    loginId,
    pinHash,
    salt,
    name: "관리자",
    role: "admin",
    active: true,
    createdAt: nowIso(),
    updatedAt: nowIso()
  };
  accounts = [user];
  currentUser = { id: user.id, loginId: user.loginId, name: user.name, role: user.role };
  await setDoc(usersRef, { accounts, updatedAt: nowIso(), updatedBy: currentUser });
  sessionStorage.setItem("orInventoryUser", JSON.stringify(currentUser));
  showApp();
}

async function handleLogin(loginId, pin) {
  if (setupMode) {
    if (!loginId || !pin) return;
    await createFirstAdmin(loginId, pin);
    return;
  }
  const user = accounts.find((item) => item.loginId === loginId && item.active !== false);
  if (!user || !user.pinHash || !user.salt) {
    setLoginStatus("아이디, PIN 또는 사용 여부를 확인해 주세요.", "error");
    return;
  }
  const pinHash = await hashPin(loginId, pin, user.salt);
  if (pinHash !== user.pinHash) {
    setLoginStatus("아이디, PIN 또는 사용 여부를 확인해 주세요.", "error");
    return;
  }
  currentUser = { id: user.id, loginId: user.loginId, name: user.name, role: user.role };
  sessionStorage.setItem("orInventoryUser", JSON.stringify(currentUser));
  showApp();
}

function resetRequestForm() {
  $("requestForm").reset();
  setRequestStatus("");
}

function openRequestDialog() {
  resetRequestForm();
  $("requestDialog").showModal();
}

async function submitAccountRequest(name, loginId, pin) {
  if (!name || !loginId || !pin) return;
  const salt = uid();
  const pinHash = await hashPin(loginId, pin, salt);
  const requestedAt = nowIso();
  const requestedAccount = {
    id: uid(),
    name,
    loginId,
    pinHash,
    salt,
    role: "staff",
    active: false,
    pendingApproval: true,
    createdAt: requestedAt,
    updatedAt: requestedAt,
    requestedAt
  };

  await runTransaction(db, async (transaction) => {
    const snap = await transaction.get(usersRef);
    const currentAccounts = snap.exists() && Array.isArray(snap.data().accounts) ? snap.data().accounts : [];
    if (currentAccounts.length === 0) {
      throw new Error("먼저 최초 관리자 계정을 생성해 주세요.");
    }
    const duplicate = currentAccounts.find((item) => String(item.loginId || "").trim() === loginId);
    if (duplicate) {
      throw new Error("이미 사용 중인 아이디입니다.");
    }
    const nextAccounts = [...currentAccounts, requestedAccount];
    transaction.set(usersRef, {
      accounts: nextAccounts,
      updatedAt: requestedAt,
      updatedBy: null
    });
    accounts = nextAccounts;
  });
}

function logout() {
  currentUser = null;
  sessionStorage.removeItem("orInventoryUser");
  $("inventoryFrame").src = "./index_new.html";
  showLogin();
}

function renderAccounts() {
  $("accountList").innerHTML = accounts.slice().sort((a, b) => String(a.name).localeCompare(String(b.name), "ko")).map((user) => `
    <div class="account-row">
      <div>
        <strong>${escapeHtml(user.name)} <span class="pill">${escapeHtml(roleLabels[user.role] || user.role)}</span>${user.pendingApproval && user.active === false ? ` <span class="pill pending">승인대기</span>` : ""}</strong>
        <span>ID: ${escapeHtml(user.loginId)} · 상태: ${accountStatusLabel(user)}</span>
      </div>
      <div class="actions">
        <button type="button" class="secondary" data-edit-account="${escapeHtml(user.id)}">수정</button>
        ${user.id === "admin" ? "" : `<button type="button" class="danger" data-toggle-account="${escapeHtml(user.id)}">${user.active === false ? "사용" : "중지"}</button>`}
        ${canDeleteAccount(user) ? `<button type="button" class="danger" data-delete-account="${escapeHtml(user.id)}">삭제</button>` : ""}
      </div>
    </div>
  `).join("");

  $("accountList").querySelectorAll("[data-edit-account]").forEach((button) => {
    button.addEventListener("click", () => {
      const user = accounts.find((item) => item.id === button.dataset.editAccount);
      if (!user) return;
      $("accountEditId").value = user.id;
      $("accountName").value = user.name;
      $("accountLoginId").value = user.loginId;
      $("accountPin").value = "";
      $("accountPin").placeholder = "변경할 때만 입력";
      $("accountRole").value = user.role;
      $("accountActive").value = user.active === false ? "false" : "true";
    });
  });

  $("accountList").querySelectorAll("[data-toggle-account]").forEach((button) => {
    button.addEventListener("click", async () => {
      const user = accounts.find((item) => item.id === button.dataset.toggleAccount);
      if (!user) return;
      user.active = user.active === false;
      if (user.active) user.pendingApproval = false;
      user.updatedAt = nowIso();
      user.updatedBy = safeUser();
      await saveAccounts(user.active ? "계정을 사용으로 변경했습니다." : "계정을 사용중지했습니다.");
      renderAccounts();
    });
  });

  $("accountList").querySelectorAll("[data-delete-account]").forEach((button) => {
    button.addEventListener("click", async () => {
      const user = accounts.find((item) => item.id === button.dataset.deleteAccount);
      if (!canDeleteAccount(user)) {
        setAccountStatus("현재 로그인 계정이나 마지막 관리자 계정은 삭제할 수 없습니다.", "error");
        return;
      }
      if (!confirm(`${user.name} (${user.loginId}) 계정을 삭제할까요?`)) return;
      accounts = accounts.filter((item) => item.id !== user.id);
      await saveAccounts("계정을 삭제했습니다.");
      renderAccounts();
      if ($("accountEditId").value === user.id) resetAccountForm();
    });
  });
}

function resetAccountForm() {
  $("accountForm").reset();
  $("accountEditId").value = "";
  $("accountRole").value = "staff";
  $("accountActive").value = "true";
  $("accountPin").placeholder = "";
}

function openAccountDialog() {
  if (currentUser?.role !== "admin") return;
  renderAccounts();
  resetAccountForm();
  $("accountDialog").showModal();
}

function renderFrameAccountControls(frameDoc) {
  if (!currentUser || !frameDoc) return;
  const topbar = frameDoc.querySelector(".topbar");
  if (!topbar) return;

  if (!frameDoc.getElementById("authShellControlsStyle")) {
    const style = frameDoc.createElement("style");
    style.id = "authShellControlsStyle";
    style.textContent = `
      .topbar {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        align-items: end;
        column-gap: 10px;
      }
      .topbar .brand,
      .topbar #nav {
        grid-column: 1 / -1;
      }
      .topbar #status {
        grid-column: 1;
        align-self: center;
      }
      .auth-shell-controls {
        grid-column: 2;
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 6px;
        min-width: 0;
        margin: 0 0 2px;
        white-space: nowrap;
      }
      .auth-shell-user {
        display: inline-flex;
        align-items: center;
        min-height: 32px;
        max-width: 220px;
        padding: 0 10px;
        border: 1px solid #d7e2ef;
        border-radius: 10px;
        background: rgba(255,255,255,.72);
        color: #2e405c;
        font-size: 12px;
        font-weight: 900;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .auth-shell-controls button {
        min-height: 32px;
        padding: 0 10px;
        border-radius: 10px;
        font-size: 12px;
        box-shadow: none;
      }
      @media (max-width: 720px) {
        .topbar { grid-template-columns: 1fr; }
        .topbar #status,
        .auth-shell-controls {
          grid-column: 1;
        }
        .auth-shell-controls {
          justify-content: flex-start;
          overflow-x: auto;
          padding-bottom: 2px;
        }
        .auth-shell-user { max-width: 170px; }
      }
    `;
    frameDoc.head.appendChild(style);
  }

  let controls = frameDoc.getElementById("authShellControls");
  if (!controls) {
    controls = frameDoc.createElement("div");
    controls.id = "authShellControls";
    controls.className = "auth-shell-controls";
    const status = frameDoc.getElementById("status");
    topbar.insertBefore(controls, status?.nextSibling || topbar.querySelector("#nav"));
  }

  controls.innerHTML = `
    <span class="auth-shell-user" title="${escapeHtml(roleLabels[currentUser.role] || currentUser.role)}">${escapeHtml(currentUser.name)} · ${escapeHtml(currentUser.loginId)}</span>
    ${currentUser.role === "admin" ? `<button type="button" class="secondary" data-auth-account>계정관리</button>` : ""}
    <button type="button" class="danger" data-auth-logout>로그아웃</button>
  `;
  controls.querySelector("[data-auth-account]")?.addEventListener("click", openAccountDialog);
  controls.querySelector("[data-auth-logout]")?.addEventListener("click", logout);
}

function applyRoleToFrame() {
  const frame = $("inventoryFrame");
  const allowed = new Set(roleAllowedViews[currentUser?.role] || []);
  const apply = () => {
    try {
      const frameDoc = frame.contentDocument;
      if (!frameDoc) return;
      renderFrameAccountControls(frameDoc);
      frameDoc.querySelectorAll("button.tab[data-view]").forEach((button) => {
        const ok = allowed.has(button.dataset.view);
        button.style.display = ok ? "" : "none";
        button.disabled = !ok;
      });
      frameDoc.querySelectorAll("[data-go-view]").forEach((button) => {
        if (button.dataset.goView && !allowed.has(button.dataset.goView)) button.style.display = "none";
      });
      if (currentUser.role === "staff") {
        frameDoc.querySelectorAll("button[data-delete-usage],button[data-edit-usage],button[data-delete-product],button[data-delete-doctor],button[data-delete-surgery],button[data-delete-rule],button[data-edit-receipt],button[data-delete-receipt]").forEach((button) => {
          button.style.display = "none";
        });
      }
      if (currentUser.role !== "admin") {
        frameDoc.querySelectorAll("button[data-delete-product],button[data-delete-doctor],button[data-delete-surgery],button[data-delete-rule]").forEach((button) => {
          button.style.display = "none";
        });
      }
    } catch (error) {
      console.info("권한 적용 대기", error);
    }
  };
  frame.addEventListener("load", () => {
    apply();
    setTimeout(apply, 500);
    setTimeout(apply, 1500);
  });
  if (roleInterval) clearInterval(roleInterval);
  roleInterval = setInterval(() => {
    if (currentUser) apply();
  }, 2000);
}

async function patchAuditFields() {
  if (!currentUser) return;
  try {
    await runTransaction(db, async (transaction) => {
      const snap = await transaction.get(mainRef);
      if (!snap.exists()) return;
      const data = snap.data();
      const user = safeUser();
      let changed = false;
      const stampList = (listName) => {
        if (!Array.isArray(data[listName])) return;
        data[listName] = data[listName].map((item) => {
          if (!item || item.createdBy) return item;
          changed = true;
          return { ...item, createdBy: user, createdByName: user.name };
        });
      };
      stampList("usages");
      stampList("receipts");
      if (changed) transaction.set(mainRef, { ...data, auditUpdatedAt: nowIso(), auditUpdatedBy: user });
    });
  } catch (error) {
    console.info("기록자 보정 실패", error);
  }
}

function startAuditLoop() {
  stopAuditLoop();
  auditTimer = setInterval(patchAuditFields, 2500);
  setTimeout(patchAuditFields, 2500);
}

function stopAuditLoop() {
  if (auditTimer) clearInterval(auditTimer);
  auditTimer = null;
}

$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  await handleLogin($("loginId").value.trim(), $("loginPin").value.trim());
});

$("logoutBtn").addEventListener("click", logout);
$("requestAccountBtn").addEventListener("click", openRequestDialog);
$("requestCloseBtn").addEventListener("click", () => $("requestDialog").close());
$("accountManageBtn").addEventListener("click", openAccountDialog);
$("accountCloseBtn").addEventListener("click", () => $("accountDialog").close());
$("accountResetBtn").addEventListener("click", resetAccountForm);

$("requestForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  setRequestStatus("신청을 저장하는 중입니다.", "");
  try {
    await submitAccountRequest($("requestName").value.trim(), $("requestLoginId").value.trim(), $("requestPin").value.trim());
    setRequestStatus("신청이 저장되었습니다. 관리자 승인 후 로그인할 수 있습니다.", "ok");
    $("requestForm").reset();
  } catch (error) {
    setRequestStatus(error.message || "신청 저장에 실패했습니다.", "error");
  }
});

$("accountForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (currentUser?.role !== "admin") return;
  const id = $("accountEditId").value || uid();
  const loginId = $("accountLoginId").value.trim();
  const pin = $("accountPin").value.trim();
  const existing = accounts.find((item) => item.id === id);
  const duplicate = accounts.find((item) => item.loginId === loginId && item.id !== id);
  if (duplicate) {
    setAccountStatus("이미 사용 중인 아이디입니다.", "error");
    return;
  }
  if (!existing && !pin) {
    setAccountStatus("새 계정은 PIN이 필요합니다.", "error");
    return;
  }
  const salt = pin ? uid() : existing?.salt;
  const pinHash = pin ? await hashPin(loginId, pin, salt) : existing?.pinHash;
  const active = $("accountActive").value === "true";
  const next = {
    id,
    name: $("accountName").value.trim(),
    loginId,
    pinHash,
    salt,
    role: $("accountRole").value,
    active,
    pendingApproval: active ? false : existing?.pendingApproval === true,
    createdAt: existing?.createdAt || nowIso(),
    updatedAt: nowIso(),
    updatedBy: safeUser()
  };
  if (!next.name || !next.loginId || !next.pinHash || !next.salt) return;
  accounts = [...accounts.filter((item) => item.id !== id), next];
  await saveAccounts();
  renderAccounts();
  resetAccountForm();
});

await loadAccounts();
unsubscribeUsers = onSnapshot(usersRef, (snap) => {
  accounts = snap.exists() && Array.isArray(snap.data().accounts) ? snap.data().accounts : [];
  setupMode = accounts.length === 0;
  if ($("accountDialog").open) renderAccounts();
});

if (currentUser && accounts.some((item) => item.id === currentUser.id && item.active !== false)) {
  showApp();
} else {
  currentUser = null;
  sessionStorage.removeItem("orInventoryUser");
  showLogin();
}

window.addEventListener("beforeunload", () => {
  if (unsubscribeUsers) unsubscribeUsers();
  stopAuditLoop();
  if (roleInterval) clearInterval(roleInterval);
});
