let initializeApp;
let getFirestore;
let doc;
let getDoc;
let getDocs;
let setDoc;
let deleteDoc;
let runTransaction;
let onSnapshot;
let enableIndexedDbPersistence;
let collection;
let getStorage;
let storageRef;
let uploadBytes;
let getDownloadURL;

const status = document.getElementById("status");
const nav = document.getElementById("nav");
const app = document.getElementById("app");
const sessionControls = document.getElementById("sessionControls");
const saveToast = document.getElementById("saveToast");
let saveToastTimer = null;

const showSaveToast = (message, type = "ok", options = {}) => {
  if (!saveToast || !message) return;
  window.clearTimeout(saveToastTimer);
  saveToast.textContent = message;
  saveToast.className = `save-toast show ${type}`;
  saveToast.hidden = false;
  if (!options.hold) {
    saveToastTimer = window.setTimeout(() => {
      saveToast.classList.remove("show");
      window.setTimeout(() => {
        if (!saveToast.classList.contains("show")) saveToast.hidden = true;
      }, 220);
    }, options.duration || 1800);
  }
};

const savingToast = (message = "저장 중입니다...") => showSaveToast(message, "saving", { hold: true });
const saveDoneToast = (message = "저장 완료") => showSaveToast(message, "ok");
const saveErrorToast = (message = "저장 실패") => showSaveToast(message, "error", { duration: 2600 });

const setButtonBusy = (button, busy, message = "저장 중...") => {
  if (!button) return;
  if (busy) {
    if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
    button.textContent = message;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  } else {
    if (button.dataset.originalText) button.textContent = button.dataset.originalText;
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
};

const firebaseConfig = {
  projectId: "nonpay-inventory"
};

const menus = [
  ["dashboard", "대시보드"],
  ["use", "사용입력"],
  ["edit", "수정"],
  ["history", "사용내역"],
  ["receipts", "입고관리"],
  ["implants", "임플란트"],
  ["settings", "설정"]
];

const roleAllowedViews = {
  admin: ["dashboard", "use", "edit", "history", "receipts", "implants", "settings"],
  manager: ["dashboard", "use", "edit", "history", "receipts", "implants", "settings"],
  receiver: ["receipts", "implants"],
  staff: ["dashboard", "use", "edit", "history", "implants"]
};

const roleLabels = {
  admin: "관리자",
  manager: "책임사용자",
  receiver: "입고담당자",
  staff: "일반사용자"
};

const settingsMenus = [
  ["products", "제품관리"],
  ["doctors", "과관리"],
  ["surgeries", "수술관리"],
  ["usageRules", "수술별 사용관리"],
  ["implantVendors", "임플란트 업체"],
  ["backup", "백업"]
];

const blankState = () => ({
  products: [],
  doctors: [],
  surgeries: [],
  receipts: [],
  usages: [],
  usageRules: [],
  hiddenLowProductIds: [],
  backupVersions: [],
  updatedAt: ""
});

const seedDoctors = [
  "NS3",
  "NS2",
  "NS19",
  "NS8",
  "NS9",
  "NS25",
  "NS26",
  "NS34",
  "NS38",
  "NS11",
  "NS42",
  "NS52",
  "CS13",
  "GS8",
  "OS1",
  "OS3",
  "OS8",
  "OS10",
  "OS14",
  "OS22",
  "OS24",
  "OS25",
  "NS39",
  "NS51",
  "URO1"
];
const defaultDepartmentOnlyNames = ["NS", "OS", "CS", "GS", "URO"];

const seedSurgeries = [
  { department: "OS", name: "A/S 수술" },
  { department: "OS", name: "A/S Shoulder" },
  { department: "OS", name: "A/S Knee" },
  { department: "OS", name: "A/S Ankle" },
  { department: "OS", name: "A/S Elbow" },
  { department: "OS", name: "기타수술" },
  { department: "OS", name: "ORIF" },
  { department: "OS", name: "Debri" },
  { department: "OS", name: "Repair" },
  { department: "OS", name: "Recon 등" },
  { department: "OS", name: "A/S & HTO" },
  { department: "OS", name: "TSRA/TARA" },
  { department: "OS", name: "TKRA/UKA" },
  { department: "OS", name: "THRA/BHR" },
  { department: "OS", name: "Removal 수술" },
  { department: "NS", name: "MD/MF/LF 50이상" },
  { department: "NS", name: "MD/MF/LF 49이하" },
  { department: "NS", name: "PEID(MIS) 50이상" },
  { department: "NS", name: "PEID(MIS) 49이하" },
  { department: "NS", name: "PEID(MIS) O-arm" },
  { department: "NS", name: "Fusion 50이상" },
  { department: "NS", name: "Fusion 49이하" },
  { department: "NS", name: "ACDF 50이상" },
  { department: "NS", name: "ACDF 49이하" },
  { department: "NS", name: "TDR 50이상" },
  { department: "NS", name: "TDR 49이하" },
  { department: "NS", name: "Foraminotomy 50이상" },
  { department: "NS", name: "Foraminotomy 49이하" },
  { department: "NS", name: "Laminoplasty 50이상" },
  { department: "NS", name: "Laminoplasty 49이하" },
  { department: "NS", name: "Lateral mass screw" },
  { department: "NS", name: "Corpectomy 50이상" },
  { department: "NS", name: "Corpectomy 49이하" },
  { department: "NS", name: "Hybride 50이상" },
  { department: "NS", name: "Hybride 49이하" },
  { department: "NS", name: "PVA" },
  { department: "NS", name: "TBA" }
];

const seedProductsText = `비급여	floseal			0	120
인체조직	OSG 1cc	올소		15	15
ANCHOR	Healicoil 4.5	남양	ANCHOR	10	10
인체조직	OSG 3cc	올소		25	25
ANCHOR	Healicoil 5.5	남양	ANCHOR	15	15
비급여	M-clot			0	100
인체조직	RAFUGEN 3cc	남양		15	15
ANCHOR	Foot Print 4.5	남양	ANCHOR	5	5
인체조직	Bone chip 15cc	한공조		3	3
ANCHOR	Healmax 4.8	남양	ANCHOR	20	20
비급여	Mediclore			0	80
인체조직	Bone chip 30cc	한공조		3	3
ANCHOR	Peek Lateral 4.5	남양	ANCHOR	30	30
인체조직	Bone chip 15cc	두성		15	15
ANCHOR	Osteoraptor	남양	ANCHOR	10	10
비급여	Tendoregen3cc			0	120
인체조직	Bone chip 30cc	두성		10	10
ANCHOR	Flexible Cannula 6.5*75 (주황)	남양	Cannula	10	10
인체조직	Bone chip 15cc	한솔		3	3
ANCHOR	Flexible Cannula 8.0*75 (연두)	남양	Cannula	10	10
비급여	Histoacyl			0	100
인체조직	Bone chip 30cc	한솔		3	3
ANCHOR	CG Derm 3*4	남양	etc	7	7
인체조직	TriCotical bone 40*20	한솔		2	2
ANCHOR	CG Derm 4*6	남양	etc	2	2
비급여	Klotpad			0	50
인체조직	Bongener 1cc	GSMedical		15	15
ANCHOR	Endo Button	남양	etc	3	3
인체조직	Osteopax	GSMedical		35	35
ANCHOR	Brostrom	남양	small joint	10	10
비급여	Tendoregen 1cc			0	50
인체조직	EXO cement	GSMedical		10	10
ANCHOR	Juggerknot 1.5	남양	small joint	15	15
인체조직	grafton	Medtronic		5	5
ANCHOR	Juggerknot 2.9	남양	small joint	13	13
비급여	Exofin(OS)			0	150
인체조직	BIO Dura (써지시스) 7*20	루모스메디칼		2	2
ANCHOR	Juggerknot 1.4 short	남양	small joint	5	5
인체조직	BIO Dura (써지시스) 7*10	루모스메디칼		2	2
ANCHOR	Juggerknot 1.0 mini	남양	small joint	4	4
비급여	타우로린			0	60
인체조직	Duragen 1*3	서림		4	4
ANCHOR	Swivelock 4.75 close	써지케어	ANCHOR	10	10
인체조직	Duragen 3*3	서림		2	2
ANCHOR	Swivelock 4.75 Tape	써지케어	ANCHOR	5	5
비급여	HydroCool			0	50
인체조직	Novosis 0.5g	CG bio		5	5
ANCHOR	Swivelock 4.75 self punch	써지케어	ANCHOR	2	2
인체조직	Novosis 1.0g	CG bio		5	5
ANCHOR	Push Lock 2.9	써지케어	ANCHOR	10	10
비급여	viscoseal			0	40
인체조직	Lyoplant 6*14	네오메드		2	2
ANCHOR	Fiber Tak 2.6	써지케어	ANCHOR	10	10
인체조직	Neuro-Pach 4*5	네오메드		2	2
ANCHOR	small joint 2.4	써지케어	small joint	6	6
비급여	hyazen 1cc			0	30
인체조직	Neuro-Pach 6*14	네오메드		1	1
ANCHOR	small joint 3.0	써지케어	small joint	8	8
인체조직	Lyoplant Onlay 10*12.5	네오메드		2	2
ANCHOR	Passport cannula 8*3	써지케어	Cannula	10	10
비급여	hyazen 3cc			0	40
인체조직	Lyoplant Onlay 7.5*7.5	네오메드		3	3
ANCHOR	Passport cannula 8*4	써지케어	Cannula	5	5
인체조직	Lyoplant Onlay 5*5	네오메드		2	2
ANCHOR	Passport cannula 10*4	써지케어	Cannula	10	10
비급여	hemostop			0	70
인체조직	Oxiplex	메디쉐어		7	7
ANCHOR	Solid Cannula 5.5 Ring type	와이즈메디칼	Cannula	10	10
인체조직	Novosis Trauma 0.5g	A-Tec		5	5
ANCHOR	Solid Cannula 5.5 non screw	와이즈메디칼	Cannula	15	15
비급여	wound clot			0	20
인체조직	Novosis Trauma 1.0g	A-Tec		5	5
ANCHOR	Solid Cannula 8.5	와이즈메디칼	Cannula	10	10
ANCHOR	Iconix 1.4	와이즈메디칼	ANCHOR	10	10
비급여	interguard			0	50
ANCHOR	Iconix 2.3	와이즈메디칼	ANCHOR	5	5
ANCHOR	Omeganut	골드메디	small joint	8	8
비급여	이노그램			0	30
ANCHOR	Mega suture 4.5(M)	골드메디	ANCHOR	10	10
ANCHOR	Mega suture 5.5(M)	골드메디	ANCHOR	2	2
비급여	Surgi Cure			0	5
ANCHOR	Mega suture 4.75(L)	골드메디	ANCHOR	10	10`;

let state = blankState();
let currentView = "dashboard";
let currentSettingsView = "products";
let commonHandlersBound = false;
let currentReceiptView = "nonpay";
let currentImplantSubView = "today";
let pendingEditUsageId = "";
let db;
let ref;
let storage;
let storageFallback;
let preferredImplantStorageBucket = null;
let unsubscribe;
let implantRecordsUnsubscribe;
let implantVendorsUnsubscribe;
let pendingUsagesUnsubscribe;
let hydrated = false;
let saving = false;
let implantRecords = [];
let implantVendors = [];
let pendingUsages = [];
let suppressPendingUsagesRender = false;
let productCategoryToKeepOpen = "";
let useEntryDirty = false;
let deferredUseEntryRender = false;
const useEntryAutosaveKey = "orInventoryUseEntryPatientDraft";
const useEntryAutosaveMaxAgeMs = 12 * 60 * 60 * 1000;

if (!window.ORInventoryUtils) throw new Error("공통 유틸 모듈을 불러오지 못했습니다.");
const {
  uid,
  today,
  num,
  alphaFirstCompare,
  sameId,
  normalizedName,
  departmentCode,
  productCategory,
  productCategoryLabel,
  formatDateTime,
  escapeHtml,
  capitalize
} = window.ORInventoryUtils;
let renderedDate = today();
const byName = (a, b) => alphaFirstCompare(a.name, b.name);
const productSortOrderValue = (item) => {
  const value = Number(item?.sortOrder);
  return Number.isFinite(value) && value > 0 ? value : null;
};
const productDisplaySort = (category = "") => (a, b) => {
  const normalizedCategory = productCategory(category || a?.category || b?.category || "");
  if (normalizedCategory === "비급여") {
    const leftOrder = productSortOrderValue(a);
    const rightOrder = productSortOrderValue(b);
    if (leftOrder !== null && rightOrder !== null && leftOrder !== rightOrder) return leftOrder - rightOrder;
    if (leftOrder !== null && rightOrder === null) return -1;
    if (leftOrder === null && rightOrder !== null) return 1;
  }
  return byName(a, b);
};
const nonpayProductsInDisplayOrder = () => state.products
  .filter((item) => productCategory(item.category) === "비급여")
  .sort(productDisplaySort("비급여"));
const normalizeNonpaySortOrders = () => {
  nonpayProductsInDisplayOrder().forEach((item, index) => {
    item.sortOrder = (index + 1) * 10;
  });
};
const nextNonpaySortOrder = (excludeId = "") => {
  const orders = nonpayProductsInDisplayOrder()
    .filter((item) => !sameId(item.id, excludeId))
    .map(productSortOrderValue)
    .filter((value) => value !== null);
  return orders.length ? Math.max(...orders) + 10 : (nonpayProductsInDisplayOrder().length + 1) * 10;
};
const productById = (id) => state.products.find((item) => item.id === id);
const departmentById = (id) => state.doctors.find((item) => item.id === id);
const surgeryById = (id) => state.surgeries.find((item) => item.id === id);
const usageRuleById = (id) => state.usageRules.find((item) => sameId(item.id, id));
const surgeryDoctorIds = (surgery) => Array.isArray(surgery?.doctorIds) ? surgery.doctorIds.filter(Boolean).map(String) : [];
const isCommonSurgery = (surgery) => surgeryDoctorIds(surgery).length === 0;
const surgeryVisibleForDoctor = (surgery, doctorId) => isCommonSurgery(surgery) || surgeryDoctorIds(surgery).some((id) => sameId(id, doctorId));
const visibleSurgeriesFor = (department, doctorId) => state.surgeries
  .slice()
  .sort((a, b) => alphaFirstCompare(a.name, b.name))
  .filter((item) => (item.department || inferSurgeryDepartment(item.name)) === department)
  .filter((item) => doctorId && surgeryVisibleForDoctor(item, doctorId));

const setStatus = (message, type = "ok") => {
  status.textContent = message;
  status.className = type;
};

const isUseEntryProtected = () => currentView === "use" && useEntryDirty;

const renderOrDeferForUseEntry = (message = "새 데이터가 들어왔습니다. 입력 중인 사용입력을 보호하고 있습니다.") => {
  if (isUseEntryProtected()) {
    deferredUseEntryRender = true;
    setStatus(message, "ok");
    return false;
  }
  render();
  return true;
};

const userStorageKey = "orInventoryUser";

const readStoredUser = () => {
  for (const storageName of ["sessionStorage", "localStorage"]) {
    try {
      const raw = window[storageName]?.getItem(userStorageKey);
      if (!raw) continue;
      const user = JSON.parse(raw);
      if (user?.id) return user;
    } catch (error) {
      console.info(`${storageName} user read failed`, error);
    }
  }
  return null;
};

const writeStoredUser = (user) => {
  for (const storageName of ["sessionStorage", "localStorage"]) {
    try {
      window[storageName]?.setItem(userStorageKey, JSON.stringify(user));
    } catch (error) {
      console.info(`${storageName} user write failed`, error);
    }
  }
};

const clearStoredUser = () => {
  for (const storageName of ["sessionStorage", "localStorage"]) {
    try {
      window[storageName]?.removeItem(userStorageKey);
    } catch (error) {
      console.info(`${storageName} user clear failed`, error);
    }
  }
};

const readUseEntryAutosave = () => {
  try {
    const raw = localStorage.getItem(useEntryAutosaveKey);
    if (!raw) return null;
    const payload = JSON.parse(raw);
    if (!payload?.savedAt) return null;
    if (Date.now() - new Date(payload.savedAt).getTime() > useEntryAutosaveMaxAgeMs) {
      localStorage.removeItem(useEntryAutosaveKey);
      return null;
    }
    return payload;
  } catch (error) {
    console.info("use entry autosave read failed", error);
    return null;
  }
};

const writeUseEntryAutosave = (payload) => {
  try {
    localStorage.setItem(useEntryAutosaveKey, JSON.stringify({
      ...payload,
      savedAt: new Date().toISOString()
    }));
  } catch (error) {
    console.info("use entry autosave write failed", error);
  }
};

const clearUseEntryAutosave = () => {
  try {
    localStorage.removeItem(useEntryAutosaveKey);
  } catch (error) {
    console.info("use entry autosave clear failed", error);
  }
};

const resetUseEntryProtection = ({ clearAutosave = true } = {}) => {
  useEntryDirty = false;
  deferredUseEntryRender = false;
  if (clearAutosave) clearUseEntryAutosave();
};

const currentAuditUser = () => {
  try {
    const user = readStoredUser();
    if (!user?.id) return null;
    return {
      id: user.id,
      loginId: user.loginId || "",
      name: user.name || user.loginId || "",
      role: user.role || "staff"
    };
  } catch (error) {
    return null;
  }
};

const auditCreateFields = () => {
  const user = currentAuditUser();
  return user ? { createdBy: user, createdByName: user.name } : {};
};

const auditUpdateFields = () => {
  const user = currentAuditUser();
  return user ? { updatedBy: user, updatedByName: user.name } : {};
};

const currentUserRole = () => currentAuditUser()?.role || "";
const allowedViews = () => new Set(roleAllowedViews[currentUserRole()] || []);
const canOpenView = (view) => allowedViews().has(view);
const canEditUsage = () => ["admin", "manager", "staff"].includes(currentUserRole());
const canDeleteUsage = () => ["admin", "manager"].includes(currentUserRole());
const isTodayUsage = (usage) => (usage?.date || "") === today();
const canModifyUsageRecord = (usage) => canEditUsage() && (isTodayUsage(usage) || currentUserRole() === "admin");
const canDeleteUsageRecord = (usage) => canDeleteUsage() && (isTodayUsage(usage) || currentUserRole() === "admin");
const usagePastLockMessage = (usage) => isTodayUsage(usage)
  ? ""
  : "당일이 아닌 사용내역은 관리자만 수정·삭제할 수 있습니다.";
const canManageReceipts = () => ["admin", "manager"].includes(currentUserRole());
const canRegisterNonpayReceipts = () => ["admin", "manager", "receiver"].includes(currentUserRole());
const canManageLandingReceipts = () => ["admin", "manager"].includes(currentUserRole());
const canManageSettings = () => ["admin", "manager"].includes(currentUserRole());
const authShellUrl = "./auth_shell.html";

const showFramedAuthBlock = (message = "로그인이 필요합니다.") => {
  document.body.innerHTML = `
    <main style="min-height:100vh;display:grid;place-items:center;padding:18px;font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f7fb;color:#122033;">
      <section style="width:min(420px,100%);padding:22px;border:1px solid #dbe7f5;border-radius:14px;background:#fff;box-shadow:0 12px 32px rgba(22,39,74,.08);">
        <h1 style="margin:0 0 8px;font-size:20px;">${escapeHtml(message)}</h1>
        <p style="margin:0;color:#667085;font-weight:800;line-height:1.45;">로그인 화면에서 다시 접속해 주세요.</p>
      </section>
    </main>
  `;
};

const redirectToLogin = (message) => {
  clearStoredUser();
  try {
    if (window.self === window.top) {
      window.location.replace(authShellUrl);
    } else {
      showFramedAuthBlock(message);
    }
  } catch (error) {
    showFramedAuthBlock(message);
  }
  return false;
};

const ensureLocalSession = () => currentAuditUser() || redirectToLogin("로그인이 필요합니다.");

const logoutToAuthShell = () => {
  clearStoredUser();
  try {
    window.top.location.replace(authShellUrl);
  } catch (error) {
    window.location.replace(authShellUrl);
  }
};

sessionControls?.addEventListener("click", (event) => {
  if (event.target.closest("[data-session-account]")) {
    try {
      window.parent.postMessage({ type: "orInventoryOpenAccountDialog" }, window.location.origin);
    } catch (error) {
      console.info("계정관리 요청 실패", error);
    }
    return;
  }
  if (event.target.closest("[data-session-logout]")) logoutToAuthShell();
});

const renderSessionControls = () => {
  if (!sessionControls) return;
  const user = currentAuditUser();
  if (!user) {
    sessionControls.innerHTML = "";
    return;
  }
  const roleLabel = roleLabels[user.role] || user.role || "";
  sessionControls.innerHTML = `
    <span class="session-user" title="${escapeHtml(roleLabel)}">${escapeHtml(user.name || user.loginId)} · ${escapeHtml(roleLabel)}</span>
    ${user.role === "admin" ? `<button class="session-account" type="button" data-session-account>계정관리</button>` : ""}
    <button class="session-logout" type="button" data-session-logout>로그아웃</button>
  `;
};

const verifySessionUser = async () => {
  const sessionUser = currentAuditUser();
  if (!sessionUser) return redirectToLogin("로그인이 필요합니다.");
  const usersSnap = await getDoc(doc(db, "app", "users"));
  const accounts = usersSnap.exists() && Array.isArray(usersSnap.data().accounts) ? usersSnap.data().accounts : [];
  const account = accounts.find((item) => String(item.id) === String(sessionUser.id) && item.active !== false);
  if (!account) return redirectToLogin("세션이 만료되었습니다.");
  const verified = {
    id: account.id,
    loginId: account.loginId || "",
    name: account.name || account.loginId || "",
    role: roleAllowedViews[account.role] ? account.role : "staff"
  };
  writeStoredUser(verified);
  return verified;
};

const ensureCurrentViewAllowed = () => {
  const visibleMenus = menus.filter(([key]) => canOpenView(key));
  if (!visibleMenus.length) return redirectToLogin("권한이 없습니다.");
  if (!canOpenView(currentView)) currentView = visibleMenus[0][0];
  if (currentView === "settings" && !canManageSettings()) currentView = visibleMenus[0][0];
  if (currentView === "edit" && !canEditUsage()) currentView = visibleMenus[0][0];
  return true;
};

const normalizeState = (data) => ({
  ...blankState(),
  ...data,
  products: Array.isArray(data?.products) ? data.products : [],
  doctors: Array.isArray(data?.doctors) ? data.doctors : [],
  surgeries: Array.isArray(data?.surgeries) ? data.surgeries : [],
  receipts: Array.isArray(data?.receipts) ? data.receipts : [],
  usages: Array.isArray(data?.usages) ? data.usages : [],
  usageRules: Array.isArray(data?.usageRules) ? data.usageRules : [],
  hiddenLowProductIds: Array.isArray(data?.hiddenLowProductIds) ? data.hiddenLowProductIds : [],
  backupVersions: Array.isArray(data?.backupVersions) ? data.backupVersions : []
});

const PRODUCT_CATEGORIES = ["비급여", "인체조직", "ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"];
const patientIdText = (usage) => String(usage?.patientId || "").trim();
const patientDisplayName = (usage) => patientIdText(usage)
  ? `${usage.patientName || ""} (${patientIdText(usage)})`
  : (usage.patientName || "");
const canAssignImplantPatientNo = () => getImplantsModule().canAssignImplantPatientNo();
const canEditImplantPatientNo = () => getImplantsModule().canEditImplantPatientNo();
const implantRecordsForUsage = (usageId) => sortImplantRecords(implantRecords.filter((record) => sameId(record.usageId, usageId)));
const pendingUsagesOpen = () => pendingUsages
  .filter((item) => (item.status || "pending") === "pending")
  .sort((a, b) => String(b.updatedAt || b.createdAt || "").localeCompare(String(a.updatedAt || a.createdAt || "")));
const pendingUsageById = (id) => pendingUsages.find((item) => sameId(item.id, id));
const isImplantEditUnlocked = (record) => getImplantsModule().isImplantEditUnlocked(record);
const isImplantLedgerClosed = (record) => getImplantsModule().isImplantLedgerClosed(record);
const implantLockLabel = (record) => getImplantsModule().implantLockLabel(record);
const implantEditLockMessage = (record) => getImplantsModule().implantEditLockMessage(record);
const canModifyImplantRecord = (record) => {
  if (!canEditUsage()) return false;
  if (currentUserRole() === "admin") return true;
  if (isImplantLedgerClosed(record)) return false;
  const linkedUsage = state.usages.find((usage) => sameId(usage.id, record?.usageId));
  if (linkedUsage) return isTodayUsage(linkedUsage);
  return implantRecordDate(record) === today();
};
const implantVendorById = (id) => implantVendors.find((item) => sameId(item.id, id));
const implantVendorNameAliases = {
  "다림티센": "다림티센(써지가이드)",
  "와이즈메디칼": "와이즈 메디칼",
  "GSMedical": "GS Medical",
  "루모스메디칼": "루모스메디컬"
};
const compactVendorName = (value) => normalizedName(value).replace(/[\s\-_.&()（）,，]/g, "");
const findImplantVendorByName = (name = "") => {
  const key = normalizedName(name);
  if (!key) return null;
  const exact = implantVendors.find((vendor) => normalizedName(vendor.name) === key);
  if (exact) return exact;
  const aliasName = Object.entries(implantVendorNameAliases)
    .find(([alias]) => normalizedName(alias) === key)?.[1];
  if (aliasName) {
    const aliasVendor = implantVendors.find((vendor) => normalizedName(vendor.name) === normalizedName(aliasName));
    if (aliasVendor) return aliasVendor;
  }
  const compactKey = compactVendorName(name);
  const compactMatches = implantVendors.filter((vendor) => compactVendorName(vendor.name) === compactKey);
  if (compactMatches.length === 1) return compactMatches[0];
  const loose = implantVendors.filter((vendor) => {
    const vendorKey = normalizedName(vendor.name);
    return vendorKey && (vendorKey.includes(key) || key.includes(vendorKey));
  });
  return loose.length === 1 ? loose[0] : null;
};
const implantVendorOptions = (selectedId = "") => {
  const vendors = implantVendors.slice().sort((a, b) => alphaFirstCompare(a.name, b.name));
  return `
    <option value="">업체 선택</option>
    ${vendors.map((item) => `<option value="${escapeHtml(item.id)}" ${sameId(item.id, selectedId) ? "selected" : ""}>${escapeHtml(item.name)}${item.active === false ? " · 발송 정지" : ""}</option>`).join("")}
    <option value="__custom__" ${selectedId === "__custom__" ? "selected" : ""}>직접 입력</option>
  `;
};
const productCompanySelectValue = (selectedName = "", selectedId = "") => {
  if (selectedId && implantVendorById(selectedId)) return selectedId;
  const matched = findImplantVendorByName(selectedName);
  return matched?.id || String(selectedName || "").trim();
};
const productCompanyOptions = (selectedName = "", selectedId = "") => {
  const selected = String(selectedName || "").trim();
  const selectedValue = productCompanySelectValue(selected, selectedId);
  const vendors = implantVendors.slice().sort((a, b) => alphaFirstCompare(a.name, b.name));
  const hasSelected = !selected || vendors.some((vendor) => sameId(vendor.id, selectedValue));
  return `
    <option value="">업체 선택</option>
    ${!hasSelected ? `<option value="${escapeHtml(selected)}" selected>${escapeHtml(selected)} · 기존 업체</option>` : ""}
    ${vendors.map((vendor) => `<option value="${escapeHtml(vendor.id || "")}" ${sameId(vendor.id, selectedValue) ? "selected" : ""}>${escapeHtml(vendor.name || "업체명 없음")}${vendor.active === false ? " · 발송 정지" : ""}</option>`).join("")}
  `;
};
const productNeedsImplantLedger = (product) => getImplantsModule().productNeedsImplantLedger(product);
const implantVendorSelectionForProduct = (product = {}) => getImplantsModule().implantVendorSelectionForProduct(product);
const implantVendorSelectionForCompany = (company = "") => getImplantsModule().implantVendorSelectionForCompany(company);
const implantDraftVendorName = (draft = {}) => getImplantsModule().implantDraftVendorName(draft);
const mergeImplantDescriptionLines = (left = "", right = "") => getImplantsModule().mergeImplantDescriptionLines(left, right);
const implantVendorEntriesMatch = (left = {}, right = {}) => getImplantsModule().implantVendorEntriesMatch(left, right);
const findImplantEntryByVendorTarget = (entries = [], target = {}) => getImplantsModule().findImplantEntryByVendorTarget(entries, target);
const implantRowHasContent = (row = {}) => getImplantsModule().implantRowHasContent(row);
const implantDraftHasManualContent = (draft = {}) => getImplantsModule().implantDraftHasManualContent(draft);
const implantDraftCanAutoUpdateDescription = (draft = {}) => getImplantsModule().implantDraftCanAutoUpdateDescription(draft);
const implantDraftAutoDescription = (items = []) => getImplantsModule().implantDraftAutoDescription(items);
const implantVendorTargetsFromUseItems = (items = []) => getImplantsModule().implantVendorTargetsFromUseItems(items);
const implantRecordDate = (record) => record?.surgeryDate || String(record?.createdAt || "").slice(0, 10) || "";
const implantPatientNoText = (record) => String(record?.patientNo || "").trim();
const implantPatientNoSortValue = (record) => {
  const value = Number.parseInt(implantPatientNoText(record), 10);
  return Number.isFinite(value) && value > 0 ? value : 999999;
};
const sortImplantRecords = (records) => records.slice().sort((a, b) =>
  alphaFirstCompare(implantRecordDate(a), implantRecordDate(b)) ||
  implantPatientNoSortValue(a) - implantPatientNoSortValue(b) ||
  alphaFirstCompare(a.surgeryTime || "", b.surgeryTime || "") ||
  alphaFirstCompare(a.createdAt || "", b.createdAt || "")
);
const auditUserText = (item) => {
  const roleTokens = new Set(["staff", "receiver", "manager", "admin", "일반사용자", "일반 사용자", "입고담당자", "책임사용자", "책임/입고 담당", "관리자"]);
  const candidates = [
    item?.createdByName,
    item?.createdBy?.name,
    item?.createdBy?.loginId
  ];
  for (const raw of candidates) {
    const value = String(raw || "").trim();
    if (!value) continue;
    if (roleTokens.has(value)) continue;
    return value;
  }
  return "";
};
const auditRoleLabel = (item) => ({
  admin: "관리자",
  manager: "책임사용자",
  receiver: "입고담당자",
  staff: "일반사용자"
}[item?.createdBy?.role] || item?.createdBy?.role || "");
const auditTimeText = (item) => formatDateTime(item?.createdAt || item?.updatedAt || item?.date || "");
const auditMetaHtml = (item, label = "입력") => `
  <span>${label}자: ${escapeHtml(auditUserText(item) || "-")}</span>
  <span>${label}시각: ${escapeHtml(auditTimeText(item))}</span>
`;
const receiptDateValue = (receipt) => receipt?.date || String(receipt?.createdAt || receipt?.updatedAt || "").slice(0, 10) || "";
const receiptProduct = (receipt) => productById(receipt?.productId);
const receiptProductName = (receipt) => receiptProduct(receipt)?.name || receipt?.productName || "삭제된 제품";
const receiptProductMeta = (receipt) => {
  const product = receiptProduct(receipt);
  return [
    productCategoryLabel(product?.category || receipt?.category || ""),
    product?.company || receipt?.company || "",
    product?.subcategory || receipt?.subcategory || ""
  ].filter(Boolean).join(" · ");
};
const receiptTypeLabel = (receipt) => receipt?.type === "landing" ? "랜딩" : "비급여";
const receiptSortValue = (receipt) => {
  const value = receipt?.createdAt || receipt?.updatedAt || receipt?.date || "";
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
};
const filteredReceipts = (start = "", end = "", query = "") => {
  const normalizedQuery = normalizedName(query || "");
  return state.receipts
    .filter((receipt) => {
      const date = receiptDateValue(receipt);
      if ((start || end) && !inDateRange(date, start, end)) return false;
      if (!normalizedQuery) return true;
      return normalizedName(receiptProductName(receipt)).includes(normalizedQuery);
    })
    .slice()
    .sort((a, b) => receiptSortValue(b) - receiptSortValue(a) || alphaFirstCompare(b.date, a.date));
};
const warningQtyFromBase = (value) => {
  const qty = num(value);
  if (qty <= 1) return 0;
  return Math.max(1, Math.ceil(qty * 0.2));
};
const parseSeedProducts = () => seedProductsText.split("\n").map((line) => {
  const [category, name, company, subcategory, landingQty, warningStock] = line.split("\t");
  const baseQty = num(landingQty) || num(warningStock);
  return {
    category,
    name,
    company,
    subcategory,
    stock: baseQty,
    baseStock: baseQty,
    landingQty: num(landingQty),
    warningStock: warningQtyFromBase(baseQty)
  };
});
const productKey = (item) => [
  normalizedName(productCategory(item.category)),
  normalizedName(item.company),
  normalizedName(item.subcategory || item.type),
  normalizedName(item.name)
].join("::");
const productLooseKey = (item) => [
  normalizedName(productCategory(item.category)),
  normalizedName(item.name)
].join("::");

const mergeSeedList = (items, seedNames) => {
  const existing = new Set(items.map((item) => normalizedName(item.name)));
  const additions = seedNames
    .map((name) => name.trim())
    .filter((name) => name && !existing.has(normalizedName(name)))
    .map((name) => ({ id: uid(), name }));
  return additions.length ? { items: [...items, ...additions], added: additions.length } : { items, added: 0 };
};

const inferSurgeryDepartment = (name) => {
  const text = normalizedName(name);
  const osTerms = ["a/s", "shoulder", "knee", "ankle", "elbow", "orif", "debri", "repair", "recon", "tsra", "tara", "tkra", "uka", "thra", "bhr", "removal"];
  return osTerms.some((term) => text.includes(term)) ? "OS" : "NS";
};

const surgeryKey = (item) => `${normalizedName(item.department || inferSurgeryDepartment(item.name))}::${normalizedName(item.name)}`;

const normalizeLegacyMasters = () => {
  state.doctors = state.doctors
    .map((item) => ({ ...item, name: String(item.name || "").trim().toUpperCase() }))
    .filter((item) => item.name && !defaultDepartmentOnlyNames.includes(item.name));

  const asChildNames = new Map([
    ["shoulder", "A/S Shoulder"],
    ["knee", "A/S Knee"],
    ["ankle", "A/S Ankle"],
    ["elbow", "A/S Elbow"]
  ]);
  state.surgeries = state.surgeries.map((item) => {
    const fixedName = asChildNames.get(normalizedName(item.name)) || item.name;
    return {
      ...item,
      name: fixedName,
      department: departmentCode(item.department) || inferSurgeryDepartment(fixedName)
    };
  });
  const seenSurgeries = new Set();
  state.surgeries = state.surgeries.filter((item) => {
    const key = surgeryKey(item);
    if (seenSurgeries.has(key)) return false;
    seenSurgeries.add(key);
    return true;
  });

  state.products = state.products.map((item) => {
    const category = productCategory(item.category);
    const landingQty = num(item.landingQty);
    const baseQty = num(item.stock) || landingQty || num(item.warningStock);
    return {
      ...item,
      category,
      company: category === "비급여" ? "" : String(item.company || "").trim(),
      subcategory: category === "ANCHOR" ? String(item.subcategory || item.type || "").trim() : "",
      landingQty,
      baseStock: item.baseStock,
      warningStock: num(item.warningStock) || warningQtyFromBase(baseQty)
    };
  });
  const seenProducts = new Set();
  state.products = state.products.filter((item) => {
    const key = productKey(item);
    if (seenProducts.has(key)) return false;
    seenProducts.add(key);
    return true;
  });
};

const addSeedMasters = () => {
  normalizeLegacyMasters();
  const doctors = mergeSeedList(state.doctors, seedDoctors);
  const existingSurgeries = new Set(state.surgeries.map(surgeryKey));
  const surgeryAdditions = seedSurgeries
    .filter((item) => !existingSurgeries.has(surgeryKey(item)))
    .map((item) => ({ id: uid(), ...item }));
  state.doctors = doctors.items;
  state.surgeries = [...state.surgeries, ...surgeryAdditions];
  const existingProducts = new Map(state.products.map((item) => [productKey(item), item]));
  const existingProductsLoose = new Map(state.products.map((item) => [productLooseKey(item), item]));
  let updatedProducts = 0;
  const productAdditions = [];
  parseSeedProducts().forEach((seed) => {
    const exact = existingProducts.get(productKey(seed));
    const loose = existingProductsLoose.get(productLooseKey(seed));
    if (exact || loose) {
      const target = exact || loose;
      if (!target) return;
      const next = {
        ...target,
        company: seed.company,
        subcategory: seed.subcategory,
        stock: target.stock,
        baseStock: Number.isFinite(Number(target.baseStock)) ? num(target.baseStock) : seed.baseStock,
        landingQty: num(target.landingQty) || seed.landingQty,
        warningStock: num(target.warningStock) || seed.warningStock
      };
      if (JSON.stringify(target) !== JSON.stringify(next)) {
        Object.assign(target, next);
        updatedProducts += 1;
      }
      return;
    }
    productAdditions.push({ id: uid(), ...seed });
  });
  state.products = [...state.products, ...productAdditions];
  return doctors.added + surgeryAdditions.length + productAdditions.length + updatedProducts;
};

const productMovementCounts = () => {
  const used = new Map();
  const received = new Map();
  state.usages.forEach((usage) => {
    (usage.productIds || []).forEach((id) => used.set(id, (used.get(id) || 0) + 1));
  });
  state.receipts.forEach((receipt) => {
    received.set(receipt.productId, (received.get(receipt.productId) || 0) + num(receipt.qty));
  });
  return { used, received };
};

const reconcileProductStocks = () => {
  const { used, received } = productMovementCounts();
  const seedByKey = new Map(parseSeedProducts().map((item) => [productKey(item), item]));
  const seedByLooseKey = new Map(parseSeedProducts().map((item) => [productLooseKey(item), item]));
  let changed = 0;
  state.products = state.products.map((product) => {
    const seed = seedByKey.get(productKey(product)) || seedByLooseKey.get(productLooseKey(product));
    const productUsed = used.get(product.id) || 0;
    const productReceived = received.get(product.id) || 0;
    const baseStock = Number.isFinite(Number(product.baseStock))
      ? num(product.baseStock)
      : seed
        ? num(seed.baseStock)
        : num(product.stock) - productReceived + productUsed;
    const next = {
      ...product,
      baseStock,
      stock: Math.max(0, baseStock + productReceived - productUsed)
    };
    if (num(product.baseStock) !== num(next.baseStock) || num(product.stock) !== num(next.stock)) changed += 1;
    return next;
  });
  return changed;
};



const itemTimestamp = (item, fallback = "") => String(item?.updatedAt || item?.createdAt || fallback || "");

const mergeArrayById = (remoteItems = [], localItems = [], fallbackRemote = "", fallbackLocal = "") => {
  const merged = new Map();
  remoteItems.forEach((item) => {
    if (!item?.id) return;
    merged.set(item.id, item);
  });
  localItems.forEach((item) => {
    if (!item?.id) return;
    const current = merged.get(item.id);
    if (!current) {
      merged.set(item.id, item);
      return;
    }
    const localTime = itemTimestamp(item, fallbackLocal);
    const remoteTime = itemTimestamp(current, fallbackRemote);
    if (localTime >= remoteTime) merged.set(item.id, { ...current, ...item });
  });
  return Array.from(merged.values());
};

const mergeStates = (remoteData, localData) => {
  const remote = normalizeState(remoteData || {});
  const local = normalizeState(localData || {});
  const merged = normalizeState({
    ...remote,
    updatedAt: new Date().toISOString(),
    products: mergeArrayById(remote.products, local.products, remote.updatedAt, local.updatedAt),
    doctors: mergeArrayById(remote.doctors, local.doctors, remote.updatedAt, local.updatedAt),
    surgeries: mergeArrayById(remote.surgeries, local.surgeries, remote.updatedAt, local.updatedAt),
    receipts: mergeArrayById(remote.receipts, local.receipts, remote.updatedAt, local.updatedAt),
    usages: mergeArrayById(remote.usages, local.usages, remote.updatedAt, local.updatedAt),
    usageRules: mergeArrayById(remote.usageRules, local.usageRules, remote.updatedAt, local.updatedAt),
    backupVersions: mergeArrayById(remote.backupVersions || [], local.backupVersions || [], remote.updatedAt, local.updatedAt),
    hiddenLowProductIds: [...new Set([...(remote.hiddenLowProductIds || []), ...(local.hiddenLowProductIds || [])])]
  });
  const before = state;
  state = merged;
  reconcileProductStocks();
  const reconciled = normalizeState(state);
  state = before;
  return reconciled;
};

const saveState = async (message = "저장 완료", options = {}) => {
  if (!ref) {
    setStatus("Firebase 연결 전입니다", "error");
    return;
  }
  saving = true;
  savingToast(options.savingMessage || "저장 중입니다...");
  state.updatedAt = new Date().toISOString();
  try {
    if (runTransaction && db) {
      const merged = await runTransaction(db, async (transaction) => {
        if (options.authoritative) {
          const nextState = normalizeState(state);
          transaction.set(ref, nextState);
          return nextState;
        }
        const serverSnap = await transaction.get(ref);
        const remoteData = serverSnap.exists() ? serverSnap.data() : blankState();
        const nextState = mergeStates(remoteData, state);
        transaction.set(ref, nextState);
        return nextState;
      });
      state = normalizeState(merged);
    } else {
      reconcileProductStocks();
      await setDoc(ref, state);
    }
    setStatus(`${message} · 동시저장 보호`, "ok");
    saveDoneToast(options.doneMessage || "저장 완료");
  } catch (error) {
    console.error(error);
    setStatus(`저장 실패: ${error.message}`, "error");
    saveErrorToast(`저장 실패: ${error.message}`);
  } finally {
    saving = false;
  }
};

const renderNav = () => {
  ensureCurrentViewAllowed();
  nav.innerHTML = menus.filter(([key]) => canOpenView(key)).map(([key, label]) => `
    <button class="tab ${currentView === key ? "active" : ""}" data-view="${key}" type="button">${label}</button>
  `).join("");
  nav.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      if (!canOpenView(button.dataset.view)) return;
      currentView = button.dataset.view;
      render();
    });
  });
};

const render = () => {
  if (!ensureLocalSession() || !ensureCurrentViewAllowed()) return;
  renderedDate = today();
  renderSessionControls();
  renderNav();
  const views = {
    dashboard: renderDashboard,
    receipts: renderReceipts,
    implants: renderImplants,
    use: renderUse,
    history: renderHistory,
    edit: renderEditUsage,
    settings: renderSettings
  };
  const currentLabel = menus.find(([key]) => key === currentView)?.[1] || "대시보드";
  app.innerHTML = `
    <div class="page-head">
      <h2>${escapeHtml(currentLabel)}</h2>
      <div class="page-user">
        <strong>수술실 재고관리</strong><br>
        <span>${escapeHtml(today())}</span>
      </div>
    </div>
    ${views[currentView]?.() || renderDashboard()}
  `;
  bindCommon();
  bindView();
};

const bindCommon = () => {
  if (commonHandlersBound) return;
  commonHandlersBound = true;
  app.addEventListener("click", async (event) => {
    const editProductBtn = event.target.closest("[data-edit-product]");
    if (editProductBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 수정할 수 있습니다.");
        return;
      }
      const item = productById(editProductBtn.dataset.editProduct);
      if (!item) return;
      document.getElementById("productFormTitle").textContent = "제품 수정";
      document.getElementById("productId").value = item.id;
      document.getElementById("productCategory").value = item.category;
      document.getElementById("productName").value = item.name;
      document.getElementById("productCompany").innerHTML = productCompanyOptions(item.company || "", item.companyVendorId || "");
      document.getElementById("productCompany").value = productCompanySelectValue(item.company || "", item.companyVendorId || "");
      document.getElementById("productSubcategory").value = item.subcategory || "";
      document.getElementById("productStock").value = num(item.stock);
      document.getElementById("productWarning").value = num(item.warningStock);
      document.getElementById("productLanding").value = num(item.landingQty);
      syncProductFields?.();
      document.getElementById("productForm")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    const deleteProductBtn = event.target.closest("[data-delete-product]");
    if (deleteProductBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 삭제할 수 있습니다.");
        return;
      }
      const id = deleteProductBtn.dataset.deleteProduct;
      const productUsed = state.usages.some((usage) => usage.productIds.some((productId) => sameId(productId, id)));
      const productReceived = state.receipts.some((receipt) => sameId(receipt.productId, id));
      if ((productUsed || productReceived) && !confirm("내역에 사용된 제품입니다. 그래도 삭제할까요?")) return;
      state.products = state.products.filter((item) => !sameId(item.id, id));
      state.receipts = state.receipts.filter((item) => !sameId(item.productId, id));
      state.usages = state.usages.map((usage) => ({ ...usage, productIds: usage.productIds.filter((productId) => !sameId(productId, id)) }));
      render();
      await saveState("제품 삭제 완료", { authoritative: true });
      return;
    }

    const moveProductOrderBtn = event.target.closest("[data-move-product-order]");
    if (moveProductOrderBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 순서를 변경할 수 있습니다.");
        return;
      }
      const [id, direction] = String(moveProductOrderBtn.dataset.moveProductOrder || "").split("::");
      const products = nonpayProductsInDisplayOrder();
      const index = products.findIndex((item) => sameId(item.id, id));
      const nextIndex = direction === "up" ? index - 1 : index + 1;
      if (index < 0 || nextIndex < 0 || nextIndex >= products.length) return;
      normalizeNonpaySortOrders();
      const current = products[index];
      const next = products[nextIndex];
      const currentOrder = current.sortOrder;
      current.sortOrder = next.sortOrder;
      next.sortOrder = currentOrder;
      productCategoryToKeepOpen = productCategory(current.category) || "비급여";
      render();
      await saveState("비급여 제품 순서 변경 완료", {
        savingMessage: "비급여 제품 순서 저장 중입니다...",
        doneMessage: "비급여 제품 순서 변경 완료"
      });
      return;
    }

    const editDoctorBtn = event.target.closest("[data-edit-doctor]");
    if (editDoctorBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 수정할 수 있습니다.");
        return;
      }
      const item = state.doctors.find((entry) => sameId(entry.id, editDoctorBtn.dataset.editDoctor));
      if (!item) return;
      document.getElementById("doctorFormTitle").textContent = "과 수정";
      document.getElementById("doctorId").value = item.id;
      document.getElementById("doctorOldName").value = item.name;
      document.getElementById("doctorDepartment").value = departmentCode(item.name);
      document.getElementById("doctorNewDepartment").value = "";
      document.getElementById("doctorNumber").value = item.name.replace(departmentCode(item.name), "");
      document.getElementById("doctorForm")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    const deleteDoctorBtn = event.target.closest("[data-delete-doctor]");
    if (deleteDoctorBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 삭제할 수 있습니다.");
        return;
      }
      const id = deleteDoctorBtn.dataset.deleteDoctor;
      const doctorToDelete = state.doctors.find((item) => sameId(item.id, id));
      if (!confirm("과를 삭제할까요?")) return;
      state.doctors = state.doctors.filter((item) => !sameId(item.id, id));
      state.surgeries = state.surgeries.filter((item) => item.department !== doctorToDelete?.name);
      render();
      await saveState("과 삭제 완료", { authoritative: true });
      return;
    }

    const editSurgeryBtn = event.target.closest("[data-edit-surgery]");
    if (editSurgeryBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 수정할 수 있습니다.");
        return;
      }
      const item = surgeryById(editSurgeryBtn.dataset.editSurgery);
      if (!item) return;
      document.getElementById("surgeryFormTitle").textContent = "수술 수정";
      document.getElementById("surgeryId").value = item.id;
      document.getElementById("surgeryDepartment").value = item.department || inferSurgeryDepartment(item.name);
      document.getElementById("surgeryName").value = item.name;
      app.querySelectorAll("[data-surgery-doctor]").forEach((input) => {
        input.checked = surgeryDoctorIds(item).some((id) => sameId(id, input.value));
      });
      syncSurgeryDoctorScope?.();
      document.getElementById("surgeryForm")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    const deleteSurgeryBtn = event.target.closest("[data-delete-surgery]");
    if (deleteSurgeryBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 삭제할 수 있습니다.");
        return;
      }
      const id = deleteSurgeryBtn.dataset.deleteSurgery;
      if (!confirm("수술을 삭제할까요?")) return;
      state.surgeries = state.surgeries.filter((item) => !sameId(item.id, id));
      render();
      await saveState("수술 삭제 완료", { authoritative: true });
      return;
    }

    const editRuleBtn = event.target.closest("[data-edit-rule]");
    if (editRuleBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 수정할 수 있습니다.");
        return;
      }
      const rule = usageRuleById(editRuleBtn.dataset.editRule);
      if (!rule) return;
      document.getElementById("usageRuleFormTitle").textContent = "수술별 사용관리 수정";
      document.getElementById("usageRuleId").value = rule.id;
      document.getElementById("ruleDepartment").value = rule.department || departmentCode(departmentById(rule.doctorId)?.name || "") || document.getElementById("ruleDepartment").value;
      filterRuleOptions?.("department");
      document.getElementById("ruleDoctor").value = rule.doctorId;
      filterRuleOptions?.("doctor");
      document.getElementById("ruleSurgery").value = rule.surgeryId;
      const items = ruleItems(rule);
      app.querySelectorAll("[data-rule-product]").forEach((input) => {
        const item = items.find((entry) => sameId(entry.productId, input.value));
        input.checked = Boolean(item);
        const qtyInput = app.querySelector(`[data-rule-product-qty="${input.value}"]`);
        if (qtyInput) qtyInput.value = item ? Math.max(1, num(item.qty)) : 1;
      });
      document.getElementById("usageRuleForm")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    const deleteRuleBtn = event.target.closest("[data-delete-rule]");
    if (deleteRuleBtn) {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 삭제할 수 있습니다.");
        return;
      }
      if (!confirm("수술별 사용관리 규칙을 삭제할까요?")) return;
      state.usageRules = state.usageRules.filter((item) => !sameId(item.id, deleteRuleBtn.dataset.deleteRule));
      render();
      await saveState("수술별 사용관리 삭제 완료", { authoritative: true });
      return;
    }
  });
};

const bindView = () => {
  const handlers = {
    dashboard: bindDashboard,
    receipts: bindReceipts,
    implants: bindImplants,
    use: bindUse,
    history: bindHistory,
    edit: bindEditUsage,
    settings: bindSettings
  };
  handlers[currentView]?.();
};

let settingsModule = null;
const getSettingsModule = () => {
  if (!window.createSettingsModule) throw new Error("설정 모듈을 불러오지 못했습니다.");
  if (!settingsModule) {
    settingsModule = window.createSettingsModule({
      getApp: () => app,
      getCurrentSettingsView: () => currentSettingsView,
      setCurrentSettingsView: (view) => { currentSettingsView = view; },
      settingsMenus,
      canManageSettings,
      render,
      renderProducts,
      renderDoctors,
      renderSurgeries,
      renderUsageRules,
      renderImplantVendors,
      renderBackup,
      bindProducts,
      bindDoctors,
      bindSurgeries,
      bindUsageRules,
      bindImplantVendors,
      bindBackup
    });
  }
  return settingsModule;
};

const renderSettings = () => getSettingsModule().renderSettings();
const bindSettings = () => getSettingsModule().bindSettings();

let dashboardModule = null;
const getDashboardModule = () => {
  if (!window.createDashboardModule) throw new Error("대시보드 모듈을 불러오지 못했습니다.");
  if (!dashboardModule) {
    dashboardModule = window.createDashboardModule({
      getState: () => state,
      getApp: () => app,
      setCurrentView: (view) => { currentView = view; },
      render,
      saveState,
      num,
      alphaFirstCompare,
      today,
      productCategory,
      productCategoryLabel,
      productById,
      landingUsageLines,
      pendingUsagesOpen,
      PRODUCT_CATEGORIES,
      escapeHtml,
      usageItem,
      lowProductItem
    });
  }
  return dashboardModule;
};

const renderDashboard = () => getDashboardModule().renderDashboard();
const bindDashboard = () => getDashboardModule().bindDashboard();

const productItem = (item, options = {}) => {
  const low = num(item.stock) <= num(item.warningStock);
  const detail = [
    `분류: ${escapeHtml(productCategoryLabel(item.category))}`,
    item.company ? `업체: ${escapeHtml(item.company)}` : "",
    item.subcategory ? `세부: ${escapeHtml(item.subcategory)}` : ""
  ].filter(Boolean).join(" · ");
  return `
    <div class="item">
      <div class="item-title">
        <span>${escapeHtml(item.name)}</span>
        <span class="pill ${low ? "low" : ""}">${low ? "경고" : item.category}</span>
      </div>
      <div class="meta">
        <span>${detail}</span>
        <span>현재고: ${num(item.stock)} · 경고수량: ${num(item.warningStock)}${item.category === "비급여" ? "" : ` · 랜딩수량: ${num(item.landingQty)}`}</span>
      </div>
      ${canManageSettings() ? `<div class="actions">
        ${options.showSort ? `
          <button class="secondary" type="button" data-move-product-order="${item.id}::up" ${options.canMoveUp ? "" : "disabled"}>위</button>
          <button class="secondary" type="button" data-move-product-order="${item.id}::down" ${options.canMoveDown ? "" : "disabled"}>아래</button>
        ` : ""}
        <button class="secondary" type="button" data-edit-product="${item.id}">수정</button>
        <button class="danger" type="button" data-delete-product="${item.id}">삭제</button>
      </div>` : ""}
    </div>
  `;
};

const lowProductItem = (item, hidden = false) => {
  const shortage = Math.max(0, num(item.warningStock) - num(item.stock));
  const reason = num(item.stock) <= num(item.warningStock)
    ? `현재고 ${num(item.stock)}개가 경고수량 ${num(item.warningStock)}개 이하입니다.${shortage ? ` ${shortage}개 더 있어야 경고에서 벗어납니다.` : ""}`
    : "";
  return `
    <div class="item">
      <div class="item-title">
        <span>${escapeHtml(item.name)}</span>
        <span class="pill low">경고</span>
      </div>
      <div class="meta">
        <span>분류: ${escapeHtml(productCategoryLabel(item.category))}${item.company ? ` · 업체: ${escapeHtml(item.company)}` : ""}${item.subcategory ? ` · 세부: ${escapeHtml(item.subcategory)}` : ""}</span>
        <span>현재고: ${num(item.stock)} · 경고수량: ${num(item.warningStock)}${item.category === "비급여" ? "" : ` · 랜딩수량: ${num(item.landingQty)}`}</span>
        <span>${escapeHtml(reason)}</span>
      </div>
      <div class="actions">
        <button class="secondary" type="button" data-${hidden ? "show" : "hide"}-low-product="${item.id}">${hidden ? "다시 보이기" : "감추기"}</button>
      </div>
    </div>
  `;
};

const renderGroupedProducts = (withActions) => {
  if (!state.products.length) return `<div class="empty">제품을 추가해 주세요.</div>`;
  const categories = PRODUCT_CATEGORIES;
  return categories.map((category) => {
    const categoryItems = state.products.filter((item) => productCategory(item.category) === category).sort(productDisplaySort(category));
    if (!categoryItems.length) return "";
    if (category === "비급여") {
      return `
        <details class="item" ${withActions && productCategoryToKeepOpen === category ? "open" : ""}>
          <summary><span>비급여</span><span class="pill">${categoryItems.length}</span></summary>
          <div class="details-body">
            ${categoryItems.map((item, index) => withActions
              ? productItem(item, { showSort: true, canMoveUp: index > 0, canMoveDown: index < categoryItems.length - 1 })
              : productCheckItem(item)).join("")}
          </div>
        </details>
      `;
    }
    const companies = [...new Set(categoryItems.map((item) => item.company || "업체 없음"))].sort(alphaFirstCompare);
    return `
      <details class="item">
        <summary><span>${escapeHtml(productCategoryLabel(category))}</span><span class="pill">${categoryItems.length}</span></summary>
        <div class="details-body">
          ${companies.map((company) => renderProductCompanyGroup(categoryItems, company, category, withActions)).join("")}
        </div>
      </details>
    `;
  }).join("");
};

const renderProductCompanyGroup = (items, company, category, withActions) => {
  const companyItems = items.filter((item) => (item.company || "업체 없음") === company).sort(byName);
  if (category !== "ANCHOR") {
    return `
      <details class="item">
        <summary><span>${escapeHtml(company)}</span><span class="pill">${companyItems.length}</span></summary>
        <div class="details-body">
          ${companyItems.map((item) => withActions ? productItem(item) : productCheckItem(item)).join("")}
        </div>
      </details>
    `;
  }
  const subcategories = [...new Set(companyItems.map((item) => item.subcategory || "분류 없음"))].sort(alphaFirstCompare);
  return `
    <details class="item">
      <summary><span>${escapeHtml(company)}</span><span class="pill">${companyItems.length}</span></summary>
      <div class="details-body">
        ${subcategories.map((subcategory) => {
          const subItems = companyItems.filter((item) => (item.subcategory || "분류 없음") === subcategory).sort(byName);
          return `
            <details class="item">
              <summary><span>${escapeHtml(subcategory)}</span><span class="pill">${subItems.length}</span></summary>
              <div class="details-body">
                ${subItems.map((item) => withActions ? productItem(item) : productCheckItem(item)).join("")}
              </div>
            </details>
          `;
        }).join("")}
      </div>
    </details>
  `;
};


const qtyStepper = (inputAttrs, value, max = 999) => `
  <div class="qty-stepper">
    <button type="button" onclick="event.preventDefault();event.stopPropagation();adjustQtyButton(this,-1)" aria-label="수량 줄이기">−</button>
    <input type="number" min="1" max="${Math.max(1, num(max))}" value="${Math.max(1, num(value))}" ${inputAttrs} readonly>
    <button type="button" onclick="event.preventDefault();event.stopPropagation();adjustQtyButton(this,1)" aria-label="수량 늘리기">+</button>
  </div>
`;

window.adjustQtyButton = (button, delta) => {
  const wrap = button.closest('.qty-stepper');
  const input = wrap?.querySelector('input');
  if (!input) return;
  const min = Math.max(1, num(input.min || 1));
  const max = Math.max(min, num(input.max || 9999));
  const next = Math.min(max, Math.max(min, num(input.value || 1) + delta));
  input.value = next;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
};

const productCheckItem = (item) => `
  <label class="check-card use-card">
    <input type="checkbox" value="${item.id}" data-use-product="${item.id}" ${num(item.stock) < 1 ? "disabled" : ""}>
    <span>${escapeHtml(item.name)}<br><span class="muted">${escapeHtml(item.company || item.category)}${item.subcategory ? ` · ${escapeHtml(item.subcategory)}` : ""}</span></span>
    ${qtyStepper(`data-use-qty="${item.id}" aria-label="${escapeHtml(item.name)} 사용 수량"`, 1, Math.max(1, num(item.stock)))}
  </label>
`;

let syncProductFields = null;
let syncSurgeryDoctorScope = null;
let filterRuleOptions = null;
let usageRuleListFilterFromForm = null;

let productsModule = null;
const getProductsModule = () => {
  if (!window.createProductsModule) throw new Error("제품관리 모듈을 불러오지 못했습니다.");
  if (!productsModule) {
    productsModule = window.createProductsModule({
      getState: () => state,
      getImplantVendors: () => implantVendors,
      setSyncProductFields: (handler) => { syncProductFields = handler; },
      canManageSettings,
      renderGroupedProducts,
      productCompanyOptions,
      implantVendorById,
      productById,
      productSortOrderValue,
      nextNonpaySortOrder,
      productMovementCounts,
      reconcileProductStocks,
      render,
      saveState,
      uid,
      num
    });
  }
  return productsModule;
};

const renderProducts = () => getProductsModule().renderProducts();
const bindProducts = () => getProductsModule().bindProducts();

let departmentsModule = null;
const getDepartmentsModule = () => {
  if (!window.createDepartmentsModule) throw new Error("과/수술관리 모듈을 불러오지 못했습니다.");
  if (!departmentsModule) {
    departmentsModule = window.createDepartmentsModule({
      getState: () => state,
      getApp: () => app,
      setSyncSurgeryDoctorScope: (handler) => { syncSurgeryDoctorScope = handler; },
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
    });
  }
  return departmentsModule;
};

const renderDoctors = () => getDepartmentsModule().renderDoctors();
const renderSurgeries = () => getDepartmentsModule().renderSurgeries();
const bindDoctors = () => getDepartmentsModule().bindDoctors();
const bindSurgeries = () => getDepartmentsModule().bindSurgeries();

const departmentPriority = (name) => {
  if (name === "NS") return 0;
  if (name === "OS") return 1;
  return 2;
};

const departmentCompare = (left, right) => departmentPriority(left) - departmentPriority(right) || alphaFirstCompare(left, right);

const departmentNames = () => [...new Set(state.doctors.map((item) => departmentCode(item.name)).filter(Boolean))]
  .sort(departmentCompare);

const departmentOptions = (selected = "") => departmentNames()
  .map((name) => `<option value="${escapeHtml(name)}" ${name === selected ? "selected" : ""}>${escapeHtml(name)}</option>`)
  .join("");

const landingReceiptKey = (usageId, productId) => `${usageId}::${productId}`;

const landingReceiptByLine = () => {
  const map = new Map();
  state.receipts
    .filter((item) => item.type === "landing")
    .forEach((item) => map.set(landingReceiptKey(item.usageId, item.productId), item));
  return map;
};

const landingUsageLines = (includeReceived = true) => {
  const received = landingReceiptByLine();
  return state.usages.flatMap((usage) => {
    const counts = (usage.productIds || []).reduce((map, productId) => {
      map.set(productId, (map.get(productId) || 0) + 1);
      return map;
    }, new Map());
    return Array.from(counts.entries()).map(([productId, qty]) => {
    const product = productById(productId);
    if (!product || productCategory(product.category) === "비급여") return null;
    const receipt = received.get(landingReceiptKey(usage.id, productId));
    if (!includeReceived && receipt) return null;
    return { usage, product, receipt, qty };
  });
  }).filter(Boolean);
};

const renderLandingBoard = () => {
  const lines = landingUsageLines(true);
  if (!lines.length) return `<div class="empty">랜딩 입고 확인 대상이 없습니다.</div>`;
  const companies = [...new Set(lines.map((line) => line.product.company || "업체 없음"))].sort(alphaFirstCompare);
  return companies.map((company) => {
    const companyLines = lines.filter((line) => (line.product.company || "업체 없음") === company);
    const pendingCount = companyLines.filter((line) => !line.receipt).length;
    const categoryLabels = [...new Set(companyLines.map((line) => productCategoryLabel(line.product.category)))].sort(alphaFirstCompare).join(", ");
    const productIds = [...new Set(companyLines.map((line) => line.product.id))]
      .sort((a, b) => alphaFirstCompare(productById(a)?.name || "", productById(b)?.name || ""));
    return `
      <details class="item">
        <summary><span>${escapeHtml(company)} 랜딩 입고</span><span class="pill">${pendingCount ? `대기 ${pendingCount}` : "완료"}</span></summary>
        <div class="details-body">
          <div class="meta"><span>${escapeHtml(categoryLabels)}</span></div>
          ${pendingCount ? `<div class="actions"><button type="button" data-receive-company="${escapeHtml(company)}">업체 전체 랜딩 입고</button></div>` : ""}
          ${productIds.map((productId) => {
            const product = productById(productId);
            const productLines = companyLines
              .filter((line) => line.product.id === productId)
              .sort((a, b) => alphaFirstCompare(a.usage.date, b.usage.date) || alphaFirstCompare(a.usage.patientName, b.usage.patientName));
            const productPending = productLines.filter((line) => !line.receipt).length;
            return `
              <details class="item">
                <summary><span>${escapeHtml(product?.name || "삭제된 제품")}</span><span class="pill">${productPending ? `대기 ${productPending}` : "완료"}</span></summary>
                <div class="details-body">
                  <div class="meta"><span>${escapeHtml(productCategoryLabel(product?.category))}${product?.subcategory ? ` · ${escapeHtml(product.subcategory)}` : ""}</span></div>
                  ${productLines.map(landingLineItem).join("")}
                </div>
              </details>
            `;
          }).join("")}
        </div>
      </details>
    `;
  }).join("");
};

const landingLineItem = ({ usage, product, receipt, qty }) => `
  <div class="item landing-line ${receipt ? "received" : "pending"}">
    <div class="compact-line">
      <div class="compact-main">${escapeHtml(product?.name || "삭제된 제품")} · ${escapeHtml(usage.patientName)} · 사용 ${escapeHtml(usage.date)} · ${Math.max(1, num(qty))}개</div>
      <div class="compact-meta">${receipt ? `입고 ${escapeHtml(receipt.date)} · ${num(receipt.qty)}개 · 입고자: ${escapeHtml(auditUserText(receipt) || "-")} · 입고시각: ${escapeHtml(auditTimeText(receipt))}` : "입고 대기"}</div>
      <span class="pill ${receipt ? "" : "low"}">${receipt ? "확인" : "대기"}</span>
      ${receipt ? "" : `<div class="compact-actions"><button type="button" data-receive-landing="${usage.id}::${product.id}">입고 확인</button></div>`}
    </div>
  </div>
`;

const receiptHistoryFiltersHtml = (prefix) => `
  <div class="row three receipt-history-filter">
    <div class="receipt-search-cell">
      <label for="${prefix}Search">제품명 검색</label>
      <input id="${prefix}Search" autocomplete="off" placeholder="제품명 입력">
      <div class="receipt-search-menu" id="${prefix}ProductMenu" hidden></div>
    </div>
    <div>
      <label for="${prefix}Start">시작일</label>
      <input id="${prefix}Start" type="date">
    </div>
    <div>
      <label for="${prefix}End">종료일</label>
      <input id="${prefix}End" type="date">
    </div>
  </div>
  <div class="actions receipt-history-tools">
    <div class="actions">
      <button class="secondary" type="button" data-receipt-quick="7" data-receipt-prefix="${prefix}">최근 7일</button>
      <button class="secondary" type="button" data-receipt-quick="30" data-receipt-prefix="${prefix}">최근 30일</button>
      <button class="secondary" type="button" data-receipt-reset data-receipt-prefix="${prefix}">초기화</button>
    </div>
    <div class="actions">
      <button class="secondary" type="button" data-export-receipt-history>엑셀 저장</button>
    </div>
  </div>
`;

const renderReceiptHistoryList = (start = "", end = "", query = "") => {
  const receipts = filteredReceipts(start, end, query);
  const manager = canManageReceipts();
  if (!receipts.length) return `<div class="empty">조회된 입고이력이 없습니다.</div>`;
  return `
    <div class="receipt-history-list">
      ${receipts.map((receipt) => {
        const product = receiptProduct(receipt);
        const name = receiptProductName(receipt);
        const meta = receiptProductMeta(receipt);
        const date = receiptDateValue(receipt);
        const updatedText = receipt.updatedAt ? ` · 수정 ${escapeHtml(formatDateTime(receipt.updatedAt))}${receipt.updatedByName || receipt.updatedBy?.name ? ` / ${escapeHtml(receipt.updatedByName || receipt.updatedBy?.name)}` : ""}` : "";
        const receiverBadge = receipt.type === "nonpay" && auditRoleLabel(receipt) === "입고담당자"
          ? `<span class="receipt-role-badge" title="입고담당자가 비급여 입고관리에서 입력한 기록입니다.">입고담당자 입력</span>`
          : "";
        return `
          <div class="item receipt-history-card" data-receipt-row="${escapeHtml(receipt.id)}">
            <div class="receipt-history-head">
              <div class="receipt-history-name">
                ${escapeHtml(name)}
                <span>${escapeHtml(meta || "-")}</span>
              </div>
              <span class="pill">${num(receipt.qty).toLocaleString()}개</span>
              ${receiverBadge}
            </div>
            <div class="receipt-history-meta">
              <span>입고일: ${escapeHtml(date || "-")}</span>
              <span>구분: ${escapeHtml(receiptTypeLabel(receipt))}</span>
              <span>입력자: ${escapeHtml(auditUserText(receipt) || "-")}</span>
              <span>입고시각: ${escapeHtml(auditTimeText(receipt))}${updatedText}</span>
            </div>
            ${receipt.memo ? `<div class="receipt-memo">메모: ${escapeHtml(receipt.memo)}</div>` : ""}
            ${receipt.type === "landing" ? `<div class="receipt-memo">사용일: ${escapeHtml(receipt.usageDate || "-")} · 환자명: ${escapeHtml(receipt.patientName || "-")}</div>` : ""}
            ${manager ? `
              <div class="actions">
                <button class="secondary" type="button" data-edit-receipt="${escapeHtml(receipt.id)}">수정</button>
                <button class="danger" type="button" data-delete-receipt="${escapeHtml(receipt.id)}">삭제</button>
              </div>
              <form class="receipt-edit-form" data-edit-receipt-form="${escapeHtml(receipt.id)}" hidden>
                <div class="row three">
                  <div>
                    <label for="receiptEditDate-${escapeHtml(receipt.id)}">입고일</label>
                    <input id="receiptEditDate-${escapeHtml(receipt.id)}" type="date" value="${escapeHtml(date)}" data-receipt-edit-date required>
                  </div>
                  <div>
                    <label for="receiptEditQty-${escapeHtml(receipt.id)}">입고수량</label>
                    <input id="receiptEditQty-${escapeHtml(receipt.id)}" type="number" min="1" value="${num(receipt.qty) || 1}" data-receipt-edit-qty required>
                  </div>
                  <div>
                    <label for="receiptEditProduct-${escapeHtml(receipt.id)}">제품명</label>
                    <input id="receiptEditProduct-${escapeHtml(receipt.id)}" value="${escapeHtml(product?.name || receipt.productName || name)}" readonly>
                  </div>
                </div>
                <label for="receiptEditMemo-${escapeHtml(receipt.id)}">메모</label>
                <textarea id="receiptEditMemo-${escapeHtml(receipt.id)}" class="memo-input" data-receipt-edit-memo placeholder="메모">${escapeHtml(receipt.memo || "")}</textarea>
                <div class="actions">
                  <button type="submit">수정 저장</button>
                  <button class="secondary" type="button" data-cancel-edit-receipt="${escapeHtml(receipt.id)}">취소</button>
                </div>
              </form>
            ` : ""}
          </div>
        `;
      }).join("")}
    </div>
  `;
};

const renderReceiptHistory = () => renderReceiptHistoryList();

let usageRulesModule = null;
const getUsageRulesModule = () => {
  if (!window.createUsageRulesModule) throw new Error("수술별 사용관리 모듈을 불러오지 못했습니다.");
  if (!usageRulesModule) {
    usageRulesModule = window.createUsageRulesModule({
      getState: () => state,
      getApp: () => app,
      setFilterRuleOptions: (handler) => { filterRuleOptions = handler; },
      setUsageRuleListFilterFromForm: (handler) => { usageRuleListFilterFromForm = handler; },
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
    });
  }
  return usageRulesModule;
};

const renderUsageRules = () => getUsageRulesModule().renderUsageRules();
const bindUsageRules = () => getUsageRulesModule().bindUsageRules();
const ruleItems = (rule) => getUsageRulesModule().ruleItems(rule);

let receiptsModule = null;
const getReceiptsModule = () => {
  if (!window.createReceiptsModule) throw new Error("입고관리 모듈을 불러오지 못했습니다.");
  if (!receiptsModule) {
    receiptsModule = window.createReceiptsModule({
      getState: () => state,
      getApp: () => app,
      getCurrentReceiptView: () => currentReceiptView,
      setCurrentReceiptView: (view) => { currentReceiptView = view; },
      canRegisterNonpayReceipts,
      canManageLandingReceipts,
      canManageReceipts,
      currentUserRole,
      productCategory,
      productDisplaySort,
      escapeHtml,
      num,
      renderLandingBoard,
      receiptHistoryFiltersHtml,
      renderReceiptHistory,
      renderReceiptHistoryList,
      receiptProduct,
      receiptProductName,
      sameId,
      today,
      auditUpdateFields,
      auditCreateFields,
      reconcileProductStocks,
      render,
      saveState,
      normalizedName,
      byName,
      exportReceiptHistory,
      productById,
      uid,
      landingUsageLines
    });
  }
  return receiptsModule;
};

const renderReceipts = () => getReceiptsModule().renderReceipts();
const bindReceipts = () => getReceiptsModule().bindReceipts();

const filteredImplantRecords = (date, patientName, patientId, patientNo) => getImplantsModule().filteredImplantRecords(date, patientName, patientId, patientNo);

const implantRecordsForDate = (date) => sortImplantRecords(implantRecords.filter((record) => implantRecordDate(record) === date));
const implantPhotoViewSrc = (photo) => getImplantsModule().implantPhotoViewSrc(photo);
const implantPhotoRotationStyle = (photo) => getImplantsModule().implantPhotoRotationStyle(photo);
const implantPhotoNeedsStorageRetry = (photo) => getImplantsModule().implantPhotoNeedsStorageRetry(photo);
const implantPhotoStatusStats = (records) => getImplantsModule().implantPhotoStatusStats(records);
const implantPhotoProblemRows = (records) => getImplantsModule().implantPhotoProblemRows(records);
const implantSendStatusLabel = (status = "pending") => getImplantsModule().implantSendStatusLabel(status);
const implantSendStatusClass = (status = "pending") => getImplantsModule().implantSendStatusClass(status);

const assignImplantPatientNosForDate = async (date) => {
  if (!canAssignImplantPatientNo()) return 0;
  if (!date) throw new Error("날짜를 선택해 주세요.");
  const targets = sortImplantRecords(implantRecordsForDate(date));
  const updates = [];
  const assignedAt = new Date().toISOString();
  targets.forEach((record, index) => {
    const patientNo = String(index + 1);
    record.patientNo = patientNo;
    record.patientNoAssignedAt = assignedAt;
    record.closedAt = assignedAt;
    record.editUnlocked = false;
    updates.push(setDoc(doc(db, "implantRecords", record.id), {
      patientNo,
      patientNoAssignedAt: assignedAt,
      closedAt: assignedAt,
      editUnlocked: false,
      updatedAt: new Date().toISOString(),
      ...auditUpdateFields()
    }, { merge: true }));
  });
  await Promise.all(updates);
  return targets.length;
};

const clearImplantPatientNosForDate = async (date) => {
  if (!canAssignImplantPatientNo()) return 0;
  if (!date) throw new Error("날짜를 선택해 주세요.");
  const targets = implantRecordsForDate(date).filter((record) =>
    implantPatientNoText(record) || record.closedAt || record.patientNoAssignedAt || record.editUnlocked === true
  );
  const clearedAt = new Date().toISOString();
  await Promise.all(targets.map((record) => {
    record.patientNo = "";
    record.patientNoAssignedAt = null;
    record.patientNoManuallyEditedAt = null;
    record.closedAt = null;
    record.editUnlocked = false;
    return setDoc(doc(db, "implantRecords", record.id), {
      patientNo: "",
      patientNoAssignedAt: null,
      patientNoManuallyEditedAt: null,
      closedAt: null,
      editUnlocked: false,
      patientNoClearedAt: clearedAt,
      patientNoClearReason: "manualDateReset",
      updatedAt: clearedAt,
      ...auditUpdateFields()
    }, { merge: true });
  }));
  return targets.length;
};

const implantDescriptionText = (record) => getImplantsModule().implantDescriptionText(record);
const implantLedgerRows = (records) => getImplantsModule().implantLedgerRows(records);

const implantLedgerTableHtml = (records) => getImplantsModule().implantLedgerTableHtml(records);

const exportImplantLedgerExcel = (date) => {
  const records = implantRecordsForDate(date);
  if (!records.length) {
    alert("엑셀로 저장할 임플란트 기록이 없습니다.");
    return;
  }
  downloadExcel(
    `임플란트장부_${date || "all"}.xlsx`,
    ["날짜", "번호", "환자이름", "ID", "수술명", "원장코드", "저장자", "저장시각", "업체", "사용분", "사진수"],
    implantLedgerRows(records)
  );
};

const safeBackupFileName = (value) => getImplantsModule().safeBackupFileName(value);
const downloadBytes = (filename, bytes, type = "application/octet-stream") => {
  const blob = new Blob([bytes], { type });
  downloadBlob(filename, blob);
};
const downloadBlob = (filename, blob) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    link.remove();
  }, 0);
};
const exportImplantMonthlyBackup = (month, onProgress) => getImplantsModule().exportImplantMonthlyBackup(month, onProgress);

const implantSendMessage = (date, vendorName, lines) => getImplantsModule().implantSendMessage(date, vendorName, lines);
const implantSendGroups = (date) => getImplantsModule().implantSendGroups(date);
const implantSendGroupStats = (group) => getImplantsModule().implantSendGroupStats(group);
const implantSendPatientGroups = (group) => getImplantsModule().implantSendPatientGroups(group);

const implantSendPhotoLedgerHtml = (group) => getImplantsModule().implantSendPhotoLedgerHtml(group);
const implantSendPrintHtml = (date, group) => getImplantsModule().implantSendPrintHtml(date, group);
const implantSendLedgerTableRowsHtml = (group, options = {}) => getImplantsModule().implantSendLedgerTableRowsHtml(group, options);
const implantSendPhotoLedgerTableHtml = (group) => getImplantsModule().implantSendPhotoLedgerTableHtml(group);
const implantSendPrintTableHtml = (date, group) => getImplantsModule().implantSendPrintTableHtml(date, group);
const implantStatementPhotoChunks = (photos = [], size = 4) => getImplantsModule().implantStatementPhotoChunks(photos, size);
const implantStatementFooterHtml = (record = {}) => getImplantsModule().implantStatementFooterHtml(record);
const implantSendStatementCardsHtml = (group) => getImplantsModule().implantSendStatementCardsHtml(group);
const implantSendStatementPrintHtml = (date, group) => getImplantsModule().implantSendStatementPrintHtml(date, group);
const implantSendStatementPrintHtmlV2 = (date, group) => getImplantsModule().implantSendStatementPrintHtmlV2(date, group);

const implantSendPanelHtml = (date) => getImplantsModule().implantSendPanelHtml(date);
const implantSendPanelOrganizedHtml = (date) => getImplantsModule().implantSendPanelOrganizedHtml(date);

const retryImplantRecordPhotos = async (recordId, onProgress) => {
  const record = implantRecords.find((item) => sameId(item.id, recordId));
  if (!record) throw new Error("임플란트 기록을 찾을 수 없습니다.");
  let total = 0;
  let done = 0;
  let failed = 0;
  (record.implants || []).forEach((implant) => {
    total += (implant.photos || []).filter(implantPhotoNeedsStorageRetry).length;
  });
  notifyImplantPhotoUpload(onProgress, done, total, failed);
  const implants = [];
  for (const implant of record.implants || []) {
    const photos = [];
    const photoUploadErrors = [];
    let retried = 0;
    for (const photo of implant.photos || []) {
      if (!implantPhotoNeedsStorageRetry(photo)) {
        photos.push(cleanImplantPhotoPayload(photo));
        continue;
      }
      retried += 1;
      try {
        photos.push(await uploadImplantPhoto(record.id, implant.id || uid(), photo, implantRecordDate(record)));
      } catch (error) {
        photos.push(cleanImplantPhotoPayload(photo));
        photoUploadErrors.push(error.message || "사진 재업로드 실패");
        failed += 1;
      } finally {
        done += 1;
        notifyImplantPhotoUpload(onProgress, done, total, failed);
      }
    }
    implants.push({
      ...implant,
      photos,
      pendingPhotoCount: Math.max(0, num(implant.pendingPhotoCount) - retried),
      photoUploadErrors: retried ? (photoUploadErrors.length ? photoUploadErrors : []) : (implant.photoUploadErrors || [])
    });
  }
  await setDoc(doc(db, "implantRecords", record.id), {
    implants,
    hasPhotoUploadError: implants.some((implant) => (implant.photoUploadErrors || []).length),
    updatedAt: new Date().toISOString(),
    ...auditUpdateFields()
  }, { merge: true });
};

const updateImplantSendGroupStatus = async (date, vendor, status) => {
  const allowed = new Set(["pending", "sent", "excluded", "resend"]);
  if (!allowed.has(status)) throw new Error("알 수 없는 발송 상태입니다.");
  const updates = implantRecordsForDate(date).map((record) => {
    let changed = false;
    const implants = (record.implants || []).map((implant) => {
      if ((implant.vendor || "업체 없음") !== vendor) return implant;
      changed = true;
      return {
        ...implant,
        sendStatus: status,
        sendStatusLabel: implantSendStatusLabel(status),
        sendStatusUpdatedAt: new Date().toISOString(),
        sendStatusUpdatedBy: auditUpdateFields().updatedBy
      };
    });
    if (!changed) return null;
    return setDoc(doc(db, "implantRecords", record.id), {
      implants,
      updatedAt: new Date().toISOString(),
      ...auditUpdateFields()
    }, { merge: true });
  }).filter(Boolean);
  await Promise.all(updates);
  return updates.length;
};

const implantPhotoHtml = (photo) => getImplantsModule().implantPhotoHtml(photo);
const implantPhotoStatusHtml = (implant) => getImplantsModule().implantPhotoStatusHtml(implant);
const implantPhotoStatusPanelHtml = (date) => getImplantsModule().implantPhotoStatusPanelHtml(date);
const implantRecordCardHtml = (record, options = {}) => getImplantsModule().implantRecordCardHtml(record, options);

const implantSubViewItems = () => [
  ["today", "오늘 장부"],
  ["hospital", "병원 확인용"],
  ["send", "업체 발송함"],
  ["photos", "사진 상태"],
  ["backup", "백업/보관"],
  ...(canEditImplantPatientNo() ? [["admin", "관리자"]] : [])
];
const ensureImplantSubView = () => {
  const allowed = new Set(implantSubViewItems().map(([key]) => key));
  if (!allowed.has(currentImplantSubView)) currentImplantSubView = "today";
  return currentImplantSubView;
};
const implantPanelVisible = (panelNames = "") => panelNames.split(/\s+/).filter(Boolean).includes(currentImplantSubView);

let implantsModule = null;
const getImplantsModule = () => {
  if (!window.createImplantsModule) throw new Error("임플란트 장부 모듈을 불러오지 못했습니다.");
  if (!implantsModule) {
    implantsModule = window.createImplantsModule({
      app,
      today,
      escapeHtml,
      implantSubViewItems,
      ensureImplantSubView,
      implantPanelVisible,
      getCurrentImplantSubView: () => currentImplantSubView,
      setCurrentImplantSubView: (value) => { currentImplantSubView = value; },
      render,
      num,
      uid,
      normalizedName,
      productCategory,
      productById,
      currentUserRole,
      alphaFirstCompare,
      implantVendorById,
      findImplantVendorByName,
      sortImplantRecords,
      surgeryById,
      departmentById,
      auditUserText,
      auditTimeText,
      currentAuditUser,
      implantRecordsForDate,
      assignImplantPatientNosForDate,
      clearImplantPatientNosForDate,
      exportImplantLedgerExcel,
      showSaveToast,
      saveDoneToast,
      saveErrorToast,
      implantPatientNoText,
      showImplantPhotoModal,
      hideImplantPhotoModal,
      updateImplantSendGroupStatus,
      setButtonBusy,
      downloadBlob,
      downloadBytes,
      zipFiles,
      xlsxWorkbook,
      retryImplantRecordPhotos,
      setDoc,
      doc,
      db,
      deleteDoc,
      getImplantRecords: () => implantRecords,
      setImplantRecords: (nextRecords) => { implantRecords = nextRecords; },
      sameId,
      implantRecordDate,
      auditUpdateFields
    });
  }
  return implantsModule;
};

const renderImplants = () => getImplantsModule().renderImplants();

let implantVendorsModule = null;
const getImplantVendorsModule = () => {
  if (!window.createImplantVendorsModule) throw new Error("임플란트 업체관리 모듈을 불러오지 못했습니다.");
  if (!implantVendorsModule) {
    implantVendorsModule = window.createImplantVendorsModule({
      getState: () => state,
      getApp: () => app,
      getImplantVendors: () => implantVendors,
      getDb: () => db,
      getDocFn: () => doc,
      getSetDoc: () => setDoc,
      implantVendorById,
      alphaFirstCompare,
      escapeHtml,
      uid,
      auditUpdateFields,
      auditCreateFields,
      sameId,
      normalizedName,
      saveState
    });
  }
  return implantVendorsModule;
};

const renderImplantVendors = () => getImplantVendorsModule().renderImplantVendors();
const bindImplantVendors = () => getImplantVendorsModule().bindImplantVendors();

let usageEntryModule = null;
const getUsageEntryModule = () => {
  if (!window.createUsageEntryModule) throw new Error("사용입력 모듈을 불러오지 못했습니다.");
  if (!usageEntryModule) {
    usageEntryModule = window.createUsageEntryModule({
      getState: () => state,
      pendingUsagesOpen,
      getApp: () => app,
      num,
      departmentById,
      surgeryById,
      escapeHtml,
      patientDisplayName,
      today,
      formatDateTime,
      productCategory,
      productById,
      productCategoryLabel,
      qtyStepper,
      implantPhotoViewSrc,
      implantPhotoRotationStyle,
      implantVendorOptions,
      uid,
      currentAuditUser,
      alphaFirstCompare,
      normalizedName,
      patientIdText,
      inferSurgeryDepartment,
      usageProductItems,
      canModifyUsageRecord,
      implantVendorEntriesMatch,
      mergeImplantDescriptionLines,
      implantVendorById,
      cleanImplantPhotoPayload
    });
  }
  return usageEntryModule;
};

const pendingUsageSummary = (item) => getUsageEntryModule().pendingUsageSummary(item);
const renderPendingUsageList = () => getUsageEntryModule().renderPendingUsageList();

const renderUse = () => `
  <section class="grid">
    ${renderPendingUsageList()}
    <form class="card" id="useForm">
      <h2>사용입력</h2>
      <div class="row four">
        <div>
          <label for="useDate">사용일</label>
          <input id="useDate" type="date" value="${today()}" required>
        </div>
        <div>
          <label for="patientName">환자명</label>
          <input id="patientName" required autocomplete="off">
        </div>
        <div>
          <label for="patientId">환자 등록번호</label>
          <input id="patientId" required inputmode="numeric" pattern="[0-9]{8}" autocomplete="off" placeholder="숫자 8자리">
        </div>
        <div>
          <label>비급여 제한</label>
          <button class="secondary" type="button" id="useRestrictNonpay" data-restrict="false">비급여 제한 꺼짐</button>
        </div>
      </div>
      <div class="row two">
        <div>
          <label for="useDepartment">과</label>
          <select id="useDepartment" required>
            <option value="">과 선택</option>
            ${departmentNames().map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}
          </select>
        </div>
        <div>
          <label for="useDoctor">원장 코드</label>
          <select id="useDoctor" required>
            <option value="">원장 코드 선택</option>
            ${state.doctors.slice().sort(byName).map((item) => `<option value="${item.id}" data-department="${escapeHtml(departmentCode(item.name))}">${escapeHtml(item.name)}</option>`).join("")}
          </select>
        </div>
      </div>
      <div class="row">
        <div>
          <label for="useSurgery">수술</label>
          <select id="useSurgery" required>
            <option value="">수술 선택</option>
            ${state.surgeries.slice().sort((a, b) => alphaFirstCompare(a.department || inferSurgeryDepartment(a.name), b.department || inferSurgeryDepartment(b.name)) || alphaFirstCompare(a.name, b.name)).map((item) => `<option value="${item.id}" data-department="${escapeHtml(item.department || inferSurgeryDepartment(item.name))}">${escapeHtml(item.department || inferSurgeryDepartment(item.name))} - ${escapeHtml(item.name)}</option>`).join("")}
          </select>
        </div>
      </div>
      <div id="useRecommendation" class="use-recommendation-gap"></div>
      <div class="card use-content-card">
        <div class="use-content-head">
          <h3>사용내용</h3>
          <button class="icon-search-btn" type="button" id="openUseProductSearch" aria-haspopup="dialog" aria-controls="useProductSearchModal" title="제품 검색">🔍 제품 검색</button>
        </div>
        <div id="selectedUseList" class="meta"><span>선택된 제품이 없습니다.</span></div>
      </div>
      ${renderUseProductSearchModal()}
      ${renderImplantPhotoModal()}
      <label>제품 여러 개 선택</label>
      <div class="product-picker">
        ${renderGroupedProducts(false)}
      </div>
      <label class="implant-toggle" for="useImplantEnabled">
        <input id="useImplantEnabled" type="checkbox">
        <span>임플란트 기록</span>
      </label>
      <div id="implantUsePanel" class="implant-panel" hidden>
        <div class="implant-send-preview">환자명, 환자ID, 과, 원장코드, 수술명, 수술일은 위 사용입력 정보로 자동 저장됩니다.</div>
        <div class="implant-common-photos">
          <div class="implant-common-head">
            <strong>공용 사진함</strong>
            <div class="implant-common-actions">
              <button class="secondary" type="button" id="openCommonImplantGallery">파일 선택</button>
              <button type="button" id="openCommonImplantCamera">공용 사진 찍기</button>
              <input id="commonImplantGallery" type="file" accept="image/*" multiple>
              <input id="commonImplantCamera" type="file" accept="image/*" capture="environment">
            </div>
          </div>
          <div class="muted">한 번 찍은 사진을 여러 업체에 복사한 뒤, 업체별로 따로 자르기/회전할 수 있습니다.</div>
          <div id="commonImplantPhotoList" class="implant-common-grid"></div>
        </div>
        <div id="implantVendorEntries"></div>
        <div class="actions">
          <button class="secondary" type="button" id="addImplantVendorEntry">임플란트 업체 추가</button>
        </div>
      </div>
      <div class="actions">
        <button type="button" id="saveUseDraft">임시저장</button>
      </div>
      <div class="use-draft-panel" id="useDraftPanel" hidden>
        <div class="use-draft-head">
          <div>
            <strong>스크럽 확인 대기</strong>
            <div class="muted">임시저장 단계에서는 재고차감과 사용내역 저장을 하지 않습니다.</div>
          </div>
          <span class="use-draft-status" id="useDraftStatus">임시저장 완료</span>
        </div>
        <div class="use-draft-summary" id="useDraftSummary"></div>
        <div class="actions">
          <button class="secondary" type="button" id="editUseDraft">수정</button>
          <button type="submit" id="finalSaveUseDraft">최종저장</button>
          <button class="danger" type="button" id="cancelUseDraft">임시저장 취소</button>
        </div>
      </div>
    </form>
  </section>
`;

const usageProductItems = (usage) => Array.from((usage?.productIds || []).reduce((map, id) => {
  map.set(id, (map.get(id) || 0) + 1);
  return map;
}, new Map()).entries()).map(([productId, qty]) => ({ productId, qty }));

const renderUseItemsList = (items, target) => getUsageEntryModule().renderUseItemsList(items, target);
const useDraftSummaryHtml = (snapshot) => getUsageEntryModule().useDraftSummaryHtml(snapshot);
const selectedUseItemsFromScope = (scope) => getUsageEntryModule().selectedUseItemsFromScope(scope);
const syncRecommendControl = (productId, checked, qty = "") => getUsageEntryModule().syncRecommendControl(productId, checked, qty);
const setRestrictButtonState = (button, value) => getUsageEntryModule().setRestrictButtonState(button, value);
const setUseDraftPanelState = (options) => getUsageEntryModule().setUseDraftPanelState(options);
const draftUserText = () => getUsageEntryModule().draftUserText();
const selectedUseListHtml = (items) => getUsageEntryModule().selectedUseListHtml(items);
const useProductSearchResults = (products, query) => getUsageEntryModule().useProductSearchResults(products, query);
const productSearchResultsHtml = (results, selectedItems) => getUsageEntryModule().productSearchResultsHtml(results, selectedItems);
const productSearchEmptyQueryHtml = () => getUsageEntryModule().productSearchEmptyQueryHtml();
const noRecommendationHtml = (hasSurgerySelection) => getUsageEntryModule().noRecommendationHtml(hasSurgerySelection);
const useRecommendedItemsWithProducts = (items) => getUsageEntryModule().useRecommendedItemsWithProducts(items);
const shouldHideUseProductForRestriction = (product, productId, recommendedItems, restrictActive) => getUsageEntryModule().shouldHideUseProductForRestriction(product, productId, recommendedItems, restrictActive);
const syncRecommendProductToUseForm = (input, form) => getUsageEntryModule().syncRecommendProductToUseForm(input, form);
const syncRecommendQtyToUseForm = (input) => getUsageEntryModule().syncRecommendQtyToUseForm(input);
const searchProductQtyValue = (container, productId) => getUsageEntryModule().searchProductQtyValue(container, productId);
const clearSearchProductFromUseForm = (productId, form) => getUsageEntryModule().clearSearchProductFromUseForm(productId, form);
const applyPendingProductItemsToForm = (form, productItems) => getUsageEntryModule().applyPendingProductItemsToForm(form, productItems);
const finalSaveRecommendationCheck = (options) => getUsageEntryModule().finalSaveRecommendationCheck(options);
const sameDayPatientUsageWarning = (options) => getUsageEntryModule().sameDayPatientUsageWarning(options);
const buildFinalUsageRecord = (options) => getUsageEntryModule().buildFinalUsageRecord(options);
const useRecommendationHtml = (recommended, restrictActive, selectedItems) => getUsageEntryModule().useRecommendationHtml(recommended, restrictActive, selectedItems);
const commonImplantPhotosHtml = (photos) => getUsageEntryModule().commonImplantPhotosHtml(photos);
const emptyImplantDraft = () => getUsageEntryModule().emptyImplantDraft();
const addCommonImplantPhotosFromFiles = (photos, files) => getUsageEntryModule().addCommonImplantPhotosFromFiles(photos, files);
const cloneCommonImplantPhoto = (photo) => getUsageEntryModule().cloneCommonImplantPhoto(photo);
const commonImplantPhotoById = (photos, id) => getUsageEntryModule().commonImplantPhotoById(photos, id);
const removeCommonImplantPhotoById = (photos, id) => getUsageEntryModule().removeCommonImplantPhotoById(photos, id);
const implantDraftByIdFromList = (drafts, id) => getUsageEntryModule().implantDraftById(drafts, id);
const addImplantDraftPhotosFromFiles = (draft, files) => getUsageEntryModule().addImplantDraftPhotosFromFiles(draft, files);
const removeImplantDraftById = (drafts, id) => getUsageEntryModule().removeImplantDraftById(drafts, id);
const mergeDuplicateImplantDraftsInList = (drafts) => getUsageEntryModule().mergeDuplicateImplantDrafts(drafts);
const implantDraftPayloadFromList = (drafts, enabled) => getUsageEntryModule().implantDraftPayloadFromList(drafts, enabled);
const useDraftValidationMessage = (useItems, implantDraftPayload) => getUsageEntryModule().useDraftValidationMessage(useItems, implantDraftPayload);
const patientIdValidationMessage = (patientId) => getUsageEntryModule().patientIdValidationMessage(patientId);
const buildUseDraftSnapshot = (options) => getUsageEntryModule().buildUseDraftSnapshot(options);
const pendingUsagePhotoCount = (implantDraftPayload) => getUsageEntryModule().pendingUsagePhotoCount(implantDraftPayload);
const pendingUsagePhotoProgressMessage = (done, total, failed) => getUsageEntryModule().pendingUsagePhotoProgressMessage(done, total, failed);
const pendingImplantDraftsFromRecord = (pending) => getUsageEntryModule().pendingImplantDraftsFromRecord(pending);
const implantDraftPhotoPair = (drafts, value) => getUsageEntryModule().implantDraftPhotoPair(drafts, value);
const implantDraftsHtml = (drafts, commonPhotoCount) => getUsageEntryModule().implantDraftsHtml(drafts, commonPhotoCount);

const editUsagePatientsForDate = (date) => getUsageEntryModule().editUsagePatientsForDate(date);
const editUsagePatientCardHtml = (usage, selectedId = "") => getUsageEntryModule().editUsagePatientCardHtml(usage, selectedId);
const editUsagePatientListHtml = (date, selectedId = "") => getUsageEntryModule().editUsagePatientListHtml(date, selectedId);
const renderUseProductSearchModal = () => getUsageEntryModule().renderUseProductSearchModal();
const renderImplantPhotoModal = () => getUsageEntryModule().renderImplantPhotoModal();

const renderEditUsage = () => {
  if (!canEditUsage()) return `<div class="empty">사용내역 수정은 관리자, 책임사용자, 일반사용자만 가능합니다.</div>`;
  const pendingUsage = pendingEditUsageId ? state.usages.find((usage) => usage.id === pendingEditUsageId) : null;
  const editSelectDate = pendingUsage?.date || today();
  return `
  <section class="grid">
    <div class="card">
      <h2>환자 사용내역 선택</h2>
      <div>
        <label for="editUsageSelectDate">사용일 선택</label>
        <input id="editUsageSelectDate" type="date" value="${escapeHtml(editSelectDate)}">
      </div>
      <input type="hidden" id="editUsageSelect" value="${escapeHtml(pendingUsage?.id || "")}">
      <div class="row two edit-patient-search-row">
        <div>
          <label for="editUsagePatientNameSearch">환자명 검색</label>
          <input id="editUsagePatientNameSearch" autocomplete="off" placeholder="환자 이름 입력">
        </div>
        <div>
          <label for="editUsagePatientIdSearch">등록번호 검색</label>
          <input id="editUsagePatientIdSearch" inputmode="numeric" autocomplete="off" placeholder="등록번호 입력">
        </div>
      </div>
      <p class="helper">기본값은 오늘 날짜입니다. 환자명이나 등록번호를 입력하면 아래 접힌 목록이 열리고 해당 환자만 표시됩니다.</p>
      <details class="item edit-patient-details" id="editUsagePatientDetails">
        <summary><span>환자 목록 보기</span><span class="pill" id="editUsagePatientCount">${editUsagePatientsForDate(editSelectDate).length}</span></summary>
        <div class="details-body">
          <div id="editUsagePatientList" class="edit-patient-list">
            ${editUsagePatientListHtml(editSelectDate, pendingUsage?.id || "")}
          </div>
        </div>
      </details>
    </div>
    <form class="card" id="editUsageForm" style="display:none;">
      <h2 id="editUsageFormTitle">사용내용 수정</h2>
      <div id="editUsageLockNote"></div>
      <input type="hidden" id="editUsageId">
      <div class="row three">
        <div>
          <label for="editPatientName">환자명</label>
          <input id="editPatientName" required autocomplete="off">
        </div>
        <div>
          <label for="editPatientId">환자 등록번호</label>
          <input id="editPatientId" required inputmode="numeric" pattern="[0-9]{8}" autocomplete="off" placeholder="숫자 8자리">
        </div>
        <div>
          <label for="editUsageDate">사용일</label>
          <input id="editUsageDate" type="date" required>
        </div>
      </div>
      <div class="row two">
        <div>
          <label for="editDepartment">과</label>
          <select id="editDepartment" required>
            <option value="">과 선택</option>
            ${departmentNames().map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}
          </select>
        </div>
        <div>
          <label for="editDoctor">원장 코드</label>
          <select id="editDoctor" required>
            <option value="">원장 코드 선택</option>
            ${state.doctors.slice().sort(byName).map((item) => `<option value="${item.id}" data-department="${escapeHtml(departmentCode(item.name))}">${escapeHtml(item.name)}</option>`).join("")}
          </select>
        </div>
      </div>
      <label for="editSurgery">수술</label>
      <select id="editSurgery" required>
        <option value="">수술 선택</option>
        ${state.surgeries.slice().sort((a, b) => alphaFirstCompare(a.department || inferSurgeryDepartment(a.name), b.department || inferSurgeryDepartment(b.name)) || alphaFirstCompare(a.name, b.name)).map((item) => `<option value="${item.id}" data-department="${escapeHtml(item.department || inferSurgeryDepartment(item.name))}">${escapeHtml(item.department || inferSurgeryDepartment(item.name))} - ${escapeHtml(item.name)}</option>`).join("")}
      </select>
      <div class="card">
        <h3>수정될 사용내용</h3>
        <div id="editSelectedUseList" class="meta"><span>선택된 제품이 없습니다.</span></div>
      </div>
      <div class="card">
        <h3>제품 검색</h3>
        <label for="editProductSearch">제품명 검색</label>
        <input id="editProductSearch" autocomplete="off" placeholder="제품명을 입력하면 바로 찾을 수 있습니다">
        <div id="editProductSearchResults" class="product-picker"></div>
      </div>
      <div class="card" id="editImplantSection" hidden>
        <h3>임플란트 기록 수정</h3>
        <p class="helper">선택한 환자 사용내역과 연결된 임플란트 업체명·사용내용과 사진을 함께 수정합니다. 기존 사진은 유지되며, 필요하면 이 화면에서 사진을 추가하거나 기존 사진 삭제 후 새 사진으로 교체할 수 있습니다.</p>
        <div id="editImplantLockNote"></div>
        <div class="implant-common-photos" id="editCommonImplantWrap">
          <div class="implant-common-head">
            <strong>공용 사진함</strong>
            <div class="implant-common-actions">
              <button class="secondary" type="button" id="openEditCommonImplantGallery">파일 선택</button>
              <button type="button" id="openEditCommonImplantCamera">공용 사진 찍기</button>
              <input id="editCommonImplantGallery" type="file" accept="image/*" multiple>
              <input id="editCommonImplantCamera" type="file" accept="image/*" capture="environment">
            </div>
          </div>
          <div class="muted">수정 화면에서도 한 번 찍은 사진을 여러 업체에 나눠 붙일 수 있습니다.</div>
          <div id="editCommonImplantPhotoList" class="implant-common-grid"></div>
        </div>
        <div id="editImplantRows" class="implant-panel"></div>
        <div class="actions">
          <button class="secondary" type="button" id="addEditImplantRow">임플란트 업체 추가</button>
        </div>
      </div>
      <div class="modal-backdrop" id="implantPhotoModal" hidden role="dialog" aria-modal="true" aria-label="&#51076;&#54540;&#46976;&#53944; &#49324;&#51652; &#54869;&#45824;">
        <div class="search-modal-panel">
          <div class="search-modal-head">
            <h3>&#49324;&#51652; &#54869;&#51064;</h3>
            <button class="search-modal-close" type="button" id="closeImplantPhotoModal" aria-label="&#49324;&#51652; &#45803;&#44592;">&times;</button>
          </div>
          <div class="implant-crop-stage" id="implantCropStage">
            <img class="implant-modal-image" id="implantPhotoModalImage" alt="&#51076;&#54540;&#46976;&#53944; &#49324;&#51652; &#54869;&#45824;">
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
            <button class="secondary" type="button" id="implantModalRotate">&#54924;&#51204;</button>
            <button class="secondary" type="button" id="implantModalCrop">&#51088;&#47476;&#44592;</button>
            <button type="button" id="implantModalDone">&#50756;&#47308;</button>
          </div>
        </div>
      </div>
      <label>제품 여러 개 선택</label>
      <div class="product-picker">
        ${renderGroupedProducts(false)}
      </div>
      <div class="actions">
        <button type="submit">수정 저장</button>
        <button class="secondary" type="button" id="editUsageCancel">선택 해제</button>
        <button class="danger" type="button" id="editUsageDelete" style="display:none;">사용내역 삭제</button>
      </div>
    </form>
  </section>
`;
};

const bindEditUsage = () => {
  if (!canEditUsage()) return;
  const dateInput = document.getElementById("editUsageSelectDate");
  const select = document.getElementById("editUsageSelect");
  const patientNameSearch = document.getElementById("editUsagePatientNameSearch");
  const patientIdSearch = document.getElementById("editUsagePatientIdSearch");
  const patientDetails = document.getElementById("editUsagePatientDetails");
  const patientCount = document.getElementById("editUsagePatientCount");
  const form = document.getElementById("editUsageForm");
  const patientList = document.getElementById("editUsagePatientList");
  const lockNote = document.getElementById("editUsageLockNote");
  const formTitle = document.getElementById("editUsageFormTitle");
  const useDepartment = document.getElementById("editDepartment");
  const doctorSelect = document.getElementById("editDoctor");
  const surgerySelect = document.getElementById("editSurgery");
  const selectedList = document.getElementById("editSelectedUseList");
  const productSearch = document.getElementById("editProductSearch");
  const productSearchResults = document.getElementById("editProductSearchResults");
  const editImplantSection = document.getElementById("editImplantSection");
  const editImplantLockNote = document.getElementById("editImplantLockNote");
  const editImplantRowsWrap = document.getElementById("editImplantRows");
  const editCommonImplantPhotoList = document.getElementById("editCommonImplantPhotoList");
  const openEditCommonImplantGallery = document.getElementById("openEditCommonImplantGallery");
  const openEditCommonImplantCamera = document.getElementById("openEditCommonImplantCamera");
  const editCommonImplantGallery = document.getElementById("editCommonImplantGallery");
  const editCommonImplantCamera = document.getElementById("editCommonImplantCamera");
  const addEditImplantRow = document.getElementById("addEditImplantRow");
  const deleteButton = document.getElementById("editUsageDelete");
  let editImplantRecordId = "";
  let editImplantRows = [];
  const editCommonImplantPhotos = [];
  let editImplantCanModify = true;
  let activeEditImplantPhotoPair = "";
  const clearEditCommonImplantPhotos = () => {
    editCommonImplantPhotos.forEach((photo) => {
      if (photo.preview) URL.revokeObjectURL(photo.preview);
      if (photo.editedPreview) URL.revokeObjectURL(photo.editedPreview);
    });
    editCommonImplantPhotos.splice(0, editCommonImplantPhotos.length);
  };
  const editPatientFilters = () => ({
    name: patientNameSearch?.value || "",
    patientId: patientIdSearch?.value || ""
  });
  const renderUsageSelectOptions = (date, selectedId = "", filters = editPatientFilters()) => {
    const validSelectedId = selectedId && state.usages.some((usage) => usage.id === selectedId && (usage.date || "") === date) ? selectedId : "";
    const patients = editUsagePatientsForDate(date, filters);
    select.value = validSelectedId;
    if (patientCount) patientCount.textContent = patients.length;
    if (patientList) patientList.innerHTML = editUsagePatientListHtml(date, validSelectedId, filters);
  };
  const resetLoadedUsage = () => {
    select.value = "";
    form.style.display = "none";
    deleteButton.style.display = "none";
    if (lockNote) lockNote.innerHTML = "";
    if (formTitle) formTitle.textContent = "사용내용 수정";
    if (editImplantSection) editImplantSection.hidden = true;
    if (editImplantLockNote) editImplantLockNote.innerHTML = "";
    editImplantRecordId = "";
    editImplantRows = [];
    clearEditCommonImplantPhotos();
    renderEditCommonImplantPhotos();
    pendingEditUsageId = "";
    if (patientList) patientList.querySelectorAll("[data-edit-usage-card]").forEach((card) => card.classList.remove("active"));
  };
  const selectedItems = () => Array.from(form.querySelectorAll("[data-use-product]:checked")).map((input) => ({
    productId: input.value,
    qty: Math.max(1, num(form.querySelector(`[data-use-qty="${input.value}"]`)?.value))
  }));
  const renderSelected = (options = {}) => {
    renderUseItemsList(selectedItems(), selectedList);
    if (options.syncImplants !== false) syncEditImplantRowsFromSelectedProducts();
  };
  const selectProduct = (productId, qty = 1, options = {}) => {
    const checkbox = form.querySelector(`[data-use-product="${productId}"]`);
    const qtyInput = form.querySelector(`[data-use-qty="${productId}"]`);
    if (checkbox) checkbox.checked = true;
    if (qtyInput) qtyInput.value = Math.max(1, num(qty));
    renderSelected(options);
  };
  const clearProducts = () => {
    form.querySelectorAll("[data-use-product]").forEach((input) => {
      input.checked = false;
      input.disabled = false;
    });
    form.querySelectorAll("[data-use-qty]").forEach((input) => {
      input.value = 1;
      input.disabled = false;
    });
  };
  const implantVendorSelectValue = (implant) => {
    if (implant.vendorId) return implant.vendorId;
    const matched = implantVendors.find((vendor) => normalizedName(vendor.name) === normalizedName(implant.vendor));
    return matched?.id || (implant.vendor ? "__custom__" : "");
  };
  const implantVendorCustomValue = (implant) => {
    const selected = implantVendorSelectValue(implant);
    return selected === "__custom__" ? (implant.vendor || "") : "";
  };
  const editImplantPhotoSrc = (photo) => implantPhotoViewSrc(photo);
  const editCommonImplantPhotoById = (id) => editCommonImplantPhotos.find((photo) => photo.id === id);
  const cloneEditCommonImplantPhoto = (photo) => ({
    id: uid(),
    file: photo.file || null,
    preview: photo.file ? URL.createObjectURL(photo.file) : (photo.preview || ""),
    url: photo.url || "",
    dataUrl: photo.dataUrl || "",
    name: photo.name || photo.file?.name || "",
    size: num(photo.size || photo.file?.size),
    contentType: photo.contentType || photo.file?.type || "image/jpeg",
    rotation: 0,
    cropped: false,
    cropRect: null,
    sourceCommonPhotoId: photo.id
  });
  const renderEditCommonImplantPhotos = () => {
    if (!editCommonImplantPhotoList) return;
    editCommonImplantPhotoList.innerHTML = editCommonImplantPhotos.map((photo, index) => {
      const src = implantPhotoViewSrc(photo);
      return `
        <div class="implant-common-photo" data-edit-common-implant-photo="${escapeHtml(photo.id)}">
          ${src ? `<img src="${escapeHtml(src)}" alt="수정 공용 임플란트 사진 ${index + 1}" data-preview-edit-common-implant-photo="${escapeHtml(photo.id)}">` : ""}
          <div class="implant-photo-actions">
            <button class="secondary" type="button" data-preview-edit-common-implant-photo="${escapeHtml(photo.id)}">확대</button>
            <button class="danger" type="button" data-remove-edit-common-implant-photo="${escapeHtml(photo.id)}" ${editImplantCanModify ? "" : "disabled"}>삭제</button>
          </div>
        </div>
      `;
    }).join("") || `<div class="empty">공용 사진을 먼저 촬영하거나 선택해 주세요.</div>`;
  };
  const addEditCommonImplantPhotos = (files = []) => {
    if (!editImplantCanModify) return;
    files.filter((file) => file.type.startsWith("image/")).forEach((file) => {
      editCommonImplantPhotos.push({
        id: uid(),
        file,
        preview: URL.createObjectURL(file),
        name: file.name || "implant.jpg",
        size: file.size,
        contentType: file.type || "image/jpeg",
        rotation: 0,
        cropped: false
      });
    });
    renderEditCommonImplantPhotos();
    renderEditImplantRows();
  };
  const renderEditImplantRows = () => {
    if (!editImplantRowsWrap) return;
    editImplantRowsWrap.innerHTML = editImplantRows.length ? editImplantRows.map((row, index) => {
      const photos = Array.isArray(row.photos) ? row.photos : [];
      const existingPhotoCount = photos.filter((photo) => photo.url && !photo.file).length;
      return `
      <div class="implant-vendor-card" data-edit-implant-row="${escapeHtml(row.id)}">
        <div class="implant-vendor-head">
          <strong>업체 ${index + 1}</strong>
          <button class="danger" type="button" data-remove-edit-implant-row="${escapeHtml(row.id)}" ${editImplantCanModify ? "" : "disabled"}>업체 삭제</button>
        </div>
        <div class="row two">
          <div>
            <label for="editImplantVendorSelect-${escapeHtml(row.id)}">업체명</label>
            <select id="editImplantVendorSelect-${escapeHtml(row.id)}" data-edit-implant-vendor-select="${escapeHtml(row.id)}" ${editImplantCanModify ? "" : "disabled"}>
              ${implantVendorOptions(row.vendorId)}
            </select>
          </div>
          <div ${row.vendorId === "__custom__" ? "" : "hidden"}>
            <label for="editImplantVendorCustom-${escapeHtml(row.id)}">직접 입력</label>
            <input id="editImplantVendorCustom-${escapeHtml(row.id)}" data-edit-implant-vendor-custom="${escapeHtml(row.id)}" value="${escapeHtml(row.customVendor || "")}" autocomplete="off" ${editImplantCanModify ? "" : "disabled"}>
          </div>
        </div>
        <label for="editImplantDescription-${escapeHtml(row.id)}">사용내용</label>
        <textarea id="editImplantDescription-${escapeHtml(row.id)}" data-edit-implant-description="${escapeHtml(row.id)}" placeholder="Plate 255-209-L&#10;Screw 22mm 3ea" ${editImplantCanModify ? "" : "disabled"}>${escapeHtml(row.description || "")}</textarea>
        <label for="editImplantPhotos-${escapeHtml(row.id)}">사진첨부/교체</label>
        <div class="implant-photo-pickers">
          <button class="secondary" type="button" data-open-edit-implant-gallery="${escapeHtml(row.id)}" ${editImplantCanModify ? "" : "disabled"}>파일 선택</button>
          <button type="button" data-open-edit-implant-camera="${escapeHtml(row.id)}" ${editImplantCanModify ? "" : "disabled"}>사진 찍기</button>
          <span class="muted">기존 사진 ${existingPhotoCount}장 유지 · 교체는 기존 사진 삭제 후 새 사진을 추가하세요.</span>
          <button class="secondary" type="button" data-use-edit-common-implant-photo="${escapeHtml(row.id)}" ${editImplantCanModify && editCommonImplantPhotos.length ? "" : "disabled"}>공용 사진 사용</button>
          <input id="editImplantGallery-${escapeHtml(row.id)}" type="file" accept="image/*" multiple data-edit-implant-photo-input="${escapeHtml(row.id)}" ${editImplantCanModify ? "" : "disabled"}>
          <input id="editImplantCamera-${escapeHtml(row.id)}" type="file" accept="image/*" capture="environment" data-edit-implant-camera-input="${escapeHtml(row.id)}" ${editImplantCanModify ? "" : "disabled"}>
        </div>
        ${implantPhotoStatusHtml(row)}
        <div class="implant-photo-grid">
          ${photos.map((photo, photoIndex) => {
            const src = editImplantPhotoSrc(photo);
            return src ? `
            <div class="implant-photo" data-edit-implant-photo="${escapeHtml(photo.id)}">
              <img class="${photo.cropped ? "cropped" : ""}" src="${escapeHtml(src)}" alt="임플란트 ${photo.file ? "신규" : "기존"} 사진" data-preview-edit-implant-photo="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" style="${implantPhotoRotationStyle(photo)} cursor:pointer;">
              <div class="implant-photo-actions">
                <button class="secondary" type="button" data-edit-existing-implant-photo="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" ${editImplantCanModify ? "" : "disabled"}>편집</button>
                <button class="secondary" type="button" data-move-edit-implant-photo-up="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" ${!editImplantCanModify || photoIndex === 0 ? "disabled" : ""}>앞</button>
                <button class="secondary" type="button" data-move-edit-implant-photo-down="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" ${!editImplantCanModify || photoIndex === photos.length - 1 ? "disabled" : ""}>뒤</button>
                <button class="danger" type="button" data-remove-edit-implant-photo="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" ${editImplantCanModify ? "" : "disabled"}>삭제</button>
              </div>
            </div>` : "";
          }).join("")}
        </div>
      </div>`;
    }).join("") : `<div class="empty">연결된 임플란트 업체 기록이 없습니다. 필요하면 업체를 추가한 뒤 저장하세요.</div>`;
  };
  const updateEditImplantRowFromInput = (target) => {
    const rowId = target.dataset.editImplantVendorSelect || target.dataset.editImplantVendorCustom || target.dataset.editImplantDescription;
    const row = editImplantRows.find((item) => item.id === rowId);
    if (!row) return;
    if (target.matches("[data-edit-implant-vendor-select]")) {
      row.vendorId = target.value;
      if (target.value !== "__custom__") row.customVendor = "";
      renderEditImplantRows();
    } else if (target.matches("[data-edit-implant-vendor-custom]")) {
      row.customVendor = target.value;
    } else if (target.matches("[data-edit-implant-description]")) {
      row.description = target.value;
    }
  };
  const readEditImplantRows = () => Array.from(editImplantRowsWrap?.querySelectorAll("[data-edit-implant-row]") || []).map((rowElement) => {
    const rowId = rowElement.dataset.editImplantRow;
    const current = editImplantRows.find((item) => item.id === rowId) || {};
    const vendorId = rowElement.querySelector("[data-edit-implant-vendor-select]")?.value || "";
    const customVendor = rowElement.querySelector("[data-edit-implant-vendor-custom]")?.value.trim() || "";
    const description = rowElement.querySelector("[data-edit-implant-description]")?.value.trim() || "";
    const vendor = vendorId === "__custom__"
      ? customVendor
      : (implantVendorById(vendorId)?.name || current.vendor || "");
    return {
      id: rowId || uid(),
      vendorId: vendorId && vendorId !== "__custom__" ? vendorId : "",
      customVendor,
      vendor: String(vendor || "").trim(),
      description,
      photos: Array.isArray(current.photos) ? current.photos : [],
      pendingPhotoCount: num(current.pendingPhotoCount),
      photoUploadErrors: Array.isArray(current.photoUploadErrors) ? current.photoUploadErrors : [],
      autoSource: current.autoSource || "",
      autoCompanyKey: current.autoCompanyKey || "",
      autoDescription: current.autoDescription || ""
    };
  }).filter((row) => row.vendor || row.description || row.photos.length);
  const editImplantRowById = (id) => editImplantRows.find((item) => item.id === id);
  const parseEditImplantPair = (value) => {
    const [rowId, photoId] = String(value || "").split("::");
    const row = editImplantRowById(rowId);
    const photo = row?.photos?.find((item) => item.id === photoId);
    return { row, photo };
  };
  const addEditImplantPhotos = (rowId, files) => {
    const row = editImplantRowById(rowId);
    if (!row || !editImplantCanModify) return;
    const imageFiles = Array.from(files || []).filter((file) => file.type.startsWith("image/"));
    imageFiles.forEach((file) => row.photos.push({
      id: uid(),
      file,
      preview: URL.createObjectURL(file),
      rotation: 0,
      cropped: false
    }));
    renderEditImplantRows();
  };
  const mergeDuplicateEditImplantRows = () => {
    const kept = [];
    let changed = false;
    for (let index = 0; index < editImplantRows.length; index += 1) {
      const row = editImplantRows[index];
      const existing = kept.find((item) => implantVendorEntriesMatch(item, row));
      if (!existing) {
        kept.push(row);
        continue;
      }
      existing.vendorId = existing.vendorId || row.vendorId || "";
      existing.customVendor = existing.customVendor || row.customVendor || "";
      existing.vendor = existing.vendor || row.vendor || "";
      existing.autoSource = existing.autoSource || row.autoSource;
      existing.autoCompanyKey = existing.autoCompanyKey || row.autoCompanyKey || "";
      existing.description = mergeImplantDescriptionLines(existing.description, row.description);
      existing.autoDescription = mergeImplantDescriptionLines(existing.autoDescription, row.autoDescription);
      const existingPhotoIds = new Set((existing.photos || []).map((photo) => photo.id));
      (row.photos || []).forEach((photo) => {
        if (!existingPhotoIds.has(photo.id)) {
          existing.photos = existing.photos || [];
          existing.photos.push(photo);
          existingPhotoIds.add(photo.id);
        }
      });
      editImplantRows.splice(index, 1);
      index -= 1;
      changed = true;
    }
    return changed;
  };
  const syncEditImplantRowsFromSelectedProducts = () => {
    if (!editImplantCanModify) return;
    const targets = implantVendorTargetsFromUseItems(selectedItems());
    const targetKeys = new Set(targets.map((target) => target.key));
    let changed = false;
    for (let index = editImplantRows.length - 1; index >= 0; index -= 1) {
      const row = editImplantRows[index];
      if (row.autoSource === "product" && !targetKeys.has(row.autoCompanyKey) && !implantDraftHasManualContent(row)) {
        editImplantRows.splice(index, 1);
        changed = true;
      }
    }
    if (mergeDuplicateEditImplantRows()) changed = true;
    targets.forEach((target) => {
      const existing = findImplantEntryByVendorTarget(editImplantRows, target);
      if (existing) {
        if (!existing.autoCompanyKey) existing.autoCompanyKey = target.key;
        if (existing.vendorId !== target.vendorId || existing.customVendor !== target.customVendor || existing.vendor !== target.vendor) {
          existing.vendorId = target.vendorId;
          existing.customVendor = target.customVendor;
          existing.vendor = target.vendor;
          changed = true;
        }
        if (implantDraftCanAutoUpdateDescription(existing) && existing.description !== target.description) {
          existing.description = target.description;
          existing.autoDescription = target.description;
          changed = true;
        } else if (existing.autoDescription !== target.description) {
          existing.autoDescription = target.description;
        }
        return;
      }
      const reusable = editImplantRows.find((row) => !row.autoSource && !implantDraftVendorName(row) && !implantRowHasContent(row));
      if (reusable) {
        Object.assign(reusable, {
          vendorId: target.vendorId,
          customVendor: target.customVendor,
          vendor: target.vendor,
          description: target.description,
          autoDescription: target.description,
          autoSource: "product",
          autoCompanyKey: target.key
        });
        changed = true;
        return;
      }
      editImplantRows.push({
        id: uid(),
        vendorId: target.vendorId,
        customVendor: target.customVendor,
        vendor: target.vendor,
        description: target.description,
        photos: [],
        pendingPhotoCount: 0,
        photoUploadErrors: [],
        autoSource: "product",
        autoDescription: target.description,
        autoCompanyKey: target.key
      });
      changed = true;
    });
    if (targets.length && editImplantSection) editImplantSection.hidden = false;
    if (changed) renderEditImplantRows();
  };
  const markEditImplantPhotoChanged = (photo) => {
    if (photo && !photo.file && (photo.url || photo.dataUrl)) photo.needsReupload = true;
  };
  const refreshEditImplantPhotoEditor = () => {
    const { photo } = parseEditImplantPair(activeEditImplantPhotoPair);
    const image = document.getElementById("implantPhotoModalImage");
    const cropButton = document.getElementById("implantModalCrop");
    if (!photo || !image) return;
    image.src = implantPhotoViewSrc(photo);
    applyImplantModalPhotoState(image, photo);
    showImplantPhotoEditTools();
    if (cropButton) cropButton.textContent = photo.cropped ? "자르기 수정" : "자르기";
  };
  const openEditImplantPhotoEditor = (pair) => {
    activeEditImplantPhotoPair = pair;
    const { photo } = parseEditImplantPair(pair);
    if (!photo) return;
    showImplantPhotoModal(implantPhotoViewSrc(photo));
    activeImplantCropPhoto = photo;
    activeImplantCropApply = async (changedPhoto) => {
      markEditImplantPhotoChanged(changedPhoto);
      await refreshEditedImplantPreview(changedPhoto);
      renderEditImplantRows();
      refreshEditImplantPhotoEditor();
    };
    refreshEditImplantPhotoEditor();
  };
  const revokeEditImplantLocalPhotos = (photos) => {
    (photos || []).forEach((photo) => {
      if (photo.preview) URL.revokeObjectURL(photo.preview);
    });
  };
  const loadEditImplantsForUsage = (usage, canModify) => {
    const record = implantRecordsForUsage(usage.id)[0];
    editImplantCanModify = canModify && (!record || canModifyImplantRecord(record));
    const implantLockMessage = record && !editImplantCanModify ? implantEditLockMessage(record) : "";
    editImplantRecordId = record?.id || "";
    clearEditCommonImplantPhotos();
    editImplantRows = (Array.isArray(record?.implants) ? record.implants : []).map((implant) => ({
      id: implant.id || uid(),
      vendorId: implantVendorSelectValue(implant),
      customVendor: implantVendorCustomValue(implant),
      vendor: implant.vendor || "",
      description: implant.description || "",
      photos: Array.isArray(implant.photos) ? implant.photos : [],
      pendingPhotoCount: num(implant.pendingPhotoCount),
      photoUploadErrors: Array.isArray(implant.photoUploadErrors) ? implant.photoUploadErrors : []
    }));
    if (editImplantSection) editImplantSection.hidden = false;
    if (editImplantLockNote) {
      editImplantLockNote.innerHTML = implantLockMessage ? `<div class="edit-lock-note">${escapeHtml(implantLockMessage)} 관리자에게 요청해 주세요.</div>` : "";
    }
    if (addEditImplantRow) addEditImplantRow.disabled = !editImplantCanModify;
    if (openEditCommonImplantGallery) openEditCommonImplantGallery.disabled = !editImplantCanModify;
    if (openEditCommonImplantCamera) openEditCommonImplantCamera.disabled = !editImplantCanModify;
    renderEditCommonImplantPhotos();
    renderEditImplantRows();
  };
  const syncEditStockLimits = (usage) => {
    const originalCounts = usageProductItems(usage).reduce((map, item) => {
      map.set(item.productId, item.qty);
      return map;
    }, new Map());
    form.querySelectorAll("[data-use-product]").forEach((input) => {
      const product = productById(input.value);
      const available = num(product?.stock) + (originalCounts.get(input.value) || 0);
      const qtyInput = form.querySelector(`[data-use-qty="${input.value}"]`);
      input.disabled = false;
      if (qtyInput) {
        qtyInput.disabled = false;
        qtyInput.max = Math.max(1, available);
      }
    });
  };
  const filterOptions = () => {
    const department = useDepartment.value;
    const currentDoctor = doctorSelect.value;
    const currentSurgery = surgerySelect.value;
    const doctors = department
      ? state.doctors.slice().sort(byName).filter((item) => departmentCode(item.name) === department)
      : [];
    doctorSelect.innerHTML = `<option value="">${department ? "원장 코드 선택" : "과를 먼저 선택하세요"}</option>` + doctors
      .map((item) => `<option value="${item.id}">${escapeHtml(item.name)}</option>`)
      .join("");
    if (doctors.some((item) => item.id === currentDoctor)) doctorSelect.value = currentDoctor;
    const surgeries = department && doctorSelect.value
      ? visibleSurgeriesFor(department, doctorSelect.value)
      : [];
    surgerySelect.innerHTML = `<option value="">${department && doctorSelect.value ? "수술 선택" : "원장 코드를 먼저 선택하세요"}</option>` + surgeries
      .map((item) => `<option value="${item.id}">${escapeHtml(item.department || inferSurgeryDepartment(item.name))} - ${escapeHtml(item.name)}${isCommonSurgery(item) ? "" : " · 전용"}</option>`)
      .join("");
    if (surgeries.some((item) => item.id === currentSurgery)) surgerySelect.value = currentSurgery;
  };
  const renderSearch = () => {
    const query = normalizedName(productSearch.value);
    if (!query) {
      productSearchResults.innerHTML = productSearchEmptyQueryHtml();
      return;
    }
    const results = state.products
      .filter((item) => normalizedName(`${item.name} ${item.company || ""} ${item.subcategory || ""} ${productCategoryLabel(item.category)}`).includes(query))
      .sort(byName)
      .slice(0, 12);
    productSearchResults.innerHTML = results.length ? results.map((item) => `
      <label class="check-card use-card">
        <input type="checkbox" value="${item.id}" data-edit-search-product="${item.id}" ${form.querySelector(`[data-use-product="${item.id}"]`)?.checked ? "checked" : ""}>
        <span>${escapeHtml(item.name)}<br><span class="muted">${escapeHtml(productCategoryLabel(item.category))}${item.company ? ` · ${escapeHtml(item.company)}` : ""}${item.subcategory ? ` · ${escapeHtml(item.subcategory)}` : ""} · 현재고 ${num(item.stock)}</span></span>
        ${qtyStepper(`data-edit-search-qty="${item.id}" aria-label="${escapeHtml(item.name)} 수정 수량"`, Math.max(1, num(form.querySelector(`[data-use-qty="${item.id}"]`)?.value) || 1), Math.max(1, num(item.stock) || 999))}
      </label>
    `).join("") : `<div class="empty">검색 결과가 없습니다.</div>`;
    productSearchResults.querySelectorAll("[data-edit-search-product]").forEach((input) => {
      input.addEventListener("change", () => {
        const qty = productSearchResults.querySelector(`[data-edit-search-qty="${input.value}"]`)?.value;
        const linked = form.querySelector(`[data-use-product="${input.value}"]`);
        if (input.checked) {
          selectProduct(input.value, qty);
        } else if (linked) {
          linked.checked = false;
          renderSelected();
        }
      });
    });
    productSearchResults.querySelectorAll("[data-edit-search-qty]").forEach((input) => {
      input.addEventListener("input", () => selectProduct(input.dataset.editSearchQty, input.value));
    });
  };
  const loadUsage = (id) => {
    pendingEditUsageId = id || "";
    const usage = state.usages.find((item) => item.id === id);
    if (!usage) {
      form.style.display = "none";
      deleteButton.style.display = "none";
      return;
    }
    if (dateInput.value !== (usage.date || today())) {
      dateInput.value = usage.date || today();
      renderUsageSelectOptions(dateInput.value, usage.id);
    }
    const canModify = canModifyUsageRecord(usage);
    const lockMessage = usagePastLockMessage(usage);
    form.style.display = "";
    deleteButton.style.display = canDeleteUsageRecord(usage) ? "" : "none";
    if (formTitle) formTitle.textContent = canModify ? "사용내용 수정" : "사용내용 확인";
    if (lockNote) {
      lockNote.innerHTML = canModify || !lockMessage ? "" : `<div class="edit-lock-note">${escapeHtml(lockMessage)} 관리자에게 요청해 주세요.</div>`;
    }
    form.querySelectorAll("input, select, textarea, button").forEach((element) => {
      element.disabled = !canModify;
    });
    document.getElementById("editUsageCancel").disabled = false;
    if (deleteButton) deleteButton.disabled = !canDeleteUsageRecord(usage);
    syncEditStockLimits(usage);
    document.getElementById("editUsageId").value = usage.id;
    document.getElementById("editPatientName").value = usage.patientName || "";
    document.getElementById("editPatientId").value = patientIdText(usage);
    document.getElementById("editUsageDate").value = usage.date || today();
    const surgery = surgeryById(usage.surgeryId);
    useDepartment.value = surgery?.department || inferSurgeryDepartment(surgery?.name || "") || departmentCode(departmentById(usage.doctorId)?.name || "");
    filterOptions();
    doctorSelect.value = usage.doctorId || "";
    filterOptions();
    surgerySelect.value = usage.surgeryId || "";
    if (usage.surgeryId && !surgerySelect.value) {
      const surgeryOption = surgeryById(usage.surgeryId);
      if (surgeryOption) {
        const fallbackOption = document.createElement("option");
        fallbackOption.value = surgeryOption.id;
        fallbackOption.textContent = `${surgeryOption.department || inferSurgeryDepartment(surgeryOption.name || "")} - ${surgeryOption.name}`;
        surgerySelect.appendChild(fallbackOption);
        surgerySelect.value = usage.surgeryId;
      }
    }
    clearProducts();
    usageProductItems(usage).forEach((item) => selectProduct(item.productId, item.qty, { syncImplants: false }));
    loadEditImplantsForUsage(usage, canModify);
    renderSearch();
    renderSelected();
    if (!canModify) {
      form.querySelectorAll("input, select, textarea, button").forEach((element) => {
        element.disabled = true;
      });
      document.getElementById("editUsageCancel").disabled = false;
      if (deleteButton) deleteButton.disabled = true;
    }
    if (patientList) {
      patientList.querySelectorAll("[data-edit-usage-card]").forEach((card) => {
        card.classList.toggle("active", card.dataset.editUsageCard === usage.id);
      });
    }
  };
  dateInput.addEventListener("change", () => {
    dateInput.value = dateInput.value || today();
    renderUsageSelectOptions(dateInput.value);
    resetLoadedUsage();
  });
  [patientNameSearch, patientIdSearch].forEach((input) => {
    input?.addEventListener("input", () => {
      renderUsageSelectOptions(dateInput.value, select.value);
      if (patientDetails) patientDetails.open = true;
    });
  });
  patientList?.addEventListener("click", (event) => {
    const card = event.target.closest("[data-edit-usage-card]");
    if (!card) return;
    select.value = card.dataset.editUsageCard;
    loadUsage(card.dataset.editUsageCard);
  });
  select.addEventListener("change", () => loadUsage(select.value));
  useDepartment.addEventListener("change", filterOptions);
  form.querySelectorAll("[data-use-product], [data-use-qty]").forEach((input) => {
    input.addEventListener("change", () => {
      renderSelected();
      renderSearch();
    });
    input.addEventListener("input", () => {
      renderSelected();
      renderSearch();
    });
  });
  productSearch.addEventListener("input", renderSearch);
  openEditCommonImplantGallery?.addEventListener("click", () => {
    if (editImplantCanModify) editCommonImplantGallery?.click();
  });
  openEditCommonImplantCamera?.addEventListener("click", () => {
    if (editImplantCanModify) editCommonImplantCamera?.click();
  });
  [editCommonImplantGallery, editCommonImplantCamera].forEach((input) => {
    input?.addEventListener("change", () => {
      addEditCommonImplantPhotos(Array.from(input.files || []));
      input.value = "";
    });
  });
  editCommonImplantPhotoList?.addEventListener("click", (event) => {
    const preview = event.target.closest("[data-preview-edit-common-implant-photo]");
    if (preview) {
      const photo = editCommonImplantPhotoById(preview.dataset.previewEditCommonImplantPhoto);
      if (photo) {
        activeEditImplantPhotoPair = "";
        const image = document.getElementById("implantPhotoModalImage");
        hideImplantPhotoEditTools();
        if (image) image.style.transform = "";
        showImplantPhotoModal(implantPhotoViewSrc(photo));
      }
      return;
    }
    const remove = event.target.closest("[data-remove-edit-common-implant-photo]");
    if (remove && editImplantCanModify) {
      const index = editCommonImplantPhotos.findIndex((photo) => photo.id === remove.dataset.removeEditCommonImplantPhoto);
      if (index >= 0) {
        if (editCommonImplantPhotos[index].preview) URL.revokeObjectURL(editCommonImplantPhotos[index].preview);
        if (editCommonImplantPhotos[index].editedPreview) URL.revokeObjectURL(editCommonImplantPhotos[index].editedPreview);
        editCommonImplantPhotos.splice(index, 1);
        renderEditCommonImplantPhotos();
        renderEditImplantRows();
      }
    }
  });
  editImplantRowsWrap?.addEventListener("input", (event) => updateEditImplantRowFromInput(event.target));
  editImplantRowsWrap?.addEventListener("change", (event) => {
    const target = event.target;
    updateEditImplantRowFromInput(target);
    if (target.matches("[data-edit-implant-photo-input], [data-edit-implant-camera-input]")) {
      addEditImplantPhotos(target.dataset.editImplantPhotoInput || target.dataset.editImplantCameraInput, target.files);
      target.value = "";
    }
  });
  editImplantRowsWrap?.addEventListener("click", async (event) => {
    const galleryButton = event.target.closest("[data-open-edit-implant-gallery]");
    if (galleryButton) {
      editImplantRowsWrap.querySelector(`[data-edit-implant-photo-input="${galleryButton.dataset.openEditImplantGallery}"]`)?.click();
      return;
    }
    const cameraButton = event.target.closest("[data-open-edit-implant-camera]");
    if (cameraButton) {
      editImplantRowsWrap.querySelector(`[data-edit-implant-camera-input="${cameraButton.dataset.openEditImplantCamera}"]`)?.click();
      return;
    }
    const useCommon = event.target.closest("[data-use-edit-common-implant-photo]");
    if (useCommon && editImplantCanModify) {
      const row = editImplantRowById(useCommon.dataset.useEditCommonImplantPhoto);
      if (!row || !editCommonImplantPhotos.length) return;
      const addedPhotos = editCommonImplantPhotos.map(cloneEditCommonImplantPhoto);
      row.photos = row.photos || [];
      row.photos.push(...addedPhotos);
      renderEditImplantRows();
      if (addedPhotos.length === 1) {
        openEditImplantPhotoEditor(`${row.id}::${addedPhotos[0].id}`);
      }
      return;
    }
    const editPhotoButton = event.target.closest("[data-edit-existing-implant-photo]");
    const editPhotoImage = event.target.closest("img[data-preview-edit-implant-photo]");
    if ((editPhotoButton || editPhotoImage) && editImplantCanModify) {
      event.preventDefault();
      event.stopPropagation();
      openEditImplantPhotoEditor(editPhotoButton?.dataset.editExistingImplantPhoto || editPhotoImage?.dataset.previewEditImplantPhoto);
      return;
    }
    const previewButton = event.target.closest("button[data-preview-edit-implant-photo]");
    if (previewButton) {
      event.preventDefault();
      event.stopPropagation();
      const pair = previewButton.dataset.previewEditImplantPhoto;
      const { photo } = parseEditImplantPair(pair);
      const src = photo ? editImplantPhotoSrc(photo) : "";
      if (src) {
        showImplantPhotoModal(src);
        document.getElementById("implantPhotoModalImage")?.classList.toggle("cropped", Boolean(photo?.cropped));
      }
      return;
    }
    const rotateButton = event.target.closest("[data-rotate-edit-implant-photo]");
    if (rotateButton && editImplantCanModify) {
      event.preventDefault();
      event.stopPropagation();
      const { photo } = parseEditImplantPair(rotateButton.dataset.rotateEditImplantPhoto);
      if (photo) {
        photo.rotation = ((photo.rotation || 0) + 90) % 360;
        clearEditedImplantPreview(photo);
        markEditImplantPhotoChanged(photo);
        renderEditImplantRows();
      }
      return;
    }
    const removePhoto = event.target.closest("[data-remove-edit-implant-photo]");
    if (removePhoto && editImplantCanModify) {
      event.preventDefault();
      event.stopPropagation();
      const { row, photo } = parseEditImplantPair(removePhoto.dataset.removeEditImplantPhoto);
      if (row && photo) {
        if (photo.preview) URL.revokeObjectURL(photo.preview);
        row.photos = row.photos.filter((item) => item.id !== photo.id);
        renderEditImplantRows();
      }
      return;
    }
    const moveUp = event.target.closest("[data-move-edit-implant-photo-up]");
    const moveDown = event.target.closest("[data-move-edit-implant-photo-down]");
    if ((moveUp || moveDown) && editImplantCanModify) {
      event.preventDefault();
      event.stopPropagation();
      const pair = moveUp?.dataset.moveEditImplantPhotoUp || moveDown?.dataset.moveEditImplantPhotoDown;
      const { row, photo } = parseEditImplantPair(pair);
      if (!row || !photo) return;
      const index = row.photos.findIndex((item) => item.id === photo.id);
      const nextIndex = moveUp ? index - 1 : index + 1;
      if (nextIndex < 0 || nextIndex >= row.photos.length) return;
      row.photos.splice(index, 1);
      row.photos.splice(nextIndex, 0, photo);
      renderEditImplantRows();
      return;
    }
    const removeButton = event.target.closest("[data-remove-edit-implant-row]");
    if (!removeButton || !editImplantCanModify) return;
    const removing = editImplantRows.find((row) => row.id === removeButton.dataset.removeEditImplantRow);
    revokeEditImplantLocalPhotos(removing?.photos);
    editImplantRows = editImplantRows.filter((row) => row.id !== removeButton.dataset.removeEditImplantRow);
    renderEditImplantRows();
  });
  addEditImplantRow?.addEventListener("click", () => {
    if (!editImplantCanModify) return;
    editImplantRows.push({ id: uid(), vendorId: "", customVendor: "", vendor: "", description: "", photos: [] });
    renderEditImplantRows();
  });
  document.getElementById("closeImplantPhotoModal")?.addEventListener("click", hideImplantPhotoModal);
  document.getElementById("implantPhotoModal")?.addEventListener("click", (event) => {
    if (event.target.id === "implantPhotoModal") hideImplantPhotoModal();
  });
  document.getElementById("implantModalRotate")?.addEventListener("click", async () => {
    const { photo } = parseEditImplantPair(activeEditImplantPhotoPair);
    if (!photo && !activeImplantCropPhoto) return;
    const targetPhoto = photo || activeImplantCropPhoto;
    targetPhoto.rotation = ((targetPhoto.rotation || 0) + 90) % 360;
    clearEditedImplantPreview(targetPhoto);
    markEditImplantPhotoChanged(targetPhoto);
    renderEditImplantRows();
    refreshEditImplantPhotoEditor();
  });
  document.getElementById("implantModalCrop")?.addEventListener("click", async () => {
    const { frame } = implantCropElements();
    if (frame && !frame.hidden) {
      await applyActiveImplantCrop();
    } else if (activeImplantCropPhoto) {
      await enableImplantCropFrame(activeImplantCropPhoto);
    }
  });
  document.getElementById("implantModalDone")?.addEventListener("click", () => {
    activeEditImplantPhotoPair = "";
    hideImplantPhotoModal();
  });
  document.getElementById("editUsageCancel").addEventListener("click", resetLoadedUsage);
  deleteButton.addEventListener("click", async () => {
    const usageId = document.getElementById("editUsageId").value;
    if (!usageId) return;
    const deleted = await deleteUsageRecord(usageId, {
      onSuccess: resetLoadedUsage
    });
    if (!deleted) return;
    renderUsageSelectOptions(dateInput.value || today());
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = event.submitter || event.currentTarget.querySelector("button[type='submit']");
    const id = document.getElementById("editUsageId").value;
    const usage = state.usages.find((item) => item.id === id);
    if (!usage) return;
    if (!canModifyUsageRecord(usage)) {
      alert(usagePastLockMessage(usage) || "사용내역 수정 권한이 없습니다.");
      return;
    }
    const newItems = selectedItems();
    const newProductIds = newItems.flatMap((item) => Array.from({ length: item.qty }, () => item.productId));
    const editPatientId = document.getElementById("editPatientId").value.trim();
    const editPatientIdMessage = patientIdValidationMessage(editPatientId);
    if (editPatientIdMessage) {
      alert(editPatientIdMessage);
      document.getElementById("editPatientId").focus();
      return;
    }
    if (!document.getElementById("editPatientName").value.trim() || !doctorSelect.value || !surgerySelect.value) {
      alert("환자명, 원장 코드, 수술을 모두 입력해 주세요.");
      return;
    }
    if (!newProductIds.length) {
      alert("제품을 하나 이상 선택해 주세요.");
      return;
    }
    if (editImplantCanModify) {
      syncEditImplantRowsFromSelectedProducts();
      mergeDuplicateEditImplantRows();
    }
    const nextImplants = readEditImplantRows();
    const incompleteImplant = nextImplants.find((implant) => !implant.vendor || (!implant.description && !(implant.photos || []).length));
    if (incompleteImplant) {
      alert("임플란트 장부가 작성되지 않았습니다. 업체명과 사용내용 또는 사진을 확인해 주세요.");
      return;
    }
    setButtonBusy(submitButton, true, "저장 중...");
    usage.productIds.forEach((productId) => {
      const product = productById(productId);
      if (product) product.stock = num(product.stock) + 1;
    });
    const unavailable = newItems.find((item) => num(productById(item.productId)?.stock) < item.qty);
    if (unavailable) {
      usage.productIds.forEach((productId) => {
        const product = productById(productId);
        if (product) product.stock = Math.max(0, num(product.stock) - 1);
      });
      alert("재고가 부족한 제품이 있습니다.");
      setButtonBusy(submitButton, false);
      return;
    }
    const hasLandingReceipt = state.receipts.some((receipt) => receipt.type === "landing" && receipt.usageId === usage.id);
    if (hasLandingReceipt && !confirm("이미 랜딩 입고 확인된 사용내역입니다. 입고내역은 보존됩니다. 그래도 수정할까요?")) {
      usage.productIds.forEach((productId) => {
        const product = productById(productId);
        if (product) product.stock = Math.max(0, num(product.stock) - 1);
      });
      setButtonBusy(submitButton, false);
      return;
    }
    newItems.forEach((item) => {
      const product = productById(item.productId);
      if (product) product.stock = Math.max(0, num(product.stock) - item.qty);
    });
    const next = {
      ...usage,
      patientName: document.getElementById("editPatientName").value.trim(),
      patientId: editPatientId,
      doctorId: doctorSelect.value,
      surgeryId: surgerySelect.value,
      productIds: newProductIds,
      date: document.getElementById("editUsageDate").value,
      updatedAt: new Date().toISOString()
    };
    state.usages = state.usages.map((item) => item.id === usage.id ? next : item);
    currentView = "dashboard";
    pendingEditUsageId = "";
    await saveState("수정 완료", {
      savingMessage: "수정 저장 중입니다...",
      doneMessage: editImplantCanModify && countEditImplantPhotosToUpload(nextImplants) ? "수정 저장 완료 · 사진 업로드 준비" : "수정 저장 완료"
    });
    if (editImplantCanModify) {
      try {
        let photoUploadFailed = 0;
        await saveImplantRecordFromEdit(next, editImplantRecordId, nextImplants, {
          onPhotoProgress: ({ done, total, failed }) => {
            photoUploadFailed = failed;
            const failText = failed ? ` · 실패 ${failed}장` : "";
            showSaveToast(`사진 업로드 중 ${done}/${total}${failText}`, failed ? "error" : "saving", { hold: done < total, duration: done >= total ? 1800 : undefined });
          }
        });
        saveDoneToast(photoUploadFailed ? "수정 완료 · 사진은 앱에 보관됨" : (countEditImplantPhotosToUpload(nextImplants) ? "수정과 사진 저장 완료" : "수정 저장 완료"));
      } catch (error) {
        saveErrorToast(`임플란트 사진 저장 실패: ${error.message}`);
        alert(`사용내역은 저장됐지만 임플란트 기록 수정에 실패했습니다: ${error.message}`);
      }
    }
    setButtonBusy(submitButton, false);
    render();
  });
  filterOptions();
  renderSearch();
  if (pendingEditUsageId) {
    const pendingUsage = state.usages.find((usage) => usage.id === pendingEditUsageId);
    if (pendingUsage) {
      dateInput.value = pendingUsage.date || today();
      renderUsageSelectOptions(dateInput.value, pendingEditUsageId);
      loadUsage(pendingEditUsageId);
    }
  }
};

let activeImplantCropPhoto = null;
let activeImplantCropApply = null;
let implantCropPointerState = null;

const implantCropElements = () => ({
  stage: document.getElementById("implantCropStage"),
  image: document.getElementById("implantPhotoModalImage"),
  frame: document.getElementById("implantCropFrame"),
  cropButton: document.getElementById("implantModalCrop")
});
const applyImplantModalPhotoState = (image, photo) => {
  if (!image) return;
  const rotation = num(photo?.rotation);
  const rotated = Math.abs(rotation % 180) === 90;
  const stage = image.closest(".implant-crop-stage");
  image.style.transform = rotation ? `rotate(${rotation}deg)` : "";
  image.classList.toggle("rotated", rotated);
  image.classList.toggle("cropped", Boolean(photo?.cropped));
  if (stage) stage.classList.toggle("rotated", rotated);
};
const implantPhotoNodes = (id) => Array.from(document.querySelectorAll(`[id="${id}"]`));
const hideImplantPhotoEditTools = () => {
  implantPhotoNodes("implantPhotoEditTools").forEach((tools) => {
    tools.hidden = true;
    tools.style.display = "none";
  });
};
const showImplantPhotoEditTools = () => {
  hideImplantPhotoEditTools();
  const tools = document.getElementById("implantPhotoEditTools");
  if (tools) {
    tools.hidden = false;
    tools.style.display = "";
  }
};
const resetImplantPhotoFrames = () => {
  implantPhotoNodes("implantCropFrame").forEach((frame) => {
    frame.hidden = true;
    frame.style.display = "";
  });
};
const implantImageBoundsInStage = () => {
  const { stage, image } = implantCropElements();
  if (!stage || !image) return null;
  const stageRect = stage.getBoundingClientRect();
  const imageRect = image.getBoundingClientRect();
  return {
    left: imageRect.left - stageRect.left,
    top: imageRect.top - stageRect.top,
    width: imageRect.width,
    height: imageRect.height
  };
};
const setImplantCropButtonText = (text) => {
  const button = document.getElementById("implantModalCrop");
  if (button) button.textContent = text;
};
const positionImplantCropFrame = (photo) => {
  const { frame } = implantCropElements();
  const bounds = implantImageBoundsInStage();
  if (!frame || !bounds || !bounds.width || !bounds.height) return;
  const rect = normalizeImplantCropRect(photo?.cropRect || defaultImplantCropRect());
  frame.style.left = `${bounds.left + rect.x * bounds.width}px`;
  frame.style.top = `${bounds.top + rect.y * bounds.height}px`;
  frame.style.width = `${rect.width * bounds.width}px`;
  frame.style.height = `${rect.height * bounds.height}px`;
};
const bindImplantCropFrame = () => {
  const { frame } = implantCropElements();
  if (!frame || frame.dataset.cropBound) return;
  frame.dataset.cropBound = "1";
  frame.addEventListener("pointerdown", (event) => {
    event.preventDefault();
    const bounds = implantImageBoundsInStage();
    if (!bounds) return;
    const frameRect = frame.getBoundingClientRect();
    const stageRect = document.getElementById("implantCropStage").getBoundingClientRect();
    implantCropPointerState = {
      handle: event.target?.dataset?.cropHandle || "move",
      startX: event.clientX,
      startY: event.clientY,
      left: frameRect.left - stageRect.left,
      top: frameRect.top - stageRect.top,
      width: frameRect.width,
      height: frameRect.height,
      bounds
    };
    frame.setPointerCapture(event.pointerId);
  });
  frame.addEventListener("pointermove", (event) => {
    if (!implantCropPointerState) return;
    event.preventDefault();
    const state = implantCropPointerState;
    const dx = event.clientX - state.startX;
    const dy = event.clientY - state.startY;
    const minSize = 42;
    const maxRight = state.bounds.left + state.bounds.width;
    const maxBottom = state.bounds.top + state.bounds.height;
    let left = state.left;
    let top = state.top;
    let width = state.width;
    let height = state.height;
    if (state.handle === "move") {
      left = implantClamp(state.left + dx, state.bounds.left, maxRight - width);
      top = implantClamp(state.top + dy, state.bounds.top, maxBottom - height);
    } else {
      const right = state.left + state.width;
      const bottom = state.top + state.height;
      if (state.handle.includes("w")) {
        left = implantClamp(state.left + dx, state.bounds.left, right - minSize);
        width = right - left;
      }
      if (state.handle.includes("e")) {
        width = implantClamp(state.width + dx, minSize, maxRight - left);
      }
      if (state.handle.includes("n")) {
        top = implantClamp(state.top + dy, state.bounds.top, bottom - minSize);
        height = bottom - top;
      }
      if (state.handle.includes("s")) {
        height = implantClamp(state.height + dy, minSize, maxBottom - top);
      }
    }
    frame.style.left = `${left}px`;
    frame.style.top = `${top}px`;
    frame.style.width = `${width}px`;
    frame.style.height = `${height}px`;
  });
  frame.addEventListener("pointerup", () => {
    implantCropPointerState = null;
  });
  frame.addEventListener("pointercancel", () => {
    implantCropPointerState = null;
  });
};
const enableImplantCropFrame = async (photo) => {
  const { image, frame } = implantCropElements();
  if (!photo || !image || !frame) return;
  activeImplantCropPhoto = photo;
  bindImplantCropFrame();
  frame.hidden = false;
  image.style.transform = "";
  image.classList.remove("cropped", "rotated");
  image.closest(".implant-crop-stage")?.classList.remove("rotated");
  setImplantCropButtonText("자르기 적용");
  try {
    if (image.decode) await image.decode();
  } catch (_) {}
  requestAnimationFrame(() => positionImplantCropFrame(photo));
  setTimeout(() => positionImplantCropFrame(photo), 120);
};
const currentImplantCropRect = () => {
  const { frame } = implantCropElements();
  const bounds = implantImageBoundsInStage();
  if (!frame || !bounds || frame.hidden || !bounds.width || !bounds.height) return defaultImplantCropRect();
  const left = implantCropNumber(frame.style.left);
  const top = implantCropNumber(frame.style.top);
  const width = implantCropNumber(frame.style.width);
  const height = implantCropNumber(frame.style.height);
  if (!width || !height) return defaultImplantCropRect();
  return normalizeImplantCropRect({
    x: (left - bounds.left) / bounds.width,
    y: (top - bounds.top) / bounds.height,
    width: width / bounds.width,
    height: height / bounds.height
  });
};
const applyActiveImplantCrop = async () => {
  if (!activeImplantCropPhoto) return;
  try {
    const rect = currentImplantCropRect();
    if (rect) {
      activeImplantCropPhoto.cropped = true;
      activeImplantCropPhoto.cropRect = rect;
    }
    if (typeof activeImplantCropApply === "function") await activeImplantCropApply(activeImplantCropPhoto);
    const { frame } = implantCropElements();
    if (frame) frame.hidden = true;
    const { image } = implantCropElements();
    if (image) {
      image.src = implantPhotoViewSrc(activeImplantCropPhoto);
      applyImplantModalPhotoState(image, activeImplantCropPhoto);
    }
    saveDoneToast("자르기 적용 완료");
    setImplantCropButtonText("자르기 수정");
  } catch (error) {
    console.error(error);
    saveErrorToast(`자르기 적용 실패: ${error.message}`);
    alert(`자르기 적용에 실패했습니다: ${error.message}`);
  }
};
const openImplantCropEditor = async (photo, onApply) => {
  if (!photo) return;
  showImplantPhotoModal(implantPhotoViewSrc(photo));
  activeImplantCropPhoto = photo;
  activeImplantCropApply = onApply;
  const { image } = implantCropElements();
  showImplantPhotoEditTools();
  if (image) {
    applyImplantModalPhotoState(image, photo);
  }
  await enableImplantCropFrame(photo);
};

const showImplantPhotoModal = (url) => {
  const modal = document.getElementById("implantPhotoModal");
  const image = document.getElementById("implantPhotoModalImage");
  const frame = document.getElementById("implantCropFrame");
  if (!modal || !image || !url) return;
  image.src = url;
  image.style.transform = "";
  image.classList.remove("cropped", "rotated");
  image.closest(".implant-crop-stage")?.classList.remove("rotated");
  hideImplantPhotoEditTools();
  resetImplantPhotoFrames();
  if (frame) frame.hidden = true;
  activeImplantCropPhoto = null;
  activeImplantCropApply = null;
  implantCropPointerState = null;
  setImplantCropButtonText("자르기");
  modal.hidden = false;
};

const hideImplantPhotoModal = () => {
  const modal = document.getElementById("implantPhotoModal");
  const image = document.getElementById("implantPhotoModalImage");
  const frame = document.getElementById("implantCropFrame");
  if (image) image.removeAttribute("src");
  if (image) image.style.transform = "";
  if (image) image.classList.remove("cropped", "rotated");
  if (image) image.closest(".implant-crop-stage")?.classList.remove("rotated");
  hideImplantPhotoEditTools();
  resetImplantPhotoFrames();
  if (frame) frame.hidden = true;
  activeImplantCropPhoto = null;
  activeImplantCropApply = null;
  implantCropPointerState = null;
  if (modal) modal.hidden = true;
};

const bindImplants = () => getImplantsModule().bindImplants();

const loadImageFromFile = (file) => new Promise((resolve, reject) => {
  const image = new Image();
  image.onload = () => resolve(image);
  image.onerror = reject;
  image.src = URL.createObjectURL(file);
});

const loadImageFromUrl = (url) => getImplantsModule().loadImageFromUrl(url);

const loadImageFromImplantPhoto = (photo) => photo.file
  ? loadImageFromFile(photo.file)
  : loadImageFromUrl(photo.preview || photo.url || photo.dataUrl || photo.editedPreview || "");

const implantCropNumber = (value, fallback = 0) => getImplantsModule().implantCropNumber(value, fallback);
const implantClamp = (value, min, max) => getImplantsModule().implantClamp(value, min, max);
const normalizeImplantCropRect = (rect) => getImplantsModule().normalizeImplantCropRect(rect);
const defaultImplantCropRect = () => getImplantsModule().defaultImplantCropRect();
const implantSourceRect = (photo, image) => getImplantsModule().implantSourceRect(photo, image);

const renderImplantPhotoBlob = async (photo, maxSide = 2400, quality = 0.9) => {
  const image = await loadImageFromImplantPhoto(photo);
  const source = implantSourceRect(photo, image);
  const sourceX = source.x;
  const sourceY = source.y;
  const sourceWidth = source.width;
  const sourceHeight = source.height;
  const scale = Math.min(1, maxSide / Math.max(sourceWidth, sourceHeight));
  const baseWidth = Math.max(1, Math.round(sourceWidth * scale));
  const baseHeight = Math.max(1, Math.round(sourceHeight * scale));
  const rotated = Math.abs((photo.rotation || 0) % 180) === 90;
  const canvas = document.createElement("canvas");
  canvas.width = rotated ? baseHeight : baseWidth;
  canvas.height = rotated ? baseWidth : baseHeight;
  const ctx = canvas.getContext("2d");
  ctx.save();
  ctx.translate(canvas.width / 2, canvas.height / 2);
  ctx.rotate(((photo.rotation || 0) * Math.PI) / 180);
  ctx.drawImage(image, sourceX, sourceY, sourceWidth, sourceHeight, -baseWidth / 2, -baseHeight / 2, baseWidth, baseHeight);
  ctx.restore();
  if ((photo.file || image.dataset.objectUrl) && image.src) URL.revokeObjectURL(image.src);
  return new Promise((resolve) => canvas.toBlob((blob) => resolve(blob), "image/jpeg", quality));
};

const compressImplantImage = (photo) => renderImplantPhotoBlob(photo, 2400, 0.9);
const blobToDataUrl = (blob) => new Promise((resolve, reject) => {
  const reader = new FileReader();
  reader.onload = () => resolve(reader.result || "");
  reader.onerror = reject;
  reader.readAsDataURL(blob);
});
const promiseWithTimeout = (promise, timeoutMs, message) => getImplantsModule().promiseWithTimeout(promise, timeoutMs, message);
const implantPhotoFallbackPayload = async (photo, errorMessage = "") => {
  const blob = await renderImplantPhotoBlob(photo, 1200, 0.82);
  return {
    id: photo.id || uid(),
    url: photo.url || "",
    path: photo.path || "",
    dataUrl: await blobToDataUrl(blob),
    name: photo.file?.name || photo.name || "implant.jpg",
    size: blob.size,
    contentType: "image/jpeg",
    rotation: photo.rotation || 0,
    cropped: Boolean(photo.cropped),
    cropRect: photo.cropped && photo.cropRect ? normalizeImplantCropRect(photo.cropRect) : null,
    sourceCommonPhotoId: photo.sourceCommonPhotoId || "",
    uploadedAt: new Date().toISOString(),
    needsReupload: true,
    storageUploadFailed: true,
    storageUploadError: errorMessage
  };
};

const refreshEditedImplantPreview = async (photo) => {
  if (!photo) return;
  if (photo.editedPreview) URL.revokeObjectURL(photo.editedPreview);
  const blob = await renderImplantPhotoBlob(photo, 1200, 0.86);
  photo.editedPreview = URL.createObjectURL(blob);
  photo.needsReupload = true;
};
const clearEditedImplantPreview = (photo) => {
  if (!photo?.editedPreview) return;
  URL.revokeObjectURL(photo.editedPreview);
  delete photo.editedPreview;
};

const initialImplantPhotoPayload = async (photo, cache = null) => {
  if (photo.url || photo.dataUrl) return cleanImplantPhotoPayload(photo);
  if (photo.file || photo.preview || photo.editedPreview) {
    return cachedImplantPhotoPayload(photo, cache, () => implantPhotoFallbackPayload(photo, "Storage upload pending"));
  }
  return cleanImplantPhotoPayload(photo);
};

const uploadImplantPhoto = async (recordId, implantId, photo, surgeryDate) => {
  if (!storageRef || !uploadBytes || !getDownloadURL) throw new Error("Firebase Storage가 준비되지 않았습니다.");
  const blob = await promiseWithTimeout(compressImplantImage(photo), 12000, "사진 처리 시간이 초과되었습니다.");
  const safeName = String(photo.file?.name || photo.name || "implant.jpg").replace(/[^a-zA-Z0-9._-]/g, "_");
  const path = `implant-records/${surgeryDate || today()}/${recordId}/${implantId}/${photo.id}-${safeName}.jpg`;
  const allCandidates = [preferredImplantStorageBucket, storage, storageFallback].filter(Boolean);
  const candidates = allCandidates.filter((bucket, index) => allCandidates.indexOf(bucket) === index);
  let lastError;
  for (const bucket of candidates) {
    try {
      const refPath = storageRef(bucket, path);
      await promiseWithTimeout(uploadBytes(refPath, blob, { contentType: "image/jpeg" }), 12000, "사진 업로드 시간이 초과되었습니다.");
      const url = await promiseWithTimeout(getDownloadURL(refPath), 6000, "사진 주소 확인 시간이 초과되었습니다.");
      preferredImplantStorageBucket = bucket;
      return {
        id: photo.id,
        url,
        path,
        name: photo.file?.name || photo.name || "",
        size: blob.size,
        contentType: "image/jpeg",
        rotation: photo.rotation || 0,
        cropped: Boolean(photo.cropped),
        cropRect: photo.cropped && photo.cropRect ? normalizeImplantCropRect(photo.cropRect) : null,
        sourceCommonPhotoId: photo.sourceCommonPhotoId || "",
        uploadedAt: new Date().toISOString()
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("사진 업로드에 실패했습니다.");
};

const implantRecordBasePayload = (usage) => {
  const surgery = surgeryById(usage.surgeryId);
  const doctor = departmentById(usage.doctorId);
  return {
    usageId: usage.id,
    surgeryDate: usage.date || today(),
    surgeryTime: usage.surgeryTime || "",
    patientName: usage.patientName || "",
    patientId: usage.patientId || "",
    department: surgery?.department || inferSurgeryDepartment(surgery?.name || "") || departmentCode(doctor?.name || ""),
    doctorId: usage.doctorId || "",
    surgeonCode: doctor?.name || "",
    surgeryId: usage.surgeryId || "",
    surgeryName: surgery?.name || ""
  };
};

const cleanImplantPhotoPayload = (photo) => getImplantsModule().cleanImplantPhotoPayload(photo);
const implantPhotoCacheKey = (photo = {}) => getImplantsModule().implantPhotoCacheKey(photo);
const cloneImplantPhotoPayload = (payload = {}, photo = {}) => getImplantsModule().cloneImplantPhotoPayload(payload, photo);
const cachedImplantPhotoPayload = (photo, cache, buildPayload) => getImplantsModule().cachedImplantPhotoPayload(photo, cache, buildPayload);
const editImplantPhotoNeedsUpload = (photo = {}) => Boolean(photo.file || photo.editedPreview);
const countEditImplantPhotosToUpload = (implants = []) => implants.reduce((sum, implant) => (
  sum + (implant.photos || []).filter(editImplantPhotoNeedsUpload).length
), 0);
const notifyImplantPhotoUpload = (onProgress, done, total, failed = 0) => getImplantsModule().notifyImplantPhotoUpload(onProgress, done, total, failed);

const saveImplantRecordFromEdit = async (usage, recordId, implants, options = {}) => {
  if (!recordId && !implants.length) return;
  const nextRecordId = recordId || uid();
  const existing = recordId ? implantRecords.find((record) => sameId(record.id, recordId)) : null;
  if (existing && !canModifyImplantRecord(existing)) {
    throw new Error("임플란트 기록 수정 권한이 없습니다.");
  }
  const surgeryDate = usage.date || today();
  const dateChanged = Boolean(existing && implantRecordDate(existing) && implantRecordDate(existing) !== surgeryDate);
  const patientNoState = dateChanged
    ? {
      patientNo: "",
      patientNoAssignedAt: null,
      patientNoManuallyEditedAt: null,
      closedAt: null,
      editUnlocked: false,
      patientNoClearedAt: new Date().toISOString(),
      patientNoClearReason: "usageDateChanged"
    }
    : (existing?.patientNo ? { patientNo: existing.patientNo } : { patientNo: "" });
  const cleanImplants = [];
  const initialPhotoCache = new Map();
  for (const implant of implants) {
    const initialPhotos = [];
    for (const photo of implant.photos || []) {
      initialPhotos.push(await initialImplantPhotoPayload(photo, initialPhotoCache));
    }
    cleanImplants.push({
      id: implant.id || uid(),
      vendorId: implant.vendorId || "",
      vendor: implant.vendor || "",
      description: implant.description || "",
      photos: initialPhotos.filter((photo) => photo.url || photo.dataUrl),
      pendingPhotoCount: (implant.photos || []).filter(editImplantPhotoNeedsUpload).length
    });
  }
  await setDoc(doc(db, "implantRecords", nextRecordId), {
    id: nextRecordId,
    ...patientNoState,
    ...implantRecordBasePayload(usage),
    implants: cleanImplants,
    sendReady: cleanImplants.length > 0,
    updatedAt: new Date().toISOString(),
    ...(existing?.createdAt ? {} : { createdAt: new Date().toISOString() }),
    ...(existing ? auditUpdateFields() : auditCreateFields())
  }, { merge: true });

  const uploadedImplants = [];
  const uploadTotal = countEditImplantPhotosToUpload(implants);
  let uploadDone = 0;
  let uploadFailed = 0;
  const uploadPhotoCache = new Map();
  notifyImplantPhotoUpload(options.onPhotoProgress, uploadDone, uploadTotal, uploadFailed);
  for (const implant of implants) {
    const implantId = implant.id || uid();
    const photos = (implant.photos || [])
      .filter((photo) => (photo.url || photo.dataUrl) && !editImplantPhotoNeedsUpload(photo))
      .map(cleanImplantPhotoPayload);
    const photoUploadErrors = [];
    for (const photo of implant.photos || []) {
      if (editImplantPhotoNeedsUpload(photo)) {
        try {
          photos.push(await cachedImplantPhotoPayload(
            photo,
            uploadPhotoCache,
            () => uploadImplantPhoto(nextRecordId, implantId, photo, surgeryDate)
          ));
        } catch (error) {
          console.error(error);
          photos.push(await implantPhotoFallbackPayload(photo, error.message || "사진 업로드 실패"));
          photoUploadErrors.push(error.message || "사진 업로드 실패");
          uploadFailed += 1;
        } finally {
          uploadDone += 1;
          notifyImplantPhotoUpload(options.onPhotoProgress, uploadDone, uploadTotal, uploadFailed);
        }
      }
    }
    uploadedImplants.push({
      id: implantId,
      vendorId: implant.vendorId || "",
      vendor: implant.vendor || "",
      description: implant.description || "",
      photos,
      pendingPhotoCount: 0,
      ...(photoUploadErrors.length ? { photoUploadErrors } : {})
    });
  }
  await setDoc(doc(db, "implantRecords", nextRecordId), {
    implants: uploadedImplants,
    updatedAt: new Date().toISOString(),
    hasPhotoUploadError: uploadedImplants.some((implant) => (implant.photoUploadErrors || []).length)
  }, { merge: true });
};

const createImplantRecordFromUsage = async (usage, implantDrafts, options = {}) => {
  const validDrafts = implantDrafts.filter((draft) => {
    const vendorId = draft.vendorId || "";
    const vendor = vendorId === "__custom__" ? draft.customVendor : implantVendorById(vendorId)?.name;
    return String(vendor || "").trim() && (String(draft.description || "").trim() || (draft.photos || []).length);
  });
  if (!validDrafts.length) return;
  const recordId = uid();
  const surgery = surgeryById(usage.surgeryId);
  const doctor = departmentById(usage.doctorId);
  const surgeryDate = usage.date || today();
  const implants = [];
  const initialPhotoCache = new Map();
  for (const draft of validDrafts) {
    const vendor = draft.vendorId === "__custom__"
      ? draft.customVendor.trim()
      : (implantVendorById(draft.vendorId)?.name || draft.customVendor || "").trim();
    const initialPhotos = [];
    for (const photo of draft.photos || []) {
      initialPhotos.push(await initialImplantPhotoPayload(photo, initialPhotoCache));
    }
    implants.push({
      id: draft.id || uid(),
      vendorId: draft.vendorId && draft.vendorId !== "__custom__" ? draft.vendorId : "",
      vendor,
      description: draft.description.trim(),
      photos: initialPhotos.filter((photo) => photo.url || photo.dataUrl),
      pendingPhotoCount: (draft.photos || []).length
    });
  }
  const baseRecord = {
    id: recordId,
    usageId: usage.id,
    surgeryDate,
    surgeryTime: usage.surgeryTime || "",
    patientNo: "",
    patientName: usage.patientName || "",
    patientId: usage.patientId || "",
    department: surgery?.department || inferSurgeryDepartment(surgery?.name || "") || departmentCode(doctor?.name || ""),
    doctorId: usage.doctorId || "",
    surgeonCode: doctor?.name || "",
    surgeryId: usage.surgeryId || "",
    surgeryName: surgery?.name || "",
    implants,
    sendReady: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...auditCreateFields()
  };
  await setDoc(doc(db, "implantRecords", recordId), baseRecord);
  if (options.deferPhotoUpload) {
    return;
  }
  const uploadTotal = validDrafts.reduce((sum, draft) => sum + (draft.photos || []).length, 0);
  let uploadDone = 0;
  let uploadFailed = 0;
  const uploadPhotoCache = new Map();
  notifyImplantPhotoUpload(options.onPhotoProgress, uploadDone, uploadTotal, uploadFailed);
  for (const draft of validDrafts) {
    const implant = implants.find((item) => sameId(item.id, draft.id)) || implants.find((item) => item.vendor === (draft.vendorId === "__custom__" ? draft.customVendor.trim() : (implantVendorById(draft.vendorId)?.name || draft.customVendor || "").trim()));
    const implantId = implant?.id || draft.id || uid();
    const photos = [];
    const photoUploadErrors = [];
    for (const photo of draft.photos || []) {
      try {
        if ((photo.url || photo.dataUrl) && !photo.file && !photo.needsReupload) {
          photos.push(cleanImplantPhotoPayload(photo));
        } else {
          photos.push(await cachedImplantPhotoPayload(
            photo,
            uploadPhotoCache,
            () => uploadImplantPhoto(recordId, implantId, photo, surgeryDate)
          ));
        }
      } catch (error) {
        console.error(error);
        photos.push(await implantPhotoFallbackPayload(photo, error.message || "사진 업로드 실패"));
        photoUploadErrors.push(error.message || "사진 업로드 실패");
        uploadFailed += 1;
      } finally {
        uploadDone += 1;
        notifyImplantPhotoUpload(options.onPhotoProgress, uploadDone, uploadTotal, uploadFailed);
      }
    }
    if (implant) {
      implant.photos = photos;
      implant.pendingPhotoCount = 0;
      if (photoUploadErrors.length) implant.photoUploadErrors = photoUploadErrors;
    }
  }
  await setDoc(doc(db, "implantRecords", recordId), {
    implants,
    updatedAt: new Date().toISOString(),
    hasPhotoUploadError: implants.some((implant) => (implant.photoUploadErrors || []).length)
  }, { merge: true });
};

const bindUse = () => {
  const useDepartment = document.getElementById("useDepartment");
  const departmentSelect = document.getElementById("useDoctor");
  const surgerySelect = document.getElementById("useSurgery");
  const useRestrictNonpay = document.getElementById("useRestrictNonpay");
  const recommendation = document.getElementById("useRecommendation");
  const selectedUseList = document.getElementById("selectedUseList");
  const productSearch = document.getElementById("useProductSearch");
  const productSearchResults = document.getElementById("useProductSearchResults");
  const form = document.getElementById("useForm");
  const useDate = document.getElementById("useDate");
  const openProductSearch = document.getElementById("openUseProductSearch");
  const closeProductSearch = document.getElementById("closeUseProductSearch");
  const productSearchModal = document.getElementById("useProductSearchModal");
  const implantEnabled = document.getElementById("useImplantEnabled");
  const implantPanel = document.getElementById("implantUsePanel");
  const implantEntriesWrap = document.getElementById("implantVendorEntries");
  const addImplantVendorEntry = document.getElementById("addImplantVendorEntry");
  const commonImplantPhotoList = document.getElementById("commonImplantPhotoList");
  const openCommonImplantGallery = document.getElementById("openCommonImplantGallery");
  const openCommonImplantCamera = document.getElementById("openCommonImplantCamera");
  const commonImplantGallery = document.getElementById("commonImplantGallery");
  const commonImplantCamera = document.getElementById("commonImplantCamera");
  const saveUseDraftButton = document.getElementById("saveUseDraft");
  const useDraftPanel = document.getElementById("useDraftPanel");
  const useDraftStatus = document.getElementById("useDraftStatus");
  const useDraftSummary = document.getElementById("useDraftSummary");
  const editUseDraftButton = document.getElementById("editUseDraft");
  const finalSaveUseDraftButton = document.getElementById("finalSaveUseDraft");
  const cancelUseDraftButton = document.getElementById("cancelUseDraft");
  const implantDrafts = [];
  const commonImplantPhotos = [];
  let activeImplantEditPair = "";
  let manualRestrictNonpay = false;
  let useDraftSnapshot = null;
  let useDraftDirty = false;
  let loadedPendingUsageId = "";
  if (useDate && !useDate.value) useDate.value = today();
  const selectedUseDate = () => useDate?.value || today();
  const useEntryPatientFields = () => ({
    date: selectedUseDate(),
    patientName: document.getElementById("patientName")?.value.trim() || "",
    patientId: document.getElementById("patientId")?.value.trim() || "",
    department: useDepartment?.value || "",
    doctorId: departmentSelect?.value || "",
    surgeryId: surgerySelect?.value || "",
    restrictNonpay: isRestrictOn()
  });
  const saveUseEntryPatientAutosave = () => {
    const payload = useEntryPatientFields();
    const hasContent = payload.patientName || payload.patientId || payload.department || payload.doctorId || payload.surgeryId;
    if (hasContent) {
      writeUseEntryAutosave(payload);
    } else {
      clearUseEntryAutosave();
    }
  };
  const markUseEntryDirty = () => {
    if (currentView !== "use") return;
    useEntryDirty = true;
    saveUseEntryPatientAutosave();
  };
  const setRestrictButton = (value) => {
    manualRestrictNonpay = Boolean(value);
    setRestrictButtonState(useRestrictNonpay, value);
  };
  const isRestrictOn = () => manualRestrictNonpay;
  const currentUseRule = () => state.usageRules.find((rule) =>
    rule.department === useDepartment.value &&
    rule.doctorId === departmentSelect.value &&
    rule.surgeryId === surgerySelect.value
  );
  const selectedUseItems = () => selectedUseItemsFromScope(form);
  const renderSelectedUseList = () => {
    const items = selectedUseItems();
    if (!items.length) {
      selectedUseList.innerHTML = `<span>선택된 제품이 없습니다.</span>`;
      syncImplantDraftsFromSelectedProducts();
      return;
    }
    selectedUseList.innerHTML = selectedUseListHtml(items);
    selectedUseList.querySelectorAll("[data-selected-remove]").forEach((button) => {
      button.addEventListener("click", () => {
        const checkbox = app.querySelector(`[data-use-product="${button.dataset.selectedRemove}"]`);
        if (checkbox) checkbox.checked = false;
        syncRecommendControl(button.dataset.selectedRemove, false);
        markUseEntryDirty();
        renderSelectedUseList();
      });
    });
    selectedUseList.querySelectorAll("[data-selected-qty]").forEach((input) => {
      input.addEventListener("input", () => {
        const linked = app.querySelector(`[data-use-qty="${input.dataset.selectedQty}"]`);
        const checkbox = app.querySelector(`[data-use-product="${input.dataset.selectedQty}"]`);
        const value = Math.max(1, num(input.value));
        if (linked) linked.value = value;
        if (checkbox) checkbox.checked = true;
        syncRecommendControl(input.dataset.selectedQty, true, value);
        markUseEntryDirty();
      });
      input.addEventListener("change", renderSelectedUseList);
    });
    selectedUseList.querySelectorAll("[data-selected-dec], [data-selected-inc]").forEach((button) => {
      button.addEventListener("click", () => {
        const productId = button.dataset.selectedDec || button.dataset.selectedInc;
        const linked = app.querySelector(`[data-use-qty="${productId}"]`);
        const checkbox = form.querySelector(`[data-use-product="${productId}"]`);
        const currentQty = Math.max(1, num(linked?.value || 1));
        const nextQty = button.dataset.selectedDec ? Math.max(1, currentQty - 1) : currentQty + 1;
        if (linked) linked.value = nextQty;
        if (checkbox) checkbox.checked = true;
        syncRecommendControl(productId, true, nextQty);
        markUseEntryDirty();
        renderSelectedUseList();
      });
    });
    syncImplantDraftsFromSelectedProducts();
  };
  const selectUseProduct = (productId, qty = 1) => {
    const checkbox = form.querySelector(`[data-use-product="${productId}"]`);
    const qtyInput = form.querySelector(`[data-use-qty="${productId}"]`);
    if (checkbox) checkbox.checked = true;
    if (qtyInput) qtyInput.value = Math.max(1, num(qty));
    syncRecommendControl(productId, true, qty);
    markUseEntryDirty();
    renderSelectedUseList();
  };
  const addImplantDraft = () => {
    implantDrafts.push(emptyImplantDraft());
    renderImplantDrafts();
  };
  const renderCommonImplantPhotos = () => {
    if (!commonImplantPhotoList) return;
    commonImplantPhotoList.innerHTML = commonImplantPhotosHtml(commonImplantPhotos);
  };
  const addCommonImplantPhotos = (files = []) => {
    addCommonImplantPhotosFromFiles(commonImplantPhotos, files);
    renderCommonImplantPhotos();
  };
  const findCommonImplantPhoto = (id) => commonImplantPhotoById(commonImplantPhotos, id);
  const mergeDuplicateImplantDrafts = () => mergeDuplicateImplantDraftsInList(implantDrafts);
  const syncImplantDraftsFromSelectedProducts = () => {
    const targets = implantVendorTargetsFromUseItems(selectedUseItems());
    const targetKeys = new Set(targets.map((target) => target.key));
    let changed = false;
    for (let index = implantDrafts.length - 1; index >= 0; index -= 1) {
      const draft = implantDrafts[index];
      if (draft.autoSource === "product" && !targetKeys.has(draft.autoCompanyKey) && !implantDraftHasManualContent(draft)) {
        implantDrafts.splice(index, 1);
        changed = true;
      }
    }
    if (mergeDuplicateImplantDrafts()) changed = true;
    targets.forEach((target) => {
      const existing = findImplantEntryByVendorTarget(implantDrafts, target);
      if (existing) {
        if (!existing.autoCompanyKey) existing.autoCompanyKey = target.key;
        const existingDescription = String(existing.description || "").trim();
        const targetDescription = String(target.description || "").trim();
        if (!existing.autoSource && (!existingDescription || existingDescription === targetDescription)) existing.autoSource = "product";
        if (existing.vendorId !== target.vendorId || existing.customVendor !== target.customVendor || existing.vendor !== target.vendor) {
          existing.vendorId = target.vendorId;
          existing.customVendor = target.customVendor;
          existing.vendor = target.vendor;
          changed = true;
        }
        if (implantDraftCanAutoUpdateDescription(existing) && existing.description !== target.description) {
          existing.description = target.description;
          existing.autoDescription = target.description;
          changed = true;
        } else if (existing.autoDescription !== target.description) {
          existing.autoDescription = target.description;
        }
        return;
      }
      const reusable = implantDrafts.find((draft) => !draft.autoSource && !implantDraftVendorName(draft) && !implantRowHasContent(draft));
      if (reusable) {
        Object.assign(reusable, {
          vendorId: target.vendorId,
          customVendor: target.customVendor,
          vendor: target.vendor,
          description: target.description,
          autoDescription: target.description,
          autoSource: "product",
          autoCompanyKey: target.key
        });
        changed = true;
        return;
      }
      implantDrafts.push({
        id: uid(),
        vendorId: target.vendorId,
        customVendor: target.customVendor,
        vendor: target.vendor,
        description: target.description,
        photos: [],
        autoSource: "product",
        autoDescription: target.description,
        autoCompanyKey: target.key
      });
      changed = true;
    });
    if (targets.length && implantEnabled) {
      if (!implantEnabled.checked) {
        implantEnabled.checked = true;
        changed = true;
      }
      if (implantPanel) implantPanel.hidden = false;
    } else if (!targets.length && implantEnabled?.checked && implantDrafts.length === 0) {
      implantEnabled.checked = false;
      if (implantPanel) implantPanel.hidden = true;
      changed = true;
    }
    if (changed) renderImplantDrafts();
  };
  const implantDraftById = (id) => implantDraftByIdFromList(implantDrafts, id);
  const currentImplantDraftPayload = () => {
    const implantWillSave = implantEnabled?.checked;
    if (implantWillSave) mergeDuplicateImplantDrafts();
    return implantDraftPayloadFromList(implantDrafts, implantWillSave);
  };
  const renderImplantDrafts = () => {
    implantEntriesWrap.innerHTML = implantDraftsHtml(implantDrafts, commonImplantPhotos.length);
  };
  const collectUseDraftSnapshot = () => {
    if (!form.reportValidity()) return null;
    const patientId = document.getElementById("patientId").value.trim();
    const patientIdMessage = patientIdValidationMessage(patientId);
    if (patientIdMessage) {
      alert(patientIdMessage);
      document.getElementById("patientId").focus();
      return null;
    }
    const useItems = selectedUseItems();
    const implantDraftPayload = currentImplantDraftPayload();
    const validationMessage = useDraftValidationMessage(useItems, implantDraftPayload);
    if (validationMessage) {
      alert(validationMessage);
      return null;
    }
    return buildUseDraftSnapshot({
      date: selectedUseDate(),
      patientName: document.getElementById("patientName").value.trim(),
      patientId,
      doctorText: departmentSelect.selectedOptions[0]?.textContent || "-",
      surgeryText: surgerySelect.selectedOptions[0]?.textContent || "-",
      enteredBy: draftUserText(),
      useItems,
      implantDraftPayload
    });
  };
  const pendingUsagePhotoPayload = async (pendingId, draft, photo, date, index, onProgress, cache = null) => {
    if (photo.url && photo.path && !photo.needsReupload) return cleanImplantPhotoPayload(photo);
    if (photo.dataUrl && !photo.file && !photo.preview && !photo.editedPreview) {
      return { ...cleanImplantPhotoPayload(photo), needsReupload: true };
    }
    const cacheKey = implantPhotoCacheKey(photo);
    if (cacheKey && cache?.has(cacheKey)) {
      if (typeof onProgress === "function") onProgress();
      return { ...cloneImplantPhotoPayload(cache.get(cacheKey), photo), needsReupload: true };
    }
    try {
      const uploaded = await implantPhotoFallbackPayload(photo, "Storage upload pending");
      if (cacheKey && cache) cache.set(cacheKey, uploaded);
      if (typeof onProgress === "function") onProgress();
      return { ...cloneImplantPhotoPayload(uploaded, photo), needsReupload: true };
    } catch (error) {
      console.error(error);
      if (typeof onProgress === "function") onProgress(true);
      throw error;
    }
  };
  const buildPendingUsagePayload = async (snapshot, pendingId, onProgress) => {
    const existingPending = loadedPendingUsageId ? pendingUsageById(loadedPendingUsageId) : null;
    const implantDraftsPayload = [];
    const pendingPhotoCache = new Map();
    for (const draft of snapshot.implantDraftPayload) {
      const photos = [];
      for (let index = 0; index < (draft.photos || []).length; index += 1) {
        photos.push(await pendingUsagePhotoPayload(pendingId, draft, draft.photos[index], snapshot.date || today(), index, onProgress, pendingPhotoCache));
      }
      const vendor = draft.vendorId === "__custom__"
        ? draft.customVendor
        : (implantVendorById(draft.vendorId)?.name || draft.customVendor || draft.vendor || "");
      implantDraftsPayload.push({
        id: draft.id || uid(),
        vendorId: draft.vendorId || "",
        customVendor: draft.customVendor || "",
        vendor,
        description: draft.description || "",
        autoSource: draft.autoSource || "",
        autoDescription: draft.autoDescription || "",
        autoCompanyKey: draft.autoCompanyKey || "",
        photos: photos.filter((photo) => photo.url || photo.dataUrl)
      });
    }
    return {
      id: pendingId,
      status: "pending",
      patientName: snapshot.patientName,
      patientId: snapshot.patientId,
      doctorId: departmentSelect.value,
      surgeryId: surgerySelect.value,
      date: snapshot.date || today(),
      productItems: snapshot.useItems.map((item) => ({ productId: item.productId, qty: Math.max(1, num(item.qty)) })),
      implantDrafts: implantDraftsPayload,
      draftSavedBy: snapshot.enteredBy,
      enteredBy: currentAuditUser(),
      createdAt: existingPending?.createdAt || snapshot.enteredAt,
      updatedAt: new Date().toISOString(),
      ...(existingPending ? auditUpdateFields() : auditCreateFields())
    };
  };
  const savePendingUsageDraft = async (snapshot) => {
    if (!db) {
      alert("Firebase 연결 후 임시저장을 사용할 수 있습니다.");
      return null;
    }
    const pendingId = loadedPendingUsageId || uid();
    const totalPhotos = pendingUsagePhotoCount(snapshot.implantDraftPayload);
    let donePhotos = 0;
    let failedPhotos = 0;
    const payload = await buildPendingUsagePayload(snapshot, pendingId, (failed) => {
      donePhotos += 1;
      if (failed) failedPhotos += 1;
      showSaveToast(pendingUsagePhotoProgressMessage(donePhotos, totalPhotos, failedPhotos), failedPhotos ? "error" : "saving", { hold: donePhotos < totalPhotos });
    });
    suppressPendingUsagesRender = true;
    await setDoc(doc(db, "pendingUsages", pendingId), payload, { merge: true });
    loadedPendingUsageId = pendingId;
    return payload;
  };
  const renderUseDraftPanel = () => {
    if (!useDraftPanel || !useDraftSummary || !useDraftSnapshot) {
      if (useDraftPanel) useDraftPanel.hidden = true;
      return;
    }
    useDraftPanel.hidden = false;
    setUseDraftPanelState({
      status: useDraftStatus,
      finalSaveButton: finalSaveUseDraftButton,
      saveButton: saveUseDraftButton,
      dirty: useDraftDirty,
      hasSnapshot: Boolean(useDraftSnapshot)
    });
    useDraftSummary.innerHTML = useDraftSummaryHtml(useDraftSnapshot);
  };
  const markUseDraftDirty = () => {
    if (!useDraftSnapshot || useDraftDirty) return;
    useDraftDirty = true;
    renderUseDraftPanel();
  };
  const loadPendingUsageIntoForm = (pending) => {
    if (!pending) return;
    if (useDate) useDate.value = pending.date || today();
    document.getElementById("patientName").value = pending.patientName || "";
    document.getElementById("patientId").value = pending.patientId || "";
    const doctor = departmentById(pending.doctorId);
    if (doctor) {
      useDepartment.value = departmentCode(doctor.name);
      filterUseOptions();
      departmentSelect.value = pending.doctorId || "";
      filterUseOptions();
    }
    surgerySelect.value = pending.surgeryId || "";
    renderUseRecommendation();
    applyPendingProductItemsToForm(form, pending.productItems || []);
    renderSelectedUseList();
    implantDrafts.splice(0, implantDrafts.length, ...pendingImplantDraftsFromRecord(pending));
    if (implantEnabled) implantEnabled.checked = implantDrafts.length > 0;
    if (implantPanel) implantPanel.hidden = !implantDrafts.length;
    loadedPendingUsageId = pending.id || "";
    syncImplantDraftsFromSelectedProducts();
    renderImplantDrafts();
    useDraftSnapshot = collectUseDraftSnapshot();
    if (useDraftSnapshot) {
      useDraftSnapshot.enteredBy = pending.draftSavedBy || pending.enteredBy?.name || pending.enteredBy?.loginId || useDraftSnapshot.enteredBy;
      useDraftSnapshot.enteredAt = pending.updatedAt || pending.createdAt || useDraftSnapshot.enteredAt;
    }
    useDraftDirty = false;
    useEntryDirty = true;
    saveUseEntryPatientAutosave();
    renderUseDraftPanel();
    useDraftPanel?.scrollIntoView({ behavior: "smooth", block: "center" });
  };
  const updateImplantDraftFromInput = (target) => {
    const vendorSelect = target.closest("[data-implant-draft]")?.querySelector("[data-implant-vendor-select]");
    const id = target.dataset.implantVendorSelect || target.dataset.implantVendorCustom || target.dataset.implantDescription || vendorSelect?.dataset.implantVendorSelect;
    const draft = implantDraftById(id);
    if (!draft) return;
    if (target.matches("[data-implant-vendor-select]")) {
      draft.vendorId = target.value;
      renderImplantDrafts();
    } else if (target.matches("[data-implant-vendor-custom]")) {
      draft.customVendor = target.value;
    } else if (target.matches("[data-implant-description]")) {
      draft.description = target.value;
    }
  };
  const parseImplantPair = (value) => {
    return implantDraftPhotoPair(implantDrafts, value);
  };
  const refreshImplantPhotoEditor = () => {
    const { photo } = parseImplantPair(activeImplantEditPair);
    const image = document.getElementById("implantPhotoModalImage");
    const cropButton = document.getElementById("implantModalCrop");
    if (!photo || !image) return;
    image.src = implantPhotoViewSrc(photo);
    applyImplantModalPhotoState(image, photo);
    showImplantPhotoEditTools();
    if (cropButton) cropButton.textContent = photo.cropped ? "자르기 수정" : "자르기";
  };
  const openImplantPhotoEditor = (pair) => {
    activeImplantEditPair = pair;
    const { photo } = parseImplantPair(pair);
    if (!photo) return;
    showImplantPhotoModal(implantPhotoViewSrc(photo));
    activeImplantCropPhoto = photo;
    activeImplantCropApply = async (changedPhoto) => {
      await refreshEditedImplantPreview(changedPhoto);
      markUseEntryDirty();
      renderImplantDrafts();
      refreshImplantPhotoEditor();
    };
    refreshImplantPhotoEditor();
  };
  const renderProductSearchResults = () => {
    const query = productSearch.value;
    if (!query) {
      productSearchResults.innerHTML = `<div class="empty">제품명을 입력해 주세요.</div>`;
      return;
    }
    const results = useProductSearchResults(state.products, query);
    productSearchResults.innerHTML = productSearchResultsHtml(results, selectedUseItems());
    productSearchResults.querySelectorAll("[data-search-product]").forEach((input) => {
      input.addEventListener("change", () => {
        const qty = searchProductQtyValue(productSearchResults, input.value);
        if (input.checked) {
          selectUseProduct(input.value, qty);
          return;
        }
        clearSearchProductFromUseForm(input.value, form);
        markUseEntryDirty();
        renderSelectedUseList();
      });
    });
    productSearchResults.querySelectorAll("[data-search-qty]").forEach((input) => {
      input.addEventListener("input", () => selectUseProduct(input.dataset.searchQty, input.value));
    });
  };
  const renderUseRecommendation = () => {
    const rule = currentUseRule();
    const restrictActive = isRestrictOn();
    if (!rule) {
      const hasSurgerySelection = useDepartment.value && departmentSelect.value && surgerySelect.value;
      recommendation.innerHTML = noRecommendationHtml(hasSurgerySelection);
      app.querySelectorAll("[data-use-product]").forEach((input) => input.closest(".check-card").style.display = "");
      renderSelectedUseList();
      return;
    }
    const recommendedItems = ruleItems(rule);
    const recommended = useRecommendedItemsWithProducts(recommendedItems);
    recommendation.innerHTML = useRecommendationHtml(recommended, restrictActive, selectedUseItems());
    form.querySelectorAll("[data-use-product]").forEach((input) => {
      const product = productById(input.value);
      if (shouldHideUseProductForRestriction(product, input.value, recommendedItems, restrictActive)) {
        input.checked = false;
        input.closest(".check-card").style.display = "none";
      } else {
        input.closest(".check-card").style.display = "";
      }
    });
    app.querySelectorAll("[data-recommend-product]").forEach((input) => {
      input.addEventListener("change", () => {
        syncRecommendProductToUseForm(input, form);
        markUseEntryDirty();
        renderSelectedUseList();
      });
    });
    app.querySelectorAll("[data-recommend-qty]").forEach((input) => {
      input.addEventListener("input", () => {
        syncRecommendQtyToUseForm(input);
        markUseEntryDirty();
        renderSelectedUseList();
      });
    });
    renderSelectedUseList();
  };
  const filterUseOptions = () => {
    const department = useDepartment.value;
    const currentDoctor = departmentSelect.value;
    const currentSurgery = surgerySelect.value;
    const doctors = department
      ? state.doctors.slice().sort(byName).filter((item) => departmentCode(item.name) === department)
      : [];
    departmentSelect.innerHTML = `<option value="">${department ? "원장 코드 선택" : "과를 먼저 선택하세요"}</option>` + doctors
      .map((item) => `<option value="${item.id}">${escapeHtml(item.name)}</option>`)
      .join("");
    if (doctors.some((item) => item.id === currentDoctor)) departmentSelect.value = currentDoctor;
    const surgeries = department && departmentSelect.value
      ? visibleSurgeriesFor(department, departmentSelect.value)
      : [];
    surgerySelect.innerHTML = `<option value="">${department && departmentSelect.value ? "수술 선택" : "원장 코드를 먼저 선택하세요"}</option>` + surgeries
      .map((item) => `<option value="${item.id}">${escapeHtml(item.department || inferSurgeryDepartment(item.name))} - ${escapeHtml(item.name)}${isCommonSurgery(item) ? "" : " · 전용"}</option>`)
      .join("");
    if (surgeries.some((item) => item.id === currentSurgery)) surgerySelect.value = currentSurgery;
    renderUseRecommendation();
  };
  const restoreUseEntryPatientAutosave = () => {
    const draft = readUseEntryAutosave();
    if (!draft) return;
    const hasCurrentInput = document.getElementById("patientName")?.value.trim() ||
      document.getElementById("patientId")?.value.trim() ||
      useDepartment.value ||
      departmentSelect.value ||
      surgerySelect.value;
    if (hasCurrentInput) return;
    if (useDate) useDate.value = draft.date || today();
    document.getElementById("patientName").value = draft.patientName || "";
    document.getElementById("patientId").value = draft.patientId || "";
    useDepartment.value = draft.department || "";
    filterUseOptions();
    departmentSelect.value = draft.doctorId || "";
    filterUseOptions();
    surgerySelect.value = draft.surgeryId || "";
    setRestrictButton(Boolean(draft.restrictNonpay));
    renderUseRecommendation();
    useEntryDirty = true;
    setStatus("작성 중이던 환자 기본정보를 복원했습니다.", "ok");
  };
  restoreUseEntryPatientAutosave();
  useDepartment.addEventListener("change", () => {
    filterUseOptions();
    markUseEntryDirty();
  });
  departmentSelect.addEventListener("change", () => {
    filterUseOptions();
    markUseEntryDirty();
  });
  surgerySelect.addEventListener("change", () => {
    renderUseRecommendation();
    markUseEntryDirty();
  });
  useRestrictNonpay.addEventListener("click", () => {
    setRestrictButton(!isRestrictOn());
    markUseEntryDirty();
    renderUseRecommendation();
  });
  form.querySelectorAll("[data-use-product], [data-use-qty]").forEach((input) => {
    const syncAndRender = () => {
      if (input.dataset.useProduct) {
        const qtyInput = form.querySelector(`[data-use-qty="${input.dataset.useProduct}"]`);
        syncRecommendControl(input.dataset.useProduct, input.checked, qtyInput?.value || 1);
      }
      if (input.dataset.useQty) {
        const checkbox = form.querySelector(`[data-use-product="${input.dataset.useQty}"]`);
        syncRecommendControl(input.dataset.useQty, Boolean(checkbox?.checked), input.value);
      }
      markUseEntryDirty();
      renderSelectedUseList();
    };
    input.addEventListener("change", syncAndRender);
    input.addEventListener("input", syncAndRender);
  });
  app.querySelectorAll("[data-load-pending-usage]").forEach((button) => {
    button.addEventListener("click", () => {
      const pending = pendingUsageById(button.dataset.loadPendingUsage);
      if (!pending) {
        alert("대기 기록을 찾을 수 없습니다. 화면을 새로고침해 주세요.");
        return;
      }
      loadPendingUsageIntoForm(pending);
      saveDoneToast("임시저장 기록을 불러왔습니다.");
    });
  });
  app.querySelectorAll("[data-delete-pending-usage]").forEach((button) => {
    button.addEventListener("click", async () => {
      const pending = pendingUsageById(button.dataset.deletePendingUsage);
      if (!pending) {
        alert("대기 기록을 찾을 수 없습니다. 화면을 새로고침해 주세요.");
        return;
      }
      if (!confirm("이 임시저장 대기 기록을 삭제할까요? 기존 사용내역과 재고에는 영향이 없습니다.")) return;
      try {
        await deleteDoc(doc(db, "pendingUsages", pending.id));
        if (sameId(loadedPendingUsageId, pending.id)) {
          loadedPendingUsageId = "";
          useDraftSnapshot = null;
          useDraftDirty = false;
          if (useDraftPanel) useDraftPanel.hidden = true;
        }
        saveDoneToast("임시저장 대기 기록을 삭제했습니다.");
      } catch (error) {
        console.error(error);
        saveErrorToast(`대기 기록 삭제 실패: ${error.message}`);
        alert(`대기 기록 삭제에 실패했습니다: ${error.message}`);
      }
    });
  });
  form.addEventListener("input", (event) => {
    markUseEntryDirty();
    markUseDraftDirty(event);
  }, true);
  form.addEventListener("change", (event) => {
    markUseEntryDirty();
    markUseDraftDirty(event);
  }, true);
  saveUseDraftButton?.addEventListener("click", async () => {
    const snapshot = collectUseDraftSnapshot();
    if (!snapshot) return;
    setButtonBusy(saveUseDraftButton, true, "임시저장 중...");
    showSaveToast("임시저장 중입니다...", "saving", { hold: true });
    try {
      const saved = await savePendingUsageDraft(snapshot);
      if (!saved) return;
      useDraftSnapshot = {
        ...snapshot,
        enteredBy: saved.draftSavedBy || snapshot.enteredBy,
        enteredAt: saved.updatedAt || saved.createdAt || snapshot.enteredAt,
        implantDraftPayload: saved.implantDrafts || []
      };
      useDraftDirty = false;
      useEntryDirty = true;
      saveUseEntryPatientAutosave();
      renderUseDraftPanel();
      useDraftPanel?.scrollIntoView({ behavior: "smooth", block: "center" });
      saveDoneToast("임시저장 완료 · 스크럽 확인 대기");
    } catch (error) {
      console.error(error);
      suppressPendingUsagesRender = false;
      saveErrorToast(`임시저장 실패: ${error.message}`);
      alert(`임시저장에 실패했습니다: ${error.message}`);
    } finally {
      setButtonBusy(saveUseDraftButton, false);
      renderUseDraftPanel();
    }
  });
  editUseDraftButton?.addEventListener("click", () => {
    if (!useDraftSnapshot) return;
    useDraftDirty = true;
    renderUseDraftPanel();
    form.scrollIntoView({ behavior: "smooth", block: "start" });
    saveDoneToast("수정 후 임시저장을 다시 눌러 주세요.");
  });
  cancelUseDraftButton?.addEventListener("click", async () => {
    if (!confirm("임시저장을 취소할까요? 입력 내용은 화면에 남아 있습니다.")) return;
    if (loadedPendingUsageId && db) {
      try {
        await deleteDoc(doc(db, "pendingUsages", loadedPendingUsageId));
        loadedPendingUsageId = "";
      } catch (error) {
        console.error(error);
        saveErrorToast(`임시저장 취소 실패: ${error.message}`);
        return;
      }
    }
    useDraftSnapshot = null;
    useDraftDirty = false;
    if (useDraftPanel) useDraftPanel.hidden = true;
    if (saveUseDraftButton) saveUseDraftButton.textContent = "임시저장";
    saveDoneToast("임시저장을 취소했습니다.");
  });
  const showProductSearchModal = () => {
    productSearchModal.hidden = false;
    renderProductSearchResults();
    setTimeout(() => productSearch?.focus(), 30);
  };
  const hideProductSearchModal = () => {
    productSearchModal.hidden = true;
  };
  openProductSearch?.addEventListener("click", showProductSearchModal);
  closeProductSearch?.addEventListener("click", hideProductSearchModal);
  productSearchModal?.addEventListener("click", (event) => {
    if (event.target === productSearchModal) hideProductSearchModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && productSearchModal && !productSearchModal.hidden) hideProductSearchModal();
  }, { once: false });
  productSearch.addEventListener("input", renderProductSearchResults);
  openCommonImplantGallery?.addEventListener("click", () => commonImplantGallery?.click());
  openCommonImplantCamera?.addEventListener("click", () => commonImplantCamera?.click());
  [commonImplantGallery, commonImplantCamera].forEach((input) => {
    input?.addEventListener("change", () => {
      addCommonImplantPhotos(Array.from(input.files || []));
      input.value = "";
      if (implantEnabled && !implantEnabled.checked) implantEnabled.checked = true;
      if (implantPanel) implantPanel.hidden = false;
      if (!implantDrafts.length) addImplantDraft();
      markUseEntryDirty();
      renderImplantDrafts();
    });
  });
  commonImplantPhotoList?.addEventListener("click", (event) => {
    const preview = event.target.closest("[data-preview-common-implant-photo]");
    if (preview) {
      const photo = findCommonImplantPhoto(preview.dataset.previewCommonImplantPhoto);
      if (photo) {
        activeImplantEditPair = "";
        const image = document.getElementById("implantPhotoModalImage");
        hideImplantPhotoEditTools();
        if (image) image.style.transform = "";
        showImplantPhotoModal(implantPhotoViewSrc(photo));
      }
      return;
    }
    const remove = event.target.closest("[data-remove-common-implant-photo]");
    if (remove) {
      if (removeCommonImplantPhotoById(commonImplantPhotos, remove.dataset.removeCommonImplantPhoto)) {
        markUseEntryDirty();
        renderCommonImplantPhotos();
        renderImplantDrafts();
      }
    }
  });
  implantEnabled?.addEventListener("change", () => {
    implantPanel.hidden = !implantEnabled.checked;
    if (implantEnabled.checked && !implantDrafts.length) addImplantDraft();
    markUseEntryDirty();
  });
  addImplantVendorEntry?.addEventListener("click", () => {
    addImplantDraft();
    markUseEntryDirty();
  });
  implantEntriesWrap?.addEventListener("input", (event) => {
    updateImplantDraftFromInput(event.target);
    markUseEntryDirty();
  });
  implantEntriesWrap?.addEventListener("change", async (event) => {
    const target = event.target;
    updateImplantDraftFromInput(target);
    markUseEntryDirty();
    if (target.matches("[data-implant-photo-input], [data-implant-camera-input]")) {
      const draft = implantDraftById(target.dataset.implantPhotoInput || target.dataset.implantCameraInput);
      if (!draft) return;
      addImplantDraftPhotosFromFiles(draft, Array.from(target.files || []));
      target.value = "";
      renderImplantDrafts();
    }
  });
  implantEntriesWrap?.addEventListener("click", async (event) => {
    const galleryButton = event.target.closest("[data-open-implant-gallery]");
    if (galleryButton) {
      implantEntriesWrap.querySelector(`[data-implant-photo-input="${galleryButton.dataset.openImplantGallery}"]`)?.click();
      return;
    }
    const cameraButton = event.target.closest("[data-open-implant-camera]");
    if (cameraButton) {
      implantEntriesWrap.querySelector(`[data-implant-camera-input="${cameraButton.dataset.openImplantCamera}"]`)?.click();
      return;
    }
    const useCommon = event.target.closest("[data-use-common-implant-photo]");
    if (useCommon) {
      const draft = implantDraftById(useCommon.dataset.useCommonImplantPhoto);
      if (!draft || !commonImplantPhotos.length) return;
      const addedPhotos = commonImplantPhotos.map(cloneCommonImplantPhoto);
      draft.photos.push(...addedPhotos);
      markUseEntryDirty();
      renderImplantDrafts();
      if (addedPhotos.length === 1) {
        openImplantPhotoEditor(`${draft.id}::${addedPhotos[0].id}`);
      }
      return;
    }
    const removeDraft = event.target.closest("[data-remove-implant-draft]");
    if (removeDraft) {
      if (removeImplantDraftById(implantDrafts, removeDraft.dataset.removeImplantDraft)) {
        markUseEntryDirty();
        renderImplantDrafts();
      }
      return;
    }
    const previewButton = event.target.closest("[data-preview-implant-photo]");
    if (previewButton) {
      const { photo } = parseImplantPair(previewButton.dataset.previewImplantPhoto);
      activeImplantEditPair = "";
      const image = document.getElementById("implantPhotoModalImage");
      hideImplantPhotoEditTools();
      if (image) image.style.transform = "";
      if (photo) {
        showImplantPhotoModal(implantPhotoViewSrc(photo));
        document.getElementById("implantPhotoModalImage")?.classList.toggle("cropped", Boolean(photo.cropped));
      }
      return;
    }
    const editButton = event.target.closest("[data-edit-implant-photo]");
    if (editButton) {
      openImplantPhotoEditor(editButton.dataset.editImplantPhoto);
      return;
    }
    const rotateButton = event.target.closest("[data-rotate-implant-photo]");
    if (rotateButton) {
      const { photo } = parseImplantPair(rotateButton.dataset.rotateImplantPhoto);
      if (photo) {
        photo.rotation = ((photo.rotation || 0) + 90) % 360;
        clearEditedImplantPreview(photo);
        markUseEntryDirty();
        renderImplantDrafts();
      }
      return;
    }
    const removePhoto = event.target.closest("[data-remove-implant-photo]");
    if (removePhoto) {
      const { draft, photo } = parseImplantPair(removePhoto.dataset.removeImplantPhoto);
      if (draft && photo) {
        URL.revokeObjectURL(photo.preview);
        draft.photos = draft.photos.filter((item) => item.id !== photo.id);
        markUseEntryDirty();
        renderImplantDrafts();
      }
      return;
    }
    const moveUp = event.target.closest("[data-move-implant-photo-up]");
    const moveDown = event.target.closest("[data-move-implant-photo-down]");
    if (moveUp || moveDown) {
      const pair = moveUp?.dataset.moveImplantPhotoUp || moveDown?.dataset.moveImplantPhotoDown;
      const { draft, photo } = parseImplantPair(pair);
      if (!draft || !photo) return;
      const index = draft.photos.findIndex((item) => item.id === photo.id);
      const nextIndex = moveUp ? index - 1 : index + 1;
      if (nextIndex < 0 || nextIndex >= draft.photos.length) return;
      [draft.photos[index], draft.photos[nextIndex]] = [draft.photos[nextIndex], draft.photos[index]];
      markUseEntryDirty();
      renderImplantDrafts();
    }
  });
  document.getElementById("closeImplantPhotoModal")?.addEventListener("click", hideImplantPhotoModal);
  document.getElementById("implantPhotoModal")?.addEventListener("click", (event) => {
    if (event.target.id === "implantPhotoModal") hideImplantPhotoModal();
  });
  document.getElementById("implantModalRotate")?.addEventListener("click", async () => {
    const { photo } = parseImplantPair(activeImplantEditPair);
    if (!photo) return;
    photo.rotation = ((photo.rotation || 0) + 90) % 360;
    clearEditedImplantPreview(photo);
    markUseEntryDirty();
    refreshImplantPhotoEditor();
    renderImplantDrafts();
    refreshImplantPhotoEditor();
  });
  document.getElementById("implantModalCrop")?.addEventListener("click", async () => {
    const { photo } = parseImplantPair(activeImplantEditPair);
    if (!photo && !activeImplantCropPhoto) return;
    const { frame } = implantCropElements();
    if (frame && !frame.hidden) {
      await applyActiveImplantCrop();
    } else {
      await enableImplantCropFrame(photo || activeImplantCropPhoto);
    }
  });
  document.getElementById("implantModalDone")?.addEventListener("click", () => {
    activeImplantEditPair = "";
    hideImplantPhotoModal();
  });
  renderCommonImplantPhotos();
  renderProductSearchResults();
  filterUseOptions();
  document.getElementById("useForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = event.submitter || event.currentTarget.querySelector("button[type='submit']");
    if (!useDraftSnapshot) {
      alert("먼저 임시저장을 눌러 스크럽 확인 대기 상태로 만들어 주세요.");
      return;
    }
    if (useDraftDirty) {
      alert("임시저장 후 입력 내용이 수정되었습니다. 임시저장 갱신 후 최종저장해 주세요.");
      return;
    }
    const rule = currentUseRule();
    const restrictActive = isRestrictOn();
    const useItems = selectedUseItems();
    const implantDraftPayload = currentImplantDraftPayload();
    const usageDate = useDraftSnapshot.date || selectedUseDate();
    const patientName = document.getElementById("patientName").value.trim();
    const patientId = document.getElementById("patientId").value.trim();
    const patientIdMessage = patientIdValidationMessage(patientId);
    if (patientIdMessage) {
      alert(patientIdMessage);
      document.getElementById("patientId").focus();
      return;
    }
    if (usageDate !== today() && !confirm(`${usageDate} 사용분으로 저장합니다. 계속할까요?`)) {
      return;
    }
    const productIds = useItems.flatMap((item) => Array.from({ length: item.qty }, () => item.productId));
    const uniqueProductIds = useItems.map((item) => item.productId);
    const selectedNonpayIds = uniqueProductIds.filter((id) => productCategory(productById(id)?.category) === "비급여");
    if (restrictActive && selectedNonpayIds.length && !confirm("비급여 제한으로 설정된 수술입니다. 그래도 비급여를 사용할까요?")) {
      return;
    }
    const recommendationCheck = finalSaveRecommendationCheck({
      ruleItems: rule ? ruleItems(rule) : [],
      productIds,
      uniqueProductIds,
      useItems,
      restrictActive
    });
    if (recommendationCheck.missingNames) {
      if (!confirm(`추천 항목이 선택되지 않았습니다: ${recommendationCheck.missingNames}\n정말 사용하지 않겠습니까?\n확인을 누르면 사용안함으로 저장합니다.`)) {
        return;
      }
    }
    if (recommendationCheck.changedNames) {
      if (!confirm(`추천 항목 수량과 다릅니다: ${recommendationCheck.changedNames}\n그래도 저장할까요?`)) {
        return;
      }
    }
    const validationMessage = useDraftValidationMessage(useItems, implantDraftPayload);
    if (validationMessage) {
      alert(validationMessage);
      return;
    }
    const duplicatePatientWarning = sameDayPatientUsageWarning({ usageDate, patientName, patientId });
    if (duplicatePatientWarning && !confirm(duplicatePatientWarning)) {
      return;
    }
    setButtonBusy(submitButton, true, "저장 중...");
    useItems.forEach((item) => {
      const product = productById(item.productId);
      product.stock = num(product.stock) - item.qty;
    });
    const finalSavedAt = new Date().toISOString();
    const usageRecord = buildFinalUsageRecord({
      patientName,
      patientId,
      doctorId: document.getElementById("useDoctor").value,
      surgeryId: document.getElementById("useSurgery").value,
      productIds,
      usageDate,
      finalSavedAt,
      draftSnapshot: useDraftSnapshot,
      finalSavedBy: draftUserText(),
      auditFields: auditCreateFields()
    });
    state.usages.push(usageRecord);
    resetUseEntryProtection();
    currentView = "edit";
    pendingEditUsageId = state.usages[state.usages.length - 1]?.id || "";
    render();
    await saveState("사용내역 저장 완료", {
      savingMessage: "사용내역 저장 중입니다...",
      doneMessage: implantDraftPayload.length ? "사용내역 저장 완료 · 사진 업로드 준비" : "사용내역 저장 완료"
    });
    if (implantDraftPayload.length) {
      try {
        await createImplantRecordFromUsage(usageRecord, implantDraftPayload, {
          deferPhotoUpload: true
        });
        saveDoneToast("사용내역과 임플란트 장부 저장 완료");
        setStatus("사용내역 및 임플란트 기록 저장 완료", "ok");
      } catch (error) {
        console.error(error);
        saveErrorToast(`임플란트 기록 저장 실패: ${error.message}`);
        alert(`사용내역은 저장됐지만 임플란트 기록 저장에 실패했습니다: ${error.message}`);
      }
    }
    if (loadedPendingUsageId && db) {
      try {
        await setDoc(doc(db, "pendingUsages", loadedPendingUsageId), {
          status: "confirmed",
          confirmedUsageId: usageRecord.id,
          confirmedAt: finalSavedAt,
          confirmedBy: currentAuditUser(),
          updatedAt: new Date().toISOString(),
          ...auditUpdateFields()
        }, { merge: true });
      } catch (error) {
        console.error(error);
        saveErrorToast(`임시저장 확정 처리 실패: ${error.message}`);
      }
    }
    setButtonBusy(submitButton, false);
  });
};

const inDateRange = (date, start, end) => {
  if (!date) return false;
  if (start && date < start) return false;
  if (end && date > end) return false;
  return true;
};

const productUsageSort = (category) => (a, b) => {
  const normalizedCategory = productCategory(category);
  if (normalizedCategory === "인체조직") {
    return alphaFirstCompare(a.company || "업체 없음", b.company || "업체 없음") ||
      alphaFirstCompare(a.name, b.name);
  }
  if (normalizedCategory === "ANCHOR") {
    return alphaFirstCompare(a.company || "업체 없음", b.company || "업체 없음") ||
      alphaFirstCompare(a.subcategory || "분류 없음", b.subcategory || "분류 없음") ||
      alphaFirstCompare(a.name, b.name);
  }
  return alphaFirstCompare(a.name, b.name);
};

const stockStatusClass = (product) => {
  const stock = num(product?.stock);
  const warning = num(product?.warningStock);
  if (stock <= warning) return "stock-danger";
  if (warning > 0 && stock <= warning * 2) return "stock-warn";
  return "stock-ok";
};

let historyModule = null;
const getHistoryModule = () => {
  if (!window.createHistoryModule) throw new Error("사용내역 모듈을 불러오지 못했습니다.");
  if (!historyModule) {
    historyModule = window.createHistoryModule({
      getState: () => state,
      getApp: () => app,
      setCurrentView: (view) => { currentView = view; },
      setPendingEditUsageId: (id) => { pendingEditUsageId = id; },
      render,
      byName,
      escapeHtml,
      normalizedName,
      inDateRange,
      receiptDateValue,
      sameId,
      parseSeedProducts,
      productKey,
      productLooseKey,
      alphaFirstCompare,
      productCategories: PRODUCT_CATEGORIES,
      productCategory,
      productUsageSort,
      stockStatusClass,
      num,
      patientDisplayName,
      auditMetaHtml,
      formatDateTime,
      productCategoryLabel,
      downloadExcel,
      departmentById,
      surgeryById,
      productById,
      patientIdText,
      auditUserText,
      auditTimeText,
      today,
      inferSurgeryDepartment,
      getImplantRecords: () => implantRecords,
      implantRecordDate,
      implantPatientNoText,
      canEditUsage,
      canModifyUsageRecord,
      canDeleteUsageRecord,
      deleteUsageRecord
    });
  }
  return historyModule;
};

const renderHistory = () => getHistoryModule().renderHistory();
const bindHistory = () => getHistoryModule().bindHistory();

const usageItem = (usage, options = {}) => getHistoryModule().usageItem(usage, options);

const zipFiles = (files) => window.ORInventoryExportUtils.zipFiles(files);
const xlsxWorkbook = (headers, rows) => window.ORInventoryExportUtils.xlsxWorkbook(headers, rows);
const downloadExcel = (filename, headers, rows) => window.ORInventoryExportUtils.downloadExcel(filename, headers, rows);

const exportReceiptHistory = (start = "", end = "", query = "") => {
  const rows = filteredReceipts(start, end, query)
    .map((receipt) => {
      const product = productById(receipt.productId);
      const usage = receipt.usageId ? state.usages.find((item) => item.id === receipt.usageId) : null;
      return [
        receiptDateValue(receipt),
        auditTimeText(receipt),
        auditUserText(receipt),
        receiptTypeLabel(receipt),
        productCategoryLabel(product?.category || receipt.category || ""),
        receiptProductName(receipt),
        product?.company || receipt.company || "",
        product?.subcategory || receipt.subcategory || "",
        receipt.patientName || usage?.patientName || "",
        patientIdText(usage),
        receipt.usageDate || usage?.date || "",
        num(receipt.qty),
        receipt.memo || "",
        receipt.updatedByName || receipt.updatedBy?.name || "",
        receipt.updatedAt ? formatDateTime(receipt.updatedAt) : ""
      ];
    });
  downloadExcel(
    "입고내역.xlsx",
    ["입고일", "입고시각", "입고자", "구분", "제품군", "제품명", "업체명", "세부분류", "환자명", "환자ID", "사용일", "입고수량", "메모", "수정자", "수정시각"],
    rows
  );
};

const deleteImplantRecordsForUsage = async (usageId) => {
  const linkedRecords = implantRecords.filter((record) => sameId(record.usageId, usageId));
  if (!linkedRecords.length) return 0;
  if (!deleteDoc) throw new Error("Firestore delete is not ready.");
  await Promise.all(linkedRecords.map((record) => deleteDoc(doc(db, "implantRecords", record.id))));
  implantRecords = implantRecords.filter((record) => !sameId(record.usageId, usageId));
  return linkedRecords.length;
};

const deleteUsageRecord = async (usageId, { onSuccess } = {}) => {
  const usage = state.usages.find((item) => String(item.id) === String(usageId));
  if (!usage) return false;
  if (!canDeleteUsageRecord(usage)) {
    alert(usagePastLockMessage(usage) || "사용내역 삭제는 관리자와 책임사용자만 가능합니다.");
    return false;
  }
  if (!confirm("사용내역을 삭제하고 재고를 복구할까요?")) return false;
  usage.productIds.forEach((id) => {
    const product = productById(id);
    if (product) product.stock = num(product.stock) + 1;
  });
  state.usages = state.usages.filter((item) => String(item.id) !== String(usage.id));
  await saveState("사용내역 삭제 완료 · 재고 복구", { authoritative: true });
  try {
    await deleteImplantRecordsForUsage(usage.id);
  } catch (error) {
    console.error(error);
    alert(`사용내역은 삭제됐지만 연결된 임플란트 장부 삭제에 실패했습니다: ${error.message}`);
  }
  if (typeof onSuccess === "function") onSuccess();
  render();
  return true;
};

let backupResetModule = null;
const getBackupResetModule = () => {
  if (!window.createBackupResetModule) throw new Error("백업/초기화 모듈을 불러오지 못했습니다.");
  if (!backupResetModule) {
    backupResetModule = window.createBackupResetModule({
      getState: () => state,
      setState: (nextState) => { state = nextState; },
      getPendingUsages: () => pendingUsages,
      setPendingUsages: (items) => { pendingUsages = items; },
      getImplantRecords: () => implantRecords,
      setImplantRecords: (items) => { implantRecords = items; },
      getDb: () => db,
      getGetDocs: () => getDocs,
      getCollection: () => collection,
      getSetDoc: () => setDoc,
      getDoc: () => doc,
      getDeleteDoc: () => deleteDoc,
      getGetDoc: () => getDoc,
      alphaFirstCompare,
      escapeHtml,
      currentAuditUser,
      today,
      render,
      saveState,
      num,
      auditUpdateFields,
      canManageSettings,
      savingToast,
      saveErrorToast,
      normalizeState,
      addSeedMasters,
      reconcileProductStocks,
      app
    });
  }
  return backupResetModule;
};

const renderBackup = () => getBackupResetModule().renderBackup();
const bindBackup = () => getBackupResetModule().bindBackup();

const subscribeImplantCollections = () => {
  if (!db || !collection || !onSnapshot) return;
  if (!implantRecordsUnsubscribe) {
    implantRecordsUnsubscribe = onSnapshot(collection(db, "implantRecords"), (snapshot) => {
      implantRecords = snapshot.docs.map((item) => ({ id: item.id, ...item.data() }));
      if (hydrated && ["implants", "edit"].includes(currentView)) render();
    }, (error) => {
      console.error(error);
      setStatus(`임플란트 기록 연결 오류: ${error.message}`, "error");
    });
  }
  if (!implantVendorsUnsubscribe) {
    implantVendorsUnsubscribe = onSnapshot(collection(db, "implantVendors"), (snapshot) => {
      implantVendors = snapshot.docs.map((item) => ({ id: item.id, ...item.data() }));
      if (hydrated && currentView === "use") {
        renderOrDeferForUseEntry("임플란트 업체 정보가 갱신됐습니다. 입력 중인 사용입력을 보호하고 있습니다.");
      } else if (hydrated && (currentView === "edit" || (currentView === "settings" && currentSettingsView === "implantVendors"))) {
        render();
      }
    }, (error) => {
      console.error(error);
      setStatus(`임플란트 업체 연결 오류: ${error.message}`, "error");
    });
  }
  if (!pendingUsagesUnsubscribe) {
    pendingUsagesUnsubscribe = onSnapshot(collection(db, "pendingUsages"), (snapshot) => {
      pendingUsages = snapshot.docs.map((item) => ({ id: item.id, ...item.data() }));
      if (hydrated && currentView === "use") {
        if (suppressPendingUsagesRender) {
          suppressPendingUsagesRender = false;
        } else {
          renderOrDeferForUseEntry("임시저장 대기목록이 갱신됐습니다. 입력 중인 사용입력을 보호하고 있습니다.");
        }
      }
    }, (error) => {
      console.error(error);
      setStatus(`임시저장 대기목록 연결 오류: ${error.message}`, "error");
    });
  }
};

const boot = async () => {
  if (!ensureLocalSession()) return;
  render();
  try {
    const firebaseApp = initializeApp(firebaseConfig);
    db = getFirestore(firebaseApp);
    if (getStorage) {
      storage = getStorage(firebaseApp, "gs://nonpay-inventory.firebasestorage.app");
      storageFallback = getStorage(firebaseApp, "gs://nonpay-inventory.appspot.com");
    }
    const verifiedUser = await verifySessionUser();
    if (!verifiedUser) return;
    ref = doc(db, "app", "main");
    subscribeImplantCollections();
    try {
      await enableIndexedDbPersistence(db);
    } catch (error) {
      console.info("Offline persistence unavailable", error);
    }
    const snap = await getDoc(ref);
    if (snap.exists()) {
      state = normalizeState(snap.data());
    } else {
      await setDoc(ref, state);
    }
    const addedSeedCount = addSeedMasters();
    const reconciledStockCount = reconcileProductStocks();
    hydrated = true;
    setStatus("Firebase 연결됨", "ok");
    if (addedSeedCount > 0 || reconciledStockCount > 0) {
      await saveState("Firebase 연결됨 · 저장 완료");
    }
    render();
    unsubscribe = onSnapshot(ref, (snapshot) => {
      if (!snapshot.exists() || saving) return;
      state = normalizeState(snapshot.data());
      reconcileProductStocks();
      if (hydrated) renderOrDeferForUseEntry("Firebase 데이터가 갱신됐습니다. 입력 중인 사용입력을 보호하고 있습니다.");
    }, (error) => {
      console.error(error);
      setStatus(`Firebase 연결 오류: ${error.message}`, "error");
    });
  } catch (error) {
    console.error(error);
    setStatus(`Firebase 연결 실패: ${error.message}`, "error");
  }
};

window.addEventListener("beforeunload", () => {
  if (unsubscribe) unsubscribe();
  if (implantRecordsUnsubscribe) implantRecordsUnsubscribe();
  if (implantVendorsUnsubscribe) implantVendorsUnsubscribe();
  if (pendingUsagesUnsubscribe) pendingUsagesUnsubscribe();
});

const loadFirebaseAndBoot = async () => {
  if (!ensureLocalSession()) return;
  render();
  try {
    setStatus("Firebase 모듈 불러오는 중", "ok");
    const appModule = await import("https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js");
    const firestoreModule = await import("https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js");
    const storageModule = await import("https://www.gstatic.com/firebasejs/10.12.5/firebase-storage.js");
    initializeApp = appModule.initializeApp;
    getFirestore = firestoreModule.getFirestore;
    doc = firestoreModule.doc;
    getDoc = firestoreModule.getDoc;
    getDocs = firestoreModule.getDocs;
    setDoc = firestoreModule.setDoc;
    deleteDoc = firestoreModule.deleteDoc;
    runTransaction = firestoreModule.runTransaction;
    onSnapshot = firestoreModule.onSnapshot;
    enableIndexedDbPersistence = firestoreModule.enableIndexedDbPersistence;
    collection = firestoreModule.collection;
    getStorage = storageModule.getStorage;
    storageRef = storageModule.ref;
    uploadBytes = storageModule.uploadBytes;
    getDownloadURL = storageModule.getDownloadURL;
    await boot();
  } catch (error) {
    console.error(error);
    setStatus(`Firebase 모듈 로딩 실패: ${error.message}`, "error");
  }
};

setInterval(() => {
  const nextDate = today();
  if (nextDate !== renderedDate) {
    renderOrDeferForUseEntry("날짜가 바뀌었지만 입력 중인 사용입력을 보호하고 있습니다.");
  } else {
    const pageDate = document.querySelector(".page-user span");
    if (pageDate) pageDate.textContent = nextDate;
  }
}, 30000);

loadFirebaseAndBoot();
