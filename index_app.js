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
const canAssignImplantPatientNo = () => ["admin", "manager"].includes(currentUserRole());
const canEditImplantPatientNo = () => currentUserRole() === "admin";
const implantRecordsForUsage = (usageId) => sortImplantRecords(implantRecords.filter((record) => sameId(record.usageId, usageId)));
const pendingUsagesOpen = () => pendingUsages
  .filter((item) => (item.status || "pending") === "pending")
  .sort((a, b) => String(b.updatedAt || b.createdAt || "").localeCompare(String(a.updatedAt || a.createdAt || "")));
const pendingUsageById = (id) => pendingUsages.find((item) => sameId(item.id, id));
const isImplantEditUnlocked = (record) => record?.editUnlocked === true;
const isImplantLedgerClosed = (record) => !isImplantEditUnlocked(record) && Boolean(implantPatientNoText(record) || record?.closedAt || record?.patientNoAssignedAt);
const implantLockLabel = (record) => isImplantLedgerClosed(record)
  ? "마감 잠금"
  : (implantPatientNoText(record) ? "관리자 해제" : "작성 가능");
const implantEditLockMessage = (record) => {
  if (!record) return "";
  if (isImplantLedgerClosed(record)) return "임플란트 장부가 마감되어 관리자만 임플란트 기록을 수정할 수 있습니다.";
  if (implantRecordDate(record) !== today()) return "당일이 아닌 임플란트 기록은 관리자만 수정할 수 있습니다.";
  return "";
};
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
const productNeedsImplantLedger = (product) => {
  const category = productCategory(product?.category);
  return ["인체조직", "ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(category);
};
const implantVendorKey = (value) => normalizedName(value);
const implantVendorSelectionForProduct = (product = {}) => {
  const byId = product.companyVendorId ? implantVendorById(product.companyVendorId) : null;
  const name = String(byId?.name || product.company || "").trim();
  if (!name || name === "업체 없음") return { key: "", vendorId: "", customVendor: "", vendor: "" };
  const matched = byId || findImplantVendorByName(name);
  if (matched) return { key: `id:${matched.id}`, vendorId: matched.id, customVendor: "", vendor: matched.name || name };
  return { key: implantVendorKey(name), vendorId: "__custom__", customVendor: name, vendor: name };
};
const implantVendorSelectionForCompany = (company = "") => implantVendorSelectionForProduct({ company });
const implantDraftVendorName = (draft = {}) => draft.vendorId === "__custom__"
  ? (draft.customVendor || draft.vendor || "")
  : (implantVendorById(draft.vendorId)?.name || draft.vendor || draft.customVendor || "");
const mergeImplantDescriptionLines = (left = "", right = "") => {
  const lines = [];
  String(left || "").split(/\r?\n/).forEach((line) => {
    const text = line.trim();
    if (text && !lines.includes(text)) lines.push(text);
  });
  String(right || "").split(/\r?\n/).forEach((line) => {
    const text = line.trim();
    if (text && !lines.includes(text)) lines.push(text);
  });
  return lines.join("\n");
};
const implantVendorMatchKeys = (entry = {}) => {
  const keys = new Set();
  const addKey = (value = "") => {
    const key = String(value || "").trim();
    if (!key) return;
    keys.add(key);
    if (key.startsWith("id:")) {
      const vendor = implantVendorById(key.slice(3));
      if (vendor?.name) addName(vendor.name);
    }
  };
  const addName = (value = "") => {
    const key = implantVendorKey(value);
    if (!key) return;
    keys.add(key);
    const matched = findImplantVendorByName(value);
    if (matched?.id) keys.add(`id:${matched.id}`);
  };
  addKey(entry.key);
  addKey(entry.autoCompanyKey);
  const vendorId = String(entry.vendorId || "").trim();
  if (vendorId && vendorId !== "__custom__") {
    addKey(`id:${vendorId}`);
    const vendor = implantVendorById(vendorId);
    if (vendor?.name) addName(vendor.name);
  }
  addName(entry.vendor);
  addName(entry.customVendor);
  addName(implantDraftVendorName(entry));
  return keys;
};
const implantVendorEntriesMatch = (left = {}, right = {}) => {
  const leftKeys = implantVendorMatchKeys(left);
  const rightKeys = implantVendorMatchKeys(right);
  if (!leftKeys.size || !rightKeys.size) return false;
  return [...leftKeys].some((key) => rightKeys.has(key));
};
const findImplantEntryByVendorTarget = (entries = [], target = {}) =>
  entries.find((entry) => implantVendorEntriesMatch(entry, target));
const implantRowHasContent = (row = {}) => Boolean(String(row.description || "").trim() || (row.photos || []).length);
const implantDraftHasManualContent = (draft = {}) => {
  const description = String(draft.description || "").trim();
  const autoDescription = String(draft.autoDescription || "").trim();
  return Boolean((draft.photos || []).length || (description && description !== autoDescription));
};
const implantDraftCanAutoUpdateDescription = (draft = {}) => {
  const description = String(draft.description || "").trim();
  const autoDescription = String(draft.autoDescription || "").trim();
  return !description || description === autoDescription;
};
const implantDraftAutoDescription = (items = []) => items
  .map(({ product, qty }) => `${product?.name || "제품명 없음"} ${Math.max(1, num(qty))}ea`)
  .join("\n");
const implantVendorTargetsFromUseItems = (items = []) => {
  const targets = new Map();
  items.forEach((item) => {
    const product = productById(item.productId);
    if (!productNeedsImplantLedger(product)) return;
    const target = implantVendorSelectionForProduct(product);
    if (!target.key) return;
    const current = targets.get(target.key) || { ...target, items: [] };
    current.items.push({ product, qty: item.qty });
    current.description = implantDraftAutoDescription(current.items);
    targets.set(target.key, current);
  });
  return [...targets.values()];
};
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

const renderProducts = () => `
  ${canManageSettings() ? "" : `<div class="empty">관리자와 책임사용자만 제품관리를 사용할 수 있습니다.</div>`}
  ${canManageSettings() ? `
  <section class="grid two">
    <form class="card" id="productForm">
      <h2 id="productFormTitle">제품 추가</h2>
      <input type="hidden" id="productId">
      <label for="productCategory">분류</label>
      <select id="productCategory" required>
        <option>비급여</option>
        <option>인체조직</option>
        <option value="ANCHOR">ANCHOR&etc</option>
        <option value="URO_LANDING">URO 랜딩</option>
        <option value="GS_LANDING">GS 랜딩</option>
        <option value="IMPLANT">IMPLANT</option>
      </select>
      <label for="productName">제품명</label>
      <input id="productName" required autocomplete="off">
      <div id="productCompanyWrap">
        <label for="productCompany">업체명</label>
        <select id="productCompany">
          ${productCompanyOptions()}
        </select>
        <div class="helper" id="productCompanyHelp">비급여 외 제품은 설정의 임플란트 업체를 먼저 등록한 뒤 선택합니다.</div>
      </div>
      <div id="productSubcategoryWrap">
        <label for="productSubcategory">세부 분류</label>
        <select id="productSubcategory">
          <option value="">선택</option>
          <option>ANCHOR</option>
          <option>Cannula</option>
          <option>etc</option>
          <option>small joint</option>
        </select>
      </div>
      <div class="row two">
        <div>
          <label for="productStock">현재고</label>
          <input id="productStock" type="number" min="0" value="0" required>
        </div>
        <div>
          <label for="productWarning">경고수량</label>
          <input id="productWarning" type="number" min="0" value="1" required>
        </div>
      </div>
      <div id="productLandingWrap">
        <label for="productLanding">랜딩수량</label>
        <input id="productLanding" type="number" min="0" value="0">
      </div>
      <div class="actions">
        <button type="submit">제품 저장</button>
        <button class="secondary" type="button" id="productReset">새로 입력</button>
      </div>
    </form>
    <div class="card">
      <h2>제품 목록</h2>
      ${renderGroupedProducts(true)}
    </div>
  </section>
` : ""}
`;

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

const bindProducts = () => {
  const form = document.getElementById("productForm");
  syncProductFields = () => {
    const category = document.getElementById("productCategory").value;
    const companySelect = document.getElementById("productCompany");
    const companyHelp = document.getElementById("productCompanyHelp");
    document.getElementById("productCompanyWrap").style.display = category === "비급여" ? "none" : "block";
    document.getElementById("productSubcategoryWrap").style.display = category === "ANCHOR" ? "block" : "none";
    document.getElementById("productLandingWrap").style.display = category === "비급여" ? "none" : "block";
    if (category === "비급여") {
      companySelect.value = "";
      document.getElementById("productSubcategory").value = "";
      document.getElementById("productLanding").value = "0";
    }
    companySelect.required = category !== "비급여";
    companySelect.disabled = category !== "비급여" && !implantVendors.length;
    if (companyHelp) companyHelp.textContent = implantVendors.length
      ? "비급여 외 제품은 등록된 임플란트 업체 중에서 선택합니다."
      : "비급여 외 제품을 등록하려면 먼저 설정 > 임플란트 업체에서 업체를 등록해 주세요.";
  };
  document.getElementById("productCategory").addEventListener("change", syncProductFields);
  document.getElementById("productReset").addEventListener("click", () => {
    form.reset();
    document.getElementById("productId").value = "";
    document.getElementById("productFormTitle").textContent = "제품 추가";
    document.getElementById("productCompany").innerHTML = productCompanyOptions();
    syncProductFields();
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = document.getElementById("productId").value || uid();
    const category = document.getElementById("productCategory").value;
    if (category !== "비급여" && !implantVendors.length) {
      alert("비급여 외 제품은 임플란트 업체를 먼저 등록해야 제품등록 할 수 있습니다.");
      return;
    }
    if (category !== "비급여" && !document.getElementById("productCompany").value.trim()) {
      alert("비급여 외 제품은 임플란트 업체를 선택해 주세요.");
      return;
    }
    const selectedCompanyValue = document.getElementById("productCompany").value.trim();
    const selectedCompanyVendor = category === "비급여" ? null : implantVendorById(selectedCompanyValue);
    const existingProduct = productById(id);
    const next = {
      id,
      category,
      name: document.getElementById("productName").value.trim(),
      company: category === "비급여" ? "" : (selectedCompanyVendor?.name || selectedCompanyValue),
      companyVendorId: category === "비급여" ? "" : (selectedCompanyVendor?.id || ""),
      subcategory: category === "ANCHOR" ? document.getElementById("productSubcategory").value : "",
      stock: num(document.getElementById("productStock").value),
      warningStock: num(document.getElementById("productWarning").value),
      landingQty: category === "비급여" ? 0 : num(document.getElementById("productLanding").value),
      sortOrder: category === "비급여" ? (productSortOrderValue(existingProduct) || nextNonpaySortOrder(id)) : 0
    };
    if (!next.name) return;
    const { used, received } = productMovementCounts();
    next.baseStock = num(next.stock) - (received.get(id) || 0) + (used.get(id) || 0);
    state.products = [...state.products.filter((item) => item.id !== id), next];
    reconcileProductStocks();
    render();
    await saveState("제품 저장 완료", {
      savingMessage: "제품 저장 중입니다...",
      doneMessage: "제품 저장 완료"
    });
  });
  syncProductFields();
};

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
  syncSurgeryDoctorScope = () => {
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

const ruleProductItem = (item) => `
  <label class="check-card rule-card">
    <input type="checkbox" value="${item.id}" data-rule-product>
    <span>${escapeHtml(item.name)}<br><span class="muted">${escapeHtml(productCategoryLabel(item.category))}${item.company ? ` · ${escapeHtml(item.company)}` : ""}${item.subcategory ? ` · ${escapeHtml(item.subcategory)}` : ""} · 현재고 ${num(item.stock)}</span></span>
    ${qtyStepper(`data-rule-product-qty="${item.id}" aria-label="${escapeHtml(item.name)} 추천 수량"`, 1, Math.max(1, num(item.stock)))}
  </label>
`;

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

const filteredImplantRecords = (date, patientName, patientId, patientNo) => {
  const nameQuery = normalizedName(patientName || "");
  const idQuery = normalizedName(patientId || "");
  const noQuery = normalizedName(patientNo || "");
  return sortImplantRecords(implantRecords).filter((record) => {
    if (date && implantRecordDate(record) !== date) return false;
    if (nameQuery && !normalizedName(record.patientName || "").includes(nameQuery)) return false;
    if (idQuery && !normalizedName(record.patientId || "").includes(idQuery)) return false;
    if (noQuery && !normalizedName(implantPatientNoText(record)).includes(noQuery)) return false;
    return true;
  });
};

const implantRecordsForDate = (date) => sortImplantRecords(implantRecords.filter((record) => implantRecordDate(record) === date));
const implantPhotoViewSrc = (photo) => {
  if (!photo) return "";
  if (photo.editedPreview) return photo.editedPreview;
  if (photo.preview) return photo.preview;
  if ((photo.needsReupload || photo.storageUploadFailed) && photo.dataUrl) return photo.dataUrl;
  return photo.url || photo.dataUrl || "";
};
const implantPhotoRotationStyle = (photo) => {
  const rotation = photo?.editedPreview ? 0 : num(photo?.rotation);
  return rotation ? `transform:rotate(${rotation}deg);` : "";
};
const implantPhotoStoredInStorage = (photo) => Boolean(photo?.url && photo?.path && photo?.storageUploadFailed !== true);
const implantPhotoNeedsStorageRetry = (photo) => Boolean(photo?.dataUrl && (!photo?.url || photo?.storageUploadFailed || !photo?.path));
const implantPhotoStatusStats = (records) => records.reduce((stats, record) => {
  (record.implants || []).forEach((implant) => {
    const photos = implant.photos || [];
    stats.implants += 1;
    stats.pending += num(implant.pendingPhotoCount);
    stats.errors += Array.isArray(implant.photoUploadErrors) ? implant.photoUploadErrors.length : 0;
    photos.forEach((photo) => {
      stats.photos += 1;
      if (implantPhotoStoredInStorage(photo)) stats.storage += 1;
      if (implantPhotoNeedsStorageRetry(photo)) stats.retry += 1;
      if (photo?.storageUploadFailed) stats.failed += 1;
      if (!implantPhotoViewSrc(photo)) stats.missing += 1;
    });
  });
  return stats;
}, { implants: 0, photos: 0, storage: 0, pending: 0, failed: 0, retry: 0, missing: 0, errors: 0 });
const implantPhotoProblemRows = (records) => records.flatMap((record) => (record.implants || []).map((implant) => {
  const photos = implant.photos || [];
  const pending = num(implant.pendingPhotoCount);
  const failed = photos.filter((photo) => photo?.storageUploadFailed).length;
  const retry = photos.filter(implantPhotoNeedsStorageRetry).length;
  const missing = photos.filter((photo) => !implantPhotoViewSrc(photo)).length;
  const errors = Array.isArray(implant.photoUploadErrors) ? implant.photoUploadErrors.length : 0;
  if (!pending && !failed && !retry && !missing && !errors) return null;
  return { record, implant, pending, failed, retry, missing, errors };
}).filter(Boolean));
const implantSendStatusLabels = {
  pending: "미발송",
  sent: "발송완료",
  excluded: "발송제외",
  resend: "재발송 필요"
};
const implantSendStatusLabel = (status = "pending") => implantSendStatusLabels[status] || implantSendStatusLabels.pending;
const implantSendStatusClass = (status = "pending") => ({
  sent: "ok",
  excluded: "low",
  resend: "low"
}[status] || "");

const assignImplantPatientNosForDate = async (date) => {
  if (!canAssignImplantPatientNo()) return 0;
  if (!date) throw new Error("날짜를 선택해 주세요.");
  const recordsForDate = implantRecordsForDate(date);
  const used = new Set(recordsForDate.map(implantPatientNoText).filter(Boolean));
  const duplicate = Array.from(used).find((value) => recordsForDate.filter((record) => implantPatientNoText(record) === value).length > 1);
  if (duplicate) throw new Error(`같은 날짜에 ${duplicate}번 환자번호가 중복되어 있습니다. 관리자 수동 수정이 필요합니다.`);
  const targets = sortImplantRecords(recordsForDate.filter((record) => !implantPatientNoText(record)));
  let nextNo = 1;
  const updates = [];
  targets.forEach((record) => {
    while (used.has(String(nextNo))) nextNo += 1;
    const patientNo = String(nextNo);
    used.add(patientNo);
    record.patientNo = patientNo;
    record.patientNoAssignedAt = new Date().toISOString();
    record.closedAt = record.patientNoAssignedAt;
    record.editUnlocked = false;
    updates.push(setDoc(doc(db, "implantRecords", record.id), {
      patientNo,
      patientNoAssignedAt: record.patientNoAssignedAt,
      closedAt: record.closedAt,
      editUnlocked: false,
      updatedAt: new Date().toISOString(),
      ...auditUpdateFields()
    }, { merge: true }));
  });
  await Promise.all(updates);
  return updates.length;
};

const implantDescriptionText = (record) => (Array.isArray(record.implants) ? record.implants : [])
  .map((implant) => `[${implant.vendor || "업체 없음"}]\n${implant.description || `사진 ${(implant.photos || []).length}장 기록`}`)
  .join("\n\n");

const implantLedgerRows = (records) => records.flatMap((record) => {
  const implants = Array.isArray(record.implants) && record.implants.length ? record.implants : [{ vendor: "", description: "", photos: [] }];
  return implants.map((implant) => [
    implantRecordDate(record),
    implantPatientNoText(record) ? `#${implantPatientNoText(record)}` : "",
    record.patientName || "",
    record.patientId || "",
    record.surgeryName || surgeryById(record.surgeryId)?.name || "",
    record.surgeonCode || departmentById(record.doctorId)?.name || "",
    auditUserText(record) || "",
    auditTimeText(record) || "",
    implant.vendor || "",
    implant.description || "",
    (implant.photos || []).length
  ]);
});

const implantLedgerTableHtml = (records) => {
  if (!records.length) return `<div class="empty">선택한 날짜의 임플란트 마감 자료가 없습니다.</div>`;
  return `
    <div class="implant-ledger-list">
      ${records.map((record) => `
        <div class="item implant-record-card">
          <div class="item-title">
            <span>${escapeHtml(implantPatientNoText(record) ? `#${implantPatientNoText(record)} ` : "미마감 ")}${escapeHtml(record.patientName || "이름 없음")}${record.patientId ? ` (${escapeHtml(record.patientId)})` : ""}</span>
            <span class="pill">${escapeHtml(implantRecordDate(record))}</span>
          </div>
          <div class="meta">
            <span>수술명: ${escapeHtml(record.surgeryName || surgeryById(record.surgeryId)?.name || "-")}</span>
            <span>원장코드: ${escapeHtml(record.surgeonCode || departmentById(record.doctorId)?.name || "-")}</span>
            <span>저장자: ${escapeHtml(auditUserText(record) || "-")}</span>
          </div>
          ${(record.implants || []).length ? (record.implants || []).map((implant) => `
            <div class="implant-vendor-block">
              <div class="item-title">
                <span>${escapeHtml(implant.vendor || "업체 없음")}</span>
                <span class="pill">${(implant.photos || []).length}장</span>
              </div>
              ${implant.description ? `<div class="implant-description">${escapeHtml(implant.description)}</div>` : `<div class="muted">사용내용 없음 · 사진 기록</div>`}
              ${implantPhotoStatusHtml(implant)}
              <div class="implant-photo-strip">
                ${(implant.photos || []).map(implantPhotoHtml).join("")}
              </div>
            </div>
          `).join("") : `<div class="empty">업체별 기록이 없습니다.</div>`}
        </div>
      `).join("")}
    </div>
  `;
};

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

const safeBackupFileName = (value) => String(value || "implant")
  .replace(/[\\/:*?"<>|]+/g, "_")
  .replace(/\s+/g, "_")
  .slice(0, 80);
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
const implantRecordsForMonth = (month) => sortImplantRecords(implantRecords.filter((record) => implantRecordDate(record).startsWith(month)));
const exportImplantMonthlyBackup = async (month, onProgress) => {
  if (!month) throw new Error("백업할 월을 선택해 주세요.");
  const records = implantRecordsForMonth(month);
  if (!records.length) throw new Error("선택한 월의 임플란트 기록이 없습니다.");
  const headers = ["날짜", "번호", "환자명", "ID", "수술명", "원장코드", "저장자", "저장시간", "업체", "사용분", "사진수"];
  const photoRefs = [];
  records.forEach((record) => {
    (record.implants || []).forEach((implant) => {
      (implant.photos || []).forEach((photo, index) => {
        const src = photo.url || photo.dataUrl || "";
        if (!src) return;
        photoRefs.push({ record, implant, photo, index, src });
      });
    });
  });
  const files = [
    { name: "implant-ledger.xlsx", content: xlsxWorkbook(headers, implantLedgerRows(records)) },
    { name: "implant-records.json", content: JSON.stringify(records, null, 2) },
    { name: "photo-urls.txt", content: photoRefs.map(({ record, implant, src, index }) => [
      implantRecordDate(record),
      implantPatientNoText(record) ? `#${implantPatientNoText(record)}` : "미마감",
      record.patientName || "",
      record.patientId || "",
      implant.vendor || "업체 없음",
      `photo ${index + 1}`,
      src
    ].join("\t")).join("\n") }
  ];
  const errors = [];
  let done = 0;
  onProgress?.({ done, total: photoRefs.length, failed: 0 });
  for (const item of photoRefs) {
    try {
      const response = await fetch(item.src);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const bytes = new Uint8Array(await response.arrayBuffer());
      const ext = (item.photo.contentType || "image/jpeg").includes("png") ? "png" : "jpg";
      const photoName = [
        item.record.surgeryDate || implantRecordDate(item.record),
        implantPatientNoText(item.record) ? `no-${implantPatientNoText(item.record)}` : "no-pending",
        item.record.patientName || "patient",
        item.implant.vendor || "vendor",
        `photo-${item.index + 1}.${ext}`
      ].map(safeBackupFileName).join("_");
      files.push({ name: `photos/${photoName}`, content: bytes });
    } catch (error) {
      errors.push(`${implantRecordDate(item.record)} ${item.record.patientName || ""} ${item.implant.vendor || ""} photo ${item.index + 1}: ${error.message}`);
    } finally {
      done += 1;
      onProgress?.({ done, total: photoRefs.length, failed: errors.length });
    }
  }
  if (errors.length) files.push({ name: "photo-download-errors.txt", content: errors.join("\n") });
  downloadBytes(`임플란트장부_백업_${month}.zip`, zipFiles(files), "application/zip");
  return { records: records.length, photos: photoRefs.length, failed: errors.length };
};

const implantVendorContact = (vendorName = "", vendorId = "") => {
  const byId = vendorId ? implantVendorById(vendorId) : null;
  if (byId) return byId;
  return findImplantVendorByName(vendorName) || {};
};
const isImplantVendorSendPaused = (vendorName = "", vendorId = "") => implantVendorContact(vendorName, vendorId)?.active === false;

const implantSendMessage = (date, vendorName, lines) => [
  `${date} 임플란트 사용분`,
  "",
  ...lines.map(({ record, implant }) => [
    `${implantPatientNoText(record) ? `#${implantPatientNoText(record)} ` : ""}${record.surgeonCode || departmentById(record.doctorId)?.name || ""}`,
    record.surgeryName || surgeryById(record.surgeryId)?.name || "",
    implant.description || `사진 ${(implant.photos || []).length}장 기록`
  ].filter(Boolean).join("\n"))
].join("\n\n");

const implantSendGroups = (date) => {
  const groups = new Map();
  implantRecordsForDate(date).forEach((record) => {
    (record.implants || []).forEach((implant) => {
      const key = implant.vendor || "업체 없음";
      if (isImplantVendorSendPaused(key, implant.vendorId)) return;
      const current = groups.get(key) || { vendor: key, contact: implantVendorContact(key, implant.vendorId), lines: [], statuses: [] };
      current.lines.push({ record, implant });
      current.statuses.push(implant.sendStatus || "pending");
      groups.set(key, current);
    });
  });
  return Array.from(groups.values()).map((group) => {
    const uniqueStatuses = Array.from(new Set(group.statuses));
    const status = uniqueStatuses.length === 1 ? uniqueStatuses[0] : "resend";
    return { ...group, status };
  }).sort((a, b) => alphaFirstCompare(a.vendor, b.vendor));
};

const implantSendGroupStats = (group) => {
  const patientNos = new Set();
  let photoCount = 0;
  let unnumbered = 0;
  group.lines.forEach(({ record, implant }) => {
    const patientNo = implantPatientNoText(record);
    if (patientNo) patientNos.add(patientNo);
    else unnumbered += 1;
    photoCount += (implant.photos || []).length;
  });
  return {
    patients: patientNos.size + unnumbered,
    photos: photoCount,
    unnumbered
  };
};

const implantSendPatientGroups = (group) => {
  const patients = new Map();
  group.lines.forEach(({ record, implant }) => {
    const key = record.id || `${implantRecordDate(record)}-${implantPatientNoText(record)}-${record.surgeryId}`;
    const current = patients.get(key) || { record, implants: [], photos: [], descriptions: [] };
    current.implants.push(implant);
    current.photos.push(...(implant.photos || []));
    if (String(implant.description || "").trim()) current.descriptions.push(String(implant.description || "").trim());
    patients.set(key, current);
  });
  return Array.from(patients.values()).sort((a, b) => {
    const noA = num(implantPatientNoText(a.record));
    const noB = num(implantPatientNoText(b.record));
    if (noA || noB) return noA - noB;
    return String(a.record.createdAt || "").localeCompare(String(b.record.createdAt || ""));
  });
};

const implantSendPhotoLedgerHtml = (group) => `
  <div class="implant-send-photo-ledger">
    ${group.lines.map(({ record, implant }) => {
      const photos = implant.photos || [];
      const patientNo = implantPatientNoText(record) || "미마감";
      const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
      const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
      return `
        <div class="implant-send-patient">
          <div class="item-title">
            <span>#${escapeHtml(patientNo)} · ${escapeHtml(doctorText)} · ${escapeHtml(surgeryText)}</span>
            <span class="pill">${escapeHtml(implantRecordDate(record) || "-")}</span>
          </div>
          <div class="implant-description">${escapeHtml(implant.description || `사진 ${photos.length}장 기록`)}</div>
          ${photos.length ? `
            <div class="implant-send-photo-grid">
              ${photos.map((photo) => {
                const src = implantPhotoViewSrc(photo);
                return src ? `<img src="${escapeHtml(src)}" alt="임플란트 발송 사진" data-implant-photo-view="${escapeHtml(src)}">` : "";
              }).join("")}
            </div>
          ` : `<div class="muted">첨부사진 없음</div>`}
        </div>
      `;
    }).join("")}
  </div>
`;

const implantSendPrintHtml = (date, group) => `<!doctype html>
  <html lang="ko">
  <head>
    <meta charset="utf-8">
    <title>${escapeHtml(date)} ${escapeHtml(group.vendor)} 임플란트 장부</title>
    <style>
      body { margin: 24px; font-family: Arial, sans-serif; color: #111827; }
      h1 { font-size: 20px; margin: 0 0 6px; }
      .note { margin: 0 0 18px; color: #64748b; font-size: 12px; }
      .patient { page-break-inside: avoid; border: 1px solid #dbeafe; border-left: 5px solid #2563eb; border-radius: 8px; padding: 12px; margin: 0 0 12px; }
      .head { display: flex; justify-content: space-between; gap: 12px; font-weight: 800; margin-bottom: 8px; }
      .desc { white-space: pre-wrap; font-family: Consolas, monospace; font-size: 13px; line-height: 1.45; margin-bottom: 10px; }
      .photos { display: flex; flex-wrap: wrap; gap: 8px; }
      .photos img { max-width: 260px; max-height: 190px; width: auto; height: auto; object-fit: contain; border: 1px solid #d1d5db; border-radius: 6px; background: #fff; }
      @media print { body { margin: 14mm; } .patient { break-inside: avoid; } }
    </style>
  </head>
  <body>
    <h1>${escapeHtml(date)} ${escapeHtml(group.vendor)} 임플란트 장부</h1>
    <p class="note">환자명/환자ID 제외 · 환자번호, 원장코드, 수술명, 사용내용, 사진 포함</p>
    ${group.lines.map(({ record, implant }) => {
      const photos = implant.photos || [];
      const patientNo = implantPatientNoText(record) || "미마감";
      const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
      const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
      return `
        <section class="patient">
          <div class="head"><span>#${escapeHtml(patientNo)} · ${escapeHtml(doctorText)} · ${escapeHtml(surgeryText)}</span><span>${escapeHtml(implantRecordDate(record) || "-")}</span></div>
          <div class="desc">${escapeHtml(implant.description || `사진 ${photos.length}장 기록`)}</div>
          <div class="photos">
            ${photos.map((photo) => {
              const src = implantPhotoViewSrc(photo);
              return src ? `<img src="${escapeHtml(src)}" alt="임플란트 사진">` : "";
            }).join("")}
          </div>
        </section>
      `;
    }).join("")}
  </body>
  </html>`;

const implantSendLedgerTableRowsHtml = (group, options = {}) => group.lines.map(({ record, implant }) => {
  const photos = implant.photos || [];
  const patientNo = implantPatientNoText(record) || "미마감";
  const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
  const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
  const opText = [doctorText, surgeryText].filter(Boolean).join(" / ");
  const imageClass = options.print ? "ledger-photo-print" : "ledger-photo";
  return `
    <tr>
      <td class="date">${escapeHtml(implantRecordDate(record) || "-")}</td>
      <td class="no">#${escapeHtml(patientNo)}</td>
      <td class="op">${escapeHtml(opText)}</td>
      <td class="vendor">${escapeHtml(group.vendor)}</td>
      <td class="implant">
        <div class="implant-ledger-desc">${escapeHtml(implant.description || `사진 ${photos.length}장 기록`)}</div>
        ${photos.length ? `
          <div class="implant-send-photo-grid">
            ${photos.map((photo) => {
              const src = implantPhotoViewSrc(photo);
              return src ? `<img class="${imageClass}" src="${escapeHtml(src)}" alt="임플란트 사진" data-implant-photo-view="${escapeHtml(src)}">` : "";
            }).join("")}
          </div>
        ` : `<div class="muted">첨부사진 없음</div>`}
      </td>
    </tr>
  `;
}).join("");

const implantSendPhotoLedgerTableHtml = (group) => `
  <div class="implant-send-photo-ledger paper-ledger">
    <table class="implant-send-ledger-table">
      <thead>
        <tr>
          <th>DATE</th>
          <th>No.</th>
          <th>OP</th>
          <th>업체명</th>
          <th>IMPLANT / 사진</th>
        </tr>
      </thead>
      <tbody>${implantSendLedgerTableRowsHtml(group)}</tbody>
    </table>
  </div>
`;

const implantSendPrintTableHtml = (date, group) => `<!doctype html>
  <html lang="ko">
  <head>
    <meta charset="utf-8">
    <title>${escapeHtml(date)} ${escapeHtml(group.vendor)} 임플란트 장부</title>
    <style>
      @page { size: A4 landscape; margin: 10mm; }
      body { margin: 0; font-family: Arial, sans-serif; color: #111827; }
      h1 { font-size: 28px; margin: 0 0 8px; }
      .note { margin: 0 0 12px; color: #374151; font-size: 16px; font-weight: 700; }
      table { width: 100%; border-collapse: collapse; table-layout: fixed; }
      th, td { border: 2px solid #111827; padding: 8px; vertical-align: top; }
      th { background: #e5e7eb; font-size: 18px; font-weight: 900; text-align: center; }
      td { font-size: 18px; font-weight: 800; }
      td.date { width: 9%; text-align: center; }
      td.no { width: 8%; text-align: center; font-size: 24px; }
      td.op { width: 20%; }
      td.vendor { width: 12%; text-align: center; }
      td.implant { width: 51%; }
      .implant-ledger-desc { white-space: pre-wrap; font-family: Consolas, monospace; font-size: 21px; line-height: 1.35; margin-bottom: 8px; }
      .implant-send-photo-grid { display: flex; flex-wrap: wrap; gap: 8px; }
      .implant-send-photo-grid img { max-width: 310px; max-height: 220px; width: auto; height: auto; object-fit: contain; border: 2px solid #111827; background: #fff; }
      tr { break-inside: avoid; page-break-inside: avoid; }
    </style>
  </head>
  <body>
    <h1>${escapeHtml(date)} ${escapeHtml(group.vendor)} 임플란트 장부</h1>
    <p class="note">환자명/환자ID 제외 · 환자번호, 원장코드, 수술명, 사용내용, 사진 포함</p>
    <table>
      <thead>
        <tr>
          <th>DATE</th>
          <th>No.</th>
          <th>OP</th>
          <th>업체명</th>
          <th>IMPLANT / 사진</th>
        </tr>
      </thead>
      <tbody>${implantSendLedgerTableRowsHtml(group, { print: true })}</tbody>
    </table>
  </body>
  </html>`;

const implantStatementPhotoChunks = (photos = [], size = 4) => {
  if (!photos.length) return [[]];
  const chunks = [];
  for (let index = 0; index < photos.length; index += size) {
    chunks.push(photos.slice(index, index + size));
  }
  return chunks;
};

const implantStatementFooterHtml = (record = {}) => {
  const user = auditUserText(record) || currentAuditUser()?.name || currentAuditUser()?.loginId || "-";
  return `
    <div class="implant-statement-footer">
      <div><span>발송일</span><strong>${escapeHtml(today())}</strong></div>
      <div><span>발송자</span><strong>${escapeHtml(user)}</strong></div>
      <div><span>확인처</span><strong>윌스기념병원 수술실</strong></div>
    </div>
  `;
};

const implantSendStatementCardsHtml = (group) => `
  <div class="implant-send-statement-list">
    ${group.lines.map(({ record, implant }) => {
      const photos = implant.photos || [];
      const patientNo = implantPatientNoText(record) || "미마감";
      const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
      const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
      return `
        <section class="implant-send-statement">
          <div class="implant-statement-head">
            <div>
              <div class="implant-statement-title">임플란트 사용 명세서</div>
              <div class="muted">환자명/환자ID 제외</div>
            </div>
          </div>
          <div class="implant-statement-meta">
            <div><span>DATE / 환자번호</span><strong>${escapeHtml(implantRecordDate(record) || "-")} · 환자번호 #${escapeHtml(patientNo)}</strong></div>
            <div><span>업체명</span><strong>${escapeHtml(group.vendor)}</strong></div>
            <div><span>원장코드</span><strong>${escapeHtml(doctorText)}</strong></div>
            <div><span>OP</span><strong>${escapeHtml(surgeryText)}</strong></div>
          </div>
          <div>
            <div class="implant-send-section-title">IMPLANT</div>
            <div class="implant-statement-desc">${escapeHtml(implant.description || `사진 ${photos.length}장 기록`)}</div>
          </div>
          <div>
            <div class="implant-send-section-title">사진</div>
            ${photos.length ? `
              <div class="implant-statement-photos">
                ${photos.map((photo) => {
                  const src = implantPhotoViewSrc(photo);
                  return src ? `<img src="${escapeHtml(src)}" alt="임플란트 사진" data-implant-photo-view="${escapeHtml(src)}">` : "";
                }).join("")}
              </div>
            ` : `<div class="empty">첨부사진 없음</div>`}
          </div>
          ${implantStatementFooterHtml(record)}
        </section>
      `;
    }).join("")}
  </div>
`;

const implantSendStatementPrintHtml = (date, group) => `<!doctype html>
  <html lang="ko">
  <head>
    <meta charset="utf-8">
    <title>${escapeHtml(date)} ${escapeHtml(group.vendor)} 임플란트 명세서</title>
    <style>
      @page { size: A4 portrait; margin: 10mm; }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: Arial, sans-serif; color: #111827; }
      .statement { width: 190mm; min-height: auto; page-break-after: always; display: grid; gap: 8px; align-content: start; overflow: hidden; }
      .statement:last-child { page-break-after: auto; }
      .head { display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: start; padding-bottom: 8px; border-bottom: 3px solid #111827; }
      .title { font-size: 28px; font-weight: 900; }
      .note { margin-top: 4px; font-size: 13px; font-weight: 700; color: #374151; }
      .no { min-width: 105px; padding: 8px 12px; border: 3px solid #111827; border-radius: 6px; text-align: center; font-size: 34px; font-weight: 900; }
      .meta { display: grid; grid-template-columns: repeat(4, 1fr); border: 2px solid #111827; border-bottom: 0; }
      .meta div { min-height: 58px; padding: 7px 9px; border-right: 2px solid #111827; border-bottom: 2px solid #111827; }
      .meta div:nth-child(4n) { border-right: 0; }
      .meta span { display: block; margin-bottom: 4px; color: #475569; font-size: 12px; font-weight: 900; }
      .meta strong { font-size: 18px; font-weight: 900; }
      .section-title { margin: 4px 0 5px; font-size: 15px; font-weight: 900; }
      .desc { min-height: 92px; padding: 10px; border: 2px solid #111827; white-space: pre-wrap; font-family: Consolas, monospace; font-size: 22px; line-height: 1.35; font-weight: 800; }
      .photos { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
      .photos img { width: 100%; height: 86mm; object-fit: contain; border: 2px solid #111827; border-radius: 4px; background: #fff; }
    </style>
  </head>
  <body>
    ${group.lines.map(({ record, implant }) => {
      const photos = implant.photos || [];
      const patientNo = implantPatientNoText(record) || "미마감";
      const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
      const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
      return `
        <section class="statement">
          <div class="head">
            <div>
              <div class="title">임플란트 사용 명세서</div>
              <div class="note">${escapeHtml(date)} · ${escapeHtml(group.vendor)} · 환자명/환자ID 제외</div>
            </div>
            <div class="no">#${escapeHtml(patientNo)}</div>
          </div>
          <div class="meta">
            <div><span>DATE</span><strong>${escapeHtml(implantRecordDate(record) || "-")}</strong></div>
            <div><span>업체명</span><strong>${escapeHtml(group.vendor)}</strong></div>
            <div><span>원장코드</span><strong>${escapeHtml(doctorText)}</strong></div>
            <div><span>OP</span><strong>${escapeHtml(surgeryText)}</strong></div>
          </div>
          <div>
            <div class="section-title">IMPLANT</div>
            <div class="desc">${escapeHtml(implant.description || `사진 ${photos.length}장 기록`)}</div>
          </div>
          <div>
            <div class="section-title">사진</div>
            <div class="photos">
              ${photos.map((photo) => {
                const src = implantPhotoViewSrc(photo);
                return src ? `<img src="${escapeHtml(src)}" alt="임플란트 사진">` : "";
              }).join("")}
            </div>
          </div>
        </section>
      `;
    }).join("")}
  </body>
  </html>`;

const implantSendStatementPrintHtmlV2 = (date, group) => `<!doctype html>
  <html lang="ko">
  <head>
    <meta charset="utf-8">
    <title>${escapeHtml(date)} ${escapeHtml(group.vendor)} 임플란트 사용 명세서</title>
    <style>
      @page { size: A4 portrait; margin: 10mm; }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: Arial, "Malgun Gothic", sans-serif; color: #111827; }
      .statement { width: 190mm; min-height: auto; page-break-after: always; display: grid; gap: 7px; align-content: start; overflow: hidden; }
      .statement:last-child { page-break-after: auto; }
      .head { display: grid; gap: 4px; padding-bottom: 6px; border-bottom: 3px solid #111827; }
      .title { font-size: 25px; font-weight: 900; letter-spacing: 0; }
      .note { margin-top: 2px; font-size: 12px; font-weight: 800; color: #374151; }
      .no { min-width: 112px; padding: 8px 12px; border: 3px solid #111827; border-radius: 6px; text-align: center; font-size: 36px; font-weight: 900; }
      .meta { display: grid; grid-template-columns: 1.15fr .95fr .8fr 1.35fr; border: 2px solid #111827; border-bottom: 0; }
      .meta div { min-height: 48px; padding: 6px 7px; border-right: 2px solid #111827; border-bottom: 2px solid #111827; overflow: hidden; }
      .meta div:nth-child(4n) { border-right: 0; }
      .meta span { display: block; margin-bottom: 3px; color: #475569; font-size: 10px; font-weight: 900; }
      .meta strong { display: block; font-size: 15px; line-height: 1.16; font-weight: 900; word-break: keep-all; overflow-wrap: anywhere; }
      .section-title { margin: 2px 0 4px; font-size: 14px; font-weight: 900; }
      .desc { min-height: 64px; max-height: 88px; overflow: hidden; padding: 9px; border: 2px solid #111827; white-space: pre-wrap; font-family: Consolas, "Malgun Gothic", monospace; font-size: 18px; line-height: 1.25; font-weight: 800; overflow-wrap: anywhere; }
      .photos { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
      .photos img { width: 100%; height: 74mm; object-fit: contain; border: 2px solid #111827; border-radius: 4px; background: #fff; }
      .empty-photo { min-height: 74mm; display: grid; place-items: center; border: 2px dashed #94a3b8; color: #64748b; font-size: 18px; font-weight: 800; }
      .footer { display: grid; grid-template-columns: repeat(3, 1fr); border: 2px solid #111827; border-right: 0; border-bottom: 0; }
      .footer div { min-height: 42px; padding: 6px 7px; border-right: 2px solid #111827; border-bottom: 2px solid #111827; }
      .footer span { display: block; margin-bottom: 3px; color: #475569; font-size: 10px; font-weight: 900; }
      .footer strong { font-size: 15px; line-height: 1.15; font-weight: 900; overflow-wrap: anywhere; }
    </style>
  </head>
  <body>
    ${implantSendPatientGroups(group).map(({ record, photos, descriptions }) => {
      const chunks = implantStatementPhotoChunks(photos, 4);
      const patientNo = implantPatientNoText(record) || "미마감";
      const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
      const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
      const user = auditUserText(record) || currentAuditUser()?.name || currentAuditUser()?.loginId || "-";
      return chunks.map((chunk, chunkIndex) => {
        const pageLabel = chunks.length > 1 ? ` ${chunkIndex + 1}/${chunks.length}` : "";
        const desc = chunkIndex
          ? `사진 계속 (${chunkIndex + 1}/${chunks.length})`
          : (descriptions.length ? descriptions.join("\n\n") : `사진 ${photos.length}장 기록`);
        return `
          <section class="statement">
            <div class="head">
              <div>
                <div class="title">임플란트 사용 명세서</div>
                <div class="note">${escapeHtml(date)} · ${escapeHtml(group.vendor)} · 환자명/환자ID 제외</div>
              </div>
            </div>
            <div class="meta">
              <div><span>DATE / 환자번호</span><strong>${escapeHtml(implantRecordDate(record) || "-")} · 환자번호 #${escapeHtml(patientNo)}${pageLabel ? ` · 사진 ${escapeHtml(pageLabel.trim())}` : ""}</strong></div>
              <div><span>업체명</span><strong>${escapeHtml(group.vendor)}</strong></div>
              <div><span>원장코드</span><strong>${escapeHtml(doctorText)}</strong></div>
              <div><span>OP</span><strong>${escapeHtml(surgeryText)}</strong></div>
            </div>
            <div>
              <div class="section-title">IMPLANT</div>
              <div class="desc">${escapeHtml(desc)}</div>
            </div>
            <div>
              <div class="section-title">사진</div>
              ${chunk.length ? `
                <div class="photos">
                  ${chunk.map((photo) => {
                    const src = implantPhotoViewSrc(photo);
                    return src ? `<img src="${escapeHtml(src)}" alt="임플란트 사진">` : "";
                  }).join("")}
                </div>
              ` : `<div class="empty-photo">첨부 사진 없음</div>`}
            </div>
            <div class="footer">
              <div><span>발송일</span><strong>${escapeHtml(today())}</strong></div>
              <div><span>발송자</span><strong>${escapeHtml(user)}</strong></div>
              <div><span>확인처</span><strong>윌스기념병원 수술실</strong></div>
            </div>
          </section>
        `;
      }).join("");
    }).join("")}
  </body>
  </html>`;

const implantVendorStatementFileName = (date, vendor, extension = "html") =>
  `임플란트명세서_${safeBackupFileName(date)}_${safeBackupFileName(vendor)}.${extension}`;

const implantVendorStatementHtmlBlob = (date, group) =>
  new Blob([implantSendStatementPrintHtmlV2(date, group)], { type: "text/html;charset=utf-8" });

const loadExternalScriptOnce = (src, globalCheck) => new Promise((resolve, reject) => {
  if (globalCheck()) {
    resolve();
    return;
  }
  const resolveWhenReady = () => {
    if (globalCheck()) resolve();
    else reject(new Error("PDF 생성 라이브러리 확인에 실패했습니다."));
  };
  const existing = document.querySelector(`script[src="${src}"]`);
  if (existing) {
    if (existing.dataset.loadState === "loaded") {
      resolveWhenReady();
      return;
    }
    if (existing.dataset.loadState === "error") {
      existing.remove();
    } else {
      const timer = window.setTimeout(() => reject(new Error("PDF 생성 라이브러리 로딩 시간이 초과되었습니다.")), 12000);
      existing.addEventListener("load", () => {
        existing.dataset.loadState = "loaded";
        window.clearTimeout(timer);
        resolveWhenReady();
      }, { once: true });
      existing.addEventListener("error", () => {
        existing.dataset.loadState = "error";
        window.clearTimeout(timer);
        reject(new Error("PDF 생성 라이브러리를 불러오지 못했습니다."));
      }, { once: true });
      return;
    }
  }
  const script = document.createElement("script");
  script.src = src;
  script.async = true;
  script.dataset.loadState = "loading";
  const timer = window.setTimeout(() => reject(new Error("PDF 생성 라이브러리 로딩 시간이 초과되었습니다.")), 12000);
  script.onload = () => {
    script.dataset.loadState = "loaded";
    window.clearTimeout(timer);
    resolveWhenReady();
  };
  script.onerror = () => {
    script.dataset.loadState = "error";
    window.clearTimeout(timer);
    reject(new Error("PDF 생성 라이브러리를 불러오지 못했습니다."));
  };
  document.head.appendChild(script);
});

const waitForRenderImages = async (root) => {
  const images = Array.from(root.querySelectorAll("img"));
  await Promise.all(images.map((image) => {
    if (image.complete && image.naturalWidth) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = window.setTimeout(resolve, 6000);
      image.onload = () => {
        window.clearTimeout(timer);
        resolve();
      };
      image.onerror = () => {
        window.clearTimeout(timer);
        resolve();
      };
    });
  }));
};

const inlineRenderImages = async (root) => {
  const images = Array.from(root.querySelectorAll("img"));
  await Promise.all(images.map(async (image) => {
    const src = image.getAttribute("src") || "";
    if (!src || src.startsWith("data:")) return;
    try {
      const response = await promiseWithTimeout(
        fetch(src, { mode: "cors" }),
        8000,
        "사진 변환 시간이 초과되었습니다."
      );
      if (!response.ok) throw new Error("사진을 불러오지 못했습니다.");
      const blob = await response.blob();
      image.src = await blobToDataUrl(blob);
      image.removeAttribute("crossorigin");
    } catch (error) {
      console.warn("PDF image inline failed", error);
      image.crossOrigin = "anonymous";
    }
  }));
};

const implantPdfWrapText = (ctx, text, maxWidth, maxLines = 99) => {
  const output = [];
  String(text || "").split(/\n/).forEach((paragraph) => {
    if (output.length >= maxLines) return;
    if (!paragraph) {
      output.push("");
      return;
    }
    let line = "";
    Array.from(paragraph).forEach((char) => {
      if (output.length >= maxLines) return;
      const next = line + char;
      if (ctx.measureText(next).width <= maxWidth || !line) {
        line = next;
      } else {
        output.push(line);
        line = char;
      }
    });
    if (line && output.length < maxLines) output.push(line);
  });
  if (output.length > maxLines) {
    output.length = maxLines;
    output[maxLines - 1] = `${output[maxLines - 1].slice(0, -1)}...`;
  }
  return output;
};

const implantPdfDrawTextBox = (ctx, label, value, x, y, width, height, options = {}) => {
  ctx.strokeStyle = "#111827";
  ctx.lineWidth = options.lineWidth || 3;
  ctx.strokeRect(x, y, width, height);
  ctx.fillStyle = "#475569";
  ctx.font = `900 ${options.labelSize || 18}px Arial, "Malgun Gothic", sans-serif`;
  ctx.fillText(label, x + 12, y + 24);
  ctx.fillStyle = "#111827";
  ctx.font = `900 ${options.valueSize || 27}px Arial, "Malgun Gothic", sans-serif`;
  const lines = implantPdfWrapText(ctx, value, width - 24, options.maxLines || 2);
  lines.forEach((line, index) => ctx.fillText(line, x + 12, y + 58 + (index * (options.lineHeight || 32))));
};

const implantPdfDrawWrapped = (ctx, text, x, y, width, lineHeight, maxLines) => {
  const lines = implantPdfWrapText(ctx, text, width, maxLines);
  lines.forEach((line, index) => ctx.fillText(line, x, y + (index * lineHeight)));
};

const implantPdfLoadPhotoImage = async (photo) => {
  const src = implantPhotoViewSrc(photo);
  if (!src) return null;
  try {
    return await promiseWithTimeout(loadImageFromUrl(src), 12000, "PDF 사진 처리 시간이 초과되었습니다.");
  } catch (error) {
    console.warn("PDF photo load failed", error);
    return null;
  }
};

const implantPdfDrawImageContain = (ctx, image, x, y, width, height) => {
  const sourceWidth = image.naturalWidth || image.width || 1;
  const sourceHeight = image.naturalHeight || image.height || 1;
  const ratio = Math.min(width / sourceWidth, height / sourceHeight);
  const drawWidth = sourceWidth * ratio;
  const drawHeight = sourceHeight * ratio;
  ctx.drawImage(image, x + ((width - drawWidth) / 2), y + ((height - drawHeight) / 2), drawWidth, drawHeight);
};

const implantPdfReleaseImage = (image) => {
  const objectUrl = image?.dataset?.objectUrl;
  if (objectUrl) URL.revokeObjectURL(objectUrl);
};

const implantStatementCanvasPage = async ({ date, group, record, photos, descriptions, chunk, chunkIndex, chunkTotal }) => {
  const canvas = document.createElement("canvas");
  canvas.width = 1240;
  canvas.height = 1754;
  const ctx = canvas.getContext("2d");
  const margin = 70;
  const pageWidth = canvas.width;
  const contentWidth = pageWidth - (margin * 2);
  const patientNo = implantPatientNoText(record) || "미마감";
  const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
  const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
  const user = auditUserText(record) || currentAuditUser()?.name || currentAuditUser()?.loginId || "-";
  const pageLabel = chunkTotal > 1 ? ` · 사진 ${chunkIndex + 1}/${chunkTotal}` : "";
  const desc = chunkIndex
    ? `사진 계속 (${chunkIndex + 1}/${chunkTotal})`
    : (descriptions.length ? descriptions.join("\n\n") : `사진 ${photos.length}장 기록`);

  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#111827";
  ctx.font = '900 44px Arial, "Malgun Gothic", sans-serif';
  ctx.fillText("임플란트 사용 명세서", margin, 82);
  ctx.fillStyle = "#475569";
  ctx.font = '800 20px Arial, "Malgun Gothic", sans-serif';
  ctx.fillText("환자명/환자ID 제외", margin, 116);
  ctx.strokeStyle = "#111827";
  ctx.lineWidth = 5;
  ctx.beginPath();
  ctx.moveTo(margin, 140);
  ctx.lineTo(pageWidth - margin, 140);
  ctx.stroke();

  const metaY = 160;
  const metaH = 118;
  const widths = [300, 270, 220, contentWidth - 790];
  let metaX = margin;
  [
    ["DATE / 환자번호", `${implantRecordDate(record) || date || "-"} · 환자번호 #${patientNo}${pageLabel}`],
    ["업체명", group.vendor],
    ["원장코드", doctorText],
    ["OP", surgeryText]
  ].forEach(([label, value], index) => {
    implantPdfDrawTextBox(ctx, label, value, metaX, metaY, widths[index], metaH, { valueSize: index === 0 ? 26 : 28 });
    metaX += widths[index];
  });

  ctx.fillStyle = "#1d4ed8";
  ctx.fillRect(margin, 314, 7, 25);
  ctx.fillStyle = "#111827";
  ctx.font = '900 24px Arial, "Malgun Gothic", sans-serif';
  ctx.fillText("IMPLANT", margin + 16, 336);
  ctx.strokeStyle = "#111827";
  ctx.lineWidth = 4;
  ctx.strokeRect(margin, 354, contentWidth, 160);
  ctx.fillStyle = "#111827";
  ctx.font = '900 30px Consolas, "Malgun Gothic", monospace';
  implantPdfDrawWrapped(ctx, desc, margin + 18, 398, contentWidth - 36, 36, 3);

  ctx.fillStyle = "#1d4ed8";
  ctx.fillRect(margin, 550, 7, 25);
  ctx.fillStyle = "#111827";
  ctx.font = '900 23px Arial, "Malgun Gothic", sans-serif';
  ctx.fillText("사진", margin + 16, 572);

  const photoGap = 22;
  const photoX = margin;
  const photoY = 595;
  const slotCount = chunk.length ? chunk.length : 1;
  const columns = slotCount === 1 ? 1 : 2;
  const rows = Math.ceil(slotCount / columns);
  const cellW = (contentWidth - (photoGap * (columns - 1))) / columns;
  const cellH = rows === 1 ? 884 : 430;
  for (let index = 0; index < slotCount; index += 1) {
    const col = index % columns;
    const row = Math.floor(index / columns);
    const x = photoX + (col * (cellW + photoGap));
    const y = photoY + (row * (cellH + photoGap));
    ctx.strokeStyle = "#111827";
    ctx.lineWidth = 3;
    ctx.strokeRect(x, y, cellW, cellH);
    if (!chunk[index]) {
      ctx.fillStyle = "#94a3b8";
      ctx.font = '800 24px Arial, "Malgun Gothic", sans-serif';
      ctx.fillText("사진 없음", x + 24, y + 52);
      continue;
    }
    const image = await implantPdfLoadPhotoImage(chunk[index]);
    if (image) {
      implantPdfDrawImageContain(ctx, image, x + 8, y + 8, cellW - 16, cellH - 16);
      implantPdfReleaseImage(image);
    } else {
      ctx.fillStyle = "#b91c1c";
      ctx.font = '900 24px Arial, "Malgun Gothic", sans-serif';
      ctx.fillText("사진 불러오기 실패", x + 24, y + 52);
    }
  }

  const footerY = 1600;
  const footerW = contentWidth / 3;
  [
    ["발송일", today()],
    ["발송자", user],
    ["확인처", "윌스기념병원 수술실"]
  ].forEach(([label, value], index) => {
    implantPdfDrawTextBox(ctx, label, value, margin + (footerW * index), footerY, footerW, 82, {
      labelSize: 18,
      valueSize: 24,
      maxLines: 1
    });
  });

  return canvas;
};

const renderImplantStatementPdfBlob = async (date, group) => {
  await loadExternalScriptOnce("vendor/jspdf.umd.min.js", () => Boolean(window.jspdf?.jsPDF));
  if (document.fonts?.ready) await document.fonts.ready;
  const pdf = new window.jspdf.jsPDF({ orientation: "portrait", unit: "mm", format: "a4", compress: true });
  let pageIndex = 0;
  for (const patientGroup of implantSendPatientGroups(group)) {
    const chunks = implantStatementPhotoChunks(patientGroup.photos, 4);
    for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += 1) {
      const canvas = await implantStatementCanvasPage({
        date,
        group,
        record: patientGroup.record,
        photos: patientGroup.photos,
        descriptions: patientGroup.descriptions,
        chunk: chunks[chunkIndex],
        chunkIndex,
        chunkTotal: chunks.length
      });
      if (pageIndex) pdf.addPage("a4", "portrait");
      pdf.addImage(canvas.toDataURL("image/jpeg", 0.9), "JPEG", 0, 0, 210, 297, undefined, "FAST");
      pageIndex += 1;
    }
  }
  return pdf.output("blob");
};

const saveAndShareImplantVendorStatementPdf = async (date, group) => {
  const blob = await renderImplantStatementPdfBlob(date, group);
  const filename = implantVendorStatementFileName(date, group.vendor, "pdf");
  downloadBlob(filename, blob);
  if (typeof File !== "function") return "saved-only";
  const file = new File([blob], filename, { type: "application/pdf" });
  const title = `${date} ${group.vendor} 임플란트 명세서`;
  const text = `${date} ${group.vendor} 임플란트 명세서 PDF`;
  if (navigator.share && navigator.canShare?.({ files: [file] })) {
    try {
      await navigator.share({ title, text, files: [file] });
      return "shared";
    } catch (error) {
      if (error?.name === "AbortError") return "cancelled";
      throw error;
    }
  }
  return "saved-only";
};

const downloadImplantVendorStatementHtml = (date, group) => {
  downloadBytes(
    implantVendorStatementFileName(date, group.vendor, "html"),
    implantSendStatementPrintHtmlV2(date, group),
    "text/html;charset=utf-8"
  );
};

const shareImplantVendorStatement = async (date, group) => {
  return saveAndShareImplantVendorStatementPdf(date, group);
};

const implantSendPanelHtml = (date) => {
  const groups = implantSendGroups(date);
  if (!groups.length) return `<div class="empty">업체별로 발송할 임플란트 기록이 없습니다.</div>`;
  return `
    <div class="implant-send-list">
      ${groups.map((group) => {
        const message = implantSendMessage(date, group.vendor, group.lines);
        const email = group.contact?.email || "";
        const phone = group.contact?.phone || "";
        return `
          <div class="implant-send-card">
            <div class="item-title">
              <span>${escapeHtml(group.vendor)}</span>
              <span class="pill">${group.lines.length}건 · ${escapeHtml(implantSendStatusLabel(group.status))}</span>
            </div>
            <div class="meta">
              ${email ? `<span>이메일: ${escapeHtml(email)}</span>` : ""}
              ${phone ? `<span>연락처: ${escapeHtml(phone)}</span>` : ""}
              ${!email && !phone ? `<span>설정에 연락처가 없습니다.</span>` : ""}
            </div>
            <div class="implant-send-text">${escapeHtml(message)}</div>
            ${implantSendStatementCardsHtml(group)}
            <div class="actions">
              ${email ? `<button type="button" data-send-implant-email="${escapeHtml(group.vendor)}">메일 작성</button>` : ""}
              ${phone ? `<button class="secondary" type="button" data-send-implant-sms="${escapeHtml(group.vendor)}">문자 작성</button>` : ""}
              <button class="secondary" type="button" data-copy-implant-send="${escapeHtml(group.vendor)}">내용 복사</button>
              <button type="button" data-print-implant-send="${escapeHtml(group.vendor)}">PDF 저장/공유</button>
              <button class="secondary" type="button" data-share-implant-send="${escapeHtml(group.vendor)}">PDF 공유</button>
              <button class="secondary" type="button" data-download-implant-send="${escapeHtml(group.vendor)}">명세서 다운로드</button>
              <button class="secondary" type="button" data-set-implant-send-status="${escapeHtml(group.vendor)}" data-send-status="pending">미발송</button>
              <button type="button" data-set-implant-send-status="${escapeHtml(group.vendor)}" data-send-status="sent">발송완료</button>
              <button class="secondary" type="button" data-set-implant-send-status="${escapeHtml(group.vendor)}" data-send-status="excluded">발송제외</button>
              <button class="secondary" type="button" data-set-implant-send-status="${escapeHtml(group.vendor)}" data-send-status="resend">재발송</button>
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
};

const implantSendPanelOrganizedHtml = (date) => {
  const groups = implantSendGroups(date);
  if (!groups.length) return `<div class="empty">업체별로 발송할 임플란트 기록이 없습니다.</div>`;
  const unnumberedTotal = implantRecordsForDate(date).filter((record) => !implantPatientNoText(record)).length;
  return `
    ${unnumberedTotal ? `<div class="implant-send-preview">선택 날짜에 환자번호가 없는 기록 ${unnumberedTotal}건이 있습니다. 업체 발송 전 마감 또는 번호 부여가 필요합니다.</div>` : ""}
    <div class="implant-send-list">
      ${groups.map((group) => {
        const message = implantSendMessage(date, group.vendor, group.lines);
        const email = group.contact?.email || "";
        const phone = group.contact?.phone || "";
        const stats = implantSendGroupStats(group);
        return `
          <div class="implant-send-card implant-send-clean-card">
            <div class="implant-send-clean-head">
              <div>
                <div class="implant-send-clean-title">
                  <span>${escapeHtml(group.vendor)}</span>
                  <span class="pill">${escapeHtml(implantSendStatusLabel(group.status))}</span>
                </div>
                <div class="implant-send-compact-meta">
                  <span>${escapeHtml(date)}</span>
                  <span>환자 ${stats.patients}명</span>
                  <span>기록 ${group.lines.length}건</span>
                  <span>사진 ${stats.photos}장</span>
                  ${stats.unnumbered ? `<span>미마감 ${stats.unnumbered}건</span>` : ""}
                </div>
                <div class="implant-send-contact-row">
                  ${email ? `<span>메일 ${escapeHtml(email)}</span>` : ""}
                  ${phone ? `<span>연락처 ${escapeHtml(phone)}</span>` : ""}
                  ${!email && !phone ? `<span>설정된 연락처 없음</span>` : ""}
                </div>
              </div>
              <label class="implant-send-status-control">
                <span>발송상태</span>
                <select data-change-implant-send-status="${escapeHtml(group.vendor)}">
                  <option value="pending" ${group.status === "pending" ? "selected" : ""}>미발송</option>
                  <option value="sent" ${group.status === "sent" ? "selected" : ""}>발송완료</option>
                  <option value="resend" ${group.status === "resend" ? "selected" : ""}>재발송</option>
                  <option value="excluded" ${group.status === "excluded" ? "selected" : ""}>발송제외</option>
                </select>
              </label>
            </div>
            <div class="implant-send-primary-actions">
              <button type="button" data-print-implant-send="${escapeHtml(group.vendor)}">PDF 저장/공유</button>
              <button type="button" data-set-implant-send-status="${escapeHtml(group.vendor)}" data-send-status="sent">발송완료</button>
            </div>
            <details class="implant-send-details">
              <summary>사진 포함 A4 명세서 미리보기</summary>
              <div class="implant-send-details-body">
                <div class="implant-send-preview">환자 1명당 A4 1장 기준입니다. 사진이 4장을 넘으면 다음 장으로 자동 분리됩니다. PDF 저장/공유를 누르면 파일 저장 후 지원 기기에서 공유창이 열립니다.</div>
                ${implantSendStatementCardsHtml(group)}
              </div>
            </details>
          </div>
        `;
      }).join("")}
    </div>
  `;
};

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

const implantPhotoHtml = (photo) => {
  const src = implantPhotoViewSrc(photo);
  return src ? `
    <img class="implant-photo-thumb" src="${escapeHtml(src)}" alt="임플란트 사진" data-implant-photo-view="${escapeHtml(src)}">
  ` : "";
};
const implantPhotoStatusHtml = (implant) => {
  const pending = num(implant.pendingPhotoCount);
  const errors = Array.isArray(implant.photoUploadErrors) ? implant.photoUploadErrors : [];
  if (!pending && !errors.length) return "";
  const missingPhotoHint = pending && !(implant.photos || []).length ? " · 사진이 보이지 않으면 수정에서 다시 첨부" : "";
  return `<div class="muted">${pending ? `사진 ${pending}장 업로드 대기${missingPhotoHint}` : ""}${pending && errors.length ? " · " : ""}${errors.length ? `사진 업로드 확인 필요 ${errors.length}건` : ""}</div>`;
};

const implantPhotoStatusPanelHtml = (date) => {
  const records = implantRecordsForDate(date);
  const stats = implantPhotoStatusStats(records);
  const rows = implantPhotoProblemRows(records);
  return `
    <div class="implant-status-grid">
      <div class="implant-status-tile"><span>전체 사진</span><strong>${stats.photos}</strong></div>
      <div class="implant-status-tile"><span>Storage 저장</span><strong>${stats.storage}</strong></div>
      <div class="implant-status-tile"><span>업로드 대기</span><strong>${stats.pending}</strong></div>
      <div class="implant-status-tile"><span>재업로드 가능</span><strong>${stats.retry}</strong></div>
      <div class="implant-status-tile"><span>확인 필요</span><strong>${stats.failed + stats.missing + stats.errors}</strong></div>
    </div>
    ${rows.length ? `
      <div class="implant-status-list">
        ${rows.map(({ record, implant, pending, failed, retry, missing, errors }) => `
          <div class="implant-status-row">
            <div class="item-title">
              <span>${escapeHtml(implantPatientNoText(record) ? `#${implantPatientNoText(record)} ` : "")}${escapeHtml(record.patientName || "이름 없음")} · ${escapeHtml(implant.vendor || "업체 없음")}</span>
              <span class="pill">${escapeHtml(implantRecordDate(record))}</span>
            </div>
            <div class="meta">
              ${pending ? `<span>대기 ${pending}장</span>` : ""}
              ${retry ? `<span>재업로드 가능 ${retry}장</span>` : ""}
              ${failed ? `<span>업로드 실패 ${failed}장</span>` : ""}
              ${missing ? `<span>미표시 ${missing}장</span>` : ""}
              ${errors ? `<span>오류 ${errors}건</span>` : ""}
            </div>
            ${retry ? `<div class="actions"><button class="secondary" type="button" data-retry-implant-photos="${escapeHtml(record.id)}">임시저장 사진 재업로드</button></div>` : ""}
          </div>
        `).join("")}
      </div>
    ` : `<div class="empty">선택 날짜의 사진 업로드 상태가 정상입니다.</div>`}
  `;
};

const implantRecordCardHtml = (record, options = {}) => {
  const vendors = Array.isArray(record.implants) ? record.implants : [];
  const patientNo = implantPatientNoText(record);
  const doctorText = record.surgeonCode || departmentById(record.doctorId)?.name || "-";
  const surgeryText = record.surgeryName || surgeryById(record.surgeryId)?.name || "-";
  const locked = isImplantLedgerClosed(record);
  const showAdminTools = options.showAdminTools !== false && canEditImplantPatientNo();
  const retryPhotoCount = vendors.reduce((sum, implant) => sum + (implant.photos || []).filter(implantPhotoNeedsStorageRetry).length, 0);
  return `
    <div class="card implant-record-card" data-implant-record="${escapeHtml(record.id)}">
      <div class="item-title">
        <span>${patientNo ? `${escapeHtml(patientNo)}번 ` : ""}${escapeHtml(record.patientName || "이름 없음")}${record.patientId ? ` (${escapeHtml(record.patientId)})` : ""}</span>
        <span class="pill">${escapeHtml(implantRecordDate(record) || "-")}</span>
      </div>
      <div class="meta">
        <span>원장코드: ${escapeHtml(doctorText)}</span>
        <span>과: ${escapeHtml(record.department || "-")}</span>
        <span>수술: ${escapeHtml(surgeryText)}</span>
        ${record.surgeryTime ? `<span>수술시간: ${escapeHtml(record.surgeryTime)}</span>` : ""}
      </div>
      <div class="implant-lock-banner">${escapeHtml(implantLockLabel(record))}${record.editUnlockedAt ? ` · 해제: ${escapeHtml(record.editUnlockedAt.slice(0, 16).replace("T", " "))}` : ""}</div>
      ${showAdminTools ? `
        <div class="actions">
          ${locked ? `<button class="secondary" type="button" data-unlock-implant-record="${escapeHtml(record.id)}">마감 잠금 해제</button>` : (patientNo ? `<button class="secondary" type="button" data-lock-implant-record="${escapeHtml(record.id)}">다시 잠금</button>` : "")}
          <button class="danger" type="button" data-delete-implant-record="${escapeHtml(record.id)}">장부 삭제</button>
        </div>
      ` : ""}
      ${retryPhotoCount ? `
        <div class="implant-lock-banner">사진 ${retryPhotoCount}장 재업로드가 필요합니다.</div>
        <div class="actions">
          <button class="secondary" type="button" data-retry-implant-record-photos="${escapeHtml(record.id)}">사진 재업로드</button>
        </div>
      ` : ""}
      ${showAdminTools ? `
        <div class="row two">
          <div>
            <label for="implantPatientNo-${escapeHtml(record.id)}">환자번호 수동 수정</label>
            <input id="implantPatientNo-${escapeHtml(record.id)}" data-implant-patient-no-input="${escapeHtml(record.id)}" value="${escapeHtml(patientNo)}" inputmode="numeric" autocomplete="off">
          </div>
          <div class="actions">
            <button class="secondary" type="button" data-implant-patient-no-save="${escapeHtml(record.id)}">번호 저장</button>
          </div>
        </div>
      ` : ""}
      ${vendors.length ? vendors.map((implant) => `
        <div class="implant-vendor-block">
          <div class="item-title">
            <span>${escapeHtml(implant.vendor || "업체 없음")}</span>
            <span class="pill">${(implant.photos || []).length}장</span>
          </div>
          <div class="implant-description">${escapeHtml(implant.description || "")}</div>
          ${implantPhotoStatusHtml(implant)}
          <div class="implant-photo-strip">
            ${(implant.photos || []).map(implantPhotoHtml).join("")}
          </div>
        </div>
      `).join("") : `<div class="empty">업체별 기록이 없습니다.</div>`}
      <div class="implant-send-preview">
        업체 발송용 데이터 준비: 환자명/환자ID 제외, 환자번호 ${escapeHtml(patientNo || "미부여")} · ${escapeHtml(doctorText)} · ${escapeHtml(surgeryText)} · 업체별 사용내용만 출력 가능
      </div>
    </div>
  `;
};

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

const renderImplants = () => {
  const date = today();
  ensureImplantSubView();
  const subTabs = implantSubViewItems();
  return `
    <section class="grid">
      <div class="card">
        <h2>임플란트 전산장부</h2>
        <div class="implant-subtabs" role="tablist" aria-label="임플란트 하위 메뉴">
          ${subTabs.map(([key, label]) => `<button class="implant-subtab ${currentImplantSubView === key ? "active" : ""}" type="button" data-implant-subview="${key}">${label}</button>`).join("")}
        </div>
        <div class="row four">
          <div>
            <label for="implantFilterDate">날짜</label>
            <input id="implantFilterDate" type="date" value="${escapeHtml(date)}">
          </div>
          <div>
            <label for="implantFilterPatientNo">환자번호</label>
            <input id="implantFilterPatientNo" inputmode="numeric" autocomplete="off" placeholder="1">
          </div>
          <div>
            <label for="implantFilterName">환자명</label>
            <input id="implantFilterName" autocomplete="off">
          </div>
          <div>
            <label for="implantFilterPatientId">환자ID</label>
            <input id="implantFilterPatientId" autocomplete="off">
          </div>
        </div>
        <div class="actions">
          <button class="secondary" type="button" id="implantFilterReset">초기화</button>
        </div>
        <div class="actions" data-implant-panel="today" ${implantPanelVisible("today") ? "" : "hidden"}>
          ${canAssignImplantPatientNo() ? `<button type="button" id="closeTodayImplants">오늘 사용분 마감하기</button>` : ""}
          ${canAssignImplantPatientNo() ? `<button class="secondary" type="button" id="assignImplantPatientNos">선택 날짜 번호 부여</button>` : ""}
        </div>
        <div class="actions" data-implant-panel="hospital" ${implantPanelVisible("hospital") ? "" : "hidden"}>
          <button class="secondary" type="button" id="exportImplantLedger">엑셀 다운로드</button>
        </div>
        <div class="actions" data-implant-panel="send" ${implantPanelVisible("send") ? "" : "hidden"}>
          <button type="button" id="prepareImplantVendorSend">마감 확인 후 발송자료 갱신</button>
        </div>
      </div>
      <div class="card" data-implant-panel="photos" ${implantPanelVisible("photos") ? "" : "hidden"}>
        <h2>사진 업로드 상태</h2>
        <div id="implantPhotoStatusPanel"></div>
      </div>
      <div class="card" data-implant-panel="backup" ${implantPanelVisible("backup") ? "" : "hidden"}>
        <h2>월별 백업/보관</h2>
        <div class="row two">
          <div>
            <label for="implantBackupMonth">백업 월</label>
            <input id="implantBackupMonth" type="month" value="${escapeHtml(date.slice(0, 7))}">
          </div>
          <div class="actions">
            <button class="secondary" type="button" id="downloadImplantMonthlyBackup">월별 ZIP 백업</button>
          </div>
        </div>
        <div class="implant-send-preview">엑셀, 원본 JSON, 사진 URL 목록을 저장하고 가능한 사진은 ZIP에 함께 담습니다.</div>
      </div>
      <div class="card" data-implant-panel="hospital" ${implantPanelVisible("hospital") ? "" : "hidden"}>
        <h2>병원 확인용 마감 자료</h2>
        <div id="implantCloseSummary"></div>
      </div>
      <div class="card" id="implantSendPanel" data-implant-panel="send" ${implantPanelVisible("send") ? "" : "hidden"}>
        <h2>업체별 장부 확인</h2>
        <div class="implant-send-preview">환자명과 환자ID는 업체 발송자료에서 제외됩니다. 실제 자동 발송은 병원 메일/SMS API 연결 후 같은 자료를 그대로 사용할 수 있습니다.</div>
        <div id="implantSendList"></div>
      </div>
      <div class="card" data-implant-panel="today admin" ${implantPanelVisible("today admin") ? "" : "hidden"}>
        <h2 id="implantLedgerTitle">${currentImplantSubView === "admin" ? "관리자 도구" : "오늘 장부"}</h2>
        <div id="implantLedgerList" class="implant-ledger-list"></div>
      </div>
      <div class="modal-backdrop" id="implantPhotoModal" hidden role="dialog" aria-modal="true" aria-label="임플란트 사진 확대">
        <div class="search-modal-panel">
          <div class="search-modal-head">
            <h3>사진 확인</h3>
            <button class="search-modal-close" type="button" id="closeImplantPhotoModal" aria-label="사진 닫기">×</button>
          </div>
          <div class="implant-crop-stage" id="implantCropStage">
            <img class="implant-modal-image" id="implantPhotoModalImage" alt="임플란트 사진 확대">
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
            <button class="secondary" type="button" id="implantModalRotate">회전</button>
            <button class="secondary" type="button" id="implantModalCrop">자르기</button>
            <button type="button" id="implantModalDone">완료</button>
          </div>
        </div>
      </div>
    </section>
  `;
};

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
        ${implantVendors.length ? implantVendors.slice().sort((a, b) => alphaFirstCompare(a.name, b.name)).map((vendor) => `
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

const pendingUsageSummary = (item) => {
  const productCount = (item.productItems || []).reduce((sum, product) => sum + Math.max(1, num(product.qty)), 0);
  const implantCount = (item.implantDrafts || []).length;
  const photoCount = (item.implantDrafts || []).reduce((sum, implant) => sum + (implant.photos || []).length, 0);
  return { productCount, implantCount, photoCount };
};

const renderPendingUsageList = () => {
  const items = pendingUsagesOpen();
  if (!items.length) return "";
  return `
    <div class="card">
      <div class="use-draft-head">
        <div>
          <h3 style="margin:0;">스크럽 확인 대기</h3>
          <div class="muted">임시저장된 기록은 새로고침 후에도 남아 있습니다. 확인할 환자를 불러와 최종저장하세요.</div>
        </div>
        <span class="use-draft-status">${items.length}건</span>
      </div>
      <div class="pending-usage-list">
        ${items.map((item) => {
          const summary = pendingUsageSummary(item);
          const doctor = departmentById(item.doctorId);
          const surgery = surgeryById(item.surgeryId);
          return `
            <div class="pending-usage-card">
              <div class="pending-usage-head">
                <strong>${escapeHtml(patientDisplayName(item) || "환자 정보 없음")}</strong>
                <span class="pill">${escapeHtml(item.date || today())}</span>
              </div>
              <div class="pending-usage-meta">
                <span>${escapeHtml(doctor?.name || "-")}</span>
                <span>${escapeHtml(surgery?.name || "-")}</span>
                <span>제품 ${summary.productCount}개</span>
                <span>임플란트 ${summary.implantCount}업체 · 사진 ${summary.photoCount}장</span>
                <span>입력 ${escapeHtml(item.enteredBy?.name || item.enteredBy?.loginId || item.draftSavedBy || "-")}</span>
                <span>${escapeHtml(formatDateTime(item.updatedAt || item.createdAt || ""))}</span>
              </div>
              <div class="actions">
                <button type="button" data-load-pending-usage="${escapeHtml(item.id)}">불러오기</button>
                <button class="danger" type="button" data-delete-pending-usage="${escapeHtml(item.id)}">대기삭제</button>
              </div>
            </div>
          `;
        }).join("")}
      </div>
    </div>
  `;
};

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
          <label for="patientId">환자ID</label>
          <input id="patientId" autocomplete="off">
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
      <div class="modal-backdrop" id="useProductSearchModal" hidden role="dialog" aria-modal="true" aria-labelledby="useProductSearchTitle">
        <div class="search-modal-panel">
          <div class="search-modal-head">
            <h3 id="useProductSearchTitle">제품 검색</h3>
            <button class="search-modal-close" type="button" id="closeUseProductSearch" aria-label="제품 검색 닫기">×</button>
          </div>
          <div>
            <label for="useProductSearch">제품명 검색</label>
            <input id="useProductSearch" autocomplete="off" placeholder="제품명, 업체, 종류를 입력하세요">
          </div>
          <div id="useProductSearchResults" class="product-picker search-modal-results"></div>
        </div>
      </div>
      <div class="modal-backdrop" id="implantPhotoModal" hidden role="dialog" aria-modal="true" aria-label="임플란트 사진 확대">
        <div class="search-modal-panel">
          <div class="search-modal-head">
            <h3>사진 확인</h3>
            <button class="search-modal-close" type="button" id="closeImplantPhotoModal" aria-label="사진 닫기">×</button>
          </div>
          <div class="implant-crop-stage" id="implantCropStage">
            <img class="implant-modal-image" id="implantPhotoModalImage" alt="임플란트 사진 확대">
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
            <button class="secondary" type="button" id="implantModalRotate">회전</button>
            <button class="secondary" type="button" id="implantModalCrop">자르기</button>
            <button type="button" id="implantModalDone">완료</button>
          </div>
        </div>
      </div>
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

const renderUseItemsList = (items, target) => {
  if (!items.length) {
    target.innerHTML = `<span>선택된 제품이 없습니다.</span>`;
    return;
  }
  const chipClass = (category) => {
    const key = productCategory(category);
    if (key === "비급여") return "nonpay";
    if (key === "인체조직") return "tissue";
    if (["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(key)) return "anchor";
    return "";
  };
  const safeItems = items
    .map((item) => ({ ...item, product: productById(item.productId) }))
    .filter((item) => item.product && num(item.qty) > 0);
  if (!safeItems.length) {
    target.innerHTML = `<span>선택된 제품이 없습니다.</span>`;
    return;
  }
  target.innerHTML = `
    <div class="selected-use-buttons">
      ${safeItems.map((item) => {
        const product = item.product;
        const linkedQty = app.querySelector(`[data-use-qty="${item.productId}"]`);
        const maxQty = Math.max(1, num(linkedQty?.max || product.stock || 999));
        const meta = [productCategoryLabel(product.category), product.company, product.subcategory].filter(Boolean).join(" · ");
        return `
          <div class="selected-use-chip ${chipClass(product.category)}">
            <div class="selected-use-name" title="${escapeHtml(product.name)}">
              ${escapeHtml(product.name)}<span>${escapeHtml(meta)}</span>
            </div>
            <div class="selected-use-controls">
              <button type="button" class="secondary" data-edit-selected-dec="${item.productId}" aria-label="수량 줄이기">−</button>
              <input type="number" min="0" max="${maxQty}" value="${Math.max(1, num(item.qty))}" data-edit-selected-qty="${item.productId}" aria-label="${escapeHtml(product.name)} 수량" readonly>
              <button type="button" class="secondary" data-edit-selected-inc="${item.productId}" aria-label="수량 늘리기">+</button>
              <button type="button" class="remove-selected" data-edit-selected-remove="${item.productId}">삭제</button>
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
  const syncProductQty = (productId, nextQty) => {
    const scope = target.closest("form") || app;
    const checkbox = scope.querySelector(`[data-use-product="${productId}"]`);
    const qtyInput = scope.querySelector(`[data-use-qty="${productId}"]`);
    const maxQty = Math.max(1, num(qtyInput?.max || 999));
    const safeQty = Math.min(maxQty, Math.max(0, num(nextQty)));
    if (safeQty <= 0) {
      if (checkbox) checkbox.checked = false;
      if (qtyInput) qtyInput.value = 1;
    } else {
      if (checkbox) checkbox.checked = true;
      if (qtyInput) qtyInput.value = safeQty;
    }
    renderUseItemsList(Array.from(scope.querySelectorAll("[data-use-product]:checked")).map((input) => ({
      productId: input.value,
      qty: Math.max(1, num(scope.querySelector(`[data-use-qty="${input.value}"]`)?.value))
    })), target);
  };
  target.querySelectorAll("[data-edit-selected-remove]").forEach((button) => {
    button.addEventListener("click", () => syncProductQty(button.dataset.editSelectedRemove, 0));
  });
  target.querySelectorAll("[data-edit-selected-dec], [data-edit-selected-inc]").forEach((button) => {
    button.addEventListener("click", () => {
      const productId = button.dataset.editSelectedDec || button.dataset.editSelectedInc;
      const linked = app.querySelector(`[data-use-qty="${productId}"]`);
      const currentQty = Math.max(1, num(linked?.value || 1));
      const nextQty = button.dataset.editSelectedDec ? currentQty - 1 : currentQty + 1;
      syncProductQty(productId, nextQty);
    });
  });
};

const editUsagePatientsForDate = (date) => state.usages
  .filter((usage) => (usage.date || "") === date)
  .slice()
  .sort((a, b) => alphaFirstCompare(a.patientName, b.patientName) || alphaFirstCompare(patientIdText(a), patientIdText(b)));

const editUsagePatientCardHtml = (usage, selectedId = "") => {
  const doctor = departmentById(usage.doctorId);
  const surgery = surgeryById(usage.surgeryId);
  const surgeryDepartment = surgery ? (surgery.department || inferSurgeryDepartment(surgery.name)) : "-";
  const productItems = usageProductItems(usage);
  const productSummary = productItems
    .slice(0, 3)
    .map((item) => `${productById(item.productId)?.name || "삭제된 제품"}${item.qty > 1 ? ` ${item.qty}개` : ""}`)
    .join(", ");
  const extraCount = Math.max(0, productItems.length - 3);
  const locked = !canModifyUsageRecord(usage);
  return `
    <button class="edit-patient-card ${selectedId === usage.id ? "active" : ""} ${locked ? "locked" : ""}" type="button" data-edit-usage-card="${escapeHtml(usage.id)}">
      <div class="edit-patient-card-head">
        <span>${escapeHtml(patientDisplayName(usage) || "이름 없음")}</span>
        <span class="pill ${locked ? "low" : ""}">${locked ? "관리자 전용" : "수정 가능"}</span>
      </div>
      <div class="edit-patient-card-meta">
        <span>원장: ${escapeHtml(doctor?.name || "-")}</span>
        <span>수술: ${escapeHtml(surgeryDepartment)} - ${escapeHtml(surgery?.name || "-")}</span>
        <span>제품: ${productItems.reduce((sum, item) => sum + item.qty, 0)}개${productSummary ? ` · ${escapeHtml(productSummary)}${extraCount ? ` 외 ${extraCount}종` : ""}` : ""}</span>
      </div>
    </button>
  `;
};

const editUsagePatientListHtml = (date, selectedId = "") => {
  const patients = editUsagePatientsForDate(date);
  if (!patients.length) return `<div class="empty">선택한 날짜에 사용내역이 없습니다.</div>`;
  return patients.map((usage) => editUsagePatientCardHtml(usage, selectedId)).join("");
};

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
      <p class="helper">기본값은 오늘 날짜입니다. 날짜를 바꾸면 아래 환자 카드만 바뀝니다. 수정할 환자는 카드에서 바로 선택하세요.</p>
      <div id="editUsagePatientList" class="edit-patient-list">
        ${editUsagePatientListHtml(editSelectDate, pendingUsage?.id || "")}
      </div>
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
          <label for="editPatientId">환자ID</label>
          <input id="editPatientId" autocomplete="off">
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
  const renderUsageSelectOptions = (date, selectedId = "") => {
    const validSelectedId = selectedId && state.usages.some((usage) => usage.id === selectedId && (usage.date || "") === date) ? selectedId : "";
    select.value = validSelectedId;
    if (patientList) patientList.innerHTML = editUsagePatientListHtml(date, validSelectedId);
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
                <button class="secondary" type="button" data-preview-edit-implant-photo="${escapeHtml(row.id)}::${escapeHtml(photo.id)}">확대</button>
                <button class="secondary" type="button" data-edit-existing-implant-photo="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" ${editImplantCanModify ? "" : "disabled"}>편집</button>
                <button class="secondary" type="button" data-rotate-edit-implant-photo="${escapeHtml(row.id)}::${escapeHtml(photo.id)}" ${editImplantCanModify ? "" : "disabled"}>회전</button>
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
    const tools = document.getElementById("implantPhotoEditTools");
    const cropButton = document.getElementById("implantModalCrop");
    if (!photo || !image || !tools) return;
    image.src = implantPhotoViewSrc(photo);
    image.style.transform = implantPhotoRotationStyle(photo).replace("transform:", "").replace(";", "");
    image.classList.toggle("cropped", Boolean(photo.cropped));
    tools.hidden = false;
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
      productSearchResults.innerHTML = `<div class="empty">제품명을 입력해 주세요.</div>`;
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
        const tools = document.getElementById("implantPhotoEditTools");
        const image = document.getElementById("implantPhotoModalImage");
        if (tools) tools.hidden = true;
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
        markEditImplantPhotoChanged(photo);
        await refreshEditedImplantPreview(photo);
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
    markEditImplantPhotoChanged(targetPhoto);
    await refreshEditedImplantPreview(targetPhoto);
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
      patientId: document.getElementById("editPatientId").value.trim(),
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
      doneMessage: editImplantCanModify && countImplantPhotosToUpload(nextImplants) ? "수정 저장 완료 · 사진 업로드 준비" : "수정 저장 완료"
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
        saveDoneToast(photoUploadFailed ? "수정 완료 · 사진 업로드 확인 필요" : (countImplantPhotosToUpload(nextImplants) ? "수정과 사진 저장 완료" : "수정 저장 완료"));
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
  image.classList.remove("cropped");
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
      image.style.transform = "";
      image.classList.toggle("cropped", Boolean(activeImplantCropPhoto.cropped));
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
  const tools = document.getElementById("implantPhotoEditTools");
  if (tools) tools.hidden = false;
  if (image) {
    image.style.transform = "";
    image.classList.remove("cropped");
  }
  await enableImplantCropFrame(photo);
};

const showImplantPhotoModal = (url) => {
  const modal = document.getElementById("implantPhotoModal");
  const image = document.getElementById("implantPhotoModalImage");
  const frame = document.getElementById("implantCropFrame");
  if (!modal || !image || !url) return;
  image.src = url;
  image.classList.remove("cropped");
  if (frame) frame.hidden = true;
  activeImplantCropPhoto = null;
  activeImplantCropApply = null;
  setImplantCropButtonText("자르기");
  modal.hidden = false;
};

const hideImplantPhotoModal = () => {
  const modal = document.getElementById("implantPhotoModal");
  const image = document.getElementById("implantPhotoModalImage");
  const tools = document.getElementById("implantPhotoEditTools");
  const frame = document.getElementById("implantCropFrame");
  if (image) image.removeAttribute("src");
  if (image) image.style.transform = "";
  if (image) image.classList.remove("cropped");
  if (tools) tools.hidden = true;
  if (frame) frame.hidden = true;
  activeImplantCropPhoto = null;
  activeImplantCropApply = null;
  implantCropPointerState = null;
  if (modal) modal.hidden = true;
};

const bindImplants = () => {
  const list = document.getElementById("implantLedgerList");
  const dateInput = document.getElementById("implantFilterDate");
  const nameInput = document.getElementById("implantFilterName");
  const idInput = document.getElementById("implantFilterPatientId");
  const noInput = document.getElementById("implantFilterPatientNo");
  const summary = document.getElementById("implantCloseSummary");
  const sendPanel = document.getElementById("implantSendPanel");
  const sendList = document.getElementById("implantSendList");
  const photoStatusPanel = document.getElementById("implantPhotoStatusPanel");
  const backupMonthInput = document.getElementById("implantBackupMonth");
  const ledgerTitle = document.getElementById("implantLedgerTitle");
  const applyImplantPanels = () => {
    app.querySelectorAll("[data-implant-panel]").forEach((panel) => {
      panel.hidden = !panel.dataset.implantPanel.split(/\s+/).filter(Boolean).includes(currentImplantSubView);
    });
    app.querySelectorAll("[data-implant-subview]").forEach((button) => {
      button.classList.toggle("active", button.dataset.implantSubview === currentImplantSubView);
    });
    if (ledgerTitle) ledgerTitle.textContent = currentImplantSubView === "admin" ? "관리자 도구" : "오늘 장부";
    if (sendList && currentImplantSubView === "send" && !sendList.innerHTML.trim()) {
      sendList.innerHTML = implantSendPanelOrganizedHtml(dateInput.value || today());
    }
  };
  const renderList = () => {
    const records = filteredImplantRecords(dateInput.value, nameInput.value, idInput.value, noInput.value).reverse();
    list.innerHTML = records.length
      ? records.map((record) => implantRecordCardHtml(record, { showAdminTools: currentImplantSubView === "admin" })).join("")
      : `<div class="empty">조회 조건에 맞는 임플란트 기록이 없습니다.</div>`;
    if (summary) summary.innerHTML = implantLedgerTableHtml(implantRecordsForDate(dateInput.value));
    if (photoStatusPanel) photoStatusPanel.innerHTML = implantPhotoStatusPanelHtml(dateInput.value);
    if (sendList && currentImplantSubView === "send") sendList.innerHTML = implantSendPanelOrganizedHtml(dateInput.value || today());
    applyImplantPanels();
  };
  app.querySelectorAll("[data-implant-subview]").forEach((button) => {
    button.addEventListener("click", () => {
      currentImplantSubView = button.dataset.implantSubview || "today";
      ensureImplantSubView();
      renderList();
    });
  });
  dateInput.addEventListener("input", () => {
    if (backupMonthInput && dateInput.value) backupMonthInput.value = dateInput.value.slice(0, 7);
    renderList();
  });
  [nameInput, idInput, noInput].forEach((input) => input.addEventListener("input", renderList));
  document.getElementById("implantFilterReset")?.addEventListener("click", () => {
    dateInput.value = today();
    if (backupMonthInput) backupMonthInput.value = today().slice(0, 7);
    nameInput.value = "";
    idInput.value = "";
    noInput.value = "";
    renderList();
  });
  document.getElementById("assignImplantPatientNos")?.addEventListener("click", async () => {
    if (!canAssignImplantPatientNo()) return;
    const date = dateInput.value;
    try {
      const count = await assignImplantPatientNosForDate(date);
      const total = implantRecordsForDate(date).length;
      alert(count ? `${count}건의 환자번호를 부여했습니다.` : (total ? "선택 날짜의 임플란트 기록은 이미 번호가 부여되어 있습니다." : "선택 날짜의 임플란트 기록이 없습니다."));
      renderList();
    } catch (error) {
      alert(error.message);
    }
  });
  document.getElementById("closeTodayImplants")?.addEventListener("click", async () => {
    if (!canAssignImplantPatientNo()) return;
    dateInput.value = today();
    try {
      const count = await assignImplantPatientNosForDate(today());
      const total = implantRecordsForDate(today()).length;
      alert(count ? `오늘 사용분 마감 완료: ${count}건 번호를 부여했습니다.` : (total ? "오늘 사용분은 이미 마감되어 있습니다." : "오늘 저장된 임플란트 기록이 없습니다."));
      renderList();
    } catch (error) {
      alert(error.message);
    }
  });
  document.getElementById("exportImplantLedger")?.addEventListener("click", () => {
    exportImplantLedgerExcel(dateInput.value);
  });
  document.getElementById("downloadImplantMonthlyBackup")?.addEventListener("click", async () => {
    try {
      const result = await exportImplantMonthlyBackup(backupMonthInput?.value || dateInput.value.slice(0, 7), ({ done, total, failed }) => {
        const failText = failed ? ` · 실패 ${failed}` : "";
        showSaveToast(total ? `월별 백업 사진 수집 중 ${done}/${total}${failText}` : "월별 백업 생성 중입니다...", failed ? "error" : "saving", { hold: done < total });
      });
      saveDoneToast(`월별 백업 완료 · 기록 ${result.records}건 · 사진 ${result.photos}장${result.failed ? ` · 실패 ${result.failed}장` : ""}`);
    } catch (error) {
      saveErrorToast(`월별 백업 실패: ${error.message}`);
      alert(error.message);
    }
  });
  document.getElementById("prepareImplantVendorSend")?.addEventListener("click", async () => {
    const date = dateInput.value || today();
    const unnumbered = implantRecordsForDate(date).filter((record) => !implantPatientNoText(record));
    if (unnumbered.length) {
      if (canAssignImplantPatientNo() && confirm(`${unnumbered.length}건에 환자번호가 없습니다. 먼저 마감하고 발송자료를 만들까요?`)) {
        try {
          await assignImplantPatientNosForDate(date);
        } catch (error) {
          alert(error.message);
          return;
        }
      } else {
        alert("업체 발송 전 환자번호가 필요합니다.");
        return;
      }
    }
    sendPanel.hidden = false;
    sendList.innerHTML = implantSendPanelOrganizedHtml(date);
    sendPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  sendPanel?.addEventListener("click", async (event) => {
    const photoImage = event.target.closest("[data-implant-photo-view]");
    if (photoImage) {
      showImplantPhotoModal(photoImage.dataset.implantPhotoView);
      return;
    }
    const statusButton = event.target.closest("[data-set-implant-send-status]");
    if (statusButton) {
      const date = dateInput.value || today();
      const vendorName = statusButton.dataset.setImplantSendStatus;
      const status = statusButton.dataset.sendStatus;
      try {
        const count = await updateImplantSendGroupStatus(date, vendorName, status);
        sendList.innerHTML = implantSendPanelOrganizedHtml(date);
        renderList();
        saveDoneToast(`${vendorName} · ${implantSendStatusLabel(status)} 저장 완료 (${count}건)`);
      } catch (error) {
        saveErrorToast(`발송 상태 저장 실패: ${error.message}`);
        alert(error.message);
      }
      return;
    }
    const printButton = event.target.closest("[data-print-implant-send]");
    if (printButton) {
      const date = dateInput.value || today();
      const vendorName = printButton.dataset.printImplantSend;
      const group = implantSendGroups(date).find((item) => item.vendor === vendorName);
      if (!group) return;
      setButtonBusy(printButton, true, "PDF 생성 중...");
      showSaveToast("PDF 파일 생성 중입니다...", "saving", { hold: true });
      try {
        const result = await saveAndShareImplantVendorStatementPdf(date, group);
        if (result === "shared") saveDoneToast(`${vendorName} PDF 저장 및 공유 완료`);
        else if (result === "cancelled") saveDoneToast(`${vendorName} PDF 저장 완료`);
        else saveDoneToast(`${vendorName} PDF 저장 완료 · 이 기기는 파일 공유 미지원`);
      } catch (error) {
        console.error(error);
        downloadImplantVendorStatementHtml(date, group);
        saveErrorToast(`PDF 생성 실패: ${error.message || error} · HTML 명세서를 대신 다운로드했습니다.`);
      } finally {
        setButtonBusy(printButton, false);
      }
      return;
    }
    const downloadButton = event.target.closest("[data-download-implant-send]");
    if (downloadButton) {
      const date = dateInput.value || today();
      const vendorName = downloadButton.dataset.downloadImplantSend;
      const group = implantSendGroups(date).find((item) => item.vendor === vendorName);
      if (!group) return;
      downloadImplantVendorStatementHtml(date, group);
      saveDoneToast(`${vendorName} 명세서 다운로드를 시작했습니다.`);
      return;
    }
    const shareButton = event.target.closest("[data-share-implant-send]");
    if (shareButton) {
      const date = dateInput.value || today();
      const vendorName = shareButton.dataset.shareImplantSend;
      const group = implantSendGroups(date).find((item) => item.vendor === vendorName);
      if (!group) return;
      setButtonBusy(shareButton, true, "PDF 공유 중...");
      showSaveToast("PDF 파일 생성 중입니다...", "saving", { hold: true });
      try {
        const result = await shareImplantVendorStatement(date, group);
        if (result === "shared") saveDoneToast(`${vendorName} PDF 공유 완료`);
        else if (result === "cancelled") saveDoneToast(`${vendorName} PDF 저장 완료`);
        else saveDoneToast(`${vendorName} PDF 저장 완료 · 이 기기는 파일 공유 미지원`);
      } catch (error) {
        if (error?.name !== "AbortError") {
          console.error(error);
          saveErrorToast(`PDF 공유 실패: ${error.message || error}`);
        }
      } finally {
        setButtonBusy(shareButton, false);
      }
      return;
    }
    const vendor = event.target.closest("[data-send-implant-email]")?.dataset.sendImplantEmail
      || event.target.closest("[data-send-implant-sms]")?.dataset.sendImplantSms
      || event.target.closest("[data-copy-implant-send]")?.dataset.copyImplantSend;
    if (!vendor) return;
    const date = dateInput.value || today();
    const group = implantSendGroups(date).find((item) => item.vendor === vendor);
    if (!group) return;
    const message = implantSendMessage(date, group.vendor, group.lines);
    const emailButton = event.target.closest("[data-send-implant-email]");
    const smsButton = event.target.closest("[data-send-implant-sms]");
    if (emailButton) {
      const subject = encodeURIComponent(`${date} 임플란트 사용분`);
      const body = encodeURIComponent(message);
      window.location.href = `mailto:${group.contact?.email || ""}?subject=${subject}&body=${body}`;
      return;
    }
    if (smsButton) {
      const phone = String(group.contact?.phone || "").replace(/[^0-9+]/g, "");
      window.location.href = `sms:${phone}?body=${encodeURIComponent(message)}`;
      return;
    }
    try {
      await navigator.clipboard.writeText(message);
      alert("업체 발송자료를 복사했습니다.");
    } catch (error) {
      alert(message);
    }
  });
  sendPanel?.addEventListener("change", async (event) => {
    const statusSelect = event.target.closest("[data-change-implant-send-status]");
    if (!statusSelect) return;
    const date = dateInput.value || today();
    const vendorName = statusSelect.dataset.changeImplantSendStatus;
    const status = statusSelect.value;
    try {
      const count = await updateImplantSendGroupStatus(date, vendorName, status);
      sendList.innerHTML = implantSendPanelOrganizedHtml(date);
      renderList();
      saveDoneToast(`${vendorName} · ${implantSendStatusLabel(status)} 저장 완료 (${count}건)`);
    } catch (error) {
      saveErrorToast(`발송 상태 저장 실패: ${error.message}`);
      alert(error.message);
    }
  });
  summary?.addEventListener("click", (event) => {
    const image = event.target.closest("[data-implant-photo-view]");
    if (!image) return;
    showImplantPhotoModal(image.dataset.implantPhotoView);
  });
  photoStatusPanel?.addEventListener("click", async (event) => {
    const retryButton = event.target.closest("[data-retry-implant-photos]");
    if (!retryButton) return;
    const recordId = retryButton.dataset.retryImplantPhotos;
    try {
      let failedCount = 0;
      await retryImplantRecordPhotos(recordId, ({ done, total, failed }) => {
        failedCount = failed;
        const failText = failed ? ` · 실패 ${failed}` : "";
        showSaveToast(`사진 재업로드 중 ${done}/${total}${failText}`, failed ? "error" : "saving", { hold: done < total });
      });
      saveDoneToast(failedCount ? "사진 재업로드 완료 · 확인 필요" : "사진 재업로드 완료");
      renderList();
    } catch (error) {
      saveErrorToast(`사진 재업로드 실패: ${error.message}`);
      alert(error.message);
    }
  });
  list.addEventListener("click", async (event) => {
    const image = event.target.closest("[data-implant-photo-view]");
    if (image) {
      showImplantPhotoModal(image.dataset.implantPhotoView);
      return;
    }
    const retryPhotosButton = event.target.closest("[data-retry-implant-record-photos]");
    if (retryPhotosButton) {
      const recordId = retryPhotosButton.dataset.retryImplantRecordPhotos;
      try {
        setButtonBusy(retryPhotosButton, true, "재업로드 중...");
        let failedCount = 0;
        await retryImplantRecordPhotos(recordId, ({ done, total, failed }) => {
          failedCount = failed;
          const failText = failed ? ` · 실패 ${failed}` : "";
          showSaveToast(`사진 재업로드 중 ${done}/${total}${failText}`, failed ? "error" : "saving", { hold: done < total });
        });
        saveDoneToast(failedCount ? "사진 재업로드 완료 · 확인 필요" : "사진 재업로드 완료");
        renderList();
      } catch (error) {
        saveErrorToast(`사진 재업로드 실패: ${error.message}`);
        alert(error.message);
      } finally {
        setButtonBusy(retryPhotosButton, false);
      }
      return;
    }
    const unlockButton = event.target.closest("[data-unlock-implant-record]");
    if (unlockButton) {
      if (!canEditImplantPatientNo()) return;
      const id = unlockButton.dataset.unlockImplantRecord;
      await setDoc(doc(db, "implantRecords", id), {
        editUnlocked: true,
        editUnlockedAt: new Date().toISOString(),
        closedAt: null,
        updatedAt: new Date().toISOString(),
        ...auditUpdateFields()
      }, { merge: true });
      const record = implantRecords.find((item) => sameId(item.id, id));
      if (record) {
        record.editUnlocked = true;
        record.editUnlockedAt = new Date().toISOString();
        record.closedAt = null;
      }
      saveDoneToast("마감 잠금 해제 완료");
      renderList();
      return;
    }
    const lockButton = event.target.closest("[data-lock-implant-record]");
    if (lockButton) {
      if (!canEditImplantPatientNo()) return;
      const id = lockButton.dataset.lockImplantRecord;
      await setDoc(doc(db, "implantRecords", id), {
        editUnlocked: false,
        relockedAt: new Date().toISOString(),
        closedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...auditUpdateFields()
      }, { merge: true });
      const record = implantRecords.find((item) => sameId(item.id, id));
      if (record) {
        record.editUnlocked = false;
        record.relockedAt = new Date().toISOString();
        record.closedAt = record.relockedAt;
      }
      saveDoneToast("마감 잠금 완료");
      renderList();
      return;
    }
    const deleteRecordButton = event.target.closest("[data-delete-implant-record]");
    if (deleteRecordButton) {
      if (!canEditImplantPatientNo()) return;
      const id = deleteRecordButton.dataset.deleteImplantRecord;
      const record = implantRecords.find((item) => sameId(item.id, id));
      if (!record) return;
      if (!confirm("이 임플란트 장부를 삭제할까요? 연결된 사용내역은 삭제하지 않습니다.")) return;
      await deleteDoc(doc(db, "implantRecords", id));
      implantRecords = implantRecords.filter((item) => !sameId(item.id, id));
      renderList();
      return;
    }
    const saveButton = event.target.closest("[data-implant-patient-no-save]");
    if (saveButton) {
      if (!canEditImplantPatientNo()) return;
      const id = saveButton.dataset.implantPatientNoSave;
      const record = implantRecords.find((item) => sameId(item.id, id));
      const input = list.querySelector(`[data-implant-patient-no-input="${id}"]`);
      const nextNo = String(input?.value || "").trim();
      if (!record || !nextNo) {
        alert("환자번호를 입력해 주세요.");
        return;
      }
      const duplicate = implantRecords.some((item) =>
        !sameId(item.id, id) &&
        implantRecordDate(item) === implantRecordDate(record) &&
        implantPatientNoText(item) === nextNo
      );
      if (duplicate) {
        alert("같은 날짜에 이미 사용 중인 환자번호입니다.");
        return;
      }
      await setDoc(doc(db, "implantRecords", id), {
        patientNo: nextNo,
        patientNoManuallyEditedAt: new Date().toISOString(),
        patientNoAssignedAt: record.patientNoAssignedAt || new Date().toISOString(),
        closedAt: new Date().toISOString(),
        editUnlocked: false,
        updatedAt: new Date().toISOString(),
        ...auditUpdateFields()
      }, { merge: true });
      saveDoneToast("환자번호 저장 및 마감 잠금 완료");
      renderList();
    }
  });
  document.getElementById("closeImplantPhotoModal")?.addEventListener("click", hideImplantPhotoModal);
  document.getElementById("implantPhotoModal")?.addEventListener("click", (event) => {
    if (event.target.id === "implantPhotoModal") hideImplantPhotoModal();
  });
  renderList();
};

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
    await setDoc(doc(db, "implantVendors", id), vendor, { merge: true });
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
      await setDoc(doc(db, "implantVendors", vendor.id), {
        active: vendor.active === false,
        updatedAt: new Date().toISOString(),
        ...auditUpdateFields()
      }, { merge: true });
    });
  });
};

const loadImageFromFile = (file) => new Promise((resolve, reject) => {
  const image = new Image();
  image.onload = () => resolve(image);
  image.onerror = reject;
  image.src = URL.createObjectURL(file);
});

const loadImageFromUrl = async (url) => {
  const response = await fetch(url);
  if (!response.ok) throw new Error("사진 원본을 불러오지 못했습니다.");
  const objectUrl = URL.createObjectURL(await response.blob());
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      image.dataset.objectUrl = objectUrl;
      resolve(image);
    };
    image.onerror = reject;
    image.src = objectUrl;
  });
};

  const loadImageFromImplantPhoto = (photo) => photo.file
  ? loadImageFromFile(photo.file)
  : loadImageFromUrl(photo.preview || photo.url || photo.dataUrl || photo.editedPreview || "");

const implantCropNumber = (value, fallback = 0) => {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};
const implantClamp = (value, min, max) => Math.min(max, Math.max(min, value));
const normalizeImplantCropRect = (rect) => {
  const source = rect && typeof rect === "object" ? rect : {};
  const x = implantClamp(implantCropNumber(source.x), 0, 0.98);
  const y = implantClamp(implantCropNumber(source.y), 0, 0.98);
  const width = implantClamp(implantCropNumber(source.width || source.w, 0.8), 0.02, 1 - x);
  const height = implantClamp(implantCropNumber(source.height || source.h, 0.8), 0.02, 1 - y);
  return { x, y, width, height };
};
const defaultImplantCropRect = () => ({ x: 0.1, y: 0.1, width: 0.8, height: 0.8 });
const implantSourceRect = (photo, image) => {
  if (photo?.cropped && photo.cropRect) {
    const rect = normalizeImplantCropRect(photo.cropRect);
    return {
      x: Math.round(rect.x * image.naturalWidth),
      y: Math.round(rect.y * image.naturalHeight),
      width: Math.max(1, Math.round(rect.width * image.naturalWidth)),
      height: Math.max(1, Math.round(rect.height * image.naturalHeight))
    };
  }
  if (photo?.cropped) {
    const cropSize = Math.min(image.naturalWidth, image.naturalHeight);
    return {
      x: Math.round((image.naturalWidth - cropSize) / 2),
      y: Math.round((image.naturalHeight - cropSize) / 2),
      width: cropSize,
      height: cropSize
    };
  }
  return { x: 0, y: 0, width: image.naturalWidth, height: image.naturalHeight };
};

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
const promiseWithTimeout = (promise, timeoutMs, message) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  promise.then((value) => {
    clearTimeout(timer);
    resolve(value);
  }).catch((error) => {
    clearTimeout(timer);
    reject(error);
  });
});
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

const cleanImplantPhotoPayload = (photo) => ({
  id: photo.id || uid(),
  url: photo.url || "",
  path: photo.path || "",
  dataUrl: photo.dataUrl || "",
  name: photo.name || "",
  size: num(photo.size),
  contentType: photo.contentType || "image/jpeg",
  rotation: num(photo.rotation),
  cropped: Boolean(photo.cropped),
  cropRect: photo.cropped && photo.cropRect ? normalizeImplantCropRect(photo.cropRect) : null,
  sourceCommonPhotoId: photo.sourceCommonPhotoId || "",
  uploadedAt: photo.uploadedAt || "",
  needsReupload: Boolean(photo.needsReupload),
  storageUploadFailed: Boolean(photo.storageUploadFailed),
  storageUploadError: photo.storageUploadError || ""
});

const implantPhotoCacheKey = (photo = {}) => {
  const source = photo.sourceCommonPhotoId
    || (photo.file ? `file:${photo.file.name || ""}:${photo.file.size || 0}:${photo.file.lastModified || 0}` : "");
  if (!source) return "";
  const crop = photo.cropped && photo.cropRect ? normalizeImplantCropRect(photo.cropRect) : null;
  return JSON.stringify({
    source,
    rotation: num(photo.rotation),
    cropped: Boolean(photo.cropped),
    crop
  });
};

const cloneImplantPhotoPayload = (payload = {}, photo = {}) => ({
  ...cleanImplantPhotoPayload(payload),
  id: photo.id || payload.id || uid(),
  name: photo.file?.name || photo.name || payload.name || "",
  sourceCommonPhotoId: photo.sourceCommonPhotoId || payload.sourceCommonPhotoId || ""
});

const cachedImplantPhotoPayload = async (photo, cache, buildPayload) => {
  const key = implantPhotoCacheKey(photo);
  if (key && cache?.has(key)) return cloneImplantPhotoPayload(cache.get(key), photo);
  const payload = await buildPayload();
  if (key && cache) cache.set(key, payload);
  return cloneImplantPhotoPayload(payload, photo);
};

const countImplantPhotosToUpload = (implants = []) => implants.reduce((sum, implant) => (
  sum + (implant.photos || []).filter((photo) => photo.file || photo.needsReupload).length
), 0);

const notifyImplantPhotoUpload = (onProgress, done, total, failed = 0) => {
  if (!total) return;
  if (typeof onProgress === "function") {
    onProgress({ done, total, failed });
  } else {
    const failText = failed ? ` · 실패 ${failed}장` : "";
    showSaveToast(`사진 업로드 중 ${done}/${total}${failText}`, failed ? "error" : "saving", { hold: done < total, duration: done >= total ? 1800 : undefined });
  }
};

const saveImplantRecordFromEdit = async (usage, recordId, implants, options = {}) => {
  if (!recordId && !implants.length) return;
  const nextRecordId = recordId || uid();
  const existing = recordId ? implantRecords.find((record) => sameId(record.id, recordId)) : null;
  if (existing && !canModifyImplantRecord(existing)) {
    throw new Error("임플란트 기록 수정 권한이 없습니다.");
  }
  const surgeryDate = usage.date || today();
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
      pendingPhotoCount: (implant.photos || []).filter((photo) => photo.file || photo.needsReupload).length
    });
  }
  await setDoc(doc(db, "implantRecords", nextRecordId), {
    id: nextRecordId,
    ...(existing?.patientNo ? { patientNo: existing.patientNo } : { patientNo: "" }),
    ...implantRecordBasePayload(usage),
    implants: cleanImplants,
    sendReady: cleanImplants.length > 0,
    updatedAt: new Date().toISOString(),
    ...(existing?.createdAt ? {} : { createdAt: new Date().toISOString() }),
    ...(existing ? auditUpdateFields() : auditCreateFields())
  }, { merge: true });

  const uploadedImplants = [];
  const uploadTotal = countImplantPhotosToUpload(implants);
  let uploadDone = 0;
  let uploadFailed = 0;
  const uploadPhotoCache = new Map();
  notifyImplantPhotoUpload(options.onPhotoProgress, uploadDone, uploadTotal, uploadFailed);
  for (const implant of implants) {
    const implantId = implant.id || uid();
    const photos = (implant.photos || [])
      .filter((photo) => (photo.url || photo.dataUrl) && !(photo.file || photo.needsReupload))
      .map(cleanImplantPhotoPayload);
    const photoUploadErrors = [];
    for (const photo of implant.photos || []) {
      if (photo.file || photo.needsReupload) {
        try {
          photos.push(await cachedImplantPhotoPayload(
            photo,
            uploadPhotoCache,
            () => uploadImplantPhoto(nextRecordId, implantId, photo, surgeryDate)
          ));
        } catch (error) {
          console.error(error);
          if (photo.url) photos.push(cleanImplantPhotoPayload(photo));
          else photos.push(await implantPhotoFallbackPayload(photo, error.message || "사진 업로드 실패"));
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
  const setRestrictButton = (value) => {
    manualRestrictNonpay = Boolean(value);
    useRestrictNonpay.dataset.restrict = value ? "true" : "false";
    useRestrictNonpay.textContent = value ? "비급여 제한 켜짐" : "비급여 제한 꺼짐";
    useRestrictNonpay.classList.toggle("danger", Boolean(value));
    useRestrictNonpay.classList.toggle("secondary", !value);
  };
  const isRestrictOn = () => manualRestrictNonpay;
  const currentUseRule = () => state.usageRules.find((rule) =>
    rule.department === useDepartment.value &&
    rule.doctorId === departmentSelect.value &&
    rule.surgeryId === surgerySelect.value
  );
  const selectedUseItems = () => Array.from(app.querySelectorAll("[data-use-product]:checked")).map((input) => ({
    productId: input.value,
    qty: Math.max(1, num(form.querySelector(`[data-use-qty="${input.value}"]`)?.value))
  }));
  const renderSelectedUseList = () => {
    const items = selectedUseItems();
    if (!items.length) {
      selectedUseList.innerHTML = `<span>선택된 제품이 없습니다.</span>`;
      syncImplantDraftsFromSelectedProducts();
      return;
    }
    const chipClass = (category) => {
      const key = productCategory(category);
      if (key === "비급여") return "nonpay";
      if (key === "인체조직") return "tissue";
      if (["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(key)) return "anchor";
      return "";
    };
    selectedUseList.innerHTML = `
      <div class="selected-use-buttons">
        ${items.map((item) => {
          const product = productById(item.productId);
          if (!product) return "";
          const meta = [productCategoryLabel(product.category), product.company, product.subcategory].filter(Boolean).join(" · ");
          return `
            <div class="selected-use-chip ${chipClass(product.category)}">
              <div class="selected-use-name" title="${escapeHtml(product.name)}">
                ${escapeHtml(product.name)}<span>${escapeHtml(meta)}</span>
              </div>
              <div class="selected-use-controls">
                <button type="button" class="secondary" data-selected-dec="${item.productId}" aria-label="수량 줄이기">−</button>
                <input type="number" min="1" max="${Math.max(1, num(product.stock) + item.qty)}" value="${item.qty}" data-selected-qty="${item.productId}" aria-label="${escapeHtml(product.name)} 수량" readonly>
                <button type="button" class="secondary" data-selected-inc="${item.productId}" aria-label="수량 늘리기">+</button>
                <button type="button" class="remove-selected" data-selected-remove="${item.productId}">삭제</button>
              </div>
            </div>
          `;
        }).join("")}
      </div>
    `;
    selectedUseList.querySelectorAll("[data-selected-remove]").forEach((button) => {
      button.addEventListener("click", () => {
        const checkbox = app.querySelector(`[data-use-product="${button.dataset.selectedRemove}"]`);
        if (checkbox) checkbox.checked = false;
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
    renderSelectedUseList();
  };
  const addImplantDraft = () => {
    implantDrafts.push({ id: uid(), vendorId: "", customVendor: "", description: "", photos: [] });
    renderImplantDrafts();
  };
  const cloneCommonImplantPhoto = (photo) => ({
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
  const renderCommonImplantPhotos = () => {
    if (!commonImplantPhotoList) return;
    commonImplantPhotoList.innerHTML = commonImplantPhotos.map((photo, index) => {
      const src = implantPhotoViewSrc(photo);
      return `
        <div class="implant-common-photo" data-common-implant-photo="${escapeHtml(photo.id)}">
          ${src ? `<img src="${escapeHtml(src)}" alt="공용 임플란트 사진 ${index + 1}" data-preview-common-implant-photo="${escapeHtml(photo.id)}">` : ""}
          <div class="implant-photo-actions">
            <button class="secondary" type="button" data-preview-common-implant-photo="${escapeHtml(photo.id)}">확대</button>
            <button class="danger" type="button" data-remove-common-implant-photo="${escapeHtml(photo.id)}">삭제</button>
          </div>
        </div>
      `;
    }).join("") || `<div class="empty">공용 사진을 먼저 촬영하거나 선택해 주세요.</div>`;
  };
  const addCommonImplantPhotos = (files = []) => {
    files.filter((file) => file.type.startsWith("image/")).forEach((file) => {
      commonImplantPhotos.push({
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
    renderCommonImplantPhotos();
  };
  const commonImplantPhotoById = (id) => commonImplantPhotos.find((photo) => photo.id === id);
  const mergeImplantDescription = (left = "", right = "") => {
    return mergeImplantDescriptionLines(left, right);
  };
  const mergeDuplicateImplantDrafts = () => {
    const kept = [];
    let changed = false;
    for (let index = 0; index < implantDrafts.length; index += 1) {
      const draft = implantDrafts[index];
      const existing = kept.find((item) => implantVendorEntriesMatch(item, draft));
      if (!existing) {
        kept.push(draft);
        continue;
      }
      existing.vendorId = existing.vendorId || draft.vendorId || "";
      existing.customVendor = existing.customVendor || draft.customVendor || "";
      existing.vendor = existing.vendor || draft.vendor || "";
      existing.autoSource = existing.autoSource || draft.autoSource;
      existing.autoCompanyKey = existing.autoCompanyKey || draft.autoCompanyKey || "";
      existing.description = mergeImplantDescription(existing.description, draft.description);
      existing.autoDescription = mergeImplantDescription(existing.autoDescription, draft.autoDescription);
      const existingPhotoIds = new Set((existing.photos || []).map((photo) => photo.id));
      (draft.photos || []).forEach((photo) => {
        if (!existingPhotoIds.has(photo.id)) {
          existing.photos = existing.photos || [];
          existing.photos.push(photo);
          existingPhotoIds.add(photo.id);
        }
      });
      implantDrafts.splice(index, 1);
      index -= 1;
      changed = true;
    }
    return changed;
  };
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
  const implantDraftById = (id) => implantDrafts.find((item) => item.id === id);
  const currentImplantDraftPayload = () => {
    const implantWillSave = implantEnabled?.checked;
    if (implantWillSave) mergeDuplicateImplantDrafts();
    return implantWillSave ? implantDrafts.map((draft) => ({
      ...draft,
      vendorId: draft.vendorId || "",
      customVendor: String(draft.customVendor || "").trim(),
      description: String(draft.description || "").trim()
    })).filter((draft) => {
      const vendor = draft.vendorId === "__custom__" ? draft.customVendor : implantVendorById(draft.vendorId)?.name;
      return String(vendor || "").trim() || draft.description || (draft.photos || []).length;
    }) : [];
  };
  const invalidImplantDraft = (payload) => payload.find((draft) => {
    const vendor = draft.vendorId === "__custom__" ? draft.customVendor : implantVendorById(draft.vendorId)?.name;
    return !String(vendor || "").trim() || (!draft.description && !(draft.photos || []).length);
  });
  const renderImplantDrafts = () => {
    implantEntriesWrap.innerHTML = implantDrafts.map((draft, index) => `
      <div class="implant-vendor-card" data-implant-draft="${escapeHtml(draft.id)}">
        <div class="implant-vendor-head">
          <strong>업체 ${index + 1}</strong>
          <button class="danger" type="button" data-remove-implant-draft="${escapeHtml(draft.id)}">업체 삭제</button>
        </div>
        <div class="row two">
          <div>
            <label for="implantVendorSelect-${escapeHtml(draft.id)}">업체명</label>
            <select id="implantVendorSelect-${escapeHtml(draft.id)}" data-implant-vendor-select="${escapeHtml(draft.id)}">
              ${implantVendorOptions(draft.vendorId)}
            </select>
          </div>
          <div ${draft.vendorId === "__custom__" ? "" : "hidden"}>
            <label for="implantVendorCustom-${escapeHtml(draft.id)}">직접 입력</label>
            <input id="implantVendorCustom-${escapeHtml(draft.id)}" data-implant-vendor-custom="${escapeHtml(draft.id)}" value="${escapeHtml(draft.customVendor || "")}" autocomplete="off">
          </div>
        </div>
        <label for="implantDescription-${escapeHtml(draft.id)}">사용내용</label>
        <textarea id="implantDescription-${escapeHtml(draft.id)}" data-implant-description="${escapeHtml(draft.id)}" placeholder="Plate 255-209-L&#10;Screw 22mm 3ea">${escapeHtml(draft.description || "")}</textarea>
        <label for="implantPhotos-${escapeHtml(draft.id)}">사진첨부</label>
        <div class="implant-photo-pickers">
          <button class="secondary" type="button" data-open-implant-gallery="${escapeHtml(draft.id)}">파일 선택</button>
          <button type="button" data-open-implant-camera="${escapeHtml(draft.id)}">사진 찍기</button>
          <button class="secondary" type="button" data-use-common-implant-photo="${escapeHtml(draft.id)}" ${commonImplantPhotos.length ? "" : "disabled"}>공용 사진 사용</button>
          <span class="muted">Android/iPad 카메라와 갤러리를 지원합니다.</span>
          <input id="implantGallery-${escapeHtml(draft.id)}" type="file" accept="image/*" multiple data-implant-photo-input="${escapeHtml(draft.id)}">
          <input id="implantCamera-${escapeHtml(draft.id)}" type="file" accept="image/*" capture="environment" data-implant-camera-input="${escapeHtml(draft.id)}">
        </div>
        <div class="implant-photo-grid">
          ${(draft.photos || []).map((photo, photoIndex) => `
            <div class="implant-photo" data-implant-photo="${escapeHtml(photo.id)}">
              <img class="${photo.cropped ? "cropped" : ""}" src="${escapeHtml(implantPhotoViewSrc(photo))}" alt="임플란트 사진 미리보기" data-preview-implant-photo="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}" style="${implantPhotoRotationStyle(photo)} cursor:pointer;">
              <div class="implant-photo-actions">
                <button class="secondary" type="button" data-preview-implant-photo="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}">확대</button>
                <button class="secondary" type="button" data-edit-implant-photo="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}">편집</button>
                <button class="secondary" type="button" data-rotate-implant-photo="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}">회전</button>
                <button class="secondary" type="button" data-move-implant-photo-up="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}" ${photoIndex === 0 ? "disabled" : ""}>앞</button>
                <button class="secondary" type="button" data-move-implant-photo-down="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}" ${photoIndex === draft.photos.length - 1 ? "disabled" : ""}>뒤</button>
                <button class="danger" type="button" data-remove-implant-photo="${escapeHtml(draft.id)}::${escapeHtml(photo.id)}">삭제</button>
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    `).join("") || `<div class="empty">임플란트 업체를 추가해 주세요.</div>`;
  };
  const draftUserText = () => currentAuditUser()?.name || currentAuditUser()?.loginId || "현재 사용자";
  const collectUseDraftSnapshot = () => {
    if (!form.reportValidity()) return null;
    const useItems = selectedUseItems();
    const implantDraftPayload = currentImplantDraftPayload();
    if (!useItems.length && !implantDraftPayload.length) {
      alert("제품을 선택하거나 임플란트 장부를 작성해 주세요.");
      return null;
    }
    const unavailable = useItems.find((item) => num(productById(item.productId)?.stock) < item.qty);
    if (unavailable) {
      alert("재고가 부족한 제품이 있습니다.");
      return null;
    }
    if (invalidImplantDraft(implantDraftPayload)) {
      alert("임플란트 장부가 작성되지 않았습니다. 업체명과 사용내용 또는 사진을 확인해 주세요.");
      return null;
    }
    return {
      date: selectedUseDate(),
      patientName: document.getElementById("patientName").value.trim(),
      patientId: document.getElementById("patientId").value.trim(),
      doctorText: departmentSelect.selectedOptions[0]?.textContent || "-",
      surgeryText: surgerySelect.selectedOptions[0]?.textContent || "-",
      enteredBy: draftUserText(),
      enteredAt: new Date().toISOString(),
      useItems,
      implantDraftPayload
    };
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
    const totalPhotos = snapshot.implantDraftPayload.reduce((sum, draft) => sum + (draft.photos || []).filter((photo) => !(photo.url || photo.dataUrl)).length, 0);
    let donePhotos = 0;
    let failedPhotos = 0;
    const payload = await buildPendingUsagePayload(snapshot, pendingId, (failed) => {
      donePhotos += 1;
      if (failed) failedPhotos += 1;
      const failText = failedPhotos ? ` · 실패 ${failedPhotos}장` : "";
      showSaveToast(`임시저장 사진 처리 중 ${donePhotos}/${totalPhotos}${failText}`, failedPhotos ? "error" : "saving", { hold: donePhotos < totalPhotos });
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
    const productLines = useDraftSnapshot.useItems.map((item) => {
      const product = productById(item.productId);
      return `${product?.name || "삭제된 제품"} ${item.qty}개`;
    });
    const implantPhotoCount = useDraftSnapshot.implantDraftPayload.reduce((sum, draft) => sum + (draft.photos || []).length, 0);
    useDraftPanel.hidden = false;
    if (useDraftStatus) {
      useDraftStatus.textContent = useDraftDirty ? "수정 중 · 임시저장 갱신 필요" : "임시저장 완료";
      useDraftStatus.classList.toggle("dirty", useDraftDirty);
    }
    if (finalSaveUseDraftButton) finalSaveUseDraftButton.disabled = useDraftDirty;
    if (saveUseDraftButton) saveUseDraftButton.textContent = useDraftSnapshot ? "임시저장 갱신" : "임시저장";
    useDraftSummary.innerHTML = `
      <div><span>환자</span> ${escapeHtml(useDraftSnapshot.patientName || "-")} ${useDraftSnapshot.patientId ? `(${escapeHtml(useDraftSnapshot.patientId)})` : ""}</div>
      <div><span>사용일</span> ${escapeHtml(useDraftSnapshot.date || today())}</div>
      <div><span>수술</span> ${escapeHtml(useDraftSnapshot.doctorText)} · ${escapeHtml(useDraftSnapshot.surgeryText)}</div>
      <div><span>사용제품</span> ${escapeHtml(productLines.join(", ") || "-")}</div>
      <div><span>임플란트</span> ${useDraftSnapshot.implantDraftPayload.length ? `${useDraftSnapshot.implantDraftPayload.length}개 업체 · 사진 ${implantPhotoCount}장` : "기록 없음"}</div>
      <div><span>임시저장</span> ${escapeHtml(useDraftSnapshot.enteredBy)} · ${escapeHtml(formatDateTime(useDraftSnapshot.enteredAt))}</div>
    `;
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
    form.querySelectorAll("[data-use-product]").forEach((input) => { input.checked = false; });
    form.querySelectorAll("[data-use-qty]").forEach((input) => { input.value = 1; });
    (pending.productItems || []).forEach((item) => {
      const checkbox = form.querySelector(`[data-use-product="${item.productId}"]`);
      const qtyInput = form.querySelector(`[data-use-qty="${item.productId}"]`);
      if (checkbox) checkbox.checked = true;
      if (qtyInput) qtyInput.value = Math.max(1, num(item.qty));
    });
    renderSelectedUseList();
    implantDrafts.splice(0, implantDrafts.length, ...(pending.implantDrafts || []).map((draft) => ({
      id: draft.id || uid(),
      vendorId: draft.vendorId || "",
      customVendor: draft.customVendor || "",
      vendor: draft.vendor || "",
      description: draft.description || "",
      photos: (draft.photos || []).map(cleanImplantPhotoPayload)
    })));
    if (implantEnabled) implantEnabled.checked = implantDrafts.length > 0;
    if (implantPanel) implantPanel.hidden = !implantDrafts.length;
    loadedPendingUsageId = pending.id || "";
    renderImplantDrafts();
    useDraftSnapshot = collectUseDraftSnapshot();
    if (useDraftSnapshot) {
      useDraftSnapshot.enteredBy = pending.draftSavedBy || pending.enteredBy?.name || pending.enteredBy?.loginId || useDraftSnapshot.enteredBy;
      useDraftSnapshot.enteredAt = pending.updatedAt || pending.createdAt || useDraftSnapshot.enteredAt;
    }
    useDraftDirty = false;
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
    const [draftId, photoId] = String(value || "").split("::");
    const draft = implantDraftById(draftId);
    const photo = draft?.photos?.find((item) => item.id === photoId);
    return { draft, photo };
  };
  const refreshImplantPhotoEditor = () => {
    const { photo } = parseImplantPair(activeImplantEditPair);
    const image = document.getElementById("implantPhotoModalImage");
    const tools = document.getElementById("implantPhotoEditTools");
    const cropButton = document.getElementById("implantModalCrop");
    if (!photo || !image || !tools) return;
    image.src = implantPhotoViewSrc(photo);
    image.style.transform = implantPhotoRotationStyle(photo).replace("transform:", "").replace(";", "");
    image.classList.toggle("cropped", Boolean(photo.cropped));
    tools.hidden = false;
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
      renderImplantDrafts();
      refreshImplantPhotoEditor();
    };
    refreshImplantPhotoEditor();
  };
  const renderProductSearchResults = () => {
    const query = normalizedName(productSearch.value);
    if (!query) {
      productSearchResults.innerHTML = `<div class="empty">제품명을 입력해 주세요.</div>`;
      return;
    }
    const results = state.products
      .filter((item) => normalizedName(`${item.name} ${item.company || ""} ${item.subcategory || ""} ${productCategoryLabel(item.category)}`).includes(query))
      .sort(byName)
      .slice(0, 12);
    productSearchResults.innerHTML = results.length ? results.map((item) => `
      <label class="check-card use-card">
        <input type="checkbox" value="${item.id}" data-search-product="${item.id}" ${form.querySelector(`[data-use-product="${item.id}"]`)?.checked ? "checked" : ""}>
        <span>${escapeHtml(item.name)}<br><span class="muted">${escapeHtml(productCategoryLabel(item.category))}${item.company ? ` · ${escapeHtml(item.company)}` : ""}${item.subcategory ? ` · ${escapeHtml(item.subcategory)}` : ""} · 현재고 ${num(item.stock)}</span></span>
        ${qtyStepper(`data-search-qty="${item.id}" aria-label="${escapeHtml(item.name)} 검색 사용 수량"`, Math.max(1, num(form.querySelector(`[data-use-qty="${item.id}"]`)?.value) || 1), Math.max(1, num(item.stock)))}
      </label>
    `).join("") : `<div class="empty">검색 결과가 없습니다.</div>`;
    productSearchResults.querySelectorAll("[data-search-product]").forEach((input) => {
      input.addEventListener("change", () => {
        const qty = productSearchResults.querySelector(`[data-search-qty="${input.value}"]`)?.value;
        if (input.checked) selectUseProduct(input.value, qty);
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
      recommendation.innerHTML = hasSurgerySelection
        ? `<div class="empty">추천 비급여가 등록되지 않은 수술입니다. 수술은 저장할 수 있으며, 필요한 제품은 아래에서 직접 선택해 주세요.</div>`
        : "";
      app.querySelectorAll("[data-use-product]").forEach((input) => input.closest(".check-card").style.display = "");
      renderSelectedUseList();
      return;
    }
    const recommendedItems = ruleItems(rule);
    const recommended = recommendedItems.map((item) => ({ ...item, product: productById(item.productId) })).filter((item) => item.product);
    recommendation.innerHTML = `
      <div class="item ${restrictActive ? "landing-line pending" : ""}">
        <div class="item-title">
          <span>${restrictActive ? "비급여 제한" : "추천 항목"}</span>
          <span class="pill ${restrictActive ? "low" : ""}">${recommended.length}</span>
        </div>
        <div class="meta"><span>${escapeHtml(restrictActive ? "이 환자는 비급여 제한으로 선택되어 있습니다. 추천 비급여만 숨겨지고, 인체조직/ANCHOR 추천은 선택할 수 있습니다." : "추천 항목을 선택하고 수량을 조절해 사용내용에 넣을 수 있습니다.")}</span></div>
        ${recommended.filter((item) => !(restrictActive && productCategory(item.product.category) === "비급여")).map((item) => `
          <label class="check-card use-card">
            <input type="checkbox" value="${item.productId}" data-recommend-product="${item.productId}">
            <span>${escapeHtml(item.product.name)}<br><span class="muted">추천 ${Math.max(1, num(item.qty))}개 · 현재고 ${num(item.product.stock)}</span></span>
            ${qtyStepper(`data-recommend-qty="${item.productId}" aria-label="${escapeHtml(item.product.name)} 추천 사용 수량"`, Math.max(1, num(item.qty)), Math.max(1, num(item.product.stock)))}
          </label>
        `).join("")}
      </div>
    `;
    form.querySelectorAll("[data-use-product]").forEach((input) => {
      const product = productById(input.value);
      const recommendedItem = recommendedItems.find((item) => item.productId === input.value);
      const isRecommended = Boolean(recommendedItem);
      if (product && productCategory(product.category) === "비급여" && restrictActive && isRecommended) {
        input.checked = false;
        input.closest(".check-card").style.display = "none";
      } else {
        input.closest(".check-card").style.display = "";
      }
    });
    app.querySelectorAll("[data-recommend-product]").forEach((input) => {
      input.addEventListener("change", () => {
        const linked = form.querySelector(`[data-use-product="${input.value}"]`);
        const qtyInput = form.querySelector(`[data-use-qty="${input.value}"]`);
        const recommendQty = app.querySelector(`[data-recommend-qty="${input.value}"]`);
        if (linked) linked.checked = input.checked;
        if (qtyInput && recommendQty) qtyInput.value = Math.max(1, num(recommendQty.value));
        renderSelectedUseList();
      });
    });
    app.querySelectorAll("[data-recommend-qty]").forEach((input) => {
      input.addEventListener("input", () => {
        const linked = app.querySelector(`[data-use-product="${input.dataset.recommendQty}"]`);
        const qtyInput = app.querySelector(`[data-use-qty="${input.dataset.recommendQty}"]`);
        if (linked) linked.checked = true;
        if (qtyInput) qtyInput.value = Math.max(1, num(input.value));
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
  useDepartment.addEventListener("change", filterUseOptions);
  departmentSelect.addEventListener("change", filterUseOptions);
  surgerySelect.addEventListener("change", renderUseRecommendation);
  useRestrictNonpay.addEventListener("click", () => {
    setRestrictButton(!isRestrictOn());
    renderUseRecommendation();
  });
  form.querySelectorAll("[data-use-product], [data-use-qty]").forEach((input) => {
    input.addEventListener("change", renderSelectedUseList);
    input.addEventListener("input", renderSelectedUseList);
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
  form.addEventListener("input", markUseDraftDirty, true);
  form.addEventListener("change", markUseDraftDirty, true);
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
      renderImplantDrafts();
    });
  });
  commonImplantPhotoList?.addEventListener("click", (event) => {
    const preview = event.target.closest("[data-preview-common-implant-photo]");
    if (preview) {
      const photo = commonImplantPhotoById(preview.dataset.previewCommonImplantPhoto);
      if (photo) {
        activeImplantEditPair = "";
        const tools = document.getElementById("implantPhotoEditTools");
        const image = document.getElementById("implantPhotoModalImage");
        if (tools) tools.hidden = true;
        if (image) image.style.transform = "";
        showImplantPhotoModal(implantPhotoViewSrc(photo));
      }
      return;
    }
    const remove = event.target.closest("[data-remove-common-implant-photo]");
    if (remove) {
      const index = commonImplantPhotos.findIndex((photo) => photo.id === remove.dataset.removeCommonImplantPhoto);
      if (index >= 0) {
        URL.revokeObjectURL(commonImplantPhotos[index].preview);
        commonImplantPhotos.splice(index, 1);
        renderCommonImplantPhotos();
        renderImplantDrafts();
      }
    }
  });
  implantEnabled?.addEventListener("change", () => {
    implantPanel.hidden = !implantEnabled.checked;
    if (implantEnabled.checked && !implantDrafts.length) addImplantDraft();
  });
  addImplantVendorEntry?.addEventListener("click", addImplantDraft);
  implantEntriesWrap?.addEventListener("input", (event) => {
    updateImplantDraftFromInput(event.target);
  });
  implantEntriesWrap?.addEventListener("change", async (event) => {
    const target = event.target;
    updateImplantDraftFromInput(target);
    if (target.matches("[data-implant-photo-input], [data-implant-camera-input]")) {
      const draft = implantDraftById(target.dataset.implantPhotoInput || target.dataset.implantCameraInput);
      if (!draft) return;
      const files = Array.from(target.files || []).filter((file) => file.type.startsWith("image/"));
      files.forEach((file) => draft.photos.push({
        id: uid(),
        file,
        preview: URL.createObjectURL(file),
        rotation: 0,
        cropped: false
      }));
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
      renderImplantDrafts();
      if (addedPhotos.length === 1) {
        openImplantPhotoEditor(`${draft.id}::${addedPhotos[0].id}`);
      }
      return;
    }
    const removeDraft = event.target.closest("[data-remove-implant-draft]");
    if (removeDraft) {
      const index = implantDrafts.findIndex((item) => item.id === removeDraft.dataset.removeImplantDraft);
      if (index >= 0) {
        (implantDrafts[index].photos || []).forEach((photo) => URL.revokeObjectURL(photo.preview));
        implantDrafts.splice(index, 1);
        renderImplantDrafts();
      }
      return;
    }
    const previewButton = event.target.closest("[data-preview-implant-photo]");
    if (previewButton) {
      const { photo } = parseImplantPair(previewButton.dataset.previewImplantPhoto);
      activeImplantEditPair = "";
      const tools = document.getElementById("implantPhotoEditTools");
      const image = document.getElementById("implantPhotoModalImage");
      if (tools) tools.hidden = true;
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
        await refreshEditedImplantPreview(photo);
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
    await refreshEditedImplantPreview(photo);
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
    if (usageDate !== today() && !confirm(`${usageDate} 사용분으로 저장합니다. 계속할까요?`)) {
      return;
    }
    const productIds = useItems.flatMap((item) => Array.from({ length: item.qty }, () => item.productId));
    const uniqueProductIds = useItems.map((item) => item.productId);
    const selectedNonpayIds = uniqueProductIds.filter((id) => productCategory(productById(id)?.category) === "비급여");
    if (restrictActive && selectedNonpayIds.length && !confirm("비급여 제한으로 설정된 수술입니다. 그래도 비급여를 사용할까요?")) {
      return;
    }
    const expectedRecommendations = productIds.length && rule
      ? ruleItems(rule).filter((item) => !(restrictActive && productCategory(productById(item.productId)?.category) === "비급여"))
      : [];
    const missingRecommended = expectedRecommendations
      .map((item) => item.productId)
      .filter((id) => !uniqueProductIds.includes(id));
    if (missingRecommended.length) {
      const missingNames = missingRecommended.map((id) => productById(id)?.name).filter(Boolean).join(", ");
      if (!confirm(`추천 항목이 선택되지 않았습니다: ${missingNames}\n정말 사용하지 않겠습니까?\n확인을 누르면 사용안함으로 저장합니다.`)) {
        return;
      }
    }
    const changedRecommended = expectedRecommendations.filter((item) => {
        const selected = useItems.find((useItem) => useItem.productId === item.productId);
        return selected && selected.qty !== Math.max(1, num(item.qty));
      });
    if (changedRecommended.length) {
      const changedNames = changedRecommended.map((item) => {
        const product = productById(item.productId);
        const selected = useItems.find((useItem) => useItem.productId === item.productId);
        return `${product?.name || "삭제된 제품"} 추천 ${Math.max(1, num(item.qty))}개 / 선택 ${selected?.qty || 0}개`;
      }).join(", ");
      if (!confirm(`추천 항목 수량과 다릅니다: ${changedNames}\n그래도 저장할까요?`)) {
        return;
      }
    }
    if (!productIds.length && !implantDraftPayload.length) {
      alert("제품을 선택하거나 임플란트 장부를 작성해 주세요.");
      return;
    }
    const unavailable = useItems.find((item) => num(productById(item.productId)?.stock) < item.qty);
    if (unavailable) {
      alert("재고가 부족한 제품이 있습니다.");
      return;
    }
    const invalidImplant = invalidImplantDraft(implantDraftPayload);
    if (invalidImplant) {
      alert("임플란트 장부가 작성되지 않았습니다. 업체명과 사용내용 또는 사진을 확인해 주세요.");
      return;
    }
    setButtonBusy(submitButton, true, "저장 중...");
    useItems.forEach((item) => {
      const product = productById(item.productId);
      product.stock = num(product.stock) - item.qty;
    });
    const finalSavedAt = new Date().toISOString();
    const usageRecord = {
      id: uid(),
      patientName: document.getElementById("patientName").value.trim(),
      patientId: document.getElementById("patientId").value.trim(),
      doctorId: document.getElementById("useDoctor").value,
      surgeryId: document.getElementById("useSurgery").value,
      productIds,
      date: usageDate,
      createdAt: finalSavedAt,
      doubleCheck: {
        mode: "circulatorDraftScrubFinal",
        status: "finalSaved",
        draftSavedBy: useDraftSnapshot.enteredBy,
        draftSavedAt: useDraftSnapshot.enteredAt,
        finalSavedBy: draftUserText(),
        finalSavedAt
      },
      ...auditCreateFields()
    };
    state.usages.push(usageRecord);
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

const filteredHistoryUsages = (start, end, query) => {
  const normalizedQuery = normalizedName(query || "");
  return state.usages.filter((usage) => {
    if (!inDateRange(usage.date, start, end)) return false;
    if (!normalizedQuery) return true;
    const doctor = departmentById(usage.doctorId);
    const surgery = surgeryById(usage.surgeryId);
    const productText = usage.productIds.map((id) => {
      const product = productById(id);
      return `${product?.name || ""} ${product?.company || ""} ${product?.subcategory || ""}`;
    }).join(" ");
    return normalizedName(`${usage.patientName || ""} ${patientIdText(usage)} ${doctor?.name || ""} ${surgery?.name || ""} ${productText}`).includes(normalizedQuery);
  });
};

const historyPeriodText = (start = "", end = "") => start || end
  ? `${start || "처음"} ~ ${end || "오늘"}`
  : "전체 기간";

const historyMovementCounts = (start = "", end = "") => {
  const usageCounts = new Map();
  filteredHistoryUsages(start, end, "").forEach((usage) => {
    usage.productIds.forEach((id) => usageCounts.set(id, (usageCounts.get(id) || 0) + 1));
  });
  const receiptCounts = new Map();
  state.receipts
    .filter((receipt) => inDateRange(receiptDateValue(receipt), start, end))
    .forEach((receipt) => receiptCounts.set(receipt.productId, (receiptCounts.get(receipt.productId) || 0) + num(receipt.qty)));
  return { usageCounts, receiptCounts };
};

const usageDateValue = (usage) => usage?.date || String(usage?.createdAt || usage?.updatedAt || "").slice(0, 10) || "";
const reportPeriodFromFilters = (start = "", end = "") => {
  const fallback = today();
  const periodStart = start || end || fallback;
  const periodEnd = end || start || fallback;
  return periodStart <= periodEnd
    ? { start: periodStart, end: periodEnd }
    : { start: periodEnd, end: periodStart };
};
const reportPeriodLabel = (period) => period.start === period.end ? period.start : `${period.start} ~ ${period.end}`;
const productSeedFor = (product) => {
  const seeds = parseSeedProducts();
  const seedByKey = new Map(seeds.map((item) => [productKey(item), item]));
  const seedByLooseKey = new Map(seeds.map((item) => [productLooseKey(item), item]));
  return seedByKey.get(productKey(product)) || seedByLooseKey.get(productLooseKey(product));
};
const productMovementTotal = (productId, type, dateMatch = () => true) => {
  if (type === "receipt") {
    return state.receipts.reduce((sum, receipt) => {
      if (!sameId(receipt.productId, productId) || !dateMatch(receiptDateValue(receipt))) return sum;
      return sum + num(receipt.qty);
    }, 0);
  }
  return state.usages.reduce((sum, usage) => {
    if (!dateMatch(usageDateValue(usage))) return sum;
    return sum + (Array.isArray(usage.productIds) ? usage.productIds : []).filter((id) => sameId(id, productId)).length;
  }, 0);
};
const productInitialStock = (product, totalReceived, totalUsed) => {
  if (Number.isFinite(Number(product.baseStock))) return num(product.baseStock);
  const seed = productSeedFor(product);
  if (seed) return num(seed.baseStock);
  return num(product.stock) - totalReceived + totalUsed;
};
const productMatchesReportQuery = (product, query = "") => {
  const normalizedQuery = normalizedName(query || "");
  if (!normalizedQuery) return true;
  return normalizedName(`${product.name} ${product.company || ""} ${product.subcategory || ""} ${productCategoryLabel(product.category)}`).includes(normalizedQuery);
};
const latestReceiptDateForProduct = (productId) => state.receipts.reduce((latest, receipt) => {
  if (!sameId(receipt.productId, productId)) return latest;
  const date = receiptDateValue(receipt);
  if (!date) return latest;
  return !latest || date > latest ? date : latest;
}, "");
const productStockFlowRows = (category, period, query = "") => state.products
  .filter((product) => productCategory(product.category) === category)
  .filter((product) => productMatchesReportQuery(product, query))
  .sort(productUsageSort(category))
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

const productUsageSummaryRows = (category, start = "", end = "", query = "") => {
  const normalizedQuery = normalizedName(query || "");
  const { usageCounts, receiptCounts } = historyMovementCounts(start, end);
  return state.products
    .filter((product) => productCategory(product.category) === category)
    .filter((product) => {
      if (!normalizedQuery) return (usageCounts.get(product.id) || 0) || (receiptCounts.get(product.id) || 0);
      return normalizedName(`${product.name} ${product.company || ""} ${product.subcategory || ""} ${productCategoryLabel(product.category)}`).includes(normalizedQuery);
    })
    .sort(productUsageSort(category))
    .map((product) => ({
      product,
      received: receiptCounts.get(product.id) || 0,
      used: usageCounts.get(product.id) || 0
    }));
};

const stockStatusClass = (product) => {
  const stock = num(product?.stock);
  const warning = num(product?.warningStock);
  if (stock <= warning) return "stock-danger";
  if (warning > 0 && stock <= warning * 2) return "stock-warn";
  return "stock-ok";
};

const productUsagePatientRows = (productId, start = "", end = "") => filteredHistoryUsages(start, end, "")
  .map((usage) => {
    const qty = (usage.productIds || []).filter((id) => id === productId).length;
    if (!qty) return null;
    const doctor = departmentById(usage.doctorId);
    const surgery = surgeryById(usage.surgeryId);
    return { usage, qty, doctor, surgery };
  })
  .filter(Boolean)
  .sort((a, b) => alphaFirstCompare(b.usage.date, a.usage.date) || alphaFirstCompare(a.usage.patientName, b.usage.patientName));

const productUsageSummaryHtml = (start = "", end = "", query = "") => {
  const periodText = historyPeriodText(start, end);
  const categories = PRODUCT_CATEGORIES;
  const groups = categories.map((category) => {
    const productRows = productUsageSummaryRows(category, start, end, query);
    const rows = productRows.map(({ product, received, used }) => {
      const isNonpay = productCategory(product.category) === "비급여";
      const patientRows = productUsagePatientRows(product.id, start, end);
      return `
        <details class="summary-row ${isNonpay ? "nonpay" : ""}">
          <summary>
            <div class="summary-headline">
              <span class="summary-name">${escapeHtml(product.name)}</span>
              ${product.company || product.subcategory ? `<span class="summary-sub">${product.company ? `${escapeHtml(product.company)}` : ""}${product.subcategory ? `${product.company ? " · " : ""}${escapeHtml(product.subcategory)}` : ""}</span>` : ""}
            </div>
            <div class="summary-metrics">
              <div class="metric"><span>기간입고</span> <strong>${received}</strong></div>
              <div class="metric"><span>기간사용</span> <strong>${used}</strong></div>
              <div class="metric ${stockStatusClass(product)}"><strong>${num(product.stock)}</strong><span>재고</span></div>
            </div>
          </summary>
          <div class="details-body">
            ${patientRows.length ? patientRows.map(({ usage, qty, doctor, surgery }) => `
              <div class="item">
                <div class="item-title"><span>${escapeHtml(patientDisplayName(usage))}</span><span class="pill">${qty}개</span></div>
                <div class="meta">
                  <span>사용일: ${escapeHtml(usage.date)}</span>
                  ${auditMetaHtml(usage, "입력")}
                  <span>과/원장 코드: ${escapeHtml(doctor?.name || "-")} · 수술: ${escapeHtml(surgery?.department || inferSurgeryDepartment(surgery?.name || ""))} - ${escapeHtml(surgery?.name || "-")}</span>
                </div>
              </div>
            `).join("") : `<div class="empty">해당 기간 사용 환자가 없습니다.</div>`}
          </div>
        </details>
      `;
    }).join("");
    return `
      <details class="item">
        <summary><span>${escapeHtml(productCategoryLabel(category))} 제품 사용내역</span><span class="pill">${productRows.length}</span></summary>
        <div class="details-body">
          <div class="actions">
            <button class="secondary" type="button" data-export-history-category="${escapeHtml(category)}">보고용 엑셀</button>
            <button class="secondary" type="button" data-export-history-category-detail="${escapeHtml(category)}">상세 엑셀</button>
          </div>
          <div class="summary-table">${rows || `<div class="empty">해당 제품 사용내역이 없습니다.</div>`}</div>
        </div>
      </details>
    `;
  }).join("");
  return `
    <div class="meta" style="margin-bottom:10px;">
      <span>조회 기간: ${escapeHtml(periodText)}${query ? ` · 검색어: ${escapeHtml(query)}` : ""}</span>
    </div>
    ${groups}
  `;
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
      productUsageSummaryHtml,
      filteredHistoryUsages,
      usageItem,
      exportHistoryCategory,
      exportHistoryCategoryDetail,
      exportHistoryPatients,
      deleteUsageRecord
    });
  }
  return historyModule;
};

const renderHistory = () => getHistoryModule().renderHistory();
const bindHistory = () => getHistoryModule().bindHistory();

const usageItem = (usage, options = {}) => {
  const showDelete = options.showDelete !== false && canDeleteUsageRecord(usage);
  const showEdit = options.showEdit !== false && canEditUsage();
  const showActions = options.showDelete !== false && (showEdit || showDelete);
  const doctor = departmentById(usage.doctorId);
  const surgery = surgeryById(usage.surgeryId);
  const surgeryDepartment = surgery ? (surgery.department || inferSurgeryDepartment(surgery.name)) : "-";
  const productCounts = usage.productIds.reduce((map, id) => {
    map.set(id, (map.get(id) || 0) + 1);
    return map;
  }, new Map());
  const groupedProducts = PRODUCT_CATEGORIES.map((category) => {
    const items = Array.from(productCounts.entries())
      .map(([id, qty]) => ({ product: productById(id), id, qty }))
      .filter((item) => productCategory(item.product?.category) === category)
      .sort((a, b) => alphaFirstCompare(a.product?.name || "", b.product?.name || ""));
    return { category, items };
  }).filter((group) => group.items.length);
  const missingProducts = Array.from(productCounts.entries())
    .map(([id, qty]) => ({ id, qty, product: productById(id) }))
    .filter((item) => !item.product);
  const groupClass = (category) => {
    const key = productCategory(category);
    if (key === "비급여") return "nonpay";
    if (key === "인체조직") return "tissue";
    if (["ANCHOR", "URO_LANDING", "GS_LANDING", "IMPLANT"].includes(key)) return "anchor";
    return "";
  };
  const doubleCheck = usage.doubleCheck || {};
  const doubleCheckText = doubleCheck.status === "finalSaved"
    ? `더블체크: 임시저장 ${doubleCheck.draftSavedBy || "-"}${doubleCheck.draftSavedAt ? ` (${formatDateTime(doubleCheck.draftSavedAt)})` : ""} · 최종저장 ${doubleCheck.finalSavedBy || "-"}${doubleCheck.finalSavedAt ? ` (${formatDateTime(doubleCheck.finalSavedAt)})` : ""}`
    : "";
  return `
    <div class="item">
      <div class="item-title">
        <span>${escapeHtml(patientDisplayName(usage))}</span>
        <span class="pill">${usage.date}</span>
      </div>
      <div class="meta">
        ${auditMetaHtml(usage, "입력")}
        ${doubleCheckText ? `<span>${escapeHtml(doubleCheckText)}</span>` : ""}
        <span>과/원장 코드: ${escapeHtml(doctor?.name || "-")} · 수술: ${escapeHtml(surgeryDepartment)} - ${escapeHtml(surgery?.name || "-")}</span>
        <div class="usage-products">
          ${groupedProducts.map((group) => `
            <div class="usage-product-group ${groupClass(group.category)}">
              <div class="usage-product-heading">
                <span>${escapeHtml(productCategoryLabel(group.category))}</span>
                <span class="pill ${group.category === "비급여" ? "low" : ""}">${group.items.reduce((sum, item) => sum + item.qty, 0)}개</span>
              </div>
              <div class="usage-product-chips">
                ${group.items.map((item) => `<span class="usage-chip">${escapeHtml(item.product.name)}${item.qty > 1 ? ` · ${item.qty}개` : ""}</span>`).join("")}
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
      </div>
      ${showActions ? `<div class="actions">
        ${showEdit ? `<button class="secondary" type="button" data-edit-usage="${usage.id}">${canModifyUsageRecord(usage) ? "사용내용 수정" : "사용내용 확인"}</button>` : ""}
        ${showDelete ? `<button class="danger" type="button" data-delete-usage="${usage.id}">사용내역 삭제</button>` : ""}
      </div>` : ""}
    </div>
  `;
};

const xlsxEncoder = new TextEncoder();
const zipPart = (value) => typeof value === "string" ? xlsxEncoder.encode(value) : value;
const zipConcat = (parts) => {
  const chunks = parts.map(zipPart);
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  chunks.forEach((chunk) => {
    output.set(chunk, offset);
    offset += chunk.length;
  });
  return output;
};
const zipU16 = (value) => new Uint8Array([value & 255, (value >>> 8) & 255]);
const zipU32 = (value) => new Uint8Array([value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255]);
const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
const crc32 = (bytes) => {
  let crc = 0xffffffff;
  bytes.forEach((byte) => {
    crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
  });
  return (crc ^ 0xffffffff) >>> 0;
};
const zipFiles = (files) => {
  const locals = [];
  const centrals = [];
  let offset = 0;
  files.forEach((file) => {
    const name = xlsxEncoder.encode(file.name);
    const data = zipPart(file.content);
    const crc = crc32(data);
    const local = zipConcat([
      zipU32(0x04034b50), zipU16(20), zipU16(0), zipU16(0), zipU16(0), zipU16(0),
      zipU32(crc), zipU32(data.length), zipU32(data.length), zipU16(name.length), zipU16(0),
      name, data
    ]);
    const central = zipConcat([
      zipU32(0x02014b50), zipU16(20), zipU16(20), zipU16(0), zipU16(0), zipU16(0), zipU16(0),
      zipU32(crc), zipU32(data.length), zipU32(data.length), zipU16(name.length), zipU16(0), zipU16(0),
      zipU16(0), zipU16(0), zipU32(0), zipU32(offset), name
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  });
  const centralSize = centrals.reduce((sum, item) => sum + item.length, 0);
  const end = zipConcat([
    zipU32(0x06054b50), zipU16(0), zipU16(0), zipU16(files.length), zipU16(files.length),
    zipU32(centralSize), zipU32(offset), zipU16(0)
  ]);
  return zipConcat([...locals, ...centrals, end]);
};
const xlsxColumnName = (index) => {
  let name = "";
  for (let value = index + 1; value > 0; value = Math.floor((value - 1) / 26)) {
    name = String.fromCharCode(65 + ((value - 1) % 26)) + name;
  }
  return name;
};
const xlsxCell = (value, rowIndex, columnIndex) => {
  const ref = `${xlsxColumnName(columnIndex)}${rowIndex}`;
  if (typeof value === "number" && Number.isFinite(value)) return `<c r="${ref}"><v>${value}</v></c>`;
  return `<c r="${ref}" t="inlineStr"><is><t>${escapeHtml(value)}</t></is></c>`;
};
const xlsxWorkbook = (headers, rows) => {
  const allRows = [headers, ...rows];
  const sheetRows = allRows.map((row, rowIndex) =>
    `<row r="${rowIndex + 1}">${row.map((value, columnIndex) => xlsxCell(value, rowIndex + 1, columnIndex)).join("")}</row>`
  ).join("");
  const worksheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheetRows}</sheetData></worksheet>`;
  return zipFiles([
    { name: "[Content_Types].xml", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>` },
    { name: "_rels/.rels", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
    { name: "xl/workbook.xml", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets></workbook>` },
    { name: "xl/_rels/workbook.xml.rels", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>` },
    { name: "xl/worksheets/sheet1.xml", content: worksheet }
  ]);
};
const downloadExcel = (filename, headers, rows) => {
  const blob = new Blob([xlsxWorkbook(headers, rows)], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename.replace(/\.(xls|csv)$/i, ".xlsx");
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    link.remove();
  }, 0);
};

const historyFilterValues = () => ({
  start: document.getElementById("historyStart")?.value || "",
  end: document.getElementById("historyEnd")?.value || "",
  query: document.getElementById("historySearch")?.value || ""
});

const exportHistoryCategory = (category) => {
  const { start, end, query } = historyFilterValues();
  const period = reportPeriodFromFilters(start, end);
  const periodText = reportPeriodLabel(period);
  const rows = productStockFlowRows(category, period, query).map((item) => [
    item.product.name,
    productCategoryLabel(item.product.category),
    item.basisStock,
    periodText,
    item.periodReceived,
    item.periodUsed,
    item.currentStock
  ]);
  downloadExcel(
    `보고용_재고흐름_${productCategoryLabel(category)}_${periodText}.xlsx`,
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
    productCategoryLabel(item.product.category),
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
  downloadExcel(
    `상세_재고흐름_${productCategoryLabel(category)}_${periodText}.xlsx`,
    ["제품명", "분류", "기준재고", "조회기간", "기간입고", "기간사용", "현재고", "업체명", "최근입고일", "초기재고", "누적입고", "누적사용", "시스템현재고"],
    rows
  );
};

const exportHistoryPatients = () => {
  const { start, end, query } = historyFilterValues();
  const rows = filteredHistoryUsages(start, end, query).slice().reverse().map((usage) => {
    const doctor = departmentById(usage.doctorId);
    const surgery = surgeryById(usage.surgeryId);
    const productText = usage.productIds.map((id) => productById(id)?.name || "삭제된 제품").join(", ");
    return [
      historyPeriodText(start, end),
      usage.date,
      usage.patientName,
      patientIdText(usage),
      auditUserText(usage),
      auditTimeText(usage),
      doctor?.name || "",
      surgery?.department || inferSurgeryDepartment(surgery?.name || ""),
      surgery?.name || "",
      productText
    ];
  });
  downloadExcel(
    `환자별_사용내역_${start || "all"}_${end || "all"}.xlsx`,
    ["조회기간", "사용일", "환자명", "환자ID", "입력자", "입력시각", "원장코드", "과", "수술", "사용제품"],
    rows
  );
};

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
      if (hydrated && (currentView === "use" || currentView === "edit" || (currentView === "settings" && currentSettingsView === "implantVendors"))) render();
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
          render();
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
      if (hydrated) render();
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
    render();
  } else {
    const pageDate = document.querySelector(".page-user span");
    if (pageDate) pageDate.textContent = nextDate;
  }
}, 30000);

loadFirebaseAndBoot();
