(() => {
  const uid = () => `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;

  const today = () => {
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    return now.toISOString().slice(0, 10);
  };

  const num = (value) => Math.max(0, Number.parseInt(value, 10) || 0);

  const alphaFirstCompare = (left, right) => String(left || "").localeCompare(String(right || ""), "en", {
    numeric: true,
    sensitivity: "base"
  });

  const sameId = (left, right) => String(left ?? "") === String(right ?? "");

  const normalizedName = (value) => String(value || "").trim().replace(/\s+/g, " ").toLowerCase();

  const departmentCode = (value) => String(value || "").trim().replace(/[0-9]+$/g, "").toUpperCase();

  const productCategory = (value) => {
    const raw = String(value || "").trim();
    if (raw === "Anchor&etc") return "ANCHOR";
    if (raw === "URO 랜딩제품" || raw === "URO 랜딩" || raw === "URO") return "URO_LANDING";
    if (raw === "GS 랜딩제품" || raw === "GS 랜딩" || raw === "GS") return "GS_LANDING";
    return raw;
  };

  const productCategoryLabel = (value) => ({
    ANCHOR: "ANCHOR&etc",
    URO_LANDING: "URO 랜딩",
    GS_LANDING: "GS 랜딩"
  }[productCategory(value)] || productCategory(value));

  const formatDateTime = (value) => {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString("ko-KR", { hour12: false });
  };

  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));

  const capitalize = (value) => String(value || "").charAt(0).toUpperCase() + String(value || "").slice(1);

  window.ORInventoryUtils = {
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
  };
})();
