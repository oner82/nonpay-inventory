(function () {
  window.createImplantsModule = (context) => {
    const {
      app,
      today,
      escapeHtml,
      implantSubViewItems,
      ensureImplantSubView,
      implantPanelVisible,
      getCurrentImplantSubView,
      setCurrentImplantSubView,
      render,
      num,
      normalizedName,
      alphaFirstCompare,
      implantVendorById,
      findImplantVendorByName,
      sortImplantRecords,
      surgeryById,
      departmentById,
      auditUserText,
      currentAuditUser,
      safeBackupFileName,
      isImplantLedgerClosed,
      implantLockLabel,
      canAssignImplantPatientNo,
      canEditImplantPatientNo,
      implantRecordsForDate,
      assignImplantPatientNosForDate,
      exportImplantLedgerExcel,
      exportImplantMonthlyBackup,
      showSaveToast,
      saveDoneToast,
      saveErrorToast,
      implantPatientNoText,
      showImplantPhotoModal,
      hideImplantPhotoModal,
      updateImplantSendGroupStatus,
      setButtonBusy,
      loadExternalScriptOnce,
      downloadBlob,
      downloadBytes,
      promiseWithTimeout,
      loadImageFromUrl,
      retryImplantRecordPhotos,
      setDoc,
      doc,
      db,
      deleteDoc,
      getImplantRecords,
      setImplantRecords,
      sameId,
      implantRecordDate,
      auditUpdateFields
    } = context;

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

    const renderImplants = () => {
      const date = today();
      ensureImplantSubView();
      const subTabs = implantSubViewItems();
      const currentImplantSubView = getCurrentImplantSubView();
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

const filteredImplantRecords = (date, patientName, patientId, patientNo) => {
  const nameQuery = normalizedName(patientName || "");
  const idQuery = normalizedName(patientId || "");
  const noQuery = normalizedName(patientNo || "");
  return sortImplantRecords(getImplantRecords()).filter((record) => {
    if (date && implantRecordDate(record) !== date) return false;
    if (nameQuery && !normalizedName(record.patientName || "").includes(nameQuery)) return false;
    if (idQuery && !normalizedName(record.patientId || "").includes(idQuery)) return false;
    if (noQuery && !normalizedName(implantPatientNoText(record)).includes(noQuery)) return false;
    return true;
  });
};

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
      panel.hidden = !panel.dataset.implantPanel.split(/\s+/).filter(Boolean).includes(getCurrentImplantSubView());
    });
    app.querySelectorAll("[data-implant-subview]").forEach((button) => {
      button.classList.toggle("active", button.dataset.implantSubview === getCurrentImplantSubView());
    });
    if (ledgerTitle) ledgerTitle.textContent = getCurrentImplantSubView() === "admin" ? "관리자 도구" : "오늘 장부";
    if (sendList && getCurrentImplantSubView() === "send" && !sendList.innerHTML.trim()) {
      sendList.innerHTML = implantSendPanelOrganizedHtml(dateInput.value || today());
    }
  };
  const renderList = () => {
    const records = filteredImplantRecords(dateInput.value, nameInput.value, idInput.value, noInput.value).reverse();
    list.innerHTML = records.length
      ? records.map((record) => implantRecordCardHtml(record, { showAdminTools: getCurrentImplantSubView() === "admin" })).join("")
      : `<div class="empty">조회 조건에 맞는 임플란트 기록이 없습니다.</div>`;
    if (summary) summary.innerHTML = implantLedgerTableHtml(implantRecordsForDate(dateInput.value));
    if (photoStatusPanel) photoStatusPanel.innerHTML = implantPhotoStatusPanelHtml(dateInput.value);
    if (sendList && getCurrentImplantSubView() === "send") sendList.innerHTML = implantSendPanelOrganizedHtml(dateInput.value || today());
    applyImplantPanels();
  };
  app.querySelector(".implant-subtabs")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-implant-subview]");
    if (!button) return;
    setCurrentImplantSubView(button.dataset.implantSubview || "today");
    ensureImplantSubView();
    render();
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
      const record = getImplantRecords().find((item) => sameId(item.id, id));
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
      const record = getImplantRecords().find((item) => sameId(item.id, id));
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
      const record = getImplantRecords().find((item) => sameId(item.id, id));
      if (!record) return;
      if (!confirm("이 임플란트 장부를 삭제할까요? 연결된 사용내역은 삭제하지 않습니다.")) return;
      await deleteDoc(doc(db, "implantRecords", id));
      setImplantRecords(getImplantRecords().filter((item) => !sameId(item.id, id)));
      renderList();
      return;
    }
    const saveButton = event.target.closest("[data-implant-patient-no-save]");
    if (saveButton) {
      if (!canEditImplantPatientNo()) return;
      const id = saveButton.dataset.implantPatientNoSave;
      const record = getImplantRecords().find((item) => sameId(item.id, id));
      const input = list.querySelector(`[data-implant-patient-no-input="${id}"]`);
      const nextNo = String(input?.value || "").trim();
      if (!record || !nextNo) {
        alert("환자번호를 입력해 주세요.");
        return;
      }
      const duplicate = getImplantRecords().some((item) =>
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

    return {
      renderImplants,
      bindImplants,
      filteredImplantRecords,
      implantLedgerTableHtml,
      implantSendStatusLabel,
      implantSendStatusClass,
      implantSendMessage,
      implantSendGroups,
      implantSendGroupStats,
      implantSendPatientGroups,
      implantSendPhotoLedgerHtml,
      implantSendPrintHtml,
      implantSendLedgerTableRowsHtml,
      implantSendPhotoLedgerTableHtml,
      implantSendPrintTableHtml,
      implantStatementPhotoChunks,
      implantStatementFooterHtml,
      implantSendStatementCardsHtml,
      implantSendStatementPrintHtml,
      implantSendStatementPrintHtmlV2,
      implantSendPanelHtml,
      implantSendPanelOrganizedHtml,
      implantPhotoViewSrc,
      implantPhotoRotationStyle,
      implantPhotoNeedsStorageRetry,
      implantPhotoStatusStats,
      implantPhotoProblemRows,
      implantPhotoHtml,
      implantPhotoStatusHtml,
      implantPhotoStatusPanelHtml,
      implantRecordCardHtml
    };
  };
})();
