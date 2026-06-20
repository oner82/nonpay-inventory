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
      canAssignImplantPatientNo,
      canEditImplantPatientNo,
      filteredImplantRecords,
      implantRecordCardHtml,
      implantLedgerTableHtml,
      implantRecordsForDate,
      implantPhotoStatusPanelHtml,
      implantSendPanelOrganizedHtml,
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
      implantSendStatusLabel,
      implantSendGroups,
      setButtonBusy,
      saveAndShareImplantVendorStatementPdf,
      downloadImplantVendorStatementHtml,
      shareImplantVendorStatement,
      implantSendMessage,
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

    return { renderImplants, bindImplants };
  };
})();
