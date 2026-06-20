(function () {
  window.createImplantsModule = (context) => {
    const {
      today,
      escapeHtml,
      implantSubViewItems,
      ensureImplantSubView,
      implantPanelVisible,
      getCurrentImplantSubView,
      canAssignImplantPatientNo
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

    return { renderImplants };
  };
})();
