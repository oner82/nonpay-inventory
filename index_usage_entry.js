(() => {
  window.createUsageEntryModule = (context) => {
    const pendingUsageSummary = (item) => {
      const productCount = (item.productItems || []).reduce((sum, product) => sum + Math.max(1, context.num(product.qty)), 0);
      const implantCount = (item.implantDrafts || []).length;
      const photoCount = (item.implantDrafts || []).reduce((sum, implant) => sum + (implant.photos || []).length, 0);
      return { productCount, implantCount, photoCount };
    };

    const renderPendingUsageList = () => {
      const items = context.pendingUsagesOpen();
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
              const doctor = context.departmentById(item.doctorId);
              const surgery = context.surgeryById(item.surgeryId);
              return `
                <div class="pending-usage-card">
                  <div class="pending-usage-head">
                    <strong>${context.escapeHtml(context.patientDisplayName(item) || "환자 정보 없음")}</strong>
                    <span class="pill">${context.escapeHtml(item.date || context.today())}</span>
                  </div>
                  <div class="pending-usage-meta">
                    <span>${context.escapeHtml(doctor?.name || "-")}</span>
                    <span>${context.escapeHtml(surgery?.name || "-")}</span>
                    <span>제품 ${summary.productCount}개</span>
                    <span>임플란트 ${summary.implantCount}업체 · 사진 ${summary.photoCount}장</span>
                    <span>입력 ${context.escapeHtml(item.enteredBy?.name || item.enteredBy?.loginId || item.draftSavedBy || "-")}</span>
                    <span>${context.escapeHtml(context.formatDateTime(item.updatedAt || item.createdAt || ""))}</span>
                  </div>
                  <div class="actions">
                    <button type="button" data-load-pending-usage="${context.escapeHtml(item.id)}">불러오기</button>
                    <button class="danger" type="button" data-delete-pending-usage="${context.escapeHtml(item.id)}">대기삭제</button>
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    };

    return {
      pendingUsageSummary,
      renderPendingUsageList
    };
  };
})();
