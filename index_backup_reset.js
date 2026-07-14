(() => {
  window.createBackupResetModule = (ctx) => {
    const state = new Proxy({}, {
      get(_target, prop) { return ctx.getState()[prop]; },
      set(_target, prop, value) { ctx.getState()[prop] = value; return true; }
    });
    const pendingUsages = new Proxy([], {
      get(_target, prop) {
        const source = ctx.getPendingUsages();
        const value = source[prop];
        return typeof value === "function" ? value.bind(source) : value;
      }
    });
    const implantRecords = new Proxy([], {
      get(_target, prop) {
        const source = ctx.getImplantRecords();
        const value = source[prop];
        return typeof value === "function" ? value.bind(source) : value;
      }
    });
    const alphaFirstCompare = ctx.alphaFirstCompare;
    const escapeHtml = ctx.escapeHtml;
    const getDocs = ctx.getGetDocs();
    const collection = ctx.getCollection();
    const db = ctx.getDb();
    const setDoc = ctx.getSetDoc();
    const doc = ctx.getDoc();
    const deleteDoc = ctx.getDeleteDoc();
    const getDoc = ctx.getGetDoc();
    const currentAuditUser = ctx.currentAuditUser;
    const today = ctx.today;
    const render = ctx.render;
    const saveState = ctx.saveState;
    const num = ctx.num;
    const auditUpdateFields = ctx.auditUpdateFields;
    const canManageSettings = ctx.canManageSettings;
    const savingToast = ctx.savingToast;
    const saveErrorToast = ctx.saveErrorToast;
    const normalizeState = ctx.normalizeState;
    const addSeedMasters = ctx.addSeedMasters;
    const reconcileProductStocks = ctx.reconcileProductStocks;
    const app = ctx.app;

    const renderBackup = () => {
      const versions = (state.backupVersions || [])
        .slice()
        .sort((a, b) => alphaFirstCompare(b.createdAt || b.date, a.createdAt || a.date));
      const resetPlan = operationalResetPlan();
      return `
      <section class="grid two">
        <div class="card">
          <h2>서버 백업 저장</h2>
          <p class="muted">현재 데이터를 Firestore 서버에 날짜별 버전으로 저장합니다. 입력/수정 데이터는 평소에도 자동 저장되며, 이 기능은 특정 시점으로 되돌리기 위한 별도 백업입니다.</p>
          <label for="backupLabel">백업 이름</label>
          <input id="backupLabel" autocomplete="off" placeholder="예: 월말 점검 전, 5월 정기 백업">
          <div class="actions">
            <button type="button" id="saveServerBackup">현재 상태 서버 백업</button>
          </div>
        </div>
        <div class="card">
          <h2>운영기록 초기화</h2>
          <p class="muted">설정은 보존하고 과거 사용입력, 입고이력, 임시저장 대기, 임플란트 사용장부만 새로 시작합니다. 실행 전 전체 백업과 설정 보존 백업을 먼저 저장합니다.</p>
          <div class="summary-table">
            <div><strong>보존</strong><span>제품 ${resetPlan.keep.products} · 과/원장 ${resetPlan.keep.doctors} · 수술 ${resetPlan.keep.surgeries} · 수술별 사용관리 ${resetPlan.keep.usageRules}</span></div>
            <div><strong>초기화 대상</strong><span>사용입력 ${resetPlan.clear.usages} · 입고이력 ${resetPlan.clear.receipts} · 임시저장 ${resetPlan.clear.pendingUsages} · 임플란트 장부 ${resetPlan.clear.implantRecords}</span></div>
            <div><strong>재고 기준</strong><span>초기화 시 각 제품의 현재고를 새 기준재고로 고정합니다.</span></div>
          </div>
          <label for="settingsBackupLabel">설정 보존 백업 이름</label>
          <input id="settingsBackupLabel" autocomplete="off" placeholder="예: 구조개선 전 설정 백업">
          <div class="actions">
            <button type="button" id="saveSettingsBackup">설정 보존 백업 저장</button>
            <button class="secondary" type="button" id="downloadResetPlan">초기화 미리보기 JSON</button>
            <button class="danger" type="button" id="runOperationalReset">운영기록 초기화 실행</button>
          </div>
        </div>
        <div class="card">
          <h2>날짜별 백업 버전</h2>
          ${versions.length ? versions.map((item) => `
            <div class="item">
              <div class="item-title">
                <span>${escapeHtml(item.label || "백업")}</span>
                <span class="pill">${escapeHtml((item.createdAt || "").slice(0, 10) || item.date || "-")}</span>
              </div>
              <div class="meta">
                <span>저장시각: ${escapeHtml(formatDateTime(item.createdAt || item.date || ""))}</span>
              </div>
              <div class="actions">
                <button class="secondary" type="button" data-download-server-backup="${escapeHtml(item.id)}">JSON 다운로드</button>
                <button class="warn" type="button" data-restore-server-backup="${escapeHtml(item.id)}">이 버전으로 복원</button>
              </div>
            </div>
          `).join("") : `<div class="empty">저장된 백업 버전이 없습니다.</div>`}
        </div>
      </section>
    `;
    };

    const formatDateTime = (value) => {
      if (!value) return "-";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString("ko-KR", { hour12: false });
    };

    const stateSnapshotForBackup = () => {
      const snapshot = JSON.parse(JSON.stringify(state));
      delete snapshot.backupVersions;
      snapshot.backedUpAt = new Date().toISOString();
      return snapshot;
    };

    const operationalResetPlan = () => ({
      keep: {
        products: state.products.length,
        doctors: state.doctors.length,
        surgeries: state.surgeries.length,
        usageRules: state.usageRules.length,
        hiddenLowProductIds: state.hiddenLowProductIds.length
      },
      clear: {
        usages: state.usages.length,
        receipts: state.receipts.length,
        roomRefills: (state.roomRefills || []).length,
        pendingUsages: pendingUsages.length,
        implantRecords: implantRecords.length
      }
    });

    const settingsOnlyStateSnapshot = () => {
      const snapshot = stateSnapshotForBackup();
      snapshot.usages = [];
      snapshot.receipts = [];
      snapshot.roomRefills = [];
      snapshot.updatedAt = new Date().toISOString();
      return snapshot;
    };

    const readCollectionForBackup = async (collectionName, fallbackItems) => {
      if (!db || !getDocs || !collection) return JSON.parse(JSON.stringify(fallbackItems));
      const snapshot = await getDocs(collection(db, collectionName));
      return snapshot.docs.map((item) => ({ id: item.id, ...item.data() }));
    };

    const backupExternalCollections = async () => ({
      pendingUsages: await readCollectionForBackup("pendingUsages", pendingUsages),
      implantRecords: await readCollectionForBackup("implantRecords", implantRecords)
    });

    const downloadJson = (filename, payload) => {
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    };

    const externalCollectionsSummary = (externalCollections = {}) => ({
      pendingUsages: Array.isArray(externalCollections.pendingUsages) ? externalCollections.pendingUsages.length : 0,
      implantRecords: Array.isArray(externalCollections.implantRecords) ? externalCollections.implantRecords.length : 0
    });

    const saveExternalBackupChunks = async (backupId, externalCollections = {}) => {
      const payload = {
        pendingUsages: Array.isArray(externalCollections.pendingUsages) ? externalCollections.pendingUsages : [],
        implantRecords: Array.isArray(externalCollections.implantRecords) ? externalCollections.implantRecords : []
      };
      const records = Object.entries(payload).flatMap(([collectionName, items]) =>
        items.map((item) => ({ collectionName, item }))
      );
      let chunk = [];
      let chunkBytes = 0;
      let chunkIndex = 0;
      const maxChunkBytes = 650000;
      const flush = async () => {
        if (!chunk.length) return;
        const chunkId = `chunk-${String(chunkIndex).padStart(4, "0")}`;
        await setDoc(doc(db, "backups", backupId, "externalChunks", chunkId), {
          id: chunkId,
          backupId,
          createdAt: new Date().toISOString(),
          records: chunk
        });
        chunk = [];
        chunkBytes = 0;
        chunkIndex += 1;
      };
      for (const record of records) {
        const recordBytes = JSON.stringify(record).length;
        if (chunk.length && chunkBytes + recordBytes > maxChunkBytes) await flush();
        chunk.push(record);
        chunkBytes += recordBytes;
      }
      await flush();
      return chunkIndex;
    };

    const saveBackupDocument = async ({ id, label, kind, data, externalCollections, message }) => {
      const createdAt = new Date().toISOString();
      const summary = externalCollections ? externalCollectionsSummary(externalCollections) : null;
      const externalChunkCount = externalCollections ? await saveExternalBackupChunks(id, externalCollections) : 0;
      await setDoc(doc(db, "backups", id), {
        id,
        label,
        kind,
        date: today(),
        createdAt,
        createdBy: currentAuditUser(),
        data,
        externalCollectionsSummary: summary,
        externalChunkCount
      });
      state.backupVersions = [
        { id, label, date: today(), createdAt, kind },
        ...(state.backupVersions || []).filter((item) => item.id !== id)
      ].slice(0, 50);
      render();
      await saveState(message);
    };

    const deleteCollectionDocs = async (collectionName, fallbackItems = []) => {
      if (!db || !collection || !deleteDoc) throw new Error("Firebase 삭제 기능이 준비되지 않았습니다.");
      const items = getDocs
        ? (await getDocs(collection(db, collectionName))).docs.map((item) => ({ id: item.id }))
        : fallbackItems;
      const ids = [...new Set(items.map((item) => item.id).filter(Boolean))];
      for (let index = 0; index < ids.length; index += 25) {
        const chunk = ids.slice(index, index + 25);
        await Promise.all(chunk.map((id) => deleteDoc(doc(db, collectionName, id))));
      }
      return ids.length;
    };

    const prepareStateForOperationalReset = () => {
      state.products = state.products.map((product) => {
        const stock = num(product.stock);
        return {
          ...product,
          stock,
          baseStock: stock,
          updatedAt: new Date().toISOString(),
          ...auditUpdateFields()
        };
      });
      state.usages = [];
      state.receipts = [];
      // 방 마감 기록도 비운다 — 남기면 기준재고 고정 후 유령 사용량으로 이중 차감된다.
      state.roomRefills = [];
      state.updatedAt = new Date().toISOString();
    };

    const runOperationalReset = async () => {
      if (!canManageSettings()) {
        alert("관리자와 책임사용자만 운영기록 초기화를 실행할 수 있습니다.");
        return;
      }
      if (!db) {
        alert("Firebase 연결 후 초기화할 수 있습니다.");
        return;
      }
      const plan = operationalResetPlan();
      const totalClear = plan.clear.usages + plan.clear.receipts + plan.clear.pendingUsages + plan.clear.implantRecords;
      if (!totalClear) {
        alert("초기화할 운영기록이 없습니다.");
        return;
      }
      if (!confirm("운영기록을 초기화합니다. 실행 전 전체 백업과 설정 보존 백업을 저장한 뒤, 사용입력/입고이력/임시저장/임플란트 장부를 삭제합니다. 계속할까요?")) return;
      const typed = prompt("정말 초기화하려면 초기화 라고 입력해 주세요.");
      if (typed !== "초기화") {
        alert("초기화가 취소되었습니다.");
        return;
      }

      const startedAt = new Date().toISOString();
      const externalCollections = await backupExternalCollections();
      savingToast("초기화 전 백업 저장 중입니다...", { hold: true });
      await saveBackupDocument({
        id: `pre-reset-full-${startedAt.replace(/[:.]/g, "-")}`,
        label: `${today()} 운영기록 초기화 전 전체 백업`,
        kind: "beforeOperationalResetFull",
        data: stateSnapshotForBackup(),
        externalCollections,
        message: "운영기록 초기화 전 전체 백업 저장 완료"
      });
      await saveBackupDocument({
        id: `pre-reset-settings-${startedAt.replace(/[:.]/g, "-")}`,
        label: `${today()} 운영기록 초기화 전 설정 보존 백업`,
        kind: "beforeOperationalResetSettings",
        data: settingsOnlyStateSnapshot(),
        externalCollections,
        message: "운영기록 초기화 전 설정 보존 백업 저장 완료"
      });

      savingToast("운영기록 초기화 중입니다...", { hold: true });
      const deletedPending = await deleteCollectionDocs("pendingUsages", externalCollections.pendingUsages);
      const deletedImplants = await deleteCollectionDocs("implantRecords", externalCollections.implantRecords);
      ctx.setPendingUsages([]);
      ctx.setImplantRecords([]);
      prepareStateForOperationalReset();
      render();
      await saveState("운영기록 초기화 완료", {
        authoritative: true,
        savingMessage: "운영기록 초기화 저장 중입니다...",
        doneMessage: `운영기록 초기화 완료 · 임시저장 ${deletedPending}건 · 임플란트 ${deletedImplants}건 삭제`
      });
      alert("운영기록 초기화가 완료되었습니다. 현재고는 새 기준재고로 보존되었습니다.");
    };

    const bindBackup = () => {
      document.getElementById("saveServerBackup")?.addEventListener("click", async () => {
        if (!db) {
          alert("Firebase 연결 후 백업할 수 있습니다.");
          return;
        }
        const createdAt = new Date().toISOString();
        const id = `backup-${createdAt.replace(/[:.]/g, "-")}`;
        const label = document.getElementById("backupLabel")?.value.trim() || `${today()} 백업`;
        try {
          await saveBackupDocument({
            id,
            label,
            kind: "full",
            data: stateSnapshotForBackup(),
            externalCollections: await backupExternalCollections(),
            message: "서버 백업 저장 완료"
          });
        } catch (error) {
          console.error(error);
          alert(`백업 저장 실패: ${error.message}`);
        }
      });

      document.getElementById("saveSettingsBackup")?.addEventListener("click", async () => {
        if (!db) {
          alert("Firebase 연결 후 백업할 수 있습니다.");
          return;
        }
        const createdAt = new Date().toISOString();
        const id = `settings-backup-${createdAt.replace(/[:.]/g, "-")}`;
        const label = document.getElementById("settingsBackupLabel")?.value.trim() || `${today()} 설정 보존 백업`;
        try {
          await saveBackupDocument({
            id,
            label,
            kind: "settingsBeforeOperationalReset",
            data: settingsOnlyStateSnapshot(),
            message: "설정 보존 백업 저장 완료"
          });
        } catch (error) {
          console.error(error);
          alert(`설정 보존 백업 실패: ${error.message}`);
        }
      });

      document.getElementById("downloadResetPlan")?.addEventListener("click", () => {
        downloadJson(`운영기록_초기화_미리보기_${today()}.json`, {
          createdAt: new Date().toISOString(),
          plan: operationalResetPlan(),
          preservedState: settingsOnlyStateSnapshot()
        });
      });

      document.getElementById("runOperationalReset")?.addEventListener("click", async () => {
        try {
          await runOperationalReset();
        } catch (error) {
          console.error(error);
          saveErrorToast(`초기화 실패: ${error.message}`);
          alert(`초기화 실패: ${error.message}`);
        }
      });

      app.querySelectorAll("[data-download-server-backup]").forEach((button) => {
        button.addEventListener("click", async () => {
          try {
            const snap = await getDoc(doc(db, "backups", button.dataset.downloadServerBackup));
            if (!snap.exists()) {
              alert("백업 데이터를 찾을 수 없습니다.");
              return;
            }
            const backup = snap.data();
            downloadJson(`${backup.id || "nonpay-backup"}.json`, backup);
          } catch (error) {
            console.error(error);
            alert(`백업 다운로드 실패: ${error.message}`);
          }
        });
      });

      app.querySelectorAll("[data-restore-server-backup]").forEach((button) => {
        button.addEventListener("click", async () => {
          if (!confirm("현재 데이터를 선택한 백업 버전으로 교체할까요?")) return;
          try {
            const snap = await getDoc(doc(db, "backups", button.dataset.restoreServerBackup));
            if (!snap.exists()) {
              alert("백업 데이터를 찾을 수 없습니다.");
              return;
            }
            const backup = snap.data();
            const currentVersions = state.backupVersions || [];
            ctx.setState(normalizeState(backup.data || {}));
            state.backupVersions = currentVersions;
            addSeedMasters();
            reconcileProductStocks();
            render();
            await saveState("백업 버전 복원 완료");
          } catch (error) {
            console.error(error);
            alert(`백업 복원 실패: ${error.message}`);
          }
        });
      });
    };



    return { renderBackup, bindBackup };
  };
})();
