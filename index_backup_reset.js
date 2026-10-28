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
          <p class="muted">제품·사용·대기·임플란트 기록을 백업합니다. 모든 기기의 입력을 멈춘 유지보수 시간에 저장·복원하세요. 사진 URL은 포함하지만 Storage 사진 원본 파일과 계정은 별도 백업 대상입니다. 구형 불완전 백업은 복원을 차단합니다.</p>
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
            <button class="danger" type="button" id="runOperationalReset" disabled title="별도 안전 검증 전 사용 중지">운영기록 초기화 · 안전 검증 대기</button>
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

    const stateSnapshotForBackup = (source = ctx.getState()) => {
      const snapshot = JSON.parse(JSON.stringify(source));
      delete snapshot.backupVersions;
      snapshot.backedUpAt = new Date().toISOString();
      return snapshot;
    };

    const validateBackup = (backup) => {
      for (const key of ['products', 'doctors', 'surgeries', 'usages', 'receipts', 'usageRules']) {
        if (!Array.isArray(backup?.data?.[key])) throw new Error(`불완전한 백업입니다: ${key} 누락. 복원할 수 없습니다.`);
        const ids = backup.data[key].map(x => x?.id);
        if (ids.some(id => typeof id !== 'string' || !id || id.includes('/')) || new Set(ids).size !== ids.length) throw new Error(`백업 ${key}의 ID가 잘못되었거나 중복됩니다.`);
      }
      if (backup.externalCollections) {
        for (const name of ['pendingUsages', 'implantRecords']) {
          const rows = backup.externalCollections[name];
          if (!Array.isArray(rows)) throw new Error(`외부 백업 ${name} 누락`);
          const ids = rows.map(x => x?.id);
          if (ids.some(id => typeof id !== 'string' || !id || id.includes('/')) || new Set(ids).size !== ids.length) throw new Error(`외부 백업 ${name} ID 오류`);
          if (backup.externalCollectionsSummary && backup.externalCollectionsSummary[name] !== rows.length) throw new Error(`외부 백업 ${name} 개수가 맞지 않습니다.`);
        }
      }
      return backup;
    };

    const readCompleteBackup = async (id) => {
      const snap = await getDoc(doc(db, 'backups', id));
      if (!snap.exists()) throw new Error('백업 데이터를 찾을 수 없습니다.');
      const backup = { ...snap.data(), id };
      validateBackup(backup);
      if (!backup.externalCollections && backup.externalCollectionsSummary) {
        const count = backup.externalChunkCount;
        if (!Number.isSafeInteger(count) || count < 0 || count > 10000) throw new Error('백업 조각 개수가 잘못되었습니다.');
        const external = { pendingUsages: [], implantRecords: [] };
        for (let i = 0; i < count; i++) {
          const chunk = await getDoc(doc(db, 'backups', id, 'externalChunks', `chunk-${String(i).padStart(4, '0')}`));
          if (!chunk.exists() || !Array.isArray(chunk.data().records)) throw new Error('백업 조각이 누락되었습니다.');
          for (const record of chunk.data().records) {
            if (!Object.hasOwn(external, record.collectionName)) throw new Error('알 수 없는 백업 컬렉션입니다.');
            external[record.collectionName].push(record.item);
          }
        }
        backup.externalCollections = external;
      }
      return validateBackup(backup);
    };

    // 유지보수 시간에만 실행한다. 부분 실패를 피하기 위해 작은 복원만 단일 거래로 처리한다.
    const restoreCompleteBackup = async (backup) => {
      if (!canManageSettings()) throw new Error('복원 권한이 없습니다.');
      validateBackup(backup);
      if (!['full','beforeOperationalResetFull','beforeRestoreFull'].includes(backup.kind)) throw new Error('설정 전용 백업은 전체 기록 복원에 사용할 수 없습니다.');
      if (!backup.externalCollections) throw new Error('외부 기록이 없는 설정/구형 백업은 전체 복원할 수 없습니다.');
      const transactionRunner = ctx.getRunTransaction?.();
      const mainRef = ctx.getMainRef?.();
      if (!transactionRunner || !mainRef || !getDocs || !collection) throw new Error('안전한 복원 연결이 준비되지 않았습니다.');
      const beforeSnap = await getDoc(mainRef);
      if (!beforeSnap.exists()) throw new Error('현재 원본을 확인할 수 없습니다.');
      const before = beforeSnap.data();
      const currentExternal = await backupExternalCollections();
      const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
      const operations = [];
      for (const name of ['pendingUsages', 'implantRecords']) {
        const existing = new Map(currentExternal[name].map(row => [row.id, row]));
        const target = new Map(backup.externalCollections[name].map(row => [row.id, row]));
        for (const id of new Set([...existing.keys(), ...target.keys()])) operations.push({ref:doc(db,name,id),before:existing.get(id),after:target.get(id)});
      }
      const recoveryId = `pre-restore-${new Date().toISOString().replace(/[:.]/g, '-')}`;
      const recovery = {id:recoveryId,kind:'beforeRestoreFull',label:'복원 직전 자동 백업',createdAt:new Date().toISOString(),data:before,externalCollections:currentExternal,externalCollectionsSummary:externalCollectionsSummary(currentExternal),externalChunkCount:0};
      if (operations.length > 400 || new Blob([JSON.stringify(recovery)]).size > 700000 || new Blob([JSON.stringify(backup.data)]).size > 700000) throw new Error('대량 복원은 앱에서 안전하게 처리할 수 없습니다. 관리자 전용 복구 절차가 필요합니다. 변경하지 않았습니다.');
      const restored = normalizeState(backup.data);
      delete restored.backedUpAt;
      restored.backupVersions = [{id:recoveryId,label:recovery.label,createdAt:recovery.createdAt,kind:recovery.kind},...(before.backupVersions || [])].slice(0,50);
      restored.updatedAt = new Date().toISOString();
      await transactionRunner(db, async transaction => {
        const latest = await transaction.get(mainRef);
        if (!latest.exists() || canonical(latest.data()) !== canonical(before)) throw new Error('복원 준비 중 데이터가 변경되었습니다. 모든 입력을 중지하고 다시 확인해 주세요.');
        for (const op of operations) {
          const snap = await transaction.get(op.ref);
          const actual = snap.exists() ? { ...snap.data(), id:op.before?.id || op.after.id } : undefined;
          if (canonical(actual) !== canonical(op.before)) throw new Error('대기/장부 기록이 변경되었습니다. 복원을 중단했습니다.');
        }
        transaction.set(doc(db,'backups',recoveryId), recovery);
        for (const op of operations) {
          if (op.after) transaction.set(op.ref, op.after);
          else transaction.delete(op.ref);
        }
        transaction.set(mainRef, restored);
      });
      ctx.setState(restored);
      ctx.setPendingUsages(backup.externalCollections.pendingUsages);
      ctx.setImplantRecords(backup.externalCollections.implantRecords);
      render();
      return recoveryId;
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

    const captureFullBackup = async () => {
      const mainRef = ctx.getMainRef?.();
      if (!mainRef) throw new Error('서버 원본 연결이 준비되지 않았습니다.');
      const first = await getDoc(mainRef);
      if (!first.exists()) throw new Error('서버 원본이 없습니다.');
      const externalCollections = await backupExternalCollections();
      const last = await getDoc(mainRef);
      if (!last.exists() || JSON.stringify(first.data()) !== JSON.stringify(last.data())) throw new Error('백업 중 데이터가 변경되었습니다. 입력을 중지한 뒤 다시 백업해 주세요.');
      return {data:stateSnapshotForBackup(first.data()),externalCollections};
    };

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
        const recordBytes = new Blob([JSON.stringify(record)]).size;
        if (recordBytes > maxChunkBytes) throw new Error('한 기록이 백업 조각 안전 크기를 넘습니다. 백업을 중단했습니다.');
        if (chunk.length && chunkBytes + recordBytes > maxChunkBytes) await flush();
        chunk.push(record);
        chunkBytes += recordBytes;
      }
      await flush();
      return chunkIndex;
    };

    const saveBackupDocument = async ({ id, label, kind, data, externalCollections, message }) => {
      validateBackup({data,externalCollections});
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
      await readCompleteBackup(id);
      state.backupVersions = [
        { id, label, date: today(), createdAt, kind },
        ...(state.backupVersions || []).filter((item) => item.id !== id)
      ].slice(0, 50);
      render();
      if (!await saveState(message)) throw new Error('백업 목록 저장에 실패했습니다. 완료로 처리하지 않습니다.');
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
      // 다중 컬렉션 삭제는 백업 수정과 분리하여 별도 검증 전까지 잠근다.
      throw new Error('운영기록 초기화는 안전 검증 전까지 중지되어 있습니다.');
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
            ...await captureFullBackup(),
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
            const backup = await readCompleteBackup(button.dataset.downloadServerBackup);
            downloadJson(`${backup.id || "nonpay-backup"}.json`, backup);
          } catch (error) {
            console.error(error);
            alert(`백업 다운로드 실패: ${error.message}`);
          }
        });
      });

      app.querySelectorAll("[data-restore-server-backup]").forEach((button) => {
        button.addEventListener("click", async () => {
          if (!canManageSettings()) return;
          if (!confirm("모든 기기에서 입력을 중지했습니까? 제품·사용·대기·임플란트 기록을 선택한 백업으로 교체합니다. 사진 원본 파일은 복구하지 않습니다. 복원 직전 사본을 자동 보존합니다.")) return;
          button.disabled = true;
          try {
            const backup = await readCompleteBackup(button.dataset.restoreServerBackup);
            await restoreCompleteBackup(backup);
            alert('백업 복원 완료. 사진 원본과 모든 기기의 재접속 상태를 확인해 주세요.');
          } catch (error) {
            console.error(error);
            alert(`백업 복원 실패: ${error.message}`);
          } finally { button.disabled = false; }
        });
      });
    };



    return { renderBackup, bindBackup };
  };
})();
