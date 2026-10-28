(() => {
  const effective = (base, settings, includeInactive = false) => {
    const rows = new Map((base || []).map(p => [p.id, { ...p }]));
    (settings || []).forEach(p => rows.set(p.id, { ...rows.get(p.id), ...p }));
    return [...rows.values()].filter(p => includeInactive || p.active !== false);
  };
  window.ORPrescriptionAdmin = { effective };
  window.createPrescriptionAdminModule = c => {
    const e = c.escapeHtml;
    let selectedId = '', dirty = false;
    const all = () => effective(window.ORPrescriptionPatterns?.patterns, c.getState().prescriptionPatternSettings, true);
    const render = () => {
      const p = all().find(x => x.id === selectedId);
      const missing = [...new Set(all().filter(x => x.active !== false && !c.getState().doctors.some(d => d.name === x.doctorCode && d.active !== false)).map(x => x.doctorCode))];
      return `${missing.length ? `<div class="card"><strong>원장 등록·복원 확인 필요</strong><p>${e(missing.join(', '))}</p><p class="helper">처방 패턴은 있지만 현재 원장 선택 목록에 없습니다. 사용하는 원장만 원장관리에서 추가 또는 복원하세요.</p></div>` : ''}<section class="grid two pattern-admin"><div class="card"><h2>원장별·수술별 처방</h2><p class="helper">추천 수량을 관리합니다. 케이스에서 실제 사용 확인 후 최종 저장해야 재고가 차감됩니다. 삭제해도 과거 사용내역은 보존됩니다.</p><input id="patternSearch" type="search" placeholder="원장코드 또는 수술명 검색" aria-label="처방 패턴 검색"><button id="patternNew" type="button">새 처방 패턴 추가</button><div class="pattern-list">${all().map(x => `<button type="button" class="secondary" data-pattern-id="${e(x.id)}" data-pattern-text="${e(`${x.doctorCode} ${x.surgery}`.toLowerCase())}">${e(x.doctorCode)} · ${e(x.surgery)} ${x.active === false ? '[삭제됨]' : ''}</button>`).join('')}</div></div><form class="card" id="patternForm"><h2>${p ? '처방 패턴 수정' : '처방 패턴 추가'}</h2><label>원장코드<select id="patternDoctor" required><option value="">선택</option>${c.getState().doctors.filter(d => d.active !== false).map(d => `<option value="${e(d.name)}" ${p?.doctorCode === d.name ? 'selected' : ''}>${e(d.name)}</option>`).join('')}</select></label><label>수술명<input id="patternSurgery" list="patternSurgeryNames" value="${e(p?.surgery || '')}" required maxlength="200"></label><label>기본 수술명 (부위·레벨 제외)<input id="patternProcedure" value="${e(window.ORSurgerySelection.metadata(p).procedure)}" placeholder="예: Discectomy"></label><div class="row two"><label>부위<select id="patternRegion"><option value="">미기재 / 해당 없음</option>${['C','T','L','S','C-T','T-L','L-S'].map(r=>`<option value="${r}" ${window.ORSurgerySelection.metadata(p).regions.join('-')===r?'selected':''}>${r}</option>`).join('')}</select></label><label>레벨 수<input id="patternLevel" type="number" min="0" max="10" step="1" value="${window.ORSurgerySelection.metadata(p).levelCount}"></label></div><p class="helper">부위·레벨이 다르면 별도 패턴으로 등록하세요. 수량을 레벨 수에 곱하지 않습니다. 0은 미기재입니다.</p><datalist id="patternSurgeryNames">${c.getState().surgeries.filter(s => s.active !== false).map(s => `<option value="${e(s.name)}"></option>`).join('')}</datalist><p class="helper">수술명을 직접 입력할 수 있습니다. 원장코드 추가는 원장관리에서 합니다.</p><div id="patternItems"></div><label>추가할 재료 검색<input id="patternMaterialSearch" type="search" placeholder="처방코드·제품명 검색"></label><div class="row two"><label>재료 선택<select id="patternMaterial"><option value="">선택</option>${c.materials().map(m => `<option value="${e(m.settingsId)}">${e(m.code || '')} ${e(m.name)}</option>`).join('')}</select></label><button id="patternAddMaterial" type="button" class="secondary">재료 추가</button></div><p class="helper">목록에 없는 재료·코드는 처방관리에서 먼저 추가하세요. 행위료는 재고 연결을 ‘재고 제외’로 설정하세요.</p><div class="actions"><button type="submit">패턴 저장</button>${p ? `<button id="patternDelete" class="danger" type="button">${p.active === false ? '복원' : '패턴 삭제'}</button>` : ''}</div></form></section>`;
    };
    const bind = () => {
      dirty = false;
      const el = id => document.getElementById(id);
      const p = all().find(x => x.id === selectedId);
      const materials = c.materials();
      let items = (p?.items || []).map(x => ({ ...x }));
      const paint = () => {
        el('patternItems').innerHTML = items.map((x, i) => `<div class="pattern-material-row"><span>${e(x.name)}</span><label>추천 수량<input data-pattern-qty="${i}" type="number" min="1" max="999" step="1" required value="${e(x.qty)}"></label><button type="button" class="danger" data-pattern-remove="${i}">삭제</button></div>`).join('') || '<p class="empty">아래에서 재료를 추가하세요.</p>';
      };
      paint();
      el('patternMaterialSearch').addEventListener('input',ev=>{
        const query=ev.target.value.toLowerCase().replace(/\s+/g,'');
        el('patternMaterial').innerHTML='<option value="">검색 결과 선택</option>'+materials.filter(m=>`${m.code||''} ${m.name}`.toLowerCase().replace(/\s+/g,'').includes(query)).map(m=>`<option value="${e(m.settingsId)}">${e(m.code||'')} ${e(m.name)}</option>`).join('');
      });
      el('patternForm').addEventListener('input', () => { dirty = true; });
      el('patternItems').addEventListener('input', ev => { if (ev.target.matches('[data-pattern-qty]')) items[Number(ev.target.dataset.patternQty)].qty = Number(ev.target.value); });
      el('patternItems').addEventListener('click', ev => { const b = ev.target.closest('[data-pattern-remove]'); if (b) { items.splice(Number(b.dataset.patternRemove), 1); dirty = true; paint(); } });
      el('patternAddMaterial').addEventListener('click', () => {
        const m = materials.find(x => x.settingsId === el('patternMaterial').value);
        if (!m) return;
        if (items.some(x => x.name === m.name)) return alert('이미 추가한 재료입니다. 수량을 수정해 주세요.');
        items.push({ name: m.name, canonicalName: m.name, materialId: m.settingsId, qty: 1, frequency: 1 }); dirty = true; paint();
      });
      el('patternSearch').addEventListener('input', ev => document.querySelectorAll('[data-pattern-id]').forEach(b => { b.hidden = !b.dataset.patternText.includes(ev.target.value.toLowerCase().trim()); }));
      const select = id => { if (dirty && !confirm('저장하지 않은 변경을 비우고 이동할까요?')) return; selectedId = id; dirty = false; c.render(); };
      el('patternNew').addEventListener('click', () => select(''));
      document.querySelectorAll('[data-pattern-id]').forEach(b => b.addEventListener('click', () => select(b.dataset.patternId)));
      const persist = async record => {
        if (!c.canManageSettings()) return false;
        const ok = await c.saveState('처방 패턴 저장 완료', { apply: s => {
          const current = effective(window.ORPrescriptionPatterns?.patterns, s.prescriptionPatternSettings, true);
          if (record.active !== false && current.some(x => x.id !== record.id && x.active !== false && x.doctorCode === record.doctorCode && window.ORSurgerySelection.key(window.ORSurgerySelection.metadata(x)) === window.ORSurgerySelection.key(window.ORSurgerySelection.metadata(record)))) throw new Error('같은 원장·수술의 패턴이 이미 있습니다. 기존 패턴을 수정해 주세요.');
          if (record.active !== false && !s.doctors.some(d => d.active !== false && d.name === record.doctorCode)) throw new Error('원장코드가 변경되었거나 삭제되었습니다. 원장관리에서 확인해 주세요.');
          s.prescriptionPatternSettings = [...(s.prescriptionPatternSettings || []).filter(x => x.id !== record.id), record];
        } });
        if (ok) { selectedId = record.id; dirty = false; c.render(); }
        return ok;
      };
      el('patternForm').addEventListener('submit', async ev => {
        ev.preventDefault();
        const doctorCode = el('patternDoctor').value, surgery = el('patternSurgery').value.trim();
        const procedureName = el('patternProcedure').value.trim() || surgery.split('·')[0].trim();
        const spineRegions = window.ORSurgerySelection.regions(el('patternRegion').value);
        const levelCount = Number(el('patternLevel').value);
        if (!Number.isSafeInteger(levelCount) || levelCount < 0 || levelCount > 10) return alert('레벨 수는 0~10의 정수로 입력해 주세요.');
        if (!doctorCode || !surgery || !items.length) return alert('원장·수술명과 재료를 입력해 주세요.');
        if (items.some(x => !Number.isSafeInteger(x.qty) || x.qty < 1 || x.qty > 999)) return alert('추천 수량은 1~999의 정수로 입력해 주세요.');
        ev.submitter.disabled = true;
        try { await persist({ ...p, id: p?.id || `manual:${c.uid()}`, doctorCode, surgery, procedureName, spineRegions, levelCount, items, caseCount: p?.caseCount || 0, active: true, ...c.auditUpdateFields(), updatedAt: new Date().toISOString() }); }
        finally { ev.submitter.disabled = false; }
      });
      el('patternDelete')?.addEventListener('click', async () => {
        if (!confirm(p.active === false ? '패턴을 복원할까요?' : '앞으로의 선택 목록에서 패턴을 삭제할까요? 과거 기록은 유지됩니다.')) return;
        await persist({ ...p, active: p.active === false, ...c.auditUpdateFields(), updatedAt: new Date().toISOString() });
      });
    };
    return { render, bind, isDirty: () => dirty };
  };
})();
