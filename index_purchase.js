(() => {
  const isPurchase = (p) => Boolean(p?.orderCode) || p?.category === 'PURCHASE';
  const unconfirmed = (p) => p?.stockConfirmed === false;
  const stockText = (p) => unconfirmed(p) ? '재고 미확정' : `현재고 ${p?.stock ?? 0} ${p?.stockUnit || '개'}`;
  // 수량은 재고단위로 기록한다. 주문단위당 재고수량은 확인된 양의 정수만 허용한다.
  const factor = (p) => Number.isSafeInteger(Number(p?.unitsPerOrder)) && Number(p.unitsPerOrder) > 0 ? Number(p.unitsPerOrder) : null;
  const orderQty = (p, qty) => factor(p) ? Math.ceil(qty / factor(p)) : null;
  const normalized = (s) => String(s || '').normalize('NFKC').toUpperCase().replace(/\s+/g, ' ').trim();
  const suggestedFactor = (spec, unit) => {
    if (normalized(unit) === 'EA') return 1;
    const match = normalized(spec).match(/^(\d+)\s*EA\s*\/\s*(BOX|PACK)$/);
    return match && match[2] === normalized(unit) ? Number(match[1]) : null;
  };
  const movement = (s, id) => {
    const used = (s.usages || []).reduce((n, u) => n + (u.productIds || []).filter(x => String(x) === String(id)).length, 0)
      + (s.roomRefills || []).reduce((n, r) => n + (r.items || []).filter(x => String(x.productId) === String(id)).reduce((a, x) => a + Number(x.qty || 0), 0), 0);
    const received = (s.receipts || []).filter(r => String(r.productId) === String(id)).reduce((n, r) => n + (r.type === 'landingCancelled' ? 0 : (r.type === 'loan' ? -1 : 1) * Number(r.qty || 0)), 0);
    return { used, received };
  };
  const confirmStock = (s, id, qty, audit) => {
    if (!Number.isSafeInteger(qty) || qty < 0) throw new Error('실사 수량은 0 이상의 정수로 입력해 주세요.');
    const p = s.products.find(x => String(x.id) === String(id));
    if (!p) throw new Error('제품을 찾을 수 없습니다.');
    const m = movement(s, id);
    // 부호 있는 기준재고를 보존해야 실사 이전 입고가 많은 경우에도 정확하다.
    p.baseStock = qty - m.received + m.used;
    p.stock = qty;
    p.stockConfirmed = true;
    p.stockCheckpoints = [...(p.stockCheckpoints || []), { qty, ...m, ...audit }];
    Object.assign(p, audit);
  };
  // 전달 당시 수량은 그대로 보존하고, 이후 사용량 감소·삭제만 비교 경고한다.
  const requestDifferences = (state) => {
    const totals = new Map();
    (state.purchaseRequests || []).filter(r => r.status !== 'cancelled').forEach(r => (r.allocations || []).forEach(a => {
      const key = JSON.stringify([a.usageId, a.productId]);
      const entry = totals.get(key) || { usageId: a.usageId, productId: a.productId, requested: 0 };
      entry.requested += Number(a.qty || 0);
      totals.set(key, entry);
    }));
    return [...totals.values()].map(a => {
      const usage = (state.usages || []).find(u => u.id === a.usageId);
      const current = (usage?.productIds || []).filter(id => id === a.productId).length;
      return { ...a, current, difference: a.requested - current };
    }).filter(a => a.difference > 0);
  };
  window.ORPurchase = { isPurchase, unconfirmed, stockText, factor, orderQty, suggestedFactor, movement, confirmStock, requestDifferences };

  window.createPurchaseModule = (c) => {
    const e = c.escapeHtml;
    let selectedCode = '', query = '', from = c.today(), to = c.today(), dirty = false;
    const catalog = () => window.ORPurchaseCatalog || [];
    const products = () => c.getState().products;
    const selected = () => catalog().find(x => x.code && x.code === selectedCode);
    const linked = (code) => code ? products().find(p => normalized(p.orderCode) === normalized(code)) : null;
    const allocationsFor = (state) => {
      if (!from || !to || from > to) return [];
      const requested = new Map();
      (state.purchaseRequests || []).filter(r=>r.status!=='cancelled').forEach(r=>(r.allocations||[]).forEach(a=>{
        const key=JSON.stringify([a.usageId,a.productId]); requested.set(key,(requested.get(key)||0)+a.qty);
      }));
      return state.usages.filter(u=>u.date>=from&&u.date<=to).flatMap(u=>{
        const counts=new Map();(u.productIds||[]).forEach(id=>counts.set(id,(counts.get(id)||0)+1));
        return [...counts].filter(([id])=>isPurchase(state.products.find(p=>p.id===id))).map(([id,qty])=>({usageId:u.id,productId:id,qty:Math.max(0,qty-(requested.get(JSON.stringify([u.id,id]))||0))})).filter(a=>a.qty>0);
      }).sort((a,b)=>JSON.stringify([a.usageId,a.productId]).localeCompare(JSON.stringify([b.usageId,b.productId])));
    };
    const lines = () => {
      const totals=new Map();allocationsFor(c.getState()).forEach(a=>totals.set(a.productId,(totals.get(a.productId)||0)+a.qty));
      return products().filter(p=>totals.get(p.id)).map(p=>({p,qty:totals.get(p.id)}));
    };
    const mayMark = () => c.canMarkRequested ? c.canMarkRequested() : c.canManageSettings();
    const requestWarning = () => {
      const differences = requestDifferences(c.getState());
      if (!differences.length) return '';
      return `<section class="card workflow-warning" id="purchaseRequestWarning" role="alert"><h3>구매팀 전달 수량 재확인 필요</h3><p>전달 후 사용량이 줄거나 사용 기록이 삭제되었습니다. 실제 주문은 자동 취소되지 않습니다. 구매팀과 대조한 뒤 필요한 전달 기록만 정리해 주세요.</p>${differences.map(a => {
        const p = products().find(x => x.id === a.productId);
        return `<p>${e(p?.orderCode || '코드 확인')} · ${e(p?.name || a.productId)}: 전달 기준 ${a.requested}, 현재 사용 ${a.current}, 차이 ${a.difference} ${e(p?.stockUnit || '개')}</p>`;
      }).join('')}</section>`;
    };
    const requestHistory = () => `<details class="card"><summary>구매팀 전달 이력</summary><p class="helper">앱에서 전달 완료를 기록한 내역입니다. 구매팀 접수·발주·입고 확인과는 별개입니다.</p>${(c.getState().purchaseRequests||[]).slice().reverse().map(r=>`<div class="item"><strong>${e(r.from)} ~ ${e(r.to)} · ${r.status==='cancelled'?'기록 취소':'전달 완료'}</strong><p>${(r.lines||[]).map(x=>`${e(x.code)} · ${e(x.name)} ${x.orderQty} ${e(x.orderUnit)}`).join('<br>')}</p>${r.status!=='cancelled'&&mayMark()?`<button type="button" class="danger" data-cancel-purchase-request="${e(r.id)}">전달 기록 취소</button>`:''}</div>`).join('')||'<p>전달 기록이 없습니다.</p>'}</details>`;
    const orderRows = () => `<p class="helper">${from > to ? '시작일은 종료일보다 늦을 수 없습니다.' : '최종 저장된 사용 중 아직 전달 완료로 기록하지 않은 수량입니다. 목록 복사만으로는 전송·신청되지 않습니다.'}</p><div class="purchase-order-table-wrap"><table class="purchase-order-table"><thead><tr><th>구매코드</th><th>제품명·규격</th><th>사용량</th><th>신청 제안</th><th>현재고</th></tr></thead><tbody>${lines().map(({p,qty}) => `<tr><td>${e(p.orderCode || '미등록')}</td><td>${e(p.purchaseName || p.name)}<br>${e(p.purchaseSpec || '')}</td><td>${qty} ${e(p.stockUnit || '개')}</td><td>${orderQty(p,qty) ?? '단위 확인 필요'} ${e(p.orderUnit || '')}</td><td>${e(stockText(p))}</td></tr>`).join('') || '<tr><td colspan="5">이 기간의 구매팀 연결 품목 사용량이 없습니다.</td></tr>'}</tbody></table></div>`;
    const setup = () => {
      const item = selected(), p = item ? linked(item.code) : null;
      return `<details class="card" open><summary>구매 품목 연결·재고 확정</summary><p class="helper">2026년 9월 목록 581행. 기존 비급여는 기존 제품을 선택해 연결하세요. 처방이 없는 비산정품목은 지금 등록할 필요가 없습니다. 9월 실사 수량은 참고값입니다.</p>
        <label for="purchaseCatalogSearch">코드·품명·보관위치 검색</label><input id="purchaseCatalogSearch" value="${e(query)}" type="search">
        <div id="purchaseCatalogResults">${catalogResults()}</div>
        ${item ? `<form id="purchaseLinkForm"><h3>${e(item.code)} · ${e(item.name)}</h3><p>${e(item.spec)} · 출고단위 ${e(item.orderUnit || '미기재')} · ${e(item.location)} · 9월 실사 ${e(item.historicalStock)}</p>
          <label>앱 제품 연결<select id="purchaseExisting" required><option value="">선택하세요</option><option value="__new__">새 구매재료로 등록</option>${products().map(x => `<option value="${e(x.id)}" ${p?.id === x.id ? 'selected' : ''}>${e(x.name)} / ${e(x.category)}${x.orderCode ? ` / ${e(x.orderCode)}` : ''}</option>`).join('')}</select></label>
          <div class="row three"><label>재고·사용 단위<input id="purchaseStockUnit" value="${e(p?.stockUnit || 'EA')}" required></label><label>신청·입고 단위<input id="purchaseOrderUnit" value="${e(p?.orderUnit || item.orderUnit)}" required></label><label>신청 1단위당 재고 수량<input id="purchaseFactor" type="number" min="1" step="1" value="${e(p?.unitsPerOrder || suggestedFactor(item.spec,item.orderUnit) || '')}" required></label></div>
          <p id="purchaseUnitPreview" class="workflow-warning"></p><p class="helper">예: 재고 EA, 신청 BOX, 100EA/BOX이면 100. 기존 제품의 재고·사용 단위를 유지하세요. PACK·CLIPS 및 여러 포장이 섞인 규격은 실제 단위를 확인해 입력하세요. 새 제품은 재고 미확정으로 시작합니다.</p>
          <label class="toggle-line"><input type="checkbox" id="purchaseUnconfirmed" ${!p || unconfirmed(p) ? 'checked' : ''}> 실사 전 사용량 기록 (재고 미확정)</label>
          <button type="submit">품목 연결 저장</button></form>` : ''}
        <p class="helper">실사 기록과 현재고 확정은 실사·재고 메뉴에서 함께 관리합니다.</p><button type="button" class="secondary" id="purchaseGoCount">실사·재고로 이동</button>
      </details>`;
    };
    const renderCount = () => c.canManageSettings() ? `<section class="card"><h2>② 실사 수량을 현재고에 반영 (관리자)</h2><p class="workflow-warning">위 실사 기록 저장과 다릅니다. 실제 수량을 다시 확인한 후 아래에서 확정해야 현재고가 바뀝니다.</p><form id="purchaseCountForm"><h3>실사로 현재고 확정</h3><p class="helper">선택 품목의 사용·입고 기록을 모두 저장한 뒤 실제 수량을 입력하세요. 이 저장 시점까지 기록된 내역을 포함한 실사입니다. 이전 기록을 나중에 수정·삭제하면 현재고도 다시 계산됩니다.</p><label>제품<select id="purchaseCountProduct" required><option value="">선택</option>${products().filter(x => x.active !== false && !x.vendorManaged).map(x=>`<option value="${e(x.id)}">${e(x.orderCode)} · ${e(x.name)} / ${e(stockText(x))}</option>`).join('')}</select></label><label>실제 수량 (재고·사용 단위)<input id="purchaseCountQty" type="number" min="0" step="1" required></label><button type="submit">실사 수량으로 재고 확정</button></form></section>` : '';
    const catalogResults = () => {
      const needle = normalized(query);
      const matches = catalog().filter(x => !needle || normalized(`${x.code} ${x.name} ${x.spec} ${x.location}`).includes(needle));
      return `<p>${matches.length}행 · 최대 40행 표시</p>${matches.slice(0,40).map(x=>`<button class="secondary purchase-catalog-result" type="button" data-purchase-code="${e(x.code)}" ${!x.code ? 'disabled' : ''}>${e(x.code || '코드 확인 필요')} · ${e(x.name)} · ${e(x.spec)} · ${e(x.location)} ${linked(x.code) ? '(연결됨)' : ''}</button>`).join('')}`;
    };
    const render = () => `<section class="grid purchase-layout"><div class="card"><h2>구매팀 신청</h2><div class="row two"><label>시작일<input id="purchaseFrom" type="date" value="${from}" required></label><label>종료일<input id="purchaseTo" type="date" value="${to}" required></label></div><div id="purchaseOrders">${orderRows()}</div><div class="actions"><button id="purchaseCopy" type="button">구매팀 전달용 목록 복사</button>${mayMark()?'<button id="purchaseMarkRequested" type="button" class="secondary">구매팀 전달 완료 기록</button>':''}</div><textarea id="purchaseCopyFallback" aria-label="복사용 신청 목록" hidden readonly></textarea></div>${c.canManageSettings() ? setup() : ''}</section>${requestHistory()}`;
    const bind = () => {
      dirty = false;
      document.getElementById('purchaseGoCount')?.addEventListener('click', () => c.openCount?.());
      const el = id => document.getElementById(id);
      const showUnit = () => {
        const qty=Number(el('purchaseFactor')?.value), stock=el('purchaseStockUnit')?.value || '', order=el('purchaseOrderUnit')?.value || '';
        if(el('purchaseUnitPreview'))el('purchaseUnitPreview').textContent=Number.isSafeInteger(qty)&&qty>0 ? `1 ${order} = ${qty} ${stock} · 2 ${order} 입고 시 ${2*qty} ${stock} 증가` : '포장당 수량을 확인해 주세요.';
      };
      ['purchaseFactor','purchaseStockUnit','purchaseOrderUnit'].forEach(id=>el(id)?.addEventListener('input',showUnit));showUnit();
      ['purchaseLinkForm', 'purchaseCountForm'].forEach(id => el(id)?.addEventListener('input', () => { dirty = true; }));
      ['purchaseFrom','purchaseTo'].forEach(id => el(id)?.addEventListener('change',()=> { from=el('purchaseFrom').value;to=el('purchaseTo').value;el('purchaseOrders').innerHTML=orderRows(); }));
      el('purchaseMarkRequested')?.addEventListener('click',async ev=>{
        if(!mayMark())return;
        const rows=lines(), allocations=allocationsFor(c.getState());
        if(!rows.length)return alert('기록할 미전달 사용량이 없습니다.');
        if(rows.some(({p})=>!p.orderCode||!factor(p)||!p.orderUnit))return alert('품목코드와 신청 단위를 확인해 주세요.');
        if(!confirm('이 목록을 실제 구매팀에 전달하셨습니까? 확인하면 해당 사용량을 다음 신청 제안에서 제외합니다. 앱이 주문을 전송하지는 않습니다.'))return;
        const record={id:c.uid(),from,to,status:'sent',allocations,lines:rows.map(({p,qty})=>({productId:p.id,code:p.orderCode,name:p.purchaseName||p.name,qty,orderQty:orderQty(p,qty),orderUnit:p.orderUnit})),...c.auditUpdateFields(),updatedAt:new Date().toISOString()};
        const b=ev.currentTarget;b.disabled=true;
        try{if(await c.saveState('구매팀 전달 기록 완료',{apply:s=>{
          if(JSON.stringify(allocationsFor(s))!==JSON.stringify(allocations))throw new Error('사용량 또는 전달 이력이 변경되었습니다. 새로고침 후 확인해 주세요.');
          s.purchaseRequests=[...(s.purchaseRequests||[]),record];
        }}))c.render();}finally{b.disabled=false;}
      });
      document.querySelectorAll('[data-cancel-purchase-request]').forEach(b=>b.addEventListener('click',async()=>{
        if(!mayMark()||!confirm('전달 기록만 취소합니다. 구매팀 주문은 취소되지 않습니다. 실제 주문 상태를 먼저 확인하셨습니까?'))return;
        if(await c.saveState('전달 기록 취소 완료',{apply:s=>{
          const r=(s.purchaseRequests||[]).find(x=>x.id===b.dataset.cancelPurchaseRequest);
          if(r)Object.assign(r,{status:'cancelled',...c.auditUpdateFields(),updatedAt:new Date().toISOString()});
        }}))c.render();
      }));
      el('purchaseCopy')?.addEventListener('click',async()=>{
        const data=lines();
        if (!data.length) return alert('기간과 사용내역을 확인해 주세요.');
        if(data.some(({p})=>!p.orderCode || !factor(p) || !p.orderUnit)) return alert('구매코드와 신청 단위를 먼저 연결해 주세요.');
        const cell = v => String(v).replace(/[\t\r\n]/g,' ').replace(/^([=+@-])/,"'$1");
        const text=[['기간',from,to],['구매코드','제품명','규격','신청수량','단위','사용량','사용단위'],...data.map(({p,qty})=>[p.orderCode,p.purchaseName||p.name,p.purchaseSpec||'',orderQty(p,qty),p.orderUnit,qty,p.stockUnit])].map(r=>r.map(cell).join('\t')).join('\n');
        try {await navigator.clipboard.writeText(text);c.saveDoneToast('신청 목록을 복사했습니다. 구매팀 전달 후 신청 여부를 기록해 주세요.');}
        catch {el('purchaseCopyFallback').hidden=false;el('purchaseCopyFallback').value=text;el('purchaseCopyFallback').select();}
      });
      el('purchaseCatalogSearch')?.addEventListener('input',ev=>{query=ev.target.value;el('purchaseCatalogResults').innerHTML=catalogResults();});
      el('purchaseCatalogResults')?.addEventListener('click',ev=>{const b=ev.target.closest('[data-purchase-code]');if(!b)return;if(dirty&&!confirm('저장하지 않은 입력을 비우고 다른 품목을 선택할까요?'))return;selectedCode=b.dataset.purchaseCode;c.render();});
      el('purchaseLinkForm')?.addEventListener('submit',async ev=>{
        ev.preventDefault();if(!c.canManageSettings())return;
        const item=selected(), choice=el('purchaseExisting').value, units=Number(el('purchaseFactor').value), stockUnit=el('purchaseStockUnit').value.trim(), orderUnit=el('purchaseOrderUnit').value.trim(), pendingStock=el('purchaseUnconfirmed').checked;
        if(!item || !choice || !Number.isSafeInteger(units)||units<1||!stockUnit||!orderUnit)return;
        if(choice==='__new__' && !confirm('같은 제품이 기존 비급여·재고 목록에 없는지 확인하셨습니까? 새 품목으로 등록합니다.'))return;
        const id=choice==='__new__'?c.uid():choice;
        const apply=s=>{
          if(s.products.some(x=>normalized(x.orderCode)===normalized(item.code) && x.id!==id))throw new Error('이미 다른 제품에 연결된 구매코드입니다.');
          let p=s.products.find(x=>x.id===id);
          if(p?.orderCode && normalized(p.orderCode)!==normalized(item.code))throw new Error('이 제품은 다른 구매코드에 연결되어 있습니다.');
          if(p?.stockUnit && p.stockUnit!==stockUnit)throw new Error('사용 중인 재고 단위는 변경할 수 없습니다.');
          if(!p){if(choice!=='__new__')throw new Error('제품이 삭제되었습니다.');p={id,name:item.name,category:'PURCHASE',stock:0,baseStock:0,stockConfirmed:false,warningStock:0,company:'',landingQty:0};s.products.push(p);}
          if(pendingStock) p.stockConfirmed=false;
          Object.assign(p,{orderCode:item.code,purchaseName:item.name,purchaseSpec:item.spec,orderUnit,stockUnit,unitsPerOrder:units,storageLocation:item.location,purchaseSource:'2026-09',historicalStock:item.historicalStock,targetStock:item.target,...c.auditUpdateFields(),updatedAt:new Date().toISOString()});
        };
        const b=ev.submitter;b.disabled=true;
        try{if(await c.saveState('구매 품목 연결 완료',{apply}))c.render();}finally{b.disabled=false;}
      });
      el('purchaseCountForm')?.addEventListener('submit',async ev=>{
        ev.preventDefault();if(!c.canManageSettings())return;
        const id=el('purchaseCountProduct').value, qty=Number(el('purchaseCountQty').value), p=products().find(x=>x.id===id);
        if(!p||!Number.isSafeInteger(qty)||qty<0)return;
        if(!confirm(`${p.name}: 실제 ${qty} ${p.stockUnit||'개'}로 확정합니다. 이 품목의 사용·입고 기록이 모두 저장되었는지 확인해 주세요.`))return;
        const audit={...c.auditUpdateFields(),updatedAt:new Date().toISOString()};
        const b=ev.submitter;b.disabled=true;
        try{if(await c.saveState('실사 재고 확정 완료',{apply:s=>confirmStock(s,id,qty,audit)}))c.render();}finally{b.disabled=false;}
      });
    };
    return {render:()=>requestWarning()+render(),bind,renderCount,isDirty:()=>dirty};
  };
})();
