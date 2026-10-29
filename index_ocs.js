// OCS 원문은 메모리에서만 해석한다. 저장 대상은 허용한 코드·명칭·수량 필드뿐이다.
(() => {
  const clone = value => JSON.parse(JSON.stringify(value));
  const number = value => /^\d+(?:\.\d+)?$/.test(String(value).trim()) ? Number(value) : null;
  const canonical = value => JSON.stringify(value, (_key, item) => item && !Array.isArray(item) && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
  const supportedProduct = p => p && p.active !== false && ['비급여', 'PURCHASE'].includes(p.category);
  const surgeryName = value => {
    const name=String(value || '').trim();
    if (name.length>200 || /[\t\r\n]/.test(name)) throw Error('수술명만 한 줄로 복사해 주세요. 최대 200자까지 입력할 수 있습니다.');
    return name;
  };
  function parse(text) {
    if (!text.trim() || text.length > 500000) throw Error('복사 내용을 확인해 주세요. 한 번에 한 케이스만 붙여넣어 주세요.');
    const records = [];
    for (const line of text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n')) {
      if (!line.trim()) continue;
      const columns = line.split('\t');
      // 상태가 다른 행도 버리지 않고 아래에서 중단한다. 설명 칸의 줄바꿈만 이어 붙인다.
      if (columns[0] === 'A' && columns.length >= 10) records.push(columns);
      else if (records.length && records.at(-1).length < 103) {
        records.at(-1)[records.at(-1).length - 1] += '\n' + columns.shift();
        records.at(-1).push(...columns);
      } else throw Error('알 수 없는 행이 있습니다. OCS에서 처방 전체 행을 다시 복사해 주세요.');
    }
    const rows = [];
    let excludedCount = 0;
    for (const c of records) {
      if (c.length !== 103) throw Error(`복사된 ${records.indexOf(c)+1}번째 행의 열 구조가 다릅니다. 전체 행을 다시 복사해 주세요.`);
      if (!['처방', '조제', '접수'].includes(c[1])) throw Error(`복사된 ${records.indexOf(c)+1}번째 행의 처방 상태를 확인할 수 없습니다. 취소·중지 여부를 확인해 주세요.`);
      const deletedName = /^\s*D\/C:1\]\s*/.test(c[4]);
      const deletedFlag = c[14].trim() === 'D';
      if (deletedName !== deletedFlag || (/D\/C/i.test(c[4]) && !deletedName)) throw Error('삭제 표식이 일치하지 않습니다. OCS에서 상태를 확인해 주세요.');
      const cancelled = deletedName && deletedFlag;
      if (cancelled) { excludedCount++; continue; }
      const code = c[3].trim(), name = c[4].replace(/^\s*(?:추가\]|D\/C:1\])\s*/, '').trim();
      // 실제 OCS 화면과 대조한 제목만 제외한다. P 값만으로 행위료를 제외하지 않는다.
      const heading = (code === '@AAOP' && name === '<< Op. Room Order >>')
        || (code === '@HH' && name === '▶ 처치수술 처방')
        || (code === '@' && ['[GS 3D Cage (2cage)]','[GS medical]','1. MIS & Long Arm Screw','<<수술팀 Order>>'].includes(name));
      if (heading) continue;
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(code) || !name || name.length > 250 || /[\r\n]/.test(name)) throw Error('코드 또는 제품명 형식을 확인해 주세요.');
      const dose = number(c[7]), times = number(c[8]), days = number(c[9]);
      if ([dose, times, days].some(v => v === null || !Number.isFinite(v) || v <= 0 || v > 10000)) throw Error('수량·횟수·일수가 비어 있거나 해석할 수 없습니다.');
      rows.push({code, name, dose, times, days, cancelled, qty: cancelled ? 0 : times === 1 && days === 1 && Number.isInteger(dose) ? dose : null, mode:cancelled?'cancelled':'unresolved', productId:''});
    }
    if ((!rows.length && !excludedCount) || records.length > 201) throw Error('처방 1~200행을 한 케이스씩 입력해 주세요.');
    rows.excludedCount = excludedCount;
    return rows;
  }
  function prepare(rows, catalog) {
    return rows.map(row => {
      if (row.cancelled || row.mode === 'cancelled') throw Error('삭제 항목은 등록할 수 없습니다. 다시 붙여넣어 주세요.');
      const item = catalog.find(c => c.code === row.code);
      // 같은 코드라도 새 명칭이면 기존 연결을 무조건 적용하지 않는다.
      const known = item?.names?.includes(row.name);
      return {...row, mode:known ? item.mode || 'unresolved' : 'unresolved', productId:known ? item.productId || '' : ''};
    });
  }
  function apply(target, remote, request, permissions) {
    const {canEdit, canManage, canModify, actor, stockUnconfirmed} = permissions;
    if (!canEdit) throw Error('사용 기록 저장 권한이 없습니다.');
    const surgeryDetail=surgeryName(request.surgeryDetail) || 'OCS 수술 후 사용';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(request.date) || !Number.isInteger(Number(request.caseRoom)) || Number(request.caseRoom)<1 || Number(request.caseRoom)>10 || !Number.isInteger(Number(request.caseOrder)) || Number(request.caseOrder)<1 || Number(request.caseOrder)>99) throw Error('날짜와 케이스 번호를 확인해 주세요.');
    const previous = request.previous;
    const latest = (remote.usages || []).find(u => u.id === request.id);
    if (previous && (!latest || canonical(latest) !== canonical(previous))) throw Error('다른 사용자가 수정 또는 삭제했습니다. 최신 기록을 다시 불러와 주세요.');
    if (!previous && latest) throw Error('이미 저장된 요청입니다. 기존 기록을 확인해 주세요.');
    if (!canModify(previous || request)) throw Error('당일이 아닌 사용내역은 관리자만 저장·수정할 수 있습니다.');
    if ((remote.usages || []).some(u => u.id !== request.id && u.date === request.date && Number(u.caseRoom) === Number(request.caseRoom) && Number(u.caseOrder) === Number(request.caseOrder))) throw Error('같은 날짜·케이스 기록이 있습니다. 기존 기록을 수정해 주세요.');
    if (!request.rows.length || request.rows.length > 200) throw Error('처방 목록을 확인해 주세요.');
    const rows = request.rows.map(row => {
      if (row.cancelled || row.mode === 'cancelled' || /^\s*D\/C/i.test(row.name || '')) throw Error('삭제 항목은 저장할 수 없습니다.');
      if (!['linked','excluded','unresolved','cancelled'].includes(row.mode) || !Number.isSafeInteger(row.qty) || row.qty < 0 || row.qty > 10000) throw Error('사용 수량은 0~10000의 정수로 확인해 주세요.');
      if ((row.cancelled || row.mode==='cancelled') && (!row.cancelled || row.mode!=='cancelled' || row.qty!==0 || row.productId)) throw Error('OCS 삭제 행은 사용량에 포함할 수 없습니다.');
      if (!row.code || !row.name) throw Error('코드와 명칭이 필요합니다.');
      const stored = (remote.ocsCatalog || []).find(c => c.code === row.code);
      const expected = (request.catalogSnapshot || []).find(c => c.code === row.code);
      const linkKey = r => `${r?.mode || 'unresolved'}:${r?.productId || ''}`;
      if (!row.cancelled && request.catalogSnapshot && canManage && linkKey(stored)!==linkKey(expected) && linkKey(row)!==linkKey(stored)) throw Error('다른 사용자가 코드 연결을 변경했습니다. 최신 목록으로 다시 확인해 주세요.');
      const oldRow = previous?.ocsRows?.find(r => r.code === row.code && r.name === row.name);
      const sameLink = r => r && r.mode === row.mode && (r.productId || '') === (row.productId || '');
      if (!canManage && !row.cancelled && row.mode !== 'unresolved' && !sameLink(oldRow) && !(stored?.names?.includes(row.name) && sameLink(stored))) throw Error('새 재고 연결·차감 제외는 관리자가 확인해야 합니다.');
      if (row.mode === 'linked' && !supportedProduct(target.products.find(p => p.id === row.productId))) throw Error('연결 제품이 삭제되었거나 별도 장부 대상입니다. 연결을 다시 확인해 주세요.');
      return {code:row.code,name:row.name,dose:row.dose,times:row.times,days:row.days,cancelled:!!row.cancelled,qty:row.qty,mode:row.mode,productId:row.mode==='linked'?row.productId:''};
    });
    // 같은 코드의 복수 행은 합산하되 연결 결정은 일치해야 한다.
    for (const row of rows.filter(r=>!r.cancelled)) if (rows.some(r => !r.cancelled && r.code === row.code && (r.mode !== row.mode || r.productId !== row.productId))) throw Error('같은 코드의 연결 설정이 서로 다릅니다.');
    const productIds = rows.flatMap(r => r.mode === 'linked' ? Array(r.qty).fill(r.productId) : []);
    if (productIds.length > 20000) throw Error('한 케이스의 수량이 너무 큽니다. 단위를 확인해 주세요.');
    const counts = ids => ids.reduce((m,id) => (m.set(id,(m.get(id)||0)+1),m),new Map());
    const oldCounts = counts(previous?.productIds || []);
    for (const [id,qty] of counts(productIds)) {
      const p = target.products.find(p => p.id === id);
      if (qty - (oldCounts.get(id)||0) > Number(p.stock || 0) && !stockUnconfirmed(p)) throw Error('최신 재고가 부족합니다. 입력은 유지됩니다.');
    }
    const at = request.at;
    const entry = {
      ...(previous || {}), id:request.id, date:request.date, caseRoom:String(Number(request.caseRoom)), caseOrder:String(Number(request.caseOrder)),
      doctorId:request.doctorId || '', surgeryId:'', surgeryDetail, productIds,
      source:'ocs-paste', ocsRows:rows, ocsOriginalRows:previous?.ocsOriginalRows || rows.map(({code,name,dose,times,days,cancelled})=>({code,name,dose,times,days,cancelled})),
      ocsRevision:(previous?.ocsRevision || 0)+1,
      ocsChanges:[...(previous?.ocsChanges || []), ...(previous ? [{at,by:actor,before:previous.ocsRows,after:rows,surgeryBefore:previous.surgeryDetail || '',surgeryAfter:surgeryDetail}] : [])],
      ...(previous ? {} : {createdAt:at,createdBy:actor,createdByName:actor.name || ''}), updatedAt:at,updatedBy:actor,updatedByName:actor.name || ''
    };
    target.usages = [...target.usages.filter(u=>u.id!==entry.id),entry];
    const catalog = clone(remote.ocsCatalog || []);
    for (const row of rows) {
      let item = catalog.find(c=>c.code===row.code);
      if (!item) { item={id:row.code,code:row.code,names:[],firstSeenAt:at,mode:'unresolved',productId:''};catalog.push(item); }
      if (!item.names.includes(row.name)) item.names.push(row.name);
      item.lastSeenAt=at;item.updatedAt=at;
      if (canManage && !row.cancelled) {item.mode=row.mode;item.productId=row.productId;item.updatedBy=actor;}
    }
    target.ocsCatalog=catalog;
    // 전체 상태가 단일 Firestore 문서이므로 크기 초과 시 부분 저장 없이 중단한다.
    if (new TextEncoder().encode(JSON.stringify(target)).length > 850000) throw Error('저장 공간이 부족합니다. 관리자에게 OCS 목록 저장소 분리를 요청해 주세요.');
  }
  window.OROcs = {parse,prepare,apply,supportedProduct,surgeryName};
  window.createOcsModule = context => {
    const e=context.escapeHtml;
    let rows=[], previous=null, dirty=false, busy=false, catalogSnapshot=[], excludedCount=0;
    const render = (record=null) => {
      previous=record?clone(record):null;rows=record?clone(record.ocsRows):[];dirty=false;
      excludedCount=0;
      catalogSnapshot=clone(context.getState().ocsCatalog||[]);
      return `<section class="card" id="ocsPanel"><h2>${record?'OCS 사용 수량 수정':'OCS 처방 붙여넣기'}</h2>
        <p>수술 후 확정된 처방을 복사해 등록하세요. 붙여넣기만으로는 재고가 바뀌지 않습니다.</p>
        <div class="row four"><div><label for="ocsDate">사용일</label><input id="ocsDate" type="date" value="${e(record?.date||context.today())}" ${record?'disabled':''}></div>
        <div><label for="ocsRoom">수술실</label><input id="ocsRoom" type="number" min="1" max="10" value="${e(record?.caseRoom||'')}" ${record?'disabled':''}></div>
        <div><label for="ocsOrder">오늘 순서</label><input id="ocsOrder" type="number" min="1" max="99" value="${e(record?.caseOrder||'')}" ${record?'disabled':''}></div>
        <div><label for="ocsDoctor">원장 코드</label><select id="ocsDoctor"><option value="">선택</option>${context.getState().doctors.filter(d=>d.active!==false||d.id===record?.doctorId).map(d=>`<option value="${e(d.id)}" ${d.id===record?.doctorId?'selected':''}>${e(d.name)}</option>`).join('')}</select></div></div>
        <label for="ocsSurgery">수술명 (붙여넣기 또는 직접 입력)</label><input id="ocsSurgery" type="text" maxlength="200" autocomplete="off" value="${e(record?.surgeryDetail==='OCS 수술 후 사용'?'':record?.surgeryDetail||'')}" placeholder="예: Laparoscopic appendectomy">
        <p class="helper">수술명만 복사해 붙여넣으세요. 목록에 없는 수술명도 입력할 수 있습니다. 환자명·등록번호는 입력하지 마세요. 처방 붙여넣기 원문은 저장하지 않습니다.</p>
        ${record?'':`<label for="ocsPaste">OCS에서 복사한 내용</label><textarea id="ocsPaste" rows="4" autocomplete="off" spellcheck="false" placeholder="OCS 처방 행을 복사해 여기에 붙여넣으세요"></textarea><button id="ocsParse" type="button">처방 읽기</button>`}
        <p id="ocsMessage" role="status"></p><div id="ocsRows"></div>
        <label><input type="checkbox" id="ocsConfirm"> 수술 후 사용 수량과 연결·미연결 항목을 확인했습니다.</label>
        <button id="ocsSave" type="button">${record?'수량 수정 저장':'확인 후 최종 저장'}</button>
        ${record?'<button id="ocsBack" class="secondary" type="button">사용내역으로</button>':''}
        <details><summary>OCS 코드·명칭 누적 목록 (${(context.getState().ocsCatalog||[]).length}코드)</summary><p class="helper">관리자는 처방 행에서 재고 제품을 선택하면 다음 등록부터 같은 코드·명칭에 적용됩니다. 1회량 1과 선택 제품의 재고 단위 1이 같을 때만 연결하세요. 인체조직·임플란트 등 별도 장부 품목은 기존 입력을 이용하세요.</p>
        <div style="max-height:240px;overflow:auto">${(context.getState().ocsCatalog||[]).map(c=>`<p><strong>${e(c.code)}</strong> · ${c.names.map(e).join(' / ')} · ${c.mode==='linked'?'재고 연결':c.mode==='excluded'?'차감 제외':'연결 필요'}</p>`).join('')}</div></details>
        ${record?`<details><summary>수정 이력 (${record.ocsChanges?.length||0}회)</summary>${(record.ocsChanges||[]).map(c=>`<p>${e(c.at)} · ${e(c.by?.name||'')}<br>${c.after.map((r,i)=>`${e(r.code)}: ${e(c.before[i]?.qty??'?')} → ${e(r.qty)}`).join('<br>')}</p>`).join('')}</details>`:''}
        ${record?(record.ocsChanges||[]).filter(c=>c.surgeryAfter!==undefined&&c.surgeryBefore!==c.surgeryAfter).map(c=>`<p class="helper">수술명 수정 · ${e(c.at)} · ${e(c.by?.name||'')}: ${e(c.surgeryBefore)} → ${e(c.surgeryAfter)}</p>`).join(''):''}
      </section>`;
    };
    function bind() {
      const panel=document.getElementById('ocsPanel');if(!panel)return;
      const $=id=>document.getElementById(id);
      const message=s=>{$('ocsMessage').textContent=s;};
      // 두 입력 방식의 미저장 내용을 서로 덮어쓰지 않는다.
      const protectOtherSave=event=>{if(dirty){event.preventDefault();event.stopImmediatePropagation();message('위 OCS 입력을 먼저 저장하거나 화면을 다시 열어 정리해 주세요.');panel.scrollIntoView({block:'start'});}};
      document.getElementById('useForm')?.addEventListener('submit',protectOtherSave,true);
      document.getElementById('saveUseDraft')?.addEventListener('click',protectOtherSave,true);
      const touch=()=>{dirty=true;$('ocsConfirm').checked=false;};
      $('ocsSurgery').addEventListener('paste',event=>{
        event.preventDefault();
        try {const input=$('ocsSurgery'),name=surgeryName(event.clipboardData.getData('text/plain'));surgeryName(input.value.slice(0,input.selectionStart)+name+input.value.slice(input.selectionEnd));input.setRangeText(name,input.selectionStart,input.selectionEnd,'end');touch();}
        catch(error){message(error.message);}
      });
      const paint=()=>{
        const products=context.getState().products.filter(supportedProduct);
        $('ocsRows').innerHTML=rows.map((r,i)=>r.cancelled?`<div class="item" data-ocs-cancelled style="display:block;overflow-wrap:anywhere;margin:8px 0"><strong>OCS 삭제 · 사용량 제외</strong><p>${e(r.code)} · ${e(r.name)}</p><p class="helper">원본 1회량 ${e(r.dose)} · 재고 차감 없음. 과거에 저장한 기록을 자동 취소하지는 않습니다.</p></div>`:`<div class="item" style="display:block;overflow-wrap:anywhere;margin:8px 0"><strong>${e(r.code)}</strong> · ${e(r.name)}
          <div class="helper">복사된 1회량 ${e(r.dose)} / 횟수 ${e(r.times)} / 일수 ${e(r.days)}${r.times!==1||r.days!==1?' · 자동 곱셈하지 않음: 실제 사용 수량을 입력하세요':''}</div>
          <div class="row two"><div><label for="ocsQty${i}">확인한 사용 수량</label><input id="ocsQty${i}" data-ocs-qty="${i}" type="number" min="0" max="10000" step="1" value="${r.qty===null?'':r.qty}"></div>
          <div><label for="ocsLink${i}">재고 연결 (단위 1:1 확인)</label><select id="ocsLink${i}" data-ocs-link="${i}" ${context.canManage()?'':'disabled'}><option value="unresolved" ${r.mode==='unresolved'?'selected':''}>미연결 · 기록만 저장</option><option value="excluded" ${r.mode==='excluded'?'selected':''}>행위료·비용 등 차감 제외</option>${products.map(p=>`<option value="p:${e(p.id)}" ${r.mode==='linked'&&r.productId===p.id?'selected':''}>${e(p.orderCode||'코드 없음')} · ${e(p.name)} (${e(p.stockUnit||'개')})</option>`).join('')}${r.mode==='linked'&&!products.some(p=>p.id===r.productId)?'<option selected value="invalid">기존 연결 제품 확인 필요</option>':''}</select></div></div></div>`).join('');
        message(`${excludedCount?`삭제 ${excludedCount}행 제외 · `:''}${rows.length?`등록 대상 ${rows.length}행 · 미연결 ${rows.filter(r=>r.mode==='unresolved').length}행은 재고에 반영되지 않습니다.`:'등록할 처방이 없습니다.'}`);
        $('ocsSave').disabled=!rows.length;
      };
      paint();
      panel.addEventListener('input',event=>{
        if(event.target.id==='ocsConfirm')return;
        touch();
        if(event.target.hasAttribute('data-ocs-qty'))rows[Number(event.target.dataset.ocsQty)].qty=number(event.target.value);
      });
      panel.addEventListener('change',event=>{
        if(!event.target.hasAttribute('data-ocs-link'))return;
        const row=rows[Number(event.target.dataset.ocsLink)];const v=event.target.value;
        row.mode=v.startsWith('p:')?'linked':v;row.productId=v.startsWith('p:')?v.slice(2):'';touch();
        message(`${excludedCount?`삭제 ${excludedCount}행 제외 · `:''}등록 대상 ${rows.length}행 · 미연결 ${rows.filter(r=>r.mode==='unresolved').length}행은 재고에 반영되지 않습니다.`);
      });
      $('ocsParse')?.addEventListener('click',()=>{
        try {catalogSnapshot=clone(context.getState().ocsCatalog||[]);const parsed=parse($('ocsPaste').value);excludedCount=parsed.excludedCount;rows=prepare(parsed,catalogSnapshot);$('ocsPaste').value='';touch();paint();}
        catch(error){rows=[];excludedCount=0;touch();paint();message(error.message);}
      });
      $('ocsBack')?.addEventListener('click',()=>{if(!dirty||confirm('저장하지 않은 변경을 닫을까요?')){dirty=false;context.back();}});
      $('ocsSave').addEventListener('click',async()=>{
        if(busy)return;
        if(context.otherFormDirty?.()){message('아래 기존 사용입력에 저장하지 않은 내용이 있습니다. 먼저 저장하거나 새 케이스 입력으로 정리해 주세요.');return;}
        const date=$('ocsDate').value,caseRoom=$('ocsRoom').value,caseOrder=$('ocsOrder').value;
        const invalid=context.validateCase(caseRoom,caseOrder);
        if(invalid||!date||!$('ocsDoctor').value){message(invalid||'사용일과 원장 코드를 선택해 주세요.');return;}
        let surgeryDetail;
        try {surgeryDetail=surgeryName($('ocsSurgery').value);}catch(error){message(error.message);return;}
        if(!rows.length||!$('ocsConfirm').checked){message('처방을 읽고 사용 수량 확인에 체크해 주세요.');return;}
        const unresolved=rows.filter(r=>r.mode==='unresolved').length;
        if(unresolved&&!confirm(`미연결 ${unresolved}행은 기록만 저장되며 재고가 차감되지 않습니다. 계속할까요?`))return;
        const request={id:previous?.id||context.uid(),previous:clone(previous),catalogSnapshot:clone(catalogSnapshot),rows:clone(rows),date,caseRoom,caseOrder,doctorId:$('ocsDoctor').value,surgeryDetail,at:new Date().toISOString()};
        busy=true;$('ocsSave').disabled=true;
        try {
          const saved=await context.saveState('OCS 사용 기록 저장 완료',{requireTransaction:true,preserveFormOnFailure:true,apply:(target,remote)=>apply(target,remote,request,{
            canEdit:context.canEdit(),canManage:context.canManage(),canModify:context.canModify,actor:context.actor()||{},stockUnconfirmed:context.stockUnconfirmed
          })});
          if(saved){dirty=false;context.saved(request.id);}else message('저장하지 못했습니다. 입력은 유지됩니다. 오류 안내를 확인해 주세요.');
        } finally {busy=false;if($('ocsSave'))$('ocsSave').disabled=false;}
      });
    }
    return {render,bind,isDirty:()=>dirty};
  };
})();
