// 저장된 처방과 차감 기록이 일치하는 케이스에만 미연결 수량을 추가한다.
(() => {
  const copy=x=>JSON.parse(JSON.stringify(x)),equal=(a,b)=>window.ORStorageV2.equal(a,b);
  const counts=ids=>{const out={};for(const id of ids)out[id]=(out[id]||0)+1;return out;};
  function inspect(state,choices={}){
    const changes=[],pending=[],totals={};let preserved=0;
    const catalog=new Map(state.ocsCatalog.map(c=>[c.code,c])),products=new Map(state.products.map(p=>[p.id,p]));
    for(const usage of state.usages){
      if(usage.source!=='ocs-paste'||!Array.isArray(usage.ocsRows))continue;
      const label=`${usage.date} ${usage.caseRoom}-${usage.caseOrder}`;
      const linked=usage.ocsRows.filter(r=>r.mode==='linked');
      if(linked.some(r=>!Number.isSafeInteger(r.qty)||r.qty<0||r.qty>10000)||!equal(counts(linked.flatMap(r=>Array(r.qty).fill(r.productId))),counts(usage.productIds||[]))){pending.push({usageId:usage.id,label,reason:'처방 연결 수량과 기존 차감 기록 불일치'});continue;}
      const additions=[];
      usage.ocsRows.forEach((row,index)=>{
        const c=catalog.get(row.code);if(!c?.linkPolicy)return;
        if(row.mode==='linked'){preserved++;return;}
        if(row.mode!=='unresolved'||row.cancelled||!row.qty)return;
        const item={usageId:usage.id,label,index,code:row.code,name:row.name,qty:row.qty};
        if(!['direct','ledger-direct','select'].includes(c.linkPolicy)){if(c.linkPolicy==='hold')pending.push({...item,reason:'현장 확인 보류'});return;}
        if(!c.names.includes(row.name)){pending.push({...item,reason:'처방명 확인 필요'});return;}
        let id=c.productId;
        if(c.linkPolicy==='select'){
          id=choices[usage.id+':'+index];
          if(!id){pending.push({...item,reason:'실제 사용 제품 선택 필요',options:c.selectionProductIds});return;}
          if(!c.selectionProductIds.includes(id))throw Error('허용되지 않은 선택 제품입니다.');
        }
        const p=products.get(id);
        if(!p||p.active===false||!(c.linkPolicy==='ledger-direct'?window.OROcsLedger.needsLedger(p):window.OROcs.supportedProduct(p))){pending.push({...item,reason:'제품 정보 확인 필요'});return;}
        if(!Number.isSafeInteger(row.qty)||row.qty<1||row.qty>10000)throw Error(label+' 사용 수량 확인 필요');
        additions.push({...item,productId:id,productName:p.name,orderCode:p.orderCode||'',ledger:window.OROcsLedger.needsLedger(p),vendorManaged:p.category==='인체조직'&&!!p.vendorManaged});
        totals[id]=(totals[id]||0)+row.qty;
      });
      if(additions.length)changes.push({usageId:usage.id,label,additions});
    }
    if(changes.length>100)throw Error('한 번에 100케이스 이하로 처리해야 합니다.');
    return {changes,pending,totals,preserved};
  }
  function apply(remote,expected,choices,actor,at,{reconcile,stockUnconfirmed}){
    if(actor?.role!=='admin')throw Error('관리자만 과거 연결을 반영할 수 있습니다.');
    if(!equal(remote,expected))throw Error('미리보기 이후 자료가 변경되었습니다. 다시 점검해 주세요.');
    const plan=inspect(remote,choices),next=copy(remote);
    for(const [id,qty] of Object.entries(plan.totals)){
      const p=remote.products.find(p=>p.id===id);
      if(!(p.category==='인체조직'&&p.vendorManaged)&&!stockUnconfirmed(p)&&qty>Number(p.stock))throw Error(`${p.name} [${p.orderCode||''}]: 현재 ${p.stock}, 추가 차감 ${qty}. 재고 확인이 필요합니다.`);
    }
    for(const change of plan.changes){
      const u=next.usages.find(u=>u.id===change.usageId),before=copy(u.ocsRows);
      for(const a of change.additions){Object.assign(u.ocsRows[a.index],{mode:'linked',productId:a.productId});u.productIds.push(...Array(a.qty).fill(a.productId));}
      u.ocsChanges=[...(u.ocsChanges||[]),{at,by:copy(actor),reason:'confirmed-link-backfill',before,after:copy(u.ocsRows),surgeryBefore:u.surgeryDetail||'',surgeryAfter:u.surgeryDetail||''}];
      u.ocsRevision=(u.ocsRevision||0)+1;u.updatedAt=at;u.updatedBy=copy(actor);u.updatedByName=actor.name||'';
    }
    if(plan.changes.length)reconcile(next);
    return {state:next,...plan};
  }
  window.OROcsBackfill={inspect,apply};
})();
