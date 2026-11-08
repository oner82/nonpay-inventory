// 확인된 연결만 반영한다. 제품·재고·과거 사용 기록은 이 모듈에서 변경하지 않는다.
(() => {
  const copy = v => JSON.parse(JSON.stringify(v));
  const equal = (a,b) => window.ORStorageV2.equal(a,b);
  const policy = c => ({mode:c.mode||'unresolved',productId:c.productId||'',selectionProductIds:c.selectionProductIds||[],linkPolicy:c.linkPolicy||'',confirmedProductIds:c.confirmedProductIds||[],linkNote:c.linkNote||''});
  const identity = p => ({id:p.id,name:p.name,category:p.category,company:p.company||'',orderCode:p.orderCode||'',stockUnit:p.stockUnit||'',active:p.active!==false,vendorManaged:!!p.vendorManaged});
  function apply(state, file, actor, at) {
    if (actor?.role !== 'admin') throw Error('관리자만 연결을 반영할 수 있습니다.');
    if (file?.format !== 'ocs-confirmed-links-v1' || !Array.isArray(file.entries) || !file.entries.length || file.entries.length>150) throw Error('확인된 연결 파일 형식을 확인해 주세요.');
    const next=copy(state),seen=new Set(),changed=[];
    for(const entry of file.entries){
      if(seen.has(entry.code))throw Error('중복 처방코드: '+entry.code);seen.add(entry.code);
      const item=next.ocsCatalog.find(c=>c.code===entry.code);
      if(!item || !equal(item.names,entry.names))throw Error('처방명 변경 또는 코드 없음: '+entry.code);
      const p=entry.policy;
      if(!p || !['direct','select','usage-only','hold','ledger-pending'].includes(p.linkPolicy) || typeof p.linkNote!=='string' || !p.linkNote.trim() || p.linkNote.length>1500)throw Error('연결 근거가 필요합니다: '+entry.code);
      const normalized=policy(p);
      if(!equal(p,normalized))throw Error('연결 필드를 확인해 주세요: '+entry.code);
      const ids=p.linkPolicy==='direct'?[p.productId]:p.linkPolicy==='select'?p.selectionProductIds:p.linkPolicy==='ledger-pending'?p.confirmedProductIds:[];
      if(!Array.isArray(ids) || new Set(ids).size!==ids.length || (['direct','select','ledger-pending'].includes(p.linkPolicy)&&!ids.length))throw Error('대상 제품을 확인해 주세요.');
      if(p.linkPolicy==='direct' && (p.mode!=='linked'||p.selectionProductIds.length||p.confirmedProductIds.length))throw Error('단일 연결 형식 오류');
      if(p.linkPolicy!=='direct' && (p.productId || p.mode!==(p.linkPolicy==='usage-only'?'excluded':'unresolved')))throw Error('연결 상태 오류');
      if(p.linkPolicy!=='select' && p.selectionProductIds.length || p.linkPolicy!=='ledger-pending' && p.confirmedProductIds.length)throw Error('대상 목록이 잘못되었습니다.');
      if(!Array.isArray(entry.products) || entry.products.length!==ids.length)throw Error('제품 대조 정보 누락');
      for(const id of ids){
        const product=state.products.find(x=>x.id===id),expected=entry.products.find(x=>x.id===id);
        if(!product || product.active===false || !equal(identity(product),expected))throw Error('제품 정보가 변경되었습니다: '+entry.code);
        if(['direct','select'].includes(p.linkPolicy) && !window.OROcs.supportedProduct(product))throw Error('별도 장부 품목은 자동 차감 연결할 수 없습니다: '+entry.code);
      }
      if(equal(policy(item),p))continue;
      if(!equal(policy(item),entry.expected))throw Error('검토 후 연결이 변경되었습니다: '+entry.code);
      const before=policy(item);
      Object.assign(item,copy(p),{updatedAt:at,updatedBy:copy(actor),linkChanges:[...(item.linkChanges||[]),{at,by:copy(actor),before,after:copy(p)}]});
      changed.push(entry.code);
    }
    return {state:next,changed};
  }
  function label(c,products){
    const names=ids=>ids.map(id=>{const p=products.find(x=>x.id===id);return p?`${p.orderCode||''} ${p.name}`.trim():'제품 확인 필요';}).join(' / ');
    if(c.linkPolicy==='select')return '사용 제품 선택 · '+names(c.selectionProductIds||[]);
    if(c.linkPolicy==='ledger-pending')return '제품 대응 확인 · 장부 연결 대기 · '+names(c.confirmedProductIds||[]);
    if(c.linkPolicy==='hold')return '확인 보류';
    return c.mode==='linked'?'재고 연결 · '+names([c.productId]):c.mode==='excluded'?'사용량만 기록 · 차감 제외':'미연결';
  }
  window.ORCatalogLinks={apply,policy,identity,label};
})();
