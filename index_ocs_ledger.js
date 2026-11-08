// OCS 사용량과 함께 저장할 수술별 업체 장부. 사진은 재고 수량과 분리해 추가한다.
(() => {
  const copy=x=>JSON.parse(JSON.stringify(x));
  const needsLedger=p=>p&&['인체조직','ANCHOR','URO_LANDING','GS_LANDING','IMPLANT'].includes(p.category);
  function build({existing,usage,products,vendorFor,doctor,actor,at}){
    if(existing && !existing.ocsManaged)throw Error('이 케이스에는 별도 작성 장부가 있습니다. 기존 장부를 먼저 확인해 주세요.');
    if(existing && existing.editUnlocked!==true && (existing.closedAt||existing.patientNo||existing.patientNoAssignedAt))throw Error('마감된 장부입니다. 장부 잠금을 해제한 뒤 수량을 수정해 주세요.');
    const counts=new Map();for(const id of usage.productIds||[])counts.set(id,(counts.get(id)||0)+1);
    const groups=new Map();
    for(const [id,qty] of counts){
      const product=products.find(p=>p.id===id);if(!needsLedger(product))continue;
      const vendor=vendorFor(product),key=vendor.vendorId||vendor.vendor;
      if(!key || !vendor.vendor)throw Error(product.name+': 장부 업체를 확인해 주세요.');
      if(!groups.has(key))groups.set(key,{...vendor,items:[]});
      groups.get(key).items.push({productId:id,name:product.name,qty,unit:product.stockUnit||'EA'});
    }
    if(!existing&&!groups.size)return null;
    const implants=[];
    for(const [key,g] of groups){
      const previous=(existing?.implants||[]).find(i=>(i.vendorId||i.vendor)===key);
      const description=g.items.map(i=>`${i.name} ${i.qty}${i.unit}`).join('\n');
      // 사진과 수기 메모는 보존한다. 수기 사용내용을 추정하여 덮어쓰지 않는다.
      if(previous && !previous.ocsCancelled && previous.description!==previous.ocsAutoDescription && previous.ocsAutoDescription!==description)throw Error(g.vendor+': 장부 사용내용이 별도 수정되어 수량 대조가 필요합니다.');
      implants.push({...copy(previous||{}),id:previous?.id||'ocs_'+encodeURIComponent(key),vendorId:g.vendorId||'',vendor:g.vendor,description:previous && !previous.ocsCancelled && previous.description!==previous.ocsAutoDescription?previous.description:description,ocsCancelled:false,ocsAutoDescription:description,ocsItems:g.items,photos:copy(previous?.photos||[])});
    }
    for(const previous of existing?.implants||[]){
      if(implants.some(i=>i.id===previous.id))continue;
      // 사용량이 0이 되어도 기존 라벨·수기 기록은 삭제하지 않는다.
      if(previous.ocsCancelled){implants.push(copy(previous));continue;}
      implants.push({...copy(previous),description:'OCS 사용 수량 0 · 사용 취소 확인\n'+(previous.description||''),ocsAutoDescription:'',ocsItems:[],ocsCancelled:true});
    }
    return {...copy(existing||{}),id:existing?.id||'ocs_'+usage.id,usageId:usage.id,ocsManaged:true,ocsRevision:usage.ocsRevision,
      surgeryDate:usage.date,caseRoom:usage.caseRoom,caseOrder:usage.caseOrder,doctorId:usage.doctorId||'',surgeonCode:doctor?.name||'',department:doctor?.department||'',surgeryId:usage.surgeryId||'',surgeryName:usage.surgeryDetail||'',
      patientNo:existing?.patientNo||'',implants,sendReady:groups.size>0,createdAt:existing?.createdAt||at,createdBy:existing?.createdBy||actor,createdByName:existing?.createdByName||actor.name||'',updatedAt:at,updatedBy:actor,updatedByName:actor.name||''};
  }
  window.OROcsLedger={build,needsLedger};
})();
