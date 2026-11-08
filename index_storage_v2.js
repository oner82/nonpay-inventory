// 화면의 기존 state 형태는 유지하고, 서버에서는 품목·케이스·코드별로 저장한다.
(() => {
  const clone = x => JSON.parse(JSON.stringify(x));
  const canonical = x => JSON.stringify(x, (_k, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
  const equal = (a, b) => canonical(a) === canonical(b);
  const arrays = ['products','doctors','surgeries','receipts','usages','roomRefills','morningCounts','usageRules','purchaseRequests','prescriptionPatternSettings','prescriptionMaterialSettings','backupVersions'];
  const groups = [...arrays, 'prescriptionCodes', 'prescriptionLinks', 'meta'];
  const bytes = x => new TextEncoder().encode(JSON.stringify(x)).length;
  const key = x => {
    if (typeof x !== 'string' || !x || x.length > 300) throw Error('저장 식별자가 없거나 너무 깁니다.');
    return encodeURIComponent(x).replace(/\./g, '%2E');
  };
  function put(map, path, data) {
    if (map.has(path)) throw Error('중복 식별자가 있어 분리 저장을 중단했습니다: '+path.split('/')[0]);
    if (bytes(data) > 750000) throw Error('개별 기록이 너무 큽니다. 관리자 확인이 필요합니다.');
    map.set(path, clone(data));
  }
  function pack(state) {
    const map = new Map(), config = clone(state);
    for (const field of arrays) {
      const rows = state[field] || [];
      if (!Array.isArray(rows)) throw Error('목록 형식 오류: '+field);
      rows.forEach((row, position) => put(map, field+'/'+key(row.id), {position, value:row}));
      delete config[field];
    }
    (state.ocsCatalog || []).forEach((row, position) => {
      if (!Array.isArray(row.names) || !row.names.length) throw Error('처방명 목록이 비어 있습니다.');
      const {names, ...link} = row;
      put(map, 'prescriptionCodes/'+key(row.code), {position, value:{code:row.code,names}});
      // 미연결 기본값만 있는 가져온 코드는 연결 문서를 만들지 않는다.
      if (Object.keys(link).some(k => !['code','mode','productId'].includes(k)) || link.mode && link.mode !== 'unresolved' || link.productId) {
        put(map, 'prescriptionLinks/'+key(row.code), {position, value:link});
      }
    });
    delete config.ocsCatalog;
    put(map, 'meta/settings', {value:config});
    return map;
  }
  function unpack(map) {
    if (!map.has('meta/settings')) throw Error('설정 문서가 누락되었습니다.');
    const state = clone(map.get('meta/settings').value);
    const rows = group => [...map].filter(([p]) => p.startsWith(group+'/')).sort((a,b) => a[1].position-b[1].position || a[0].localeCompare(b[0])).map(([,d]) => clone(d.value));
    for (const field of arrays) state[field] = rows(field);
    state.ocsCatalog = rows('prescriptionCodes').map(row => {
      const link = map.get('prescriptionLinks/'+key(row.code));
      return link ? {...clone(link.value),names:row.names} : {...row,mode:'unresolved',productId:''};
    });
    for (const [p] of map) if (p.startsWith('prescriptionLinks/') && !map.has(p.replace('prescriptionLinks/','prescriptionCodes/'))) throw Error('처방명 없는 연결 문서가 있습니다.');
    return state;
  }
  function diff(before, after) {
    return [...new Set([...before.keys(), ...after.keys()])].filter(p => !equal(before.get(p), after.get(p))).map(path => ({path,before:before.get(path),after:after.get(path)}));
  }
  function stablePositions(next, before) {
    for (const group of groups.filter(g=>g!=='meta')) {
      let last=Math.max(-1,...[...before].filter(([p])=>p.startsWith(group+'/')).map(([,v])=>v.position));
      for (const [p,v] of next) if(p.startsWith(group+'/')) v.position=before.has(p)?before.get(p).position:++last;
    }
    return next;
  }
  // 한 직원의 변경 부분만 최신 서버에 적용한다. 삭제된 항목의 부활·동시 덮어쓰기를 방지한다.
  function merge(base, local, remote) {
    const result = clone(remote);
    for (const field of arrays) {
      const index = rows => new Map((rows || []).map(r => [r.id,r]));
      const b=index(base[field]), l=index(local[field]), r=index(remote[field]);
      for (const id of new Set([...b.keys(),...l.keys()])) {
        const old=b.get(id), changed=l.get(id), current=r.get(id);
        if (equal(old,changed)) continue;
        if (!old || !changed || !current) {
          if (!equal(old,current) && !equal(changed,current)) throw Error('다른 사용자가 같은 항목을 수정 또는 삭제했습니다. 최신 내용을 확인해 주세요.');
          if (changed) r.set(id,clone(changed)); else r.delete(id);
          continue;
        }
        const next=clone(current);
        for (const k of new Set([...Object.keys(old),...Object.keys(changed)])) {
          if (field==='products' && k==='stock' || equal(old[k],changed[k])) continue;
          if (!equal(old[k],current[k]) && !equal(changed[k],current[k]) && !['updatedAt','updatedBy','updatedByName'].includes(k)) throw Error('다른 사용자가 같은 항목을 수정했습니다. 최신 내용을 확인해 주세요.');
          if (Object.hasOwn(changed,k)) next[k]=clone(changed[k]); else delete next[k];
        }
        r.set(id,next);
      }
      result[field]=[...r.values()];
    }
    // 코드 연결은 기존 업무 저장의 apply가 최신 서버 목록에서 처리한다.
    result.ocsCatalog=clone(remote.ocsCatalog || []);
    for (const k of new Set([...Object.keys(base),...Object.keys(local)])) {
      if (arrays.includes(k) || k==='ocsCatalog' || k==='updatedAt' || equal(base[k],local[k])) continue;
      if (!equal(base[k],remote[k]) && !equal(local[k],remote[k])) throw Error('다른 사용자가 설정을 변경했습니다. 최신 내용을 확인해 주세요.');
      if (Object.hasOwn(local,k)) result[k]=clone(local[k]); else delete result[k];
    }
    return result;
  }
  function importNames(state, entries) {
    if (!Array.isArray(entries) || !entries.length || entries.length>10000) throw Error('처방코드 목록 크기를 확인해 주세요.');
    const next=clone(state), byCode=new Map((next.ocsCatalog || []).map(c=>[c.code,c]));
    let codes=0,names=0;
    for (const row of entries) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(row.code) || !Array.isArray(row.names) || !row.names.length || row.names.some(n=>typeof n!=='string'||!n.trim()||n.length>250||/[\r\n\t]/.test(n))) throw Error('처방코드·명칭 형식을 확인해 주세요.');
      let existing=byCode.get(row.code);
      if (!existing) {existing={code:row.code,names:[],mode:'unresolved',productId:''};byCode.set(row.code,existing);codes++;}
      for (const name of row.names) if (!existing.names.includes(name)) {
        // 연결된 코드의 새 명칭을 추가하면 자동 연결 범위가 넓어지므로 별도 확인한다.
        if (existing.mode==='linked'||existing.mode==='excluded') throw Error('기존 연결 코드에 새 명칭이 있습니다. 별도 확인 필요: '+row.code);
        existing.names.push(name);names++;
      }
    }
    next.ocsCatalog=[...byCode.values()];
    return {state:next,codes,names};
  }
  function create(sdk, db, {actor=()=>null}={}) {
    const {doc,collection,getDocFromServer,getDocsFromServer,runTransaction,writeBatch}=sdk;
    const root=doc(db,'app','main'); let cached=null;
    const recordRef=(g,p)=>doc(db,'inventoryData',g,...p.split('/'));
    const conflict=()=>Object.assign(Error('다른 저장과 겹쳐 최신 자료를 다시 읽습니다.'),{storageConflict:true});
    async function catchUp(records, from) {
      return runTransaction(db,async tx=>{
        const latest=(await tx.get(root)).data();
        if(latest.generation!==from.generation || latest.revision<from.revision || latest.revision-from.revision>50)throw conflict();
        const revisions=Array.from({length:latest.revision-from.revision},(_,i)=>from.revision+i+1);
        const changes=await Promise.all(revisions.map(r=>tx.get(recordRef(from.generation,'changes/'+r))));
        if(changes.some(d=>!d.exists()))throw Error('변경 이력이 누락되어 최신 자료를 확인할 수 없습니다.');
        const paths=[...new Set(changes.flatMap(d=>d.data().changed))];
        const docs=await Promise.all(paths.map(p=>tx.get(recordRef(from.generation,p))));
        const map=new Map(records);docs.forEach((d,i)=>d.exists()?map.set(paths[i],d.data()):map.delete(paths[i]));
        return {meta:latest,map};
      });
    }
    async function read() {
      for(let attempt=0;attempt<12;attempt++) {
        const snap=await getDocFromServer(root);
        if(!snap.exists()) throw Error('운영 데이터가 없습니다. 자동 생성하지 않습니다.');
        const meta=snap.data();
        if(meta.storageVersion!==undefined && ![1,2].includes(meta.storageVersion)) throw Error('지원하지 않는 저장 구조입니다. 앱을 업데이트해 주세요.');
        if(meta.storageVersion!==2) return {state:meta,meta:null};
        if(!meta.generation||!Number.isInteger(meta.revision)) throw Error('저장 구조 정보가 올바르지 않습니다.');
        if(cached?.meta.generation===meta.generation && cached.meta.revision===meta.revision) return {state:unpack(cached.map),meta:clone(meta),records:new Map(cached.map)};
        if(cached?.meta.generation===meta.generation && meta.revision>cached.meta.revision && meta.revision-cached.meta.revision<=50) {
          const priorCache=cached;
          try {
            cached=await catchUp(priorCache.map,priorCache.meta);
            return {state:unpack(cached.map),meta:clone(cached.meta),records:new Map(cached.map)};
          } catch(e) {if(e.storageConflict)continue;throw e;}
        }
        const records=new Map();
        const results=await Promise.all(groups.map(g=>getDocsFromServer(collection(db,'inventoryData',meta.generation,g))));
        results.forEach((result,i)=>result.docs.forEach(d=>records.set(groups[i]+'/'+d.id,d.data())));
        const end=(await getDocFromServer(root)).data();
        if(!equal(meta,end)) {
          try {
            cached=await catchUp(records,meta);
            return {state:unpack(cached.map),meta:clone(cached.meta),records:new Map(cached.map)};
          } catch(e) {if(e.storageConflict)continue;throw e;}
        }
        const state=unpack(records);cached={meta:clone(meta),map:records};return {state,meta:clone(meta),records:new Map(records)};
      }
      throw Error('동시 저장이 많아 최신 자료를 확정하지 못했습니다. 잠시 후 다시 시도해 주세요.');
    }
    async function commit(transform, {prepareWrites} = {}) {
      for(let attempt=0;attempt<12;attempt++) {
        const before=await read();
        if(!before.meta) throw Error('분리 저장 전환이 완료되지 않았습니다.');
        const after=await transform(clone(before.state));
        const nextMap=stablePositions(pack(after),before.records), ops=diff(before.records,nextMap);
        if(!ops.length)return before;
        if(ops.length>350)throw Error('한 번에 변경할 항목이 너무 많습니다. 일괄 전환 절차를 사용해 주세요.');
        if(ops.reduce((n,o)=>n+bytes(o.after||{}),0)>6000000)throw Error('한 번에 저장할 자료가 너무 큽니다.');
        const meta={storageVersion:2,generation:before.meta.generation,revision:before.meta.revision+1,updatedAt:new Date().toISOString(),changed:ops.map(o=>o.path)};
        try {
          await runTransaction(db,async tx=>{
            const latest=(await tx.get(root)).data();
            if(!equal(latest,before.meta))throw conflict();
            const extraWrites=prepareWrites ? await prepareWrites(tx,before.state,after) : null;
            for(const op of ops) if(op.after)tx.set(recordRef(meta.generation,op.path),op.after);else tx.delete(recordRef(meta.generation,op.path));
            tx.set(recordRef(meta.generation,'changes/'+meta.revision),{revision:meta.revision,changed:meta.changed,at:meta.updatedAt,by:actor()});
            tx.set(root,meta);
            if(extraWrites)extraWrites();
          });
          cached={meta,map:nextMap};return {state:unpack(nextMap),meta:clone(meta)};
        } catch(e) {
          // 규칙의 개정번호 검사와 다른 기기의 저장이 겹치면 권한 오류로 보고될 수도 있다.
          // 접근 권한을 다시 확인하고 실제 개정번호가 달라진 경우에만 재시도한다.
          if(e.code==='permission-denied') {
            const latest=(await getDocFromServer(root)).data();
            if(latest?.generation===before.meta.generation && latest.revision!==before.meta.revision) e.storageConflict=true;
          }
          if(e.storageConflict){cached=null;await new Promise(resolve=>setTimeout(resolve,20+Math.random()*40*(attempt+1)));continue;}
          throw e;
        }
      }
      throw Error('동시 변경 때문에 저장하지 못했습니다. 입력을 유지한 채 다시 시도해 주세요.');
    }
    // 새 세대에 먼저 복사·대조하고, 마지막 한 거래에서만 새 저장소로 전환한다.
    async function migrate({generation,source,actor,onProgress=()=>{}}) {
      if(!/^[A-Za-z0-9_-]{8,100}$/.test(generation))throw Error('전환 식별자를 확인해 주세요.');
      const live=(await getDocFromServer(root)).data();
      if(live.storageVersion===2)throw Error('이미 전환된 저장소입니다. 재실행하지 않습니다.');
      if(!equal(live,source))throw Error('전환 준비 후 운영 자료가 바뀌었습니다. 다시 내려받아 주세요.');
      const records=pack(source), stage=doc(db,'inventoryData',generation), archive=doc(db,'inventoryArchives',generation);
      await runTransaction(db,async tx=>{
        const [main,prior,backup]=await Promise.all([tx.get(root),tx.get(stage),tx.get(archive)]);
        if(!equal(main.data(),source))throw Error('운영 자료가 변경되었습니다. 전환하지 않았습니다.');
        if(prior.exists() && (prior.data().status!=='staging'||!backup.exists()||!equal(backup.data().state,source)))throw Error('이전 전환 자료와 다릅니다. 새 전환 식별자가 필요합니다.');
        if(!prior.exists()) {
          if(backup.exists())throw Error('복구 백업 식별자가 중복됩니다.');
          tx.set(archive,{state:source,createdAt:new Date().toISOString(),actor});
          tx.set(stage,{status:'staging',createdAt:new Date().toISOString(),actor});
        }
      });
      const entries=[...records];
      for(let start=0;start<entries.length;start+=150) {
        const batch=writeBatch(db);
        for(const [p,value]of entries.slice(start,start+150))batch.set(recordRef(generation,p),value);
        await batch.commit();onProgress(Math.min(start+150,entries.length),entries.length);
      }
      const actual=new Map();
      const results=await Promise.all(groups.map(g=>getDocsFromServer(collection(db,'inventoryData',generation,g))));
      results.forEach((result,i)=>result.docs.forEach(d=>actual.set(groups[i]+'/'+d.id,d.data())));
      if(diff(records,actual).length)throw Error('복사 자료가 원본과 다릅니다. 기존 앱을 유지합니다.');
      // 원본 구조의 빈 배열도 보존된 자료만 활성화한다.
      if(diff(pack(unpack(actual)),pack(source)).length)throw Error('복원 대조에 실패했습니다.');
      const meta={storageVersion:2,generation,revision:0,updatedAt:new Date().toISOString(),changed:[]};
      await runTransaction(db,async tx=>{
        const [main,staged,backup]=await Promise.all([tx.get(root),tx.get(stage),tx.get(archive)]);
        if(!equal(main.data(),source)||staged.data()?.status!=='staging'||!equal(backup.data()?.state,source))throw Error('전환 중 운영 자료가 변경되어 활성화를 중단했습니다.');
        tx.set(stage,{...staged.data(),status:'active',activatedAt:meta.updatedAt,documents:records.size});
        tx.set(root,meta);
      });
      cached={meta,map:actual};return {state:unpack(actual),meta};
    }
    return {read,commit,migrate};
  }
  window.ORStorageV2={clone,canonical,equal,pack,unpack,diff,merge,importNames,groups,create};
})();
