(() => {
  window.createStorageAdminModule = ctx => {
    const api=window.ORStorageV2,e=ctx.escapeHtml;
    let busy=false,prepared=null,result='',generation='';
    const download=(name,data)=>{
      const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
      const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    };
    const render=()=>`<section class="card" id="storageAdmin"><h2>처방코드·저장 관리</h2>
      <p>${ctx.separated()?'품목·케이스·입고·코드가 개별 문서에 저장됩니다.':'현재는 전체 자료를 한 문서에 저장하고 있습니다.'}</p>
      <p class="helper">처방코드 등록은 재고 연결 승인과 별개입니다. 기존 제품·사용량·현재고를 유지합니다.</p>
      <label for="catalogSearch">처방코드·처방명 검색</label><input id="catalogSearch" type="search" placeholder="코드 또는 처방명" autocomplete="off"><p id="catalogCount"></p><div id="catalogResults"></div>
      ${ctx.actor()?.role==='admin'?`<details><summary>관리자 자료 등록</summary><p>코드·명칭 전용 JSON 파일을 선택하면 추가 대상부터 확인합니다. 이미 등록된 내용은 중복 추가하지 않습니다.</p><input id="catalogFile" type="file" accept=".json"><p id="catalogPreview" role="status"></p><button type="button" id="catalogImport" disabled>확인한 코드·명칭 등록</button></details>
      <details><summary>저장 구조 전환·백업</summary><p>전환 전에 다른 기기의 입력을 멈추세요. 기존 자료를 백업·복사하고 원본과 일치하는지 확인한 뒤 전환합니다. 복사 실패 시 기존 저장소를 유지합니다.</p>
      <button type="button" id="coreBackup">현재 핵심 자료 백업 다운로드</button><p class="helper">제품·코드·케이스·입고·설정을 포함합니다. 별도 임플란트 장부·대기 장부와 사진은 이 파일에 포함되지 않으며 기존 저장소에 보존됩니다.</p>
      ${ctx.separated()?'':`<label><input type="checkbox" id="storagePauseConfirm"> 다른 기기 입력을 중지했고, 저장 구조 전환을 진행합니다.</label><button type="button" id="storageMigrate">백업 후 분리 저장으로 전환</button>`}</details>`:''}
      <p id="storageResult" role="status" aria-live="polite">${e(result)}</p></section>`;
    function bind() {
      const $=id=>document.getElementById(id),message=t=>{result=t;if($('storageResult'))$('storageResult').textContent=t;};
      const paint=()=>{
        const all=ctx.state().ocsCatalog||[],q=$('catalogSearch').value.trim().toLowerCase();
        const rows=all.filter(c=>[c.code,...c.names].some(n=>n.toLowerCase().includes(q)));
        $('catalogCount').textContent=`전체 ${all.length}코드 · 검색 ${rows.length}코드${rows.length>50?' · 앞 50개 표시':''}`;
        $('catalogResults').innerHTML=rows.slice(0,50).map(c=>`<p><strong>${e(c.code)}</strong> · ${c.names.map(e).join(' / ')} <small>${c.mode==='linked'?'재고 연결':c.mode==='excluded'?'차감 제외':'미연결'}</small></p>`).join('');
      };
      const operation=async fn=>{
        if(busy)return;busy=true;ctx.lock(true);
        for(const b of $('storageAdmin').querySelectorAll('button,input[type=file]'))b.disabled=true;
        try{await fn();}catch(error){message('완료하지 못했습니다: '+error.message);}
        finally{busy=false;ctx.lock(false);ctx.render();}
      };
      $('catalogSearch').addEventListener('input',paint);paint();
      $('coreBackup')?.addEventListener('click',()=>operation(async()=>{
        const current=await ctx.store().read();
        download('수술실_핵심자료_백업_'+ctx.today()+'.json',{format:'or-inventory-core-backup-v2',createdAt:new Date().toISOString(),storage:current.meta,data:current.state});
        message('핵심 자료 백업 파일을 내려받았습니다.');
      }));
      $('storageMigrate')?.addEventListener('click',()=>{
        if(!$('storagePauseConfirm').checked){message('다른 기기의 입력 중지를 먼저 확인해 주세요.');return;}
        operation(async()=>{
          const current=await ctx.store().read();if(current.meta)throw Error('이미 전환되었습니다. 새로고침해 주세요.');
          download('수술실_전환전_핵심자료_'+ctx.today()+'.json',{format:'or-inventory-core-backup-v2',createdAt:new Date().toISOString(),data:current.state});
          generation=generation||'m'+Date.now()+'_'+crypto.randomUUID().replace(/-/g,'');
          const migrated=await ctx.store().migrate({generation,source:current.state,actor:ctx.actor(),onProgress:(n,total)=>message(`자료 복사·검증 중 ${n}/${total}`)});
          ctx.accept(migrated);message('분리 저장 전환 완료. 기존 기록과 재고를 보존했습니다.');
        });
      });
      $('catalogFile')?.addEventListener('change',async()=>{
        prepared=null;$('catalogImport').disabled=true;
        try{
          const file=$('catalogFile').files[0];if(!file)return;
          if(file.size>3000000)throw Error('파일이 너무 큽니다.');
          const data=JSON.parse(await file.text());if(data.format!=='ocs-code-names-v1')throw Error('코드·명칭 전용 파일이 아닙니다.');
          const current=await ctx.store().read(),check=api.importNames(current.state,data.entries);
          if(!current.meta)throw Error('먼저 분리 저장으로 전환해 주세요.');
          prepared=check.names?data.entries:null;
          $('catalogPreview').textContent=`새 코드 ${check.codes}개 · 추가 별칭 ${check.names-check.codes}개. 재고·사용내역은 바뀌지 않습니다.`;
          $('catalogImport').disabled=!check.names;
        }catch(error){$('catalogPreview').textContent=error.message;}
      });
      $('catalogImport')?.addEventListener('click',()=>operation(async()=>{
        if(!prepared)throw Error('코드 파일을 먼저 확인해 주세요.');
        const entries=prepared;let addedCodes=0,addedNames=0;
        api.importNames((await ctx.store().read()).state,entries);
        for(let start=0;start<entries.length;start+=100){
          let counts;
          const saved=await ctx.store().commit(remote=>{counts=api.importNames(remote,entries.slice(start,start+100));return counts.state;});
          ctx.accept(saved);addedCodes+=counts.codes;addedNames+=counts.names;
          message(`코드 등록 중 ${Math.min(start+100,entries.length)}/${entries.length}. 중단되면 같은 파일로 재개할 수 있습니다.`);
        }
        const final=await ctx.store().read(),check=api.importNames(final.state,entries);
        if(check.names||check.codes)throw Error('등록 후 대조가 일치하지 않습니다. 같은 파일로 다시 확인해 주세요.');
        ctx.accept(final);prepared=null;message(`등록·재조회 확인 완료: 새 코드 ${addedCodes}개, 추가 별칭 ${addedNames-addedCodes}개. 재고 연결과 수량은 유지했습니다.`);
      }));
    }
    return {render,bind,isDirty:()=>busy||!!prepared};
  };
})();
