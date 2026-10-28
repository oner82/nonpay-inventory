(() => {
  const regionOrder = ['C', 'T', 'L', 'S'];
  const regions = value => regionOrder.filter(r => (Array.isArray(value) ? value : String(value || '').match(/[CTLS](?=[\s),-]|$)/g) || []).includes(r));
  const metadata = p => ({
    procedure: String(p?.procedureName || p?.surgery || '').split('·')[0].trim(),
    regions: regions(p?.spineRegions || p?.spineRegion),
    levelCount: Math.max(0, Number(p?.levelCount) || 0)
  });
  const key = v => `${String(v.procedure || '').trim().toLowerCase()}|${regions(v.regions).join('-')}|${Number(v.levelCount) || 0}`;
  const match = (patterns, selection) => patterns.filter(p => key(metadata(p)) === key(selection));
  const label = s => `${s.procedure}${s.regions?.length ? ` · ${s.regions.join('-')}` : ''}${s.levelCount ? ` ${s.levelCount}레벨` : ''}`;
  const isSpine = (p, patterns) => patterns.some(x => metadata(x).procedure === p && (metadata(x).regions.length || /척추|천골/.test(x.surgeryFamily || ''))) || /discectomy|laminectomy|foraminotomy|fusion|ACDF|TDR|laminoplasty|vertebroplasty|kyphoplasty/i.test(p);
  const controlsHtml = () => `<div class="surgery-simple-controls"><label>수술명<select id="useProcedureName"><option value="">원장을 먼저 선택하세요</option></select></label><fieldset id="useSpineFields" hidden><legend>수술 부위 · 레벨 수</legend><div class="spine-region-options">${regionOrder.map(r => `<label><input type="checkbox" data-spine-region="${r}">${r}</label>`).join('')}</div><label>수술 레벨 수<select id="useLevelCount"><option value="0">미확인 / 미기재</option>${Array.from({length:10},(_,i)=>`<option value="${i+1}">${i+1}레벨</option>`).join('')}</select></label><p class="helper">경계 부위는 함께 체크하세요. 레벨 수는 수술계획에 확인된 값을 입력합니다.</p></fieldset><p id="useSurgeryMatchStatus" class="helper" role="status">수술을 선택해 주세요.</p></div>`;
  const bind = c => {
    const el = id => document.getElementById(id);
    const name = el('useProcedureName'), levels = el('useLevelCount');
    let previous = {procedure:'',regions:[],levelCount:0};
    const value = () => ({procedure:name.value, regions:regionOrder.filter(r => document.querySelector(`[data-spine-region="${r}"]`)?.checked),levelCount:Number(levels.value)||0});
    const setValue = s => {
      name.value = s.procedure || ''; levels.value = String(s.levelCount || 0);
      document.querySelectorAll('[data-spine-region]').forEach(x => {x.checked = (s.regions || []).includes(x.dataset.spineRegion);});
      el('useSpineFields').hidden = !isSpine(name.value,c.patterns());
      previous = value();
    };
    const status = () => {
      const s = value(), hits = match(c.patterns(),s);
      el('useSurgeryMatchStatus').textContent = !s.procedure ? '수술을 선택해 주세요.' : hits.length === 1 ? `등록 패턴 적용: ${hits[0].surgery} · 수량은 실제 사용 후 확인하세요.` : hits.length > 1 ? '같은 조건의 패턴이 여러 개입니다. 아래 직접 선택에서 확인해 주세요.' : '이 원장·수술·부위·레벨 조합의 등록 수량이 없습니다. 임의 배수 계산 없이 직접 입력합니다.';
    };
    const refresh = (pattern = null, saved = null) => {
      const recent = [...new Set(c.recent?.() || [])];
      const rank = name => recent.includes(name) ? recent.indexOf(name) : 999;
      const names = [...new Set(c.patterns().map(p=>metadata(p).procedure))].sort((a,b)=>rank(a)-rank(b)||a.localeCompare(b));
      const selected = saved || (pattern ? metadata(pattern) : null);
      if (selected?.procedure && !names.includes(selected.procedure)) names.push(selected.procedure);
      name.innerHTML = '<option value="">수술 선택</option>' + names.map(n=>`<option value="${c.escapeHtml(n)}">${recent.includes(n)?'최근 · ':''}${c.escapeHtml(n)}</option>`).join('');
      setValue(selected || {procedure:'',regions:[],levelCount:0}); status();
    };
    const change = ev => {
      if (!c.confirmChange()) {setValue(previous);return;}
      if (ev.target === name) { levels.value='0'; document.querySelectorAll('[data-spine-region]').forEach(x=>{x.checked=false;}); }
      const s=value(); setValue(s); status();
      const hits=match(c.patterns(),s); c.onChange(hits.length===1 ? hits[0] : null,s);
    };
    [name,levels,...document.querySelectorAll('[data-spine-region]')].forEach(x=>x.addEventListener('change',change));
    return {value,refresh};
  };
  window.ORSurgerySelection = {regions,metadata,key,match,label,isSpine,controlsHtml,bind};
})();
