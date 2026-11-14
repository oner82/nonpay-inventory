// 외부 의존성이나 Firebase 없이 OCS 입력 이벤트의 회귀를 검사한다.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function setup() {
  const elements = new Map();
  let focused=null;
  class Element {
    constructor(id) { this.id=id; this.value=''; this.checked=false; this.hidden=false; this.disabled=false; this.listeners={}; this.dataset={}; }
    addEventListener(name, handler) { (this.listeners[name] ||= []).push(handler); }
    async fire(name, extra={}) { for(const handler of this.listeners[name]||[]) await handler({target:this,...extra}); }
    focus() { focused=this.id; }
    checkValidity() { return this.valid!==false; } reportValidity() { this.reported=true; }
    scrollIntoView() {} hasAttribute(name) { return name==='data-ocs-qty' && this.dataset.ocsQty!==undefined; }
    set innerHTML(html) {
      this.html=html;
      if(this.id==='ocsRows') for(const id of [...elements.keys()]) if(/^ocsQty\d+$/.test(id)) elements.delete(id);
      // 이 검사에서 필요한 동적 수량 입력만 DOM 대신 추적한다.
      for(const match of html.matchAll(/<input id="(ocsQty\d+)"[^>]*data-ocs-qty="(\d+)"[^>]*value="([^"]*)"/g)) {
        const input=new Element(match[1]);input.dataset.ocsQty=match[2];input.value=match[3];elements.set(match[1],input);
      }
    }
    get innerHTML() { return this.html || ''; }
  }
  const ids=['ocsPanel','ocsMessage','ocsSaveMessage','ocsStockNotice','ocsTestStockConfirm','ocsStockList','ocsConfirm','ocsUnlinkedConfirm','ocsUnlinkedNotice','ocsSurgery','ocsRoom','ocsOrder','ocsCaseHint','ocsRows','ocsSave','ocsLinkPicker','ocsPickerClose','ocsExcelOpen','ocsExcelFile','ocsLinkSearch','ocsLinkStatus','ocsLinkOptions','ocsParse','ocsPaste','ocsPasteTitle','ocsPasteStatus','ocsPasteDetails','ocsExcelSheets','ocsExcelSheet','ocsExcelStatus','ocsExcelRead','ocsDate','ocsDoctor','ocsUnlinkedText'];
  ids.forEach(id=>elements.set(id,new Element(id)));
  const $=id=>elements.get(id);
  const sandbox={window:{},document:{getElementById:$},TextEncoder,console,confirm:()=>true};
  vm.createContext(sandbox);vm.runInContext(fs.readFileSync(path.resolve(__dirname,'../../index_ocs.js'),'utf8'),sandbox);
  let saves=0;
  const state={products:[],ocsCatalog:[],doctors:[]};
  const module=sandbox.window.createOcsModule({escapeHtml:String,getState:()=>state,today:()=> '2026-11-14',canManage:()=>true,validateCase:()=>'',uid:()=> 'test',actor:()=>({}),saveState:async()=>{saves++;return false;}});
  module.render();module.bind();
  $('ocsDate').value='2026-11-14';$('ocsRoom').value='1';$('ocsOrder').value='1';$('ocsDoctor').value='test';
  const paste=async text=>{$('ocsPaste').value=text;await $('ocsPanel').fire('input',{target:$('ocsPaste')});};
  const order=(code='TEST001')=>{const row=Array(103).fill('');Object.assign(row,{0:'A',1:'처방',3:code,4:'시험 품목',7:'2',8:'1',9:'1'});return row.join('\t');};
  return {$,paste,order,saves:()=>saves,focused:()=>focused};
}
test('새 원문 미해석·해석 실패 시 기존 처방을 잘못 저장하거나 잃지 않는다',async()=>{
  const {$,paste,order,saves}=setup();
  await paste(order());await $('ocsParse').fire('click');
  $('ocsQty0').value='7';await $('ocsPanel').fire('input',{target:$('ocsQty0')});
  await paste('잘못된 새 처방');$('ocsConfirm').checked=true;
  await $('ocsSave').fire('click');assert.equal(saves(),0);assert.match($('ocsSaveMessage').textContent,/아직 읽히지/);
  await $('ocsParse').fire('click');assert.equal($('ocsQty0').value,'7');assert.equal($('ocsConfirm').checked,false);
  assert.match($('ocsMessage').textContent,/기존 처방 목록과 수정 수량은 유지/);
  $('ocsConfirm').checked=true;await $('ocsSave').fire('click');assert.equal(saves(),0);
  await paste('');$('ocsConfirm').checked=true;await $('ocsSave').fire('click');
  $('ocsUnlinkedConfirm').checked=true;await $('ocsSave').fire('click');assert.equal(saves(),1);
  await paste(order('TEST002'));await $('ocsParse').fire('click');assert.equal($('ocsQty0').value,'2');assert.match($('ocsRows').innerHTML,/TEST002/);assert.equal($('ocsPaste').value,'');
});

test('수량 Enter 이동은 경계·조합 입력·유효성·저장 안전을 지킨다',async()=>{
  const {$,paste,order,saves,focused}=setup();
  await paste(order()+'\n'+order('TEST002'));await $('ocsParse').fire('click');
  let prevented=0;
  const key=async(index,extra={})=>$('ocsPanel').fire('keydown',{target:$('ocsQty'+index),key:'Enter',preventDefault:()=>prevented++,...extra});
  await key(0);assert.equal(focused(),'ocsQty1');assert.equal(prevented,1);
  await key(1,{shiftKey:true});assert.equal(focused(),'ocsQty0');
  await key(0,{shiftKey:true});assert.equal(focused(),'ocsQty0');
  $('ocsQty0').valid=false;await key(0);assert.equal(focused(),'ocsQty0');assert.equal($('ocsQty0').reported,true);
  $('ocsQty0').valid=true;
  for(const extra of [{isComposing:true},{ctrlKey:true},{metaKey:true},{altKey:true},{key:'Tab'}]){const before=prevented;await key(0,extra);assert.equal(prevented,before);assert.equal(focused(),'ocsQty0');}
  await key(0);await key(1);assert.equal(focused(),'ocsQty1');assert.equal(saves(),0);
  assert.match($('ocsRows').innerHTML,/aria-describedby="ocsQtyHelp"/);
});
