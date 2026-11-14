// 운영 Firebase에 연결하지 않고 실제 OCS 입력 모듈을 브라우저에서 검사한다.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}) });
  try {
    const page = await browser.newPage();
    await page.route('**/*', route => route.abort());
    await page.setContent('<main id="app"></main>');
    await page.addScriptTag({ path: path.resolve(__dirname, '../../index_ocs.js') });
    await page.evaluate(() => {
      window.savedRequests = [];
      const state = { products: [], ocsCatalog: [], doctors: [{ id: 'test-doctor', name: '시험 원장' }] };
      const module = createOcsModule({
        escapeHtml: value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])),
        getState: () => state, today: () => '2026-11-14', canManage: () => true,
        validateCase: () => '', uid: () => 'test-case', actor: () => ({ role: 'admin' }),
        saveState: async (_message, options) => { window.savedRequests.push(options); return false; }
      });
      document.getElementById('app').innerHTML = module.render(); module.bind();
      window.orderText = (code, name) => {
        const cols = Array(103).fill('');
        Object.assign(cols, {0: 'A', 1: '처방', 3: code, 4: name, 7: '2', 8: '1', 9: '1'});
        return cols.join('\t');
      };
    });
    await page.locator('#ocsRoom').fill('1');
    await page.locator('#ocsOrder').fill('1');
    await page.locator('#ocsDoctor').selectOption('test-doctor');
    const order = await page.evaluate(() => orderText('TEST001', '시험 품목'));
    await page.locator('#ocsPasteDetails').evaluate(element => { element.open = true; });
    await page.locator('#ocsPaste').fill(order);
    await page.locator('#ocsParse').click();
    await page.locator('#ocsQty0').fill('7');
    assert.equal(await page.locator('#ocsQty0').inputValue(), '7');
    assert.equal(await page.locator('#ocsPaste').inputValue(), '');

    // 새 원문을 붙여넣었지만 읽지 않았으면 기존 행을 저장하지 않는다.
    await page.locator('#ocsPasteDetails').evaluate(element => { element.open = true; });
    await page.locator('#ocsPaste').fill('잘못된 새 처방');
    await page.locator('#ocsConfirm').check();
    await page.locator('#ocsSave').click();
    assert.match(await page.locator('#ocsSaveMessage').textContent(), /아직 읽히지/);
    assert.equal(await page.evaluate(() => savedRequests.length), 0);

    // 해석 실패 후에도 수정한 수량과 기존 목록을 유지하고 확인을 해제한다.
    await page.locator('#ocsParse').click();
    assert.equal(await page.locator('#ocsQty0').inputValue(), '7');
    assert.equal(await page.locator('#ocsConfirm').isChecked(), false);
    assert.match(await page.locator('#ocsMessage').textContent(), /기존 처방 목록과 수정 수량은 유지/);
    await page.locator('#ocsConfirm').check();
    await page.locator('#ocsSave').click();
    assert.equal(await page.evaluate(() => savedRequests.length), 0);

    // 원문을 비운 뒤 다시 확인하면 기존 목록 저장 절차를 진행할 수 있다.
    await page.locator('#ocsPasteDetails').evaluate(element => { element.open = true; });
    await page.locator('#ocsPaste').fill('');
    await page.locator('#ocsConfirm').check();
    await page.locator('#ocsSave').click();
    await page.locator('#ocsUnlinkedConfirm').check();
    await page.locator('#ocsSave').click();
    assert.equal(await page.evaluate(() => savedRequests.length), 1);
    assert.equal(await page.locator('#ocsQty0').inputValue(), '7');

    // 정상 재읽기는 새 목록으로 교체하고 원문을 지운다.
    await page.locator('#ocsPasteDetails').evaluate(element => { element.open = true; });
    await page.locator('#ocsPaste').fill(await page.evaluate(() => orderText('TEST002', '새 시험 품목')));
    await page.locator('#ocsParse').click();
    assert.equal(await page.locator('#ocsQty0').inputValue(), '2');
    assert.match(await page.locator('#ocsRows').textContent(), /TEST002/);
    assert.equal(await page.locator('#ocsPaste').inputValue(), '');
    // 실제 number 입력의 키보드 이동, 범위/소수 오류 및 자동 저장 방지를 확인한다.
    await page.locator('#ocsPasteDetails').evaluate(element => { element.open = true; });
    await page.locator('#ocsPaste').fill(await page.evaluate(() => orderText('TEST001', '시험 하나')+'\n'+orderText('TEST002', '시험 둘')));
    await page.locator('#ocsParse').click();
    const focused = () => page.evaluate(() => document.activeElement.id);
    await page.locator('#ocsQty0').press('Enter');assert.equal(await focused(), 'ocsQty1');
    await page.locator('#ocsQty1').press('Shift+Enter');assert.equal(await focused(), 'ocsQty0');
    for(const invalid of ['-1','10001','1.5']) {
      await page.locator('#ocsQty0').fill(invalid);
      await page.locator('#ocsQty0').press('Enter');assert.equal(await focused(), 'ocsQty0');
    }
    await page.locator('#ocsQty0').fill('3');
    await page.locator('#ocsQty0').press('Enter');
    await page.locator('#ocsQty1').press('Enter');assert.equal(await focused(), 'ocsQty1');
    assert.equal(await page.evaluate(() => savedRequests.length), 1);
    assert.equal(await page.locator('#ocsConfirm').isChecked(), false);
    console.log('PASS: 입력 보존, 미해석 저장 차단, 수량 키보드 이동 및 자동 저장 방지');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
