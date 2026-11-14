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
    console.log('PASS: 미해석 원문 저장 차단, 재읽기 실패 보존, 재확인, 정상 교체');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
