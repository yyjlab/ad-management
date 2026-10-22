// Run with Node.js, Playwright, and Microsoft Edge. All network requests are mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
    const browser = await chromium.launch({channel: 'msedge', headless: true});
    try {
        const page = await browser.newPage({viewport: {width: 1366, height: 900}});
        const html = fs.readFileSync(path.join(__dirname, 'admin_manage.html'), 'utf8');
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        let role = 'super_admin', passwordReady = true, previews = 0, starts = 0, steps = 0, reveals = 0;
        let previewSpec, batch = null, unknownOnce = true, releaseStep;
        const gate = new Promise(resolve => {releaseStep = resolve;});
        const batchId = '5273447d-bbb0-4389-8ae3-f3c603692bb5';
        const ou = 'OU=用户,DC=wfq,DC=com';
        function count() {
            batch.counts = {pending: 0, processing: 0, created: 0, skipped: 0, failed: 0, unknown: 0};
            for (const item of batch.items) batch.counts[item.status]++;
        }
        await page.route('**/*', async route => {
            const request = route.request(), url = new URL(request.url());
            if (url.pathname === '/admin/manage') return route.fulfill({contentType: 'text/html', body: html});
            let result = {success: true};
            if (url.pathname === '/api/admin/check') result = {logged_in: true, username: 'test', role, permissions: ['view_user']};
            if (url.pathname === '/api/admin/stats') result = {success: true};
            const endpoint = url.pathname.replace('/api/admin/ad-precreate/', '');
            if (url.pathname.startsWith('/api/admin/ad-precreate/')) {
                assert.equal(role, 'super_admin');
                if (request.method() === 'POST') {
                    assert.equal(request.headers()['x-csrf-token'], 'precreate-csrf');
                    assert(!request.postData().includes('IsolatedUiPassword1!'));
                }
                if (endpoint === 'config') result = {success: true, ou, password_ready: passwordReady, csrf_token: 'precreate-csrf'};
                if (endpoint === 'password') { reveals++; result = {success: true, password: 'IsolatedUiPassword1!'}; }
                if (endpoint === 'preview') {
                    previews++;
                    previewSpec = {...request.postDataJSON(), ou};
                    const items = Array.from({length: previewSpec.end - previewSpec.start + 1}, (_, index) => ({
                        employee_id: `wfq${String(previewSpec.year).slice(-2)}${String(previewSpec.month).padStart(2,'0')}${String(previewSpec.start + index).padStart(2,'0')}`,
                        status: index === 0 ? 'skipped' : 'pending', message: index === 0 ? '账号已存在，将跳过且不修改' : '可创建'
                    }));
                    result = {success: true, spec: previewSpec, items, preview_token: 'signed-preview'};
                }
                if (endpoint === 'batches' && request.method() === 'POST') {
                    starts++;
                    const payload = request.postDataJSON();
                    assert.equal(payload.confirm_text, 'YES');
                    assert.match(payload.request_key, /^[a-f0-9-]{36}$/);
                    assert.equal(payload.confirm_enabled, false);
                    batch = {id: batchId, spec: previewSpec, created_by: 'test', created_at: '2026-10-22 10:00:00',
                        items: Array.from({length: 3}, (_, index) => ({employee_id: `wfq26110${index}`, status: 'pending', message: '待创建'}))};
                    count(); result = {success: true, batch};
                }
                if (endpoint === 'batches' && request.method() === 'GET') result = {success: true, batches: batch ? [batch] : []};
                if (endpoint === `batches/${batchId}`) result = {success: true, batch};
                if (endpoint.endsWith('/step')) {
                    steps++;
                    if (steps === 1) await gate;
                    const item = batch.items.find(item => item.status === 'pending');
                    if (item.employee_id.endsWith('00')) {item.status = 'skipped'; item.message = '已有账号未修改';}
                    else if (item.employee_id.endsWith('02') && unknownOnce) {
                        unknownOnce = false; item.status = 'unknown'; item.message = '创建结果未确认';
                    } else {item.status = 'created'; item.message = '已创建并回读确认；已禁用';}
                    count(); result = {success: true, batch, waiting: false};
                }
                if (endpoint.endsWith('/retry')) {
                    for (const item of batch.items) if (['failed', 'unknown'].includes(item.status)) item.status = 'pending';
                    count(); result = {success: true, batch};
                }
            }
            return route.fulfill({contentType: 'application/json', body: JSON.stringify(result)});
        });

        await page.goto('http://ad-precreate.test/admin/manage');
        await page.locator('[data-page="adUsers"]').click();
        await page.locator('#precreateEntryButton').click();
        await page.waitForFunction(() => !document.getElementById('precreatePreviewButton').disabled);
        assert.equal(await page.locator('#precreateOu').inputValue(), ou);
        assert(!(await page.locator('#precreateEnabled').isChecked()));
        await page.locator('#precreateEye').click();
        await page.waitForFunction(() => document.getElementById('precreatePassword').type === 'text');
        assert.equal(await page.locator('#precreatePassword').inputValue(), 'IsolatedUiPassword1!');
        await page.locator('#precreateEye').click();
        assert.equal(await page.locator('#precreatePassword').inputValue(), '');
        assert.equal(reveals, 1);
        await page.locator('#precreateYear').fill('2026');
        await page.locator('#precreateMonth').fill('11');
        await page.locator('#precreateEnd').fill('2');
        await page.locator('#precreatePreviewButton').click();
        await page.waitForFunction(() => !document.getElementById('precreateCreateButton').disabled);
        assert.equal(await page.locator('#precreateRows tr').count(), 3);
        assert.equal(steps, 0);
        await page.locator('#precreateName').fill('张三');
        assert(await page.locator('#precreateCreateButton').isDisabled());
        await page.locator('#precreatePreviewButton').click();
        await page.locator('#precreateCreateButton').click();
        await page.locator('#yesModal.show').waitFor();
        assert.equal(starts, 0);
        assert((await page.locator('#yesText').textContent()).includes('账号保持禁用'));
        await page.locator('#yesInput').fill('YES');
        await page.locator('#yesModal .btn-danger').click();
        await page.waitForFunction(() => document.getElementById('precreatePauseButton').hidden === false);
        await page.locator('#precreatePauseButton').click();
        releaseStep();
        await page.waitForFunction(() => !document.getElementById('precreateContinueButton').disabled);
        assert.equal(steps, 1);
        await page.locator('#precreateContinueButton').click();
        await page.waitForFunction(() => document.getElementById('precreateStatus').textContent.includes('已暂停'));
        assert.equal(steps, 3);
        assert(await page.locator('#precreateRetryButton').isVisible());
        await page.locator('#precreateRetryButton').click();
        await page.locator('#yesInput').fill('YES');
        await page.locator('#yesModal .btn-danger').click();
        await page.waitForFunction(() => document.getElementById('precreateStatus').textContent.includes('成功 2'));
        assert.equal(steps, 4);
        assert.equal(await page.locator('#precreateMonth').inputValue(), '11');
        assert.equal(await page.locator('#precreateName').inputValue(), '张三');
        assert.equal(starts, 1);
        assert.equal(previewSpec.full_name, '张三');

        await page.reload();
        await page.locator('[data-page="adUsers"]').click();
        await page.locator('#precreateEntryButton').click();
        await page.locator(`#precreateHistory option[value="${batchId}"]`).waitFor({state: 'attached'});
        await page.locator('#precreateHistory').selectOption(batchId);
        await page.waitForFunction(() => document.getElementById('precreateStatus').textContent.includes('成功 2'));
        assert.equal(steps, 4);
        await page.setViewportSize({width: 390, height: 844});
        const bounds = await page.locator('#page-adPrecreate .precreate-panel').boundingBox();
        assert(bounds.x >= 0 && bounds.x + bounds.width <= 390);
        const fields = await page.locator('#precreateFields').boundingBox();
        assert(fields.width > 200 && fields.x + fields.width <= 390);
        assert((await page.screenshot()).length > 5000);
        await page.locator('#precreateMonth').fill('12');
        assert(await page.evaluate(() => precreateState.batch === null));
        assert(await page.locator('#precreateCreateButton').isDisabled());

        passwordReady = false;
        await page.reload();
        await page.locator('[data-page="adUsers"]').click();
        await page.locator('#precreateEntryButton').click();
        await page.locator('#precreateStatus').filter({hasText: 'AD_PRECREATE_DEFAULT_PASSWORD'}).waitFor();
        assert(await page.locator('#precreatePreviewButton').isDisabled());
        assert(await page.locator('#precreateEye').isDisabled());

        role = 'readonly';
        await page.reload();
        await page.locator('[data-page="adUsers"]').click();
        assert(await page.locator('#precreateEntryButton').isHidden());
        await page.evaluate(() => switchPage('adPrecreate'));
        assert(!(await page.locator('#page-adPrecreate').isVisible()));
        assert.equal(errors.length, 0, errors.join('\n'));
        assert.equal(previews, 2);
        console.log('Precreate UI passed: preview, password masking, confirmation, pause/resume, retry, history, roles, mobile and missing configuration.');
    } finally { await browser.close(); }
}

run().catch(error => {console.error(error); process.exitCode = 1;});
