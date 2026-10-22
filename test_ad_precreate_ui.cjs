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
        let role = 'super_admin', inputSupported = true, previews = 0, starts = 0, steps = 0, reveals = 0;
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
                    assert.equal(request.postDataJSON().password, 'IsolatedUiPassword1!');
                    assert(!url.search.includes('IsolatedUiPassword1!'));
                }
                if (endpoint === 'config') result = {success: true, ou, password_ready: false, password_input: inputSupported, csrf_token: 'precreate-csrf'};
                if (endpoint === 'password') { reveals++; result = {success: true, password: 'IsolatedUiPassword1!'}; }
                if (endpoint === 'preview') {
                    previews++;
                    const {password, ...spec} = request.postDataJSON();
                    previewSpec = {...spec, ou, password_source: 'input'};
                    const items = Array.from({length: previewSpec.end - previewSpec.start + 1}, (_, index) => ({
                        employee_id: `${previewSpec.prefix}${String(previewSpec.start + index).padStart(2,'0')}`,
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
                        items: Array.from({length: 3}, (_, index) => ({employee_id: `${previewSpec.prefix}${String(index).padStart(2,'0')}`, status: 'pending', message: '待创建'}))};
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
        await page.waitForFunction(() => precreateState.config?.password_input);
        assert.equal(await page.locator('#precreateOu').inputValue(), ou);
        assert(!(await page.locator('#precreateEnabled').isChecked()));
        assert(await page.locator('#precreatePreviewButton').isDisabled());
        assert.equal(await page.locator('#precreatePassword').getAttribute('readonly'), null);
        await page.locator('#precreatePassword').fill('IsolatedUiPassword1!');
        await page.locator('#precreateEye').click();
        await page.waitForFunction(() => document.getElementById('precreatePassword').type === 'text');
        assert.equal(await page.locator('#precreatePassword').inputValue(), 'IsolatedUiPassword1!');
        await page.locator('#precreateEye').click();
        assert.equal(await page.locator('#precreatePassword').getAttribute('type'), 'password');
        assert.equal(await page.locator('#precreatePassword').inputValue(), 'IsolatedUiPassword1!');
        assert.equal(reveals, 0);
        await page.locator('#precreatePrefix').fill('wfq2611');
        assert((await page.locator('#precreateRange').textContent()).includes('wfq261100 ~ wfq261199'));
        await page.locator('#precreateEnd').fill('2');
        await page.locator('#precreatePreviewButton').click();
        await page.waitForFunction(() => !document.getElementById('precreateCreateButton').disabled);
        assert.equal(await page.locator('#precreateRows tr').count(), 3);
        assert((await page.locator('#precreateRows tr').first().textContent()).includes('wfq261100'));
        assert.equal(steps, 0);
        await page.locator('#precreatePrefix').fill('wfq2612');
        await page.locator('#precreateName').fill('张三');
        assert(await page.locator('#precreateCreateButton').isDisabled());
        await page.locator('#precreatePreviewButton').click();
        await page.waitForFunction(() => !document.getElementById('precreateCreateButton').disabled);
        assert((await page.locator('#precreateRows tr').first().textContent()).includes('wfq261200'));
        await page.locator('#precreatePassword').fill('EditedUiPassword2!');
        assert(await page.locator('#precreateCreateButton').isDisabled());
        await page.locator('#precreatePassword').fill('IsolatedUiPassword1!');
        await page.locator('#precreatePreviewButton').click();
        await page.waitForFunction(() => !document.getElementById('precreateCreateButton').disabled);
        await page.locator('#precreateCreateButton').click();
        await page.locator('#yesModal.show').waitFor();
        assert.equal(starts, 0);
        assert((await page.locator('#yesText').textContent()).includes('账号保持禁用'));
        assert((await page.locator('#yesText').textContent()).includes('wfq261200 至 wfq261202'));
        assert(!(await page.locator('#yesText').textContent()).includes('IsolatedUiPassword1!'));
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
        assert.equal(await page.locator('#precreatePrefix').inputValue(), 'wfq2612');
        assert.equal(await page.locator('#precreateName').inputValue(), '张三');
        assert.equal(starts, 1);
        assert.equal(previewSpec.full_name, '张三');

        batch.items[2].status = 'pending'; count();
        // Old saved batches also display their original prefix after this update.
        batch.spec = {year: 2026, month: 12, start: 0, end: 2, full_name: '张三', enabled: false, ou};
        await page.reload();
        await page.locator('[data-page="adUsers"]').click();
        await page.locator('#precreateEntryButton').click();
        await page.locator(`#precreateHistory option[value="${batchId}"]`).waitFor({state: 'attached'});
        await page.locator('#precreateHistory').selectOption(batchId);
        await page.waitForFunction(() => document.getElementById('precreateStatus').textContent.includes('成功 1'));
        assert.equal(steps, 4);
        assert.equal(await page.locator('#precreatePrefix').inputValue(), 'wfq2612');
        assert.equal(await page.locator('#precreatePassword').inputValue(), '');
        assert(await page.locator('#precreateContinueButton').isDisabled());
        await page.locator('#precreatePassword').fill('IsolatedUiPassword1!');
        assert(await page.evaluate(() => precreateState.batch !== null));
        await page.locator('#precreateContinueButton').click();
        await page.waitForFunction(() => document.getElementById('precreateStatus').textContent.includes('成功 2'));
        assert.equal(steps, 5);
        assert.equal(starts, 1);
        assert(!(await page.evaluate(() => JSON.stringify({...localStorage, ...sessionStorage}))).includes('IsolatedUiPassword1!'));
        await page.setViewportSize({width: 390, height: 844});
        const bounds = await page.locator('#page-adPrecreate .precreate-panel').boundingBox();
        assert(bounds.x >= 0 && bounds.x + bounds.width <= 390);
        const fields = await page.locator('#precreateFields').boundingBox();
        assert(fields.width > 200 && fields.x + fields.width <= 390);
        assert((await page.screenshot()).length > 5000);
        await page.locator('#precreatePrefix').fill('wfq2701');
        assert(await page.evaluate(() => precreateState.batch === null));
        assert(await page.locator('#precreateCreateButton').isDisabled());

        await page.locator('[data-page="adUsers"]').click();
        assert.equal(await page.locator('#precreatePassword').inputValue(), '');
        batch.items[2].status = 'pending'; count();
        inputSupported = false;
        await page.reload();
        await page.locator('[data-page="adUsers"]').click();
        await page.locator('#precreateEntryButton').click();
        await page.locator('#precreateStatus').filter({hasText: '更新后端镜像'}).waitFor();
        assert(await page.locator('#precreatePreviewButton').isDisabled());
        assert(await page.locator('#precreateEye').isDisabled());
        await page.locator('#precreateHistory').selectOption(batchId);
        await page.waitForFunction(() => precreateState.batch !== null);
        await page.locator('#precreatePassword').fill('IsolatedUiPassword1!');
        assert(await page.locator('#precreatePreviewButton').isDisabled());
        assert(await page.locator('#precreateContinueButton').isDisabled());

        role = 'readonly';
        await page.reload();
        await page.locator('[data-page="adUsers"]').click();
        assert(await page.locator('#precreateEntryButton').isHidden());
        await page.evaluate(() => switchPage('adPrecreate'));
        assert(!(await page.locator('#page-adPrecreate').isVisible()));
        assert.equal(errors.length, 0, errors.join('\n'));
        assert.equal(previews, 3);
        assert.equal(reveals, 0);
        console.log('Precreate UI passed: editable prefixes/passwords without env, range preview, password masking, confirmation, pause/resume, retry, legacy history, roles, mobile and backend compatibility.');
    } finally { await browser.close(); }
}

run().catch(error => {console.error(error); process.exitCode = 1;});
