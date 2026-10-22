// Run with Node.js, Playwright, and Edge. No live AD or deployment requests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
    const browser = await chromium.launch({channel: 'msedge', headless: true});
    try {
        const page = await browser.newPage({viewport: {width: 1366, height: 900}});
        const html = fs.readFileSync(path.join(__dirname, 'admin_manage.html'), 'utf8');
        const errors = [], requests = [];
        page.on('pageerror', error => errors.push(error.message));
        let role = 'super_admin', enabled = true, scans = 0, starts = 0, steps = 0, many = false;
        let batch = null, preview = [], unknown = true, release;
        const gate = new Promise(resolve => {release = resolve;});
        const id = 'ed5563d9-4d37-45eb-9a94-f55045b84c03';
        const ou = 'OU=用户,DC=wfq,DC=com';
        function rows(scope) {
            const count = many ? 100 : scope === 'precreated' ? 4 : 1;
            return Array.from({length: count}, (_, index) => ({employee_id: many ? `wfq2700${String(index).padStart(2,'0')}` : scope === 'precreated' ? `wfq26080${index}` : 'wfq102179',
                guid: String(index), name: index === 0 ? '<img src=x onerror=alert(1)>' : '预建待分配', department: 'IT',
                created: '2026-06-01T01:00:00', last_logon: null, can_delete: many || index !== 2,
                message: index === 2 && !many ? '组权限信息不完整，禁止删除' : '满足 45 天规则', source: scope}));
        }
        function count() {
            batch.counts = {pending: 0, processing: 0, deleted: 0, absent: 0, skipped: 0, failed: 0, unknown: 0};
            batch.items.forEach(row => batch.counts[row.status]++);
        }
        await page.route('**/*', async route => {
            const request = route.request(), url = new URL(request.url());
            requests.push({path: url.pathname, method: request.method()});
            if (url.pathname === '/admin/manage') return route.fulfill({contentType: 'text/html', body: html});
            let result = {success: true};
            if (url.pathname === '/api/admin/check') result = {logged_in: true, username: 'test', role, permissions: ['view_user', 'delete_user']};
            if (url.pathname.startsWith('/api/admin/ad-bulk-delete/')) {
                assert.equal(role, 'super_admin');
                const endpoint = url.pathname.replace('/api/admin/ad-bulk-delete/', '');
                if (request.method() === 'POST') assert.equal(request.headers()['x-csrf-token'], 'bulk-delete-csrf');
                if (endpoint === 'config') result = {success: true, csrf_token: 'bulk-delete-csrf', enabled, days: 45, limit: 100, ou};
                if (endpoint === 'scan') {
                    scans++;
                    preview = rows(request.postDataJSON().scope);
                    result = {success: true, items: preview, preview_token: 'signed-preview', controllers: ['dc01.wfq.com', 'dc02.wfq.com'], days: 45};
                }
                if (endpoint === 'batches' && request.method() === 'POST') {
                    starts++;
                    const data = request.postDataJSON();
                    assert.equal(data.confirm_text, 'YES'); assert.equal(data.acknowledge_recovery, true);
                    assert.equal(data.confirm_count, 2); assert.deepEqual(data.selected, ['wfq260800', 'wfq260801']);
                    batch = {id, spec: {scope: 'precreated'}, created_at: '2026-10-22 10:00:00',
                        items: preview.filter(row => data.selected.includes(row.employee_id)).map(row => ({...row, status: 'pending'}))};
                    count(); result = {success: true, batch};
                }
                if (endpoint === 'batches' && request.method() === 'GET') result = {success: true, batches: batch ? [batch] : []};
                if (endpoint === `batches/${id}`) result = {success: true, batch};
                if (endpoint.endsWith('/step')) {
                    steps++;
                    if (steps === 1) await gate;
                    const row = batch.items.find(row => row.status === 'pending');
                    if (row.employee_id.endsWith('01') && unknown) {unknown = false; row.status = 'unknown'; row.message = '结果未确认';}
                    else {row.status = steps === 3 ? 'absent' : 'deleted'; row.message = '计算机保留';}
                    count(); result = {success: true, batch, waiting: false};
                }
                if (endpoint.endsWith('/retry')) {
                    assert.equal(request.postDataJSON().acknowledge_recovery, true);
                    batch.items.filter(row => row.status === 'unknown').forEach(row => {row.status = 'pending';});
                    count(); result = {success: true, batch};
                }
            }
            return route.fulfill({contentType: 'application/json', body: JSON.stringify(result)});
        });
        async function enter() {
            await page.goto('http://ad-bulk-delete.test/admin/manage');
            await page.locator('[data-page="adUsers"]').click();
            await page.locator('#bulkDeleteEntryButton').click();
            await page.waitForFunction(() => bulkDeleteState.config !== null);
        }
        async function confirm() {
            await page.locator('#yesModal.show').waitFor();
            await page.locator('#yesInput').fill('YES');
            await page.locator('#yesModal .modal-btns .btn-danger').click();
        }

        await enter();
        assert.equal(await page.locator('#bulkDeleteScope').inputValue(), 'precreated');
        assert.equal(await page.locator('#bulkDeleteOu').inputValue(), ou);
        await page.locator('#bulkDeleteScan').click();
        await page.waitForFunction(() => !bulkDeleteState.busy);
        assert.equal(starts, 0); assert.equal(steps, 0);
        assert.equal(await page.locator('#bulkDeleteRows input:checked').count(), 0);
        assert.equal(await page.locator('#bulkDeleteRows img').count(), 0);
        assert(await page.locator('#bulkDeleteRows input[data-account="wfq260802"]').isDisabled());
        await page.locator('#bulkDeleteAll').check();
        assert.equal(await page.locator('#bulkDeleteRows input:checked').count(), 3);
        await page.locator('#bulkDeleteAll').uncheck();
        await page.locator('#bulkDeleteRows input[data-account="wfq260800"]').check();
        await page.locator('#bulkDeleteRows input[data-account="wfq260801"]').check();
        assert(await page.locator('#bulkDeleteStart').isDisabled());
        await page.locator('#bulkDeleteRecovery').check();
        await page.evaluate(() => {currentUser = {employee_id: 'wfq260800', computers: [{name: 'PC-KEEP', dn: 'CN=PC-KEEP,DC=wfq,DC=com'}]};});
        await page.locator('#bulkDeleteStart').click();
        await page.locator('#yesModal.show').waitFor();
        const text = await page.locator('#yesText').textContent();
        assert(text.includes('wfq260800') && text.includes('wfq260801') && !text.includes('wfq260803'));
        assert.equal(starts, 0);
        await confirm();
        await page.waitForFunction(() => bulkDeleteState.running);
        await page.locator('#bulkDeletePause').click(); release();
        await page.waitForFunction(() => !bulkDeleteState.busy);
        assert.equal(steps, 1);
        assert.equal(await page.evaluate(() => deletedUserComputers[0].name), 'PC-KEEP');
        assert(await page.evaluate(() => currentUser === null));
        await page.locator('#bulkDeleteContinue').click(); await confirm();
        await page.waitForFunction(() => document.getElementById('bulkDeleteStatus').textContent.includes('已暂停'));
        assert.equal(steps, 2);
        await page.locator('#bulkDeleteRetry').click(); await confirm();
        await page.waitForFunction(() => document.getElementById('bulkDeleteStatus').textContent.includes('已不存在 1'));
        assert.equal(steps, 3); assert.equal(starts, 1);

        await enter();
        await page.locator('#bulkDeleteHistory').selectOption(id);
        await page.waitForFunction(() => bulkDeleteState.batch !== null);
        assert(!(await page.locator('#bulkDeleteRecovery').isChecked()));
        assert.equal(steps, 3);
        await page.locator('#bulkDeleteScope').selectOption('ordinary');
        assert(await page.evaluate(() => bulkDeleteState.preview === null && bulkDeleteState.batch === null));
        await page.locator('#bulkDeleteScan').click();
        await page.waitForFunction(() => !bulkDeleteState.busy);
        assert((await page.locator('#bulkDeleteRows').textContent()).includes('wfq102179'));
        assert.equal(await page.locator('#bulkDeleteRows input:checked').count(), 0);
        many = true;
        await page.locator('#bulkDeleteScan').click(); await page.waitForFunction(() => !bulkDeleteState.busy);
        await page.setViewportSize({width: 390, height: 844});
        const panel = await page.locator('#page-adBulkDelete > .card').boundingBox();
        assert(panel.x >= 0 && panel.x + panel.width <= 390);
        await page.locator('#bulkDeleteAll').check(); await page.locator('#bulkDeleteRecovery').check();
        await page.locator('#bulkDeleteStart').click(); await page.locator('#yesModal.show').waitFor();
        const modal = await page.locator('#yesModal .modal').boundingBox();
        assert(modal.y >= 0 && modal.y + modal.height <= 844);
        await page.locator('#yesModal .modal-btns .btn-light').scrollIntoViewIfNeeded();
        assert((await page.screenshot()).length > 5000);
        await page.locator('#yesModal .modal-btns .btn-light').click();
        assert.equal(starts, 1); assert.equal(steps, 3);
        enabled = false; await enter(); assert(await page.locator('#bulkDeleteScan').isDisabled());
        for (const value of ['admin', 'readonly']) {
            role = value;
            await page.goto('http://ad-bulk-delete.test/admin/manage');
            await page.locator('[data-page="adUsers"]').click();
            assert(await page.locator('#bulkDeleteEntryButton').isHidden());
            await page.evaluate(() => switchPage('adBulkDelete'));
            assert(!(await page.locator('#page-adBulkDelete').isVisible()));
        }
        assert(!requests.some(request => request.path === '/api/admin/delete' ||
            (request.path.includes('/computers/') && request.method !== 'GET')));
        assert.equal(scans, 3); assert.equal(errors.length, 0, errors.join('\n'));
        console.log('Bulk delete UI passed: scopes, no automatic selection/deletion, blocked rows, explicit recovery/YES confirmation, selected-only batch, pause/resume, unknown retry, history, preserved computers, roles, disabled setting and mobile 100-account dialog.');
    } finally {await browser.close();}
}
run().catch(error => {console.error(error); process.exitCode = 1;});
