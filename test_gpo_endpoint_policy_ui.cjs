// Browser regression with mocked APIs; no domain or server is contacted.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
    const browser = await chromium.launch({channel: 'msedge', headless: true});
    try {
        const page = await browser.newPage({viewport: {width: 1366, height: 900}});
        const html = fs.readFileSync(path.join(__dirname, 'admin_manage.html'), 'utf8');
        const errors = [], saves = [], previews = [], reads = [];
        let mode = 'normal', role = 'super_admin', version = 1;
        page.on('pageerror', error => errors.push(error.message));
        const policies = {lock: {seconds: 901}, usb: {mode: 'readonly'}, software: {enabled: false, name: '', source: ''}};
        const state = kind => ({success: true, enabled: true, writable: mode !== 'readonly',
            source: {name: '<b>Endpoint test</b>', guid: '{TEST-' + kind + '}', dc: 'dc.test', scope: 'workstations', version},
            policy: policies[kind], revision: 'a'.repeat(64), domain_dn: 'DC=wfq,DC=com', csrf_token: 'csrf-test'});
        await page.route('**/*', async route => {
            const request = route.request(), url = new URL(request.url());
            if (url.pathname === '/admin/manage') return route.fulfill({contentType: 'text/html', body: html});
            if (url.pathname === '/api/admin/check') return route.fulfill({json: {logged_in: true, username: 'test', role, permissions: ['password_policy']}});
            if (!url.pathname.startsWith('/api/admin/gpo-endpoint/')) return route.fulfill({json: {success: false, message: 'Unused test endpoint'}});
            const kind = url.pathname.split('/')[4];
            let result;
            if (request.method() === 'GET') {
                reads.push(kind);
                result = mode === 'off' ? {success: true, enabled: false, writable: false, message: '设备组策略接入未启用'} :
                    mode === 'unsafe-scope' ? {success: false, message: '缺少办公电脑 WMI 筛选，禁止写入'} : state(kind);
            } else {
                const payload = request.postDataJSON();
                assert.equal(request.headers()['x-csrf-token'], 'csrf-test');
                assert.equal(payload.revision, 'a'.repeat(64));
                if (url.pathname.endsWith('/preview')) {
                    previews.push({kind, policy: payload.policy});
                    result = mode === 'conflict' ? {success: false, message: '策略已变化，请刷新后重试'} : {...state(kind), after: payload.policy};
                } else {
                    assert.equal(payload.confirm_text, 'YES');
                    assert.equal(payload.confirm_scope, 'DC=wfq,DC=com');
                    assert.deepEqual(payload.policy, previews.at(-1).policy);
                    saves.push({kind, policy: payload.policy});
                    if (mode === 'recovery') result = {success: false, recovery_required: true, backup_id: 'backup-error', message: '自动恢复未完成'};
                    else {
                        policies[kind] = payload.policy; version++;
                        result = {...state(kind), backup_id: 'backup-test', message: '已写入真实 GPO 并回读校验；不代表客户端已应用'};
                    }
                }
            }
            return route.fulfill({json: result});
        });
        const previewButton = page.locator('#endpointPolicyPreview');
        const dialog = page.locator('#endpointPolicyDialog');
        async function confirm() {
            await page.locator('#endpointPolicyScopeAck').check();
            await page.locator('#endpointPolicyConfirm').fill('YES');
            await page.locator('#endpointPolicySave').click();
            await dialog.waitFor({state: 'hidden'});
        }
        async function choose(kind) {
            await page.locator('#endpointPolicyKind').selectOption(kind);
            await page.locator('#endpointPolicyStatus').filter({hasText: '已读取真实 GPO'}).waitFor();
        }
        await page.goto('http://endpoint-policy.test/admin/manage');
        await page.locator('#endpointPolicyMenu').click();
        await page.locator('#endpointPolicyStatus').filter({hasText: '已读取真实 GPO'}).waitFor();
        assert.deepEqual(reads, ['lock']);
        assert.equal(saves.length, 0);
        assert(await page.locator('#endpointLockFields').isVisible());
        assert(await page.locator('#endpointUsbFields').isHidden());
        assert(await page.locator('#endpointSoftwareFields').isHidden());
        assert.equal(await page.locator('#endpointPolicySource b').count(), 0);
        assert.equal(Math.round(Number(await page.locator('#endpointLockMinutes').inputValue()) * 60), 901);
        await previewButton.click();
        await page.locator('.toast').filter({hasText: '没有需要保存的变更'}).waitFor();
        assert.equal(previews.length, 0);
        await page.locator('#endpointLockMinutes').fill('15');
        await previewButton.click();
        await dialog.waitFor({state: 'visible'});
        assert.deepEqual(previews.at(-1).policy, {seconds: 900});
        assert.equal(saves.length, 0);
        await page.locator('#endpointPolicyConfirm').fill('YES');
        await page.locator('#endpointPolicySave').click();
        assert.equal(saves.length, 0);
        await confirm();
        assert.equal(saves.length, 1);
        await page.locator('#endpointPolicyStatus').filter({hasText: '备份编号 backup-test'}).waitFor();
        await choose('usb');
        assert(await page.locator('#endpointLockFields').isHidden());
        assert(await page.locator('#endpointUsbFields').isVisible());
        await page.locator('#endpointUsbMode').selectOption('deny');
        await previewButton.click();
        await dialog.waitFor({state: 'visible'});
        assert.deepEqual(previews.at(-1), {kind: 'usb', policy: {mode: 'deny'}});
        await page.locator('#endpointPolicyCancel').click();
        assert.equal(saves.length, 1);
        await previewButton.click();
        await dialog.waitFor({state: 'visible'});
        await confirm();
        assert.equal(saves.length, 2);
        await choose('software');
        assert(await page.locator('#endpointSoftwareName').isDisabled());
        await page.locator('#endpointSoftwareEnabled').check();
        await page.locator('#endpointSoftwareName').fill('Green App');
        await page.locator('#endpointSoftwareSource').fill('\\\\files.test\\Software\\app.exe');
        await previewButton.click();
        await dialog.waitFor({state: 'visible'});
        assert.deepEqual(previews.at(-1).policy, {enabled: true, name: 'Green App', source: '\\\\files.test\\Software\\app.exe'});
        assert((await page.locator('#endpointPolicyDiff').innerText()).includes('不自动启动'));
        await confirm();
        assert.equal(saves.length, 3);
        await page.setViewportSize({width: 390, height: 844});
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile page must not overflow horizontally');
        await page.locator('#endpointSoftwareEnabled').uncheck();
        await previewButton.click();
        await dialog.waitFor({state: 'visible'});
        const bounds = await dialog.boundingBox();
        assert(bounds.x >= 0 && bounds.x + bounds.width <= 391 && bounds.height <= 844);
        assert.deepEqual(previews.at(-1).policy, {enabled: false, name: '', source: ''});
        mode = 'recovery';
        await confirm();
        await page.locator('#endpointPolicyStatus').filter({hasText: '自动恢复未完成'}).waitFor();
        assert(await previewButton.isDisabled());
        assert(await page.locator('#endpointSoftwareEnabled').isDisabled());
        assert.equal(saves.length, 4);
        mode = 'readonly';
        await page.locator('#endpointPolicyRefresh').click();
        await page.locator('#endpointPolicyStatus').filter({hasText: '写入未启用'}).waitFor();
        assert(await previewButton.isHidden());
        mode = 'off';
        await page.locator('#endpointPolicyRefresh').click();
        await page.locator('#endpointPolicyStatus').filter({hasText: '接入未启用'}).waitFor();
        assert(await page.locator('#endpointSoftwareEnabled').isDisabled());
        mode = 'unsafe-scope';
        await page.locator('#endpointPolicyRefresh').click();
        await page.locator('#endpointPolicyStatus').filter({hasText: 'WMI 筛选'}).waitFor();
        assert(await previewButton.isHidden());
        role = 'readonly';
        const beforeReads = reads.length;
        await page.reload();
        await page.waitForFunction(() => currentRole === 'readonly');
        assert(await page.locator('#endpointPolicyMenu').isHidden());
        await page.evaluate(() => switchPage('endpointPolicy'));
        assert.equal(reads.length, beforeReads);
        assert.deepEqual(errors, []);
        console.log('Endpoint GPO UI passed: lock seconds/minutes, USB, manual EXE, explicit scope + YES, cancellation, mobile, readonly, unsafe scope, recovery, roles, XSS and no automatic saves.');
    } finally { await browser.close(); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
