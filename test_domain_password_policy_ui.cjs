// Run with Node.js, Playwright, and an installed Microsoft Edge. All requests are mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
    const browser = await chromium.launch({channel: 'msedge', headless: true});
    try {
        const page = await browser.newPage({viewport: {width: 1366, height: 900}});
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const html = fs.readFileSync(path.join(__dirname, 'admin_manage.html'), 'utf8');
        const policy = {relax_min_password_length_limits: null, complexity_enabled: true,
            min_password_length: 8, min_age_days: 1, max_age_days: 180, password_history_count: 0,
            reversible_encryption_enabled: false, min_password_length_audit: null};
        const source = {name: 'Default Domain Policy', guid: '{TEST}', version: 1, dc: 'dc.test'};
        let mode = 'normal', saves = 0, fallbackReads = 0, previews = 0;
        await page.route('**/*', async route => {
            const request = route.request(), url = new URL(request.url());
            if (url.pathname === '/admin/manage') return route.fulfill({contentType: 'text/html', body: html});
            let result = {success: false, message: 'Unused test endpoint'};
            if (url.pathname === '/api/admin/check') result = {logged_in: true, username: 'test', role: 'super_admin', permissions: ['password_policy']};
            if (url.pathname === '/api/admin/domain_password_policy/gpo' && request.method() === 'GET') {
                result = mode === 'off' ? {success: true, enabled: false, writable: false} :
                    {success: true, enabled: true, writable: mode !== 'readonly', policy, source, revision: 'revision', csrf_token: 'csrf'};
            }
            if (url.pathname.endsWith('/gpo/preview')) {
                previews++;
                assert.equal(request.headers()['x-csrf-token'], 'csrf');
                const payload = request.postDataJSON();
                assert.equal(payload.revision, 'revision');
                const diff = Object.entries(payload.changes).map(([key, after]) => ({key, before: policy[key], after}));
                result = mode === 'conflict' ? {success: false, message: '策略已变化，请刷新后重新预览'} : {success: true, source, diff};
            }
            if (url.pathname === '/api/admin/domain_password_policy/gpo' && request.method() === 'POST') {
                saves++;
                assert.equal(request.headers()['x-csrf-token'], 'csrf');
                const payload = request.postDataJSON();
                assert.equal(payload.confirm_text, 'YES');
                result = mode === 'recovery' ? {success: false, message: '自动恢复未完成', recovery_required: true, backup_id: 'backup-test'} :
                    {success: true, message: '已写入真实 GPO 并回读校验', backup_id: 'backup-test'};
            }
            if (url.pathname === '/api/admin/domain_password_policy') {
                fallbackReads++;
                result = {success: true, policy: {min_password_length: 8, complexity_enabled: true, min_age_seconds: 0,
                    max_age_seconds: 86400, password_history_count: 0, reversible_encryption_enabled: false}};
            }
            return route.fulfill({contentType: 'application/json', body: JSON.stringify(result)});
        });
        await page.goto('http://ad-policy.test/admin/manage');
        await page.locator('[data-page="domainPasswordPolicy"]').click();
        await page.getByText('已读取真实 GPO 配置', {exact: true}).waitFor();
        assert.equal(await page.locator('[data-policy-input]').count(), 8);
        assert.equal(await page.locator('#domainPolicyRows tr').count(), 8);
        assert.equal(fallbackReads, 0);
        await page.locator('[data-policy-input="min_age_days"]').fill('0');
        await page.locator('[data-policy-input="complexity_enabled"]').selectOption('false');
        await page.locator('#domainPolicySaveButton').click();
        await page.locator('#domainPolicyDialog[open]').waitFor();
        assert.equal(await page.locator('#domainPolicyDiff tr').count(), 2);
        assert.equal(saves, 0);
        await page.locator('#domainPolicyConfirmButton').click();
        assert.equal(saves, 0);
        await page.locator('#domainPolicyConfirm').fill('YES');
        await page.locator('#domainPolicyConfirmButton').click();
        await page.locator('#domainPolicyStatus').filter({hasText: '备份编号 backup-test'}).waitFor();
        assert.equal(saves, 1);
        assert.equal(previews, 1);

        await page.setViewportSize({width: 390, height: 844});
        const bounds = await page.locator('#domainPolicyRows').evaluate(element => {
            const rect = element.getBoundingClientRect();
            return {right: rect.right, width: rect.width, screen: innerWidth};
        });
        assert(bounds.width > 200 && bounds.right <= bounds.screen, JSON.stringify(bounds));
        await page.locator('[data-policy-input="min_age_days"]').fill('0');
        mode = 'recovery';
        await page.locator('#domainPolicySaveButton').click();
        await page.locator('#domainPolicyDialog[open]').waitFor();
        const dialogBounds = await page.locator('#domainPolicyDialog').boundingBox();
        assert(dialogBounds.x >= 0 && dialogBounds.x + dialogBounds.width <= 390);
        await page.locator('#domainPolicyConfirm').fill('YES');
        await page.locator('#domainPolicyConfirmButton').click();
        await page.locator('#domainPolicyStatus').filter({hasText: '自动恢复未完成'}).waitFor();
        assert(await page.locator('#domainPolicySaveButton').isDisabled());

        mode = 'conflict';
        await page.locator('#domainPolicyRefreshButton').click();
        await page.getByText('已读取真实 GPO 配置', {exact: true}).waitFor();
        await page.locator('[data-policy-input="min_age_days"]').fill('0');
        await page.locator('#domainPolicySaveButton').click();
        await page.locator('.toast').filter({hasText: '策略已变化，请刷新后重新预览'}).waitFor();
        assert.equal(await page.locator('#domainPolicyDialog[open]').count(), 0);
        assert.equal(saves, 2);

        mode = 'readonly';
        await page.locator('#domainPolicyRefreshButton').click();
        await page.getByText('已读取真实 GPO 配置；写入未启用', {exact: true}).waitFor();
        assert(await page.locator('#domainPolicySaveButton').isHidden());
        mode = 'off';
        await page.locator('#domainPolicyRefreshButton').click();
        await page.locator('#domainPolicyStatus').filter({hasText: 'GPO 接入未启用'}).waitFor();
        assert.equal(fallbackReads, 1);
        assert(await page.locator('#domainPolicySaveButton').isHidden());
        assert.deepEqual(errors, []);
        console.log('Domain password policy UI: desktop/mobile, preview, confirmation, save, recovery, readonly and fallback passed');
    } finally {
        await browser.close();
    }
}

run().catch(error => {console.error(error); process.exitCode = 1;});
