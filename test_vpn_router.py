import importlib.util
import sys
import unittest
from types import SimpleNamespace
from urllib.parse import urlsplit

from vpn_router import create_from_page, manage_route


ORIGIN = 'https://router.example.test'
SESSION = '/cgi-bin/luci/;stok=mocksession'
ACCOUNT = 'new-employee'
PASSWORD = 'TestPassword12'

LOGIN = """
<input type="password" id="password">
<button id="login" onclick="if (document.querySelector('input').value === 'test-device') location.href = 'SESSION/admin/home'">
    Log In
</button>
""".replace('SESSION', SESSION)

MANAGE = """
<button onclick="document.querySelector('.el-dialog').hidden = false">添加</button>
<div class="el-table"></div>
<div class="el-dialog" hidden>
    <h2 class="el-dialog__title">添加用户</h2>
    <div class="el-form-item"><label>服务类型</label><input id="service" readonly
         onclick="document.querySelector('.el-select-dropdown').hidden = false"></div>
    <input id="username" placeholder="请输入用户名">
    <input id="password" type="password" placeholder="请输入密码">
    <label class="el-switch"><input id="enabled" type="checkbox">启用</label>
    <button onclick="save()">确定</button>
</div>
<div class="el-select-dropdown" hidden>
    <button class="el-select-dropdown__item" onclick="choose()">OpenVpn</button>
</div>
<div class="el-message--success" hidden>操作成功</div>
<script>
    const scenario = 'SCENARIO';
    const users = scenario === 'exists' ? [{username: 'NEW-EMPLOYEE', provider: 'openvpn'}] : [];
    const get = id => document.getElementById(id);
    document.querySelector('.el-table').__vue__ = { $parent: {
        userList: users,
        $apiArr: async keys => keys.join() === 'vpn_user' && scenario !== 'lookup'
            ? {vpn_user: {list: users}} : null,
    } };
    function choose() {
        get('service').value = 'openvpn';
        document.querySelector('.el-select-dropdown').hidden = true;
    }
    function save() {
        if (get('service').value !== 'openvpn' || !get('enabled').checked ||
            get('password').value !== 'TestPassword12' || get('username').value !== 'new-employee') return;
        document.body.dataset.saves = '1';
        if (scenario !== 'unknown') users.push({username: get('username').value, provider: 'openvpn'});
        document.querySelector('.el-message--success').hidden = false;
    }
</script>
"""


class RouterUrlTests(unittest.TestCase):
    def test_only_device_origin_and_exact_native_path_are_accepted(self):
        page = ORIGIN + SESSION + '/admin/home'
        expected = ORIGIN + SESSION + '/admin/alone/vpn/vpn_user'
        self.assertEqual(manage_route(page, ORIGIN), expected)
        self.assertIsNone(manage_route(page, 'https://other.example.test'))
        self.assertIsNone(manage_route(page.replace('/admin/', '/not-admin/'), ORIGIN))
        self.assertIsNone(manage_route(page.replace('https:', 'http:'), ORIGIN))


@unittest.skipUnless(importlib.util.find_spec('playwright'), 'Playwright is optional')
class RouterBrowserTests(unittest.TestCase):
    def test_create_duplicate_failed_lookup_and_unverified_save(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            options = {'channel': 'msedge'} if sys.platform == 'win32' else {}
            browser = playwright.chromium.launch(**options)
            for scenario, result, saves in (
                ('success', 'created', '1'), ('exists', 'exists', None),
                ('lookup', 'lookup_failed', None), ('unknown', 'unknown', '1'),
            ):
                with self.subTest(scenario=scenario):
                    page = browser.new_page()
                    try:
                        def mock_device(route):
                            path = urlsplit(route.request.url).path
                            body = (LOGIN if path == '/cgi-bin/luci/' else MANAGE.replace('SCENARIO', scenario)
                                    if path.endswith('/vpn_user') else '<p>Router homepage</p>')
                            route.fulfill(content_type='text/html; charset=utf-8', body=body)

                        page.route(ORIGIN + '/**', mock_device)
                        page.route('**/*', lambda route: route.fallback()
                                   if route.request.url.startswith(ORIGIN + '/') else route.abort())
                        page.set_default_timeout(3000)
                        config = SimpleNamespace(url=ORIGIN, password=lambda: 'test-device')
                        self.assertEqual(create_from_page(page, config, ACCOUNT, PASSWORD), result)
                        self.assertEqual(page.locator('body').get_attribute('data-saves'), saves)
                    finally:
                        page.close()
            browser.close()
