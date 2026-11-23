"""Create-only OpenVPN provisioning through the Reyee EG web UI."""

import base64
import hashlib
import importlib.util
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


VPN_PATH = '/admin/alone/vpn/vpn_user'
LOGIN_PATH = '/cgi-bin/luci/'
TIMEOUT = 6000


@dataclass(frozen=True)
class RouterConfig:
    url: str
    password_file: Path
    certificate_file: Path | None

    @classmethod
    def from_env(cls):
        url = os.environ.get('VPN_ROUTER_URL', '').strip()
        password = os.environ.get('VPN_ROUTER_PASSWORD_FILE', '').strip()
        cert = os.environ.get('VPN_ROUTER_CERT_FILE', '').strip()
        try:
            target = urlsplit(url)
            if (target.scheme != 'https' or not target.hostname or target.port == 0
                    or target.username is not None or target.path not in ('', '/')
                    or target.query or target.fragment or any(c.isspace() for c in url)
                    or not password or not Path(password).is_file() or (cert and not Path(cert).is_file())
                    or importlib.util.find_spec('playwright') is None):
                return None
        except (OSError, ValueError):
            return None
        return cls(url.rstrip('/'), Path(password), Path(cert) if cert else None)

    def password(self):
        with self.password_file.open(encoding='utf-8-sig') as stream:
            value = stream.read(67).rstrip('\r\n')
        if not value or len(value) > 64 or '\r' in value or '\n' in value:
            raise ValueError('Invalid device password file')
        return value

    def browser_args(self):
        args = ['--no-proxy-server']
        if self.certificate_file:
            data = self.certificate_file.read_bytes()
            cert = (x509.load_pem_x509_certificate(data) if b'-----BEGIN CERTIFICATE-----' in data
                    else x509.load_der_x509_certificate(data))
            key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            pin = base64.b64encode(hashlib.sha256(key).digest()).decode('ascii')
            args.append('--ignore-certificate-errors-spki-list=' + pin)
        return args


@contextmanager
def router_lock(instance_path):
    import fcntl

    # A device password failure must not trigger repeated logins across Gunicorn workers.
    with (Path(instance_path) / '.vpn-router.lock').open('a+', encoding='ascii') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield None
            return
        yield lock


READ_ACCOUNT = '''async ({ username, timeout }) => {
    const panel = [...document.querySelectorAll('.vpn-user-pool, .el-table')];
    let component;
    for (const node of panel) {
        for (let vm = node.__vue__; vm; vm = vm.$parent) {
            if (Array.isArray(vm.userList) && typeof vm.$apiArr === 'function') {
                component = vm;
                break;
            }
        }
        if (component) break;
    }
    if (!component) return null;
    let timer;
    try {
        const result = await Promise.race([
            component.$apiArr(['vpn_user'], false, { showError: false }),
            new Promise(resolve => { timer = setTimeout(() => resolve(null), timeout); })
        ]);
        const users = result?.vpn_user?.list;
        if (!Array.isArray(users)) return null;
        const names = users.map(row => row?.username ?? row?.name ?? row?.user);
        if (names.some(name => typeof name !== 'string' || !name)) return null;
        const matches = users.filter((_, i) => names[i].toLowerCase() === username.toLowerCase());
        return { exists: matches.length > 0, openvpn: matches.length === 1 &&
            String(matches[0].provider).toLowerCase() === 'openvpn' };
    } catch (_) {
        return null;
    } finally {
        clearTimeout(timer);
    }
}'''


def same_origin(url, origin):
    a, b = urlsplit(url), urlsplit(origin)
    return a.scheme == b.scheme == 'https' and a.hostname == b.hostname and (a.port or 443) == (b.port or 443)


def manage_route(url, origin):
    if same_origin(url, origin):
        session_path = re.match(r'^/cgi-bin/luci/;stok=([A-Za-z0-9_-]{8,160})/admin(?:/|$)', urlsplit(url).path)
        if session_path:
            return origin + LOGIN_PATH + ';stok=' + session_path[1] + VPN_PATH
    return None


def read_account(page, username):
    return page.evaluate(READ_ACCOUNT, {'username': username, 'timeout': TIMEOUT})


def create_from_page(page, config, username, password):
    from playwright.sync_api import Error

    phase = 'connect'
    try:
        page.goto(config.url + LOGIN_PATH, wait_until='domcontentloaded')
        if not same_origin(page.url, config.url):
            return 'router_unreachable'
        if not manage_route(page.url, config.url):
            phase = 'login'
            page.locator('#password[type=password]').fill(config.password())
            page.locator('button#login').click()
            page.wait_for_url(lambda url: bool(manage_route(url, config.url)), timeout=10000)
        url = manage_route(page.url, config.url)
        if not url:
            return 'auth_failed'
        phase = 'prepare'
        page.goto(url, wait_until='domcontentloaded')
        if manage_route(page.url, config.url) != url or urlsplit(page.url).path != urlsplit(url).path:
            return 'auth_failed'
        add = page.get_by_role('button', name=re.compile(r'^(添加|Add|Add User)$', re.I))
        add.wait_for(state='visible')
        before = read_account(page, username)
        if before is None:
            return 'lookup_failed'
        if before['exists']:
            return 'exists'

        add.click()
        dialog = page.locator('.el-dialog:visible').filter(
            has=page.locator('.el-dialog__title').filter(has_text=re.compile(r'^\s*(添加用户|Add User)\s*$', re.I)))
        dialog.wait_for(state='visible')
        service = dialog.locator('.el-form-item').filter(has=page.locator('label').filter(
            has_text=re.compile(r'^\s*(服务类型|Service Type)\s*$', re.I)))
        service.locator('input').click()
        page.locator('.el-select-dropdown:visible .el-select-dropdown__item').filter(
            has_text=re.compile(r'^\s*OpenVPN\s*$', re.I)).click()
        dialog.get_by_placeholder(re.compile(r'^(请输入用户名|Enter (?:a |the )?username)$', re.I)).fill(username)
        dialog.get_by_placeholder(re.compile(r'^(请输入密码|Enter (?:a |the )?password)$', re.I)).fill(password)
        switch = dialog.locator('.el-switch:visible')
        if not switch.locator('input[type=checkbox]').is_checked():
            switch.click()
        if not switch.locator('input[type=checkbox]').is_checked():
            return 'router_form_failed'

        phase = 'submitted'
        dialog.get_by_role('button', name=re.compile(r'^(确定|OK|Confirm)$', re.I)).click()
        page.locator('.el-message--success').wait_for(state='visible')
        verified = read_account(page, username)
        return 'created' if verified and verified['openvpn'] else 'unknown'
    except (Error, OSError, ValueError):
        return {'connect': 'router_unreachable', 'login': 'auth_failed', 'prepare': 'router_form_failed',
                'submitted': 'unknown'}[phase]


def create_openvpn(config, instance_path, username, password):
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        return 'router_unavailable'

    try:
        with router_lock(instance_path) as lock:
            if lock is None:
                return 'router_busy'
            lock.seek(0)
            last_failure = lock.read().strip()
            if last_failure and time.time() - float(last_failure) < 60:
                return 'auth_failed'
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(args=config.browser_args(), timeout=10000)
                try:
                    context = browser.new_context(locale='zh-CN', service_workers='block', accept_downloads=False)
                    context.route('**/*', lambda route: route.continue_() if same_origin(route.request.url, config.url) else route.abort())
                    page = context.new_page()
                    page.set_default_timeout(TIMEOUT)
                    result = create_from_page(page, config, username, password)
                finally:
                    try:
                        browser.close()
                    except Error:
                        pass
            if result == 'auth_failed':
                lock.seek(0)
                lock.truncate()
                lock.write(str(time.time()))
            return result
    except (Error, OSError, ValueError):
        return 'router_unavailable'
