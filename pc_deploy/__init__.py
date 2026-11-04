"""PC Deploy control plane. It never runs disk utilities or installs an OS locally."""
import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
import zipfile
from collections import defaultdict, deque
from functools import wraps
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from flask import Blueprint, Response, g, jsonify, redirect, request, send_file, send_from_directory, session
from werkzeug.local import LocalProxy
from werkzeug.exceptions import RequestEntityTooLarge

from .deployment import (ACTIVE, ERRORS, STATES, Invalid, answer_file, canonical, digest,
                        integer, inventory, profile_record, public_url, source_record,
                        target_check, text, partition_target, finalizer_command)
from .storage import Store
from .media import register_media_routes, media_dashboard

ROOT = Path(__file__).parent
ENROLLMENT_TTL = 7 * 24 * 3600


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


PREFIX = '/pc-deploy'


def register_pc_deploy(host_app, current_user, touch_session):
    """Add PC Deploy without changing host routes, settings or database models."""
    app = Blueprint('pc_deploy', __name__, static_folder='static', url_prefix=PREFIX)
    store_lock = threading.Lock()

    def get_store():
        with store_lock:
            if 'pc_deploy_store' not in host_app.extensions:
                directory = host_app.config.get('PC_DEPLOY_DATA_DIR',
                    str(Path(host_app.instance_path) / 'pc-deploy'))
                value = Store(directory)
                with value.connect(write=True) as c:
                    if value.setting(c, 'public_url') is None:
                        value.put(c, 'public_url', 'http://127.0.0.1/pc-deploy')
                        value.put(c, 'enabled', False)
                        value.put(c, 'concurrency', 2)
                        value.put(c, 'ca_pem', '')
                host_app.extensions['pc_deploy_store'] = value
            return host_app.extensions['pc_deploy_store']

    store = LocalProxy(get_store)

    def authorize():
        if not session.get('admin_logged_in'):
            return jsonify(error='请先登录 AD 管理后台'), 401
        user = current_user()
        if not user:
            return jsonify(error='后台账号已失效，请重新登录'), 401
        if user.role != 'super_admin':
            return jsonify(error='只有超级管理员可以使用电脑装机'), 403
        g.pc_deploy_operator = user.username
        touch_session()

    def http_allowed():
        return host_app.config.get('PC_DEPLOY_ALLOW_HTTP', True) is True

    def secure_request():
        trust_proxy = host_app.config.get('PC_DEPLOY_TRUST_PROXY',
            os.getenv('DEPLOY_TRUST_PROXY') == 'true') is True
        return request.is_secure or (trust_proxy and request.headers.get('X-Forwarded-Proto') == 'https')

    attempts, lock = defaultdict(deque), threading.Lock()

    def limited(key, limit, window=60):
        with lock:
            now = time.time()
            entries = attempts[key]
            while entries and entries[0] < now - window:
                entries.popleft()
            if len(entries) >= limit:
                return True
            entries.append(now)
            if len(attempts) > 5000:
                for old in list(attempts):
                    if not attempts[old] or attempts[old][-1] < now - 300:
                        del attempts[old]
            return False

    def body():
        if not request.is_json:
            raise Invalid('请提交 JSON 对象')
        raw = request.stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise RequestEntityTooLarge()
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Invalid('请提交 JSON 对象') from None
        if not isinstance(data, dict):
            raise Invalid('请提交 JSON 对象')
        return data

    def csrf():
        value = request.headers.get('X-CSRF-Token', '')
        if not value or not hmac.compare_digest(value, session.get('pc_deploy_csrf', '')):
            return False
        origin = request.headers.get('Origin')
        return not origin or urlsplit(origin).netloc == request.host

    def admin(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            denied = authorize()
            if denied:
                if request.endpoint == 'pc_deploy.index' and denied[1] == 401:
                    if request.args.get('embedded') == '1':
                        return send_from_directory(ROOT / 'static', 'index.html'), 401
                    return redirect('/admin')
                return denied
            if request.method not in ('GET', 'HEAD') and (not csrf() or not session.get('pc_deploy_session_id')):
                return jsonify(error='页面凭据失效，请刷新后重试'), 403
            return fn(*args, **kwargs)
        return wrapper

    def tls_required():
        if not http_allowed() and not secure_request() and not host_app.testing:
            raise Invalid('客户端接口只接受 HTTPS；请先配置部署服务器证书')

    def bearer():
        value = request.headers.get('Authorization', '')
        if not value.startswith('Bearer ') or not 20 <= len(value[7:]) <= 200:
            raise Invalid('客户端凭据缺失或格式错误')
        return value[7:]

    def agent(c):
        tls_required()
        row = c.execute('SELECT * FROM devices WHERE token_hash=?', (token_hash(bearer()),)).fetchone()
        if not row:
            raise Invalid('客户端会话已失效，请重新进入部署环境')
        return row

    def load(c, table, identity):
        if table not in ('sources', 'profiles', 'jobs'):
            raise RuntimeError('invalid table')
        if not isinstance(identity, str) or len(identity) > 64:
            raise Invalid('记录 ID 无效')
        row = c.execute(f'SELECT * FROM {table} WHERE id=?', (identity,)).fetchone()
        if not row:
            raise Invalid('所选记录不存在')
        return row, json.loads(row['data'])

    def event(c, kind, message, job=None):
        if getattr(g, 'pc_deploy_operator', None):
            message = '[' + g.pc_deploy_operator + '] ' + message
        c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                  (job, kind, message, time.time()))

    def agent_job(c, device, job_id, states):
        row, data = load(c, 'jobs', job_id)
        if row['device_id'] != device['id'] or row['boot_id'] != device['boot_id'] or row['state'] not in states:
            raise Invalid('任务与当前启动会话不符，或任务不允许此操作')
        if row['expires'] < time.time():
            raise Invalid('任务凭据已过期，请人工核对；不会自动重装')
        return row, data

    def snapshot_target(c, target, profile, source):
        if not isinstance(target.get('device_id'), str):
            raise Invalid('设备 ID 无效')
        row = c.execute('SELECT * FROM devices WHERE id=?', (target.get('device_id'),)).fetchone()
        if not row or time.time() - row['last_seen'] > 45:
            raise Invalid('设备已离线，请等待客户端重新登记')
        if row['consumed']:
            raise Invalid('该启动会话已经启动过安装，禁止重复清盘；请先人工核对')
        if c.execute('SELECT id FROM jobs WHERE device_id=? AND state IN (?,?,?,?)', (row['id'], *ACTIVE)).fetchone():
            raise Invalid('设备已有未结束任务')
        inv = json.loads(row['data'])
        disk = target_check(inv, target.get('disk_key'), profile)
        if source['family'] == 'windows11' and not (inv['secure_boot'] and inv['tpm2']):
            raise Invalid('Windows 11 方案要求客户端确认 TPM 2.0 和已启用的 Secure Boot')
        result = dict(device_id=row['id'], boot_id=row['boot_id'], inventory_hash=row['inventory_hash'],
                      disk_key=disk['key'], disk=disk, serial=inv['serial'], model=inv['model'],
                      boot_code=row['boot_code'], inventory=inv)
        if source.get('kind') == 'wim':
            if inv.get('wim_apply_v1') is not True:
                raise Invalid('该 PE 版本只支持登记或原版安装，请用更新后的装机 ISO 启动')
            if profile.get('disk_mode') == 'system_partition':
                result['partition_key'] = target.get('partition_key')
                result['partitions'] = partition_target(disk, result['partition_key'])
        return result

    @app.errorhandler(Invalid)
    def invalid(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(sqlite3.IntegrityError)
    def conflict(exc):
        return jsonify(error='记录已变化或设备已有任务，请刷新重试'), 409

    @app.errorhandler(413)
    def too_large(exc):
        return jsonify(error='请求太大；Windows 安装文件应放在只读 SMB 安装源，不通过网页上传 ISO'), 413

    @app.before_request
    def remote_api_requires_https():
        if request.content_length is not None and request.content_length > 256 * 1024:
            return too_large(None)
        if (request.path.startswith(PREFIX + '/api/') and not host_app.testing and not http_allowed() and not secure_request()
                and request.remote_addr not in ('127.0.0.1', '::1')):
            return jsonify(error='远程管理和客户端接口必须使用 HTTPS'), 403

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/')
    @admin
    def index():
        return send_from_directory(ROOT / 'static', 'index.html')

    @app.get('/healthz')
    def health():
        return jsonify(status='ok')

    @app.get('/api/session')
    @admin
    def session_info():
        session.setdefault('pc_deploy_csrf', secrets.token_urlsafe(32))
        session.setdefault('pc_deploy_session_id', secrets.token_urlsafe(24))
        return jsonify(authenticated=True, username=g.pc_deploy_operator,
                       csrf=session['pc_deploy_csrf'], test_mode=host_app.testing)

    def job_timings(c, identities):
        if not identities:
            return {}
        placeholders = ','.join('?' for _ in identities)
        return {r['job_id']: dict(r) for r in c.execute(f"""
            SELECT job_id,
                   MIN(CASE WHEN kind='installing' THEN created END) AS started_at,
                   MIN(CASE WHEN kind IN ('completed','failed','cancelled') THEN created END) AS finished_at
            FROM events WHERE job_id IN ({placeholders}) GROUP BY job_id
        """, identities)}

    def public_job(row, now, timing):
        data = json.loads(row['data'])
        timing = timing or {}
        return dict(id=row['id'], device_id=row['device_id'], serial=data['target']['serial'],
                    model=data['target']['model'], disk=data['target']['disk'], profile=data['profile']['name'],
                    state=row['state'], state_name=STATES[row['state']], created=row['created'],
                    updated=row['updated'], stale=row['state'] in ACTIVE and now-row['updated'] > 600,
                    progress=data.get('progress'), kind=data['source'].get('kind', 'setup'),
                    started_at=timing.get('started_at'),
                    finished_at=None if row['state'] in ACTIVE else timing.get('finished_at') or row['updated'])

    @app.get('/api/dashboard')
    @admin
    def dashboard():
        now = time.time()
        with store.connect() as c:
            devices = []
            for row in c.execute('SELECT * FROM devices ORDER BY last_seen DESC LIMIT 500'):
                item = json.loads(row['data'])
                item.update(id=row['id'], last_seen=row['last_seen'], online=now-row['last_seen'] < 45,
                            boot_code=row['boot_code'], consumed=bool(row['consumed']))
                devices.append(item)
            sources = [dict(json.loads(r['data']), has_password=True) for r in c.execute('SELECT data FROM sources')]
            profiles = [dict(json.loads(r['data']), has_password=True) for r in c.execute('SELECT data FROM profiles')]
            job_rows = list(c.execute('SELECT * FROM jobs ORDER BY created DESC LIMIT 200'))
            timings = job_timings(c, [r['id'] for r in job_rows])
            jobs = [public_job(r, now, timings.get(r['id'])) for r in job_rows]
            settings = {k: store.setting(c, k) for k in ('public_url', 'enabled', 'concurrency', 'ca_pem')}
            settings['enrollment_days'] = store.setting(c, 'enrollment_days', 7)
            media = media_dashboard(c)
            enrollments = [dict(id=r['token_hash'], expires_at=None if r['expires'] == -1 else r['expires'], uses=r['uses'])
                           for r in c.execute('SELECT * FROM enrollments ORDER BY expires DESC')]
            logs = [dict(r) for r in c.execute(
                'SELECT id,job_id,kind,message,created FROM events WHERE job_id IS NULL ORDER BY id DESC LIMIT 100')]
        boot = store.root / 'boot'
        files = {n: (boot / n).is_file() for n in ('wimboot', 'boot.wim', 'BCD', 'boot.sdi')}
        return jsonify(devices=devices, sources=sources, profiles=profiles, jobs=jobs, settings=settings,
                       events=logs, boot_files=files, server_time=now, enrollments=enrollments, media=media)

    @app.get('/api/jobs/<identity>/events')
    @admin
    def job_events(identity):
        before = request.args.get('before')
        if before is not None:
            if not re.fullmatch(r'[1-9][0-9]{0,18}', before) or int(before) > 9223372036854775807:
                raise Invalid('日志分页位置无效')
            before = int(before)
        with store.connect() as c:
            row, _ = load(c, 'jobs', identity)
            # Collapse old heartbeats within this job before paging, without deleting audit rows.
            logs = [dict(r) for r in c.execute("""
                WITH ordered AS (
                    SELECT *, LAG(kind) OVER (ORDER BY id DESC) AS newer_kind,
                           LAG(message) OVER (ORDER BY id DESC) AS newer_message
                    FROM events WHERE job_id=?
                )
                SELECT id,job_id,kind,message,created FROM ordered
                WHERE NOT (kind='installing' AND message IN (?,?)
                           AND newer_kind IS kind AND newer_message IS message)
                  AND (? IS NULL OR id<?)
                ORDER BY id DESC LIMIT 101
            """, (identity, '正在还原封装 WIM', '正在配置系统引导与安装后回报', before, before))]
            now = time.time()
            job = public_job(row, now, job_timings(c, [identity]).get(identity))
        return jsonify(job=job, events=logs[:100], next_before=logs[99]['id'] if len(logs) > 100 else None,
                       server_time=now)

    @app.post('/api/sources')
    @app.put('/api/sources/<identity>')
    @admin
    def save_source(identity=None):
        data = body()
        value = source_record(data)
        with store.connect(write=True) as c:
            old = load(c, 'sources', identity)[0] if identity else None
            if old and json.loads(old['data']).get('kind', 'setup') != value['kind']:
                referenced = any(json.loads(r['data'])['source_id'] == identity
                                 for r in c.execute('SELECT data FROM profiles'))
                if referenced:
                    raise Invalid('该安装源已有装机方案，不能切换安装方式；请另建安装源以保留原有流程')
            password = data.get('password', '')
            if password:
                if not isinstance(password, str) or not 1 <= len(password) <= 128 or '\x00' in password:
                    raise Invalid('安装源密码无效')
                secret = store.encrypt(password)
            elif old:
                secret = old['secret']
            else:
                raise Invalid('需要安装源专用只读账号的密码，不能使用域管理员账号')
            identity = identity or str(uuid.uuid4())
            value.update(id=identity, revision=secrets.token_hex(12))
            c.execute('INSERT INTO sources VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,secret=excluded.secret',
                      (identity, canonical(value), secret))
            event(c, 'source', '已保存安装源：' + value['name'])
        return jsonify(ok=True, id=identity)

    @app.post('/api/profiles')
    @app.put('/api/profiles/<identity>')
    @admin
    def save_profile(identity=None):
        data = body()
        with store.connect(write=True) as c:
            _, source = load(c, 'sources', data.get('source_id'))
            value = profile_record(data, source)
            old = load(c, 'profiles', identity)[0] if identity else None
            old_secret = store.decrypt(old['secret']) if old else {}
            if isinstance(old_secret, str):
                old_secret = dict(password=old_secret)
            password = data.get('password', '')
            if source.get('kind') == 'wim':
                saved_password = ''
            elif password:
                if not isinstance(password, str) or not 12 <= len(password) <= 64 or any(ord(ch) < 32 for ch in password):
                    raise Invalid('临时本地管理员密码需要 12–64 个字符')
                saved_password = password
            elif old and isinstance(old_secret.get('password'), str) and 12 <= len(old_secret['password']) <= 64:
                saved_password = old_secret['password']
            else:
                raise Invalid('请设置装机后的临时本地管理员密码')
            if source.get('kind') == 'wim' and (data.get('password') or data.get('product_key')):
                raise Invalid('封装 WIM 沿用镜像内账号与授权配置，不填写原版安装账号或密钥')
            product_key = data.get('product_key') or old_secret.get('product_key', '')
            if source.get('kind') == 'wim':
                product_key = ''
            if data.get('clear_product_key') is True:
                product_key = ''
            if not isinstance(product_key, str) or (product_key and not re.fullmatch(r'(?:[A-Za-z0-9]{5}-){4}[A-Za-z0-9]{5}', product_key)):
                raise Invalid('安装密钥格式无效，请使用与你的版本匹配的合法密钥')
            secret = store.encrypt(dict(password=saved_password, product_key=product_key.upper()))
            value['has_product_key'] = bool(product_key)
            identity = identity or str(uuid.uuid4())
            value.update(id=identity, revision=secrets.token_hex(12))
            c.execute('INSERT INTO profiles VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,secret=excluded.secret',
                      (identity, canonical(value), secret))
            event(c, 'profile', '已保存装机方案：' + value['name'])
        return jsonify(ok=True, id=identity)

    @app.post('/api/settings')
    @admin
    def save_settings():
        data = body()
        url = public_url(data.get('public_url'))
        if urlsplit(url).scheme == 'http' and not http_allowed():
            raise Invalid('当前配置只允许 HTTPS 地址')
        parallel = integer(data.get('concurrency'), '并发数量', 1, 16)
        pem = data.get('ca_pem', '')
        if not isinstance(pem, str) or len(pem) > 4096 or 'PRIVATE KEY' in pem.upper():
            raise Invalid('这里只能填写一张公开的 CA PEM 证书，不能包含私钥')
        if pem:
            try:
                if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', pem):
                    raise ValueError()
                cert = x509.load_pem_x509_certificate(pem.encode('ascii'))
                if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError()
            except (ValueError, x509.ExtensionNotFound, UnicodeEncodeError) as exc:
                raise Invalid('CA 证书无效，请使用 Base-64 X.509 格式的根 CA 公共证书') from exc
        enabled = data.get('enabled') is True
        if enabled and data.get('confirmation') != 'ENABLE':
            raise Invalid('开启真实下发必须输入 ENABLE 确认')
        with store.connect(write=True) as c:
            if (url != store.setting(c, 'public_url') or pem != store.setting(c, 'ca_pem', '')) and c.execute(
                    'SELECT id FROM jobs WHERE state IN (?,?,?,?) LIMIT 1', ACTIVE).fetchone():
                raise Invalid('存在未结束安装任务，不能更换平台地址或 CA 证书')
            if enabled and not store.setting(c, 'enabled', False) and not data.get('isolated_network_confirmed'):
                raise Invalid('请确认部署网络已隔离，并确认安装源账号只有读取权限')
            for key, value in dict(public_url=url, concurrency=parallel, ca_pem=pem, enabled=enabled).items():
                store.put(c, key, value)
            event(c, 'security', '真实下发已开启' if enabled else '真实下发已关闭；已启动的安装不会被强行中断')
        return jsonify(ok=True)

    @app.post('/api/jobs/preview')
    @admin
    def preview():
        data = body()
        targets = data.get('targets')
        if not isinstance(targets, list) or not 1 <= len(targets) <= 25 or not all(isinstance(t, dict) for t in targets):
            raise Invalid('每批选择 1–25 台设备，并分别确认目标硬盘')
        if len({t.get('device_id') for t in targets}) != len(targets):
            raise Invalid('设备重复')
        with store.connect(write=True) as c:
            _, profile = load(c, 'profiles', data.get('profile_id'))
            _, source = load(c, 'sources', profile['source_id'])
            chosen = [snapshot_target(c, t, profile, source) for t in targets]
            value = dict(profile_id=profile['id'], profile_revision=profile['revision'],
                         source_revision=source['revision'], targets=chosen)
            identity = str(uuid.uuid4())
            c.execute('DELETE FROM previews WHERE expires < ?', (time.time()-3600,))
            c.execute('INSERT INTO previews VALUES(?,?,?,?,0)',
                      (identity, canonical(value), time.time()+180, session['pc_deploy_session_id']))
        return jsonify(id=identity, profile=profile['name'], source=source['name'], targets=chosen,
                       expires_in=180, warning=(
                           '只格式化明确选中的 Windows 分区，其数据将丢失；保留其他分区，更新同盘 EFI 引导文件。'
                           if profile.get('disk_mode') == 'system_partition' else
                           '仅清空所选物理硬盘上的全部分区，不是隐私安全擦除；其他硬盘不处理。'))

    @app.post('/api/jobs/commit')
    @admin
    def commit():
        data = body()
        if data.get('confirmation') != 'YES' or data.get('physical_confirmed') is not True:
            raise Invalid('请核对整机序列号、客户端校验码和硬盘，并输入 YES 确认')
        with store.connect(write=True) as c:
            if not store.setting(c, 'enabled', False):
                raise Invalid('真实下发尚未开启，请先完成隔离测试和启动配置')
            row = c.execute('SELECT * FROM previews WHERE id=?', (data.get('preview_id'),)).fetchone()
            if not row or row['used'] or row['expires'] < time.time() or row['session_id'] != session['pc_deploy_session_id']:
                raise Invalid('预览已失效，请重新预览，不能重复提交')
            pv = json.loads(row['data'])
            pr, profile = load(c, 'profiles', pv['profile_id'])
            sr, source = load(c, 'sources', profile['source_id'])
            if profile['revision'] != pv['profile_revision'] or source['revision'] != pv['source_revision']:
                raise Invalid('方案或安装源已变化，请重新预览')
            targets = []
            for before in pv['targets']:
                current = snapshot_target(c, before, profile, source)
                if current != before:
                    raise Invalid('硬件或启动会话已变化，请重新预览')
                targets.append(current)
            ids = []
            for target in targets:
                identity = str(uuid.uuid4())
                payload = dict(target=target, source=source, profile=profile)
                profile_secret = store.decrypt(pr['secret'])
                if isinstance(profile_secret, str):
                    profile_secret = dict(password=profile_secret)
                secret = dict(source_password=store.decrypt(sr['secret']),
                              local_password=profile_secret['password'], product_key=profile_secret.get('product_key', ''),
                              finish_token=secrets.token_urlsafe(40))
                now = time.time()
                c.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)',
                          (identity, target['device_id'], target['boot_id'], 'queued', canonical(payload),
                           store.encrypt(secret), now, now, now+72*3600))
                event(c, 'queued', '已确认整机 ' + target['serial'] + '，仅处理所选硬盘', identity)
                ids.append(identity)
            c.execute('UPDATE previews SET used=1 WHERE id=?', (row['id'],))
        return jsonify(ok=True, ids=ids)

    @app.post('/api/jobs/<identity>/cancel')
    @admin
    def cancel(identity):
        with store.connect(write=True) as c:
            row, _ = load(c, 'jobs', identity)
            if row['state'] not in ('queued', 'preflight'):
                raise Invalid('安装已启动或任务已结束，不能远程强停；请现场核对')
            c.execute('UPDATE jobs SET state=?,updated=? WHERE id=?', ('cancelled', time.time(), identity))
            event(c, 'cancelled', '管理员取消；尚未授权启动 Windows Setup', identity)
        return jsonify(ok=True)

    @app.post('/api/jobs/<identity>/reconcile')
    @admin
    def reconcile(identity):
        if body().get('confirmation') != 'CHECKED':
            raise Invalid('必须现场确认电脑状态后输入 CHECKED；不会重试或重新清盘')
        with store.connect(write=True) as c:
            row, _ = load(c, 'jobs', identity)
            if row['state'] not in ACTIVE:
                raise Invalid('任务已经结束')
            c.execute('UPDATE jobs SET state=?,updated=? WHERE id=?', ('failed', time.time(), identity))
            event(c, 'failed', '管理员现场核对后结束记录；未向电脑发送停止或重试命令', identity)
        return jsonify(ok=True)

    def validity_days(value):
        if value is None:
            return None
        return integer(value, '有效天数', 1, 3650)

    def create_config(c, issue=True):
        url = store.setting(c, 'public_url')
        if urlsplit(url).scheme == 'http' and not http_allowed():
            raise Invalid('当前配置只允许 HTTPS 地址')
        public_url(url)
        hostname = urlsplit(url).hostname
        try:
            loopback = ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == 'localhost'
        if loopback:
            raise Invalid('先填写目标电脑可访问的平台地址，不能使用本机回环地址')
        cfg = dict(server_url=url, allow_http=http_allowed() and urlsplit(url).scheme == 'http',
                   ca_pem=store.setting(c, 'ca_pem', ''))
        if issue:
            days = validity_days(store.setting(c, 'enrollment_days', 7))
            now = time.time()
            expires = now + days * 86400 if days is not None else -1
            token = secrets.token_urlsafe(40)
            c.execute('INSERT INTO enrollments VALUES(?,?,0)', (token_hash(token), expires))
            cfg.update(enrollment_token=token, expires_at=None if expires == -1 else expires)
            event(c, 'bootstrap', '已生成' + ('永不过期' if days is None else str(days)+' 天有效期') +
                  '的客户端登记包；不含管理员或安装源密码')
        return cfg

    def bootstrap_zip(cfg):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('config.json', json.dumps(cfg, indent=2))
            for name in ('Deploy-Agent.ps1', 'Start.ps1'):
                z.write(ROOT / 'agent' / name, name)
            z.write(ROOT / 'scripts' / 'Build-WinPE.ps1', 'Build-WinPE.ps1')
        buf.seek(0)
        return buf

    @app.post('/api/enrollment-policy')
    @admin
    def enrollment_policy():
        data = body()
        if 'days' not in data:
            raise Invalid('请选择有效天数或永不过期')
        days = validity_days(data['days'])
        with store.connect(write=True) as c:
            store.put(c, 'enrollment_days', days)
            event(c, 'bootstrap', '新登记包有效期已设为：' + ('永不过期' if days is None else str(days)+' 天'))
        return jsonify(ok=True)

    @app.post('/api/enrollments/<identity>/validity')
    @admin
    def enrollment_validity(identity):
        data = body()
        if 'days' not in data or not re.fullmatch(r'[0-9a-f]{64}', identity):
            raise Invalid('请选择登记包和有效期')
        days = validity_days(data['days'])
        expires = time.time() + days * 86400 if days is not None else -1
        with store.connect(write=True) as c:
            row = c.execute('SELECT * FROM enrollments WHERE token_hash=?', (identity,)).fetchone()
            if not row or row['uses'] >= 500:
                raise Invalid('登记包已撤销或达到登记上限，请重新下载')
            c.execute('UPDATE enrollments SET expires=? WHERE token_hash=?', (expires, identity))
            event(c, 'bootstrap', '登记包 '+identity[:12]+' 有效期已修改为：' +
                  ('永不过期' if days is None else str(days)+' 天；现有 ISO 可继续使用'))
        return jsonify(ok=True, expires_at=None if expires == -1 else expires)

    @app.post('/api/enrollments/<identity>/revoke')
    @admin
    def revoke_enrollment(identity):
        if not re.fullmatch(r'[0-9a-f]{64}', identity):
            raise Invalid('登记包编号无效')
        with store.connect(write=True) as c:
            c.execute('DELETE FROM enrollments WHERE token_hash=?', (identity,))
            event(c, 'bootstrap', '登记包 '+identity[:12]+' 已撤销，不能再用于 PE 报到')
        return jsonify(ok=True)

    @app.post('/api/bootstrap')
    @admin
    def bootstrap():
        with store.connect(write=True) as c:
            cfg = create_config(c)
        return send_file(bootstrap_zip(cfg), mimetype='application/zip',
                         as_attachment=True, download_name='pc-deploy-bootstrap.zip')

    @app.post('/api/enrollments/<identity>/extend')
    @admin
    def extend_enrollment(identity):
        if not re.fullmatch(r'[0-9a-f]{64}', identity):
            raise Invalid('登记包编号无效')
        now = time.time()
        with store.connect(write=True) as c:
            row = c.execute('SELECT * FROM enrollments WHERE token_hash=?', (identity,)).fetchone()
            if not row or (row['expires'] != -1 and row['expires'] <= now) or row['uses'] >= 500:
                raise Invalid('登记包已过期、被撤销或达到登记上限，请重新下载')
            expires = max(row['expires'], now + ENROLLMENT_TTL) if row['expires'] != -1 else -1
            c.execute('UPDATE enrollments SET expires=? WHERE token_hash=?', (expires, identity))
            event(c, 'bootstrap', '登记包 ' + identity[:12] + ' 已续期至至少 7 天后；现有 ISO 可继续使用')
        return jsonify(ok=True, expires_at=None if expires == -1 else expires)

    @app.post('/api/devices/<identity>/rearm')
    @admin
    def rearm(identity):
        if body().get('confirmation') != 'CHECKED':
            raise Invalid('请现场核对设备后输入 CHECKED；此操作只放行重新登记，不下发清盘')
        with store.connect(write=True) as c:
            row = c.execute('SELECT id FROM devices WHERE id=?', (identity,)).fetchone()
            if not row:
                raise Invalid('设备不存在')
            if c.execute('SELECT id FROM jobs WHERE device_id=? AND state IN (?,?,?,?)', (identity, *ACTIVE)).fetchone():
                raise Invalid('设备存在未结束任务，先现场核对任务状态')
            revoked = secrets.token_urlsafe(40)
            c.execute('UPDATE devices SET consumed=0,last_seen=0,boot_id=?,token_hash=?,token_secret=? WHERE id=?',
                      (str(uuid.uuid4()), token_hash(revoked), store.encrypt(revoked), identity))
            event(c, 'security', '已放行重新进入 WinPE 登记；旧会话已撤销，仍需重新选盘确认')
        return jsonify(ok=True)

    @app.get('/api/tools/inspect-source')
    @admin
    def inspect_tool():
        return send_file(ROOT / 'scripts' / 'Inspect-InstallSource.ps1', as_attachment=True)

    @app.post('/api/agent/register')
    def register():
        tls_required()
        if limited('enroll:' + (request.remote_addr or ''), 30):
            return jsonify(error='登记过于频繁'), 429
        inv = inventory(body())
        with store.connect(write=True) as c:
            join = c.execute('SELECT * FROM enrollments WHERE token_hash=?', (token_hash(bearer()),)).fetchone()
            if not join or (join['expires'] != -1 and join['expires'] < time.time()) or join['uses'] >= 500:
                raise Invalid('登记包已过期或被撤销，请在平台重新下载')
            old = c.execute('SELECT * FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()
            if old and old['boot_id'] == inv['boot_id']:
                if old['inventory_hash'] != digest(inv):
                    raise Invalid('登记重试的硬件信息不一致')
                return jsonify(device_id=old['id'], token=store.decrypt(old['token_secret']), boot_code=old['boot_code'])
            if c.execute('SELECT id FROM jobs WHERE device_id=? AND state IN (?,?,?,?)', (inv['hardware_uuid'], *ACTIVE)).fetchone():
                raise Invalid('该电脑有未结束任务，请先在平台现场核对，禁止自动接续清盘')
            token = secrets.token_urlsafe(40)
            code = secrets.token_hex(3).upper()
            c.execute('INSERT INTO devices(id,boot_id,data,inventory_hash,token_hash,token_secret,boot_code,last_seen,consumed) '
                      'VALUES(?,?,?,?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET '
                      'boot_id=excluded.boot_id,data=excluded.data,inventory_hash=excluded.inventory_hash,'
                      'token_hash=excluded.token_hash,token_secret=excluded.token_secret,boot_code=excluded.boot_code,'
                      'last_seen=excluded.last_seen,consumed=0',
                      (inv['hardware_uuid'], inv['boot_id'], canonical(inv), digest(inv), token_hash(token),
                       store.encrypt(token), code, time.time()))
            c.execute('UPDATE enrollments SET uses=uses+1 WHERE token_hash=?', (join['token_hash'],))
            event(c, 'device', '设备已登记，等待人工选盘：' + inv['serial'])
        return jsonify(device_id=inv['hardware_uuid'], token=token, boot_code=code)

    @app.post('/api/agent/poll')
    def poll():
        payload = body()
        inv = inventory(payload)
        with store.connect(write=True) as c:
            dev = agent(c)
            if inv['hardware_uuid'] != dev['id'] or inv['boot_id'] != dev['boot_id']:
                raise Invalid('设备身份不匹配')
            c.execute('UPDATE devices SET data=?,inventory_hash=?,last_seen=? WHERE id=?',
                      (canonical(inv), digest(inv), time.time(), dev['id']))
            if payload.get('registration_only') is True:
                return jsonify(job=None, registration_only=True)
            row = c.execute('SELECT * FROM jobs WHERE device_id=? AND state IN (?,?,?,?)', (dev['id'], *ACTIVE)).fetchone()
            if not row or not store.setting(c, 'enabled', False):
                return jsonify(job=None)
            data = json.loads(row['data'])
            if row['boot_id'] != dev['boot_id'] or digest(inv) != data['target']['inventory_hash']:
                raise Invalid('设备硬件已变化，请取消旧任务并重新预览')
            if row['state'] not in ('queued', 'preflight') or dev['consumed']:
                return jsonify(job=None)
            if row['expires'] < time.time() or (row['state'] == 'queued' and time.time()-row['created'] > 900):
                raise Invalid('任务已过领取期限，请人工取消后重新确认')
            if row['state'] == 'queued':
                running = c.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('preflight','installing','awaiting_report')").fetchone()[0]
                if running >= store.setting(c, 'concurrency', 2):
                    return jsonify(job=None)
                c.execute('UPDATE jobs SET state=?,updated=? WHERE id=?', ('preflight', time.time(), row['id']))
                event(c, 'preflight', '客户端已领取，正在验证安装源；尚未启动清盘', row['id'])
            secret = store.decrypt(row['secret'])
            return jsonify(job=dict(id=row['id'], target=data['target'], source=data['source'],
                                    profile=data['profile'], source_password=secret['source_password']))

    @app.post('/api/agent/jobs/<identity>/start')
    def start(identity):
        inv = inventory(body())
        with store.connect(write=True) as c:
            dev = agent(c)
            row, data = agent_job(c, dev, identity, ('preflight',))
            if not store.setting(c, 'enabled', False) or dev['consumed']:
                raise Invalid('真实下发已关闭或该启动会话已执行过安装')
            if digest(inv) != data['target']['inventory_hash']:
                raise Invalid('启动安装前硬件复核不一致')
            secret = store.decrypt(row['secret'])
            finalizer = dict(server_url=store.setting(c, 'public_url'), job_id=identity,
                             allow_http=http_allowed() and urlsplit(store.setting(c, 'public_url')).scheme == 'http',
                             hardware_uuid=dev['id'], token=secret['finish_token'],
                             ca_pem=store.setting(c, 'ca_pem', ''))
            if data['source'].get('kind') == 'wim':
                if inv.get('wim_apply_v1') is not True:
                    raise Invalid('客户端不支持封装 WIM 还原')
                target_check(inv, data['target']['disk_key'], data['profile'])
                if data['profile'].get('disk_mode') == 'system_partition':
                    current_parts = partition_target(data['target']['disk'], data['target']['partition_key'])
                    if current_parts != data['target']['partitions']:
                        raise Invalid('分区与已确认目标不一致')
                authorization = dict(kind='wim', finalizer_command=finalizer_command(finalizer))
            else:
                xml = answer_file(inv, data['target']['disk'], data['profile'], data['source'],
                                  secret['local_password'], finalizer, secret.get('product_key'))
                authorization = dict(answer_xml=xml)
            c.execute('UPDATE jobs SET state=?,updated=? WHERE id=?', ('installing', time.time(), identity))
            c.execute('UPDATE devices SET consumed=1,last_seen=? WHERE id=?', (time.time(), dev['id']))
            event(c, 'installing', '最终硬件复核通过，已授权启动' +
                  (' WIM 还原' if data['source'].get('kind') == 'wim' else ' Windows Setup') +
                  '；之后不可远程取消', identity)
        return jsonify(authorization)

    @app.post('/api/agent/jobs/<identity>/event')
    def report(identity):
        value = body()
        with store.connect(write=True) as c:
            dev = agent(c)
            row, job_data = agent_job(c, dev, identity, ('preflight', 'installing', 'awaiting_report'))
            emit_event, track_progress = True, False
            if value.get('code') in ERRORS:
                state, message = 'failed', ERRORS[value['code']]
                detail = value.get('detail')
                if isinstance(detail, str):
                    detail = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '',
                                    detail.replace('\r\n', '\n').replace('\r', '\n')).strip()
                if isinstance(detail, str) and detail:
                    # Do not trust client-side redaction; also hide this job's stored credentials.
                    sensitive = [bearer(), *store.decrypt(row['secret']).values()]
                    for secret in sorted((s for s in sensitive if isinstance(s, str) and s), key=len, reverse=True):
                        detail = detail.replace(secret, '[REDACTED]')
                    message += '\n客户端错误详情：\n' + detail[:8192]
                else:
                    message += '\n客户端未上报有效错误详情；当前日志仅包含错误分类。'
            elif value.get('stage') == 'verifying' and row['state'] == 'preflight':
                state, message = 'preflight', '正在核对安装源 SHA-256，尚未启动安装'
                emit_event = False
            elif (value.get('stage') in ('applying', 'boot_files') and row['state'] == 'installing'
                  and job_data['source'].get('kind') == 'wim'):
                state = 'installing'
                track_progress = True
                message = '正在还原封装 WIM' if value['stage'] == 'applying' else '正在配置系统引导与安装后回报'
            elif value.get('stage') == 'awaiting_report' and row['state'] in ('installing', 'awaiting_report'):
                track_progress = True
                state, message = 'awaiting_report', (
                    'WIM 已还原并配置引导，等待新系统回报；非封装 OOBE 镜像需首次管理员登录'
                    if job_data['source'].get('kind') == 'wim' else 'Windows Setup 已返回，等待安装后系统回报')
            else:
                raise Invalid('不允许的任务状态变更')
            now = time.time()
            if track_progress:
                stage = value['stage']
                previous = job_data.get('progress') or {}
                order = {'applying': 0, 'boot_files': 1, 'awaiting_report': 2}
                if order.get(previous.get('stage'), -1) > order[stage]:
                    raise Invalid('任务阶段不能倒退')
                percent = value.get('percent')
                if percent is not None and (stage != 'applying' or type(percent) is not int or not 0 <= percent <= 100):
                    raise Invalid('WIM 还原进度必须是 0 到 100 的整数')
                old_percent = previous.get('percent') if previous.get('stage') == stage else None
                if old_percent is not None:
                    percent = old_percent if percent is None else max(old_percent, percent)
                emit_event = previous.get('stage') != stage or row['state'] != state
                job_data['progress'] = dict(stage=stage, percent=percent, updated=now)
            c.execute('UPDATE jobs SET state=?,data=?,updated=? WHERE id=?', (state, canonical(job_data), now, identity))
            c.execute('UPDATE devices SET last_seen=? WHERE id=?', (now, dev['id']))
            if emit_event:
                event(c, state, message, identity)
        return jsonify(ok=True)

    @app.post('/api/agent/jobs/<identity>/finish')
    def finish(identity):
        tls_required()
        value = body()
        with store.connect(write=True) as c:
            row, data = load(c, 'jobs', identity)
            token = store.decrypt(row['secret'])['finish_token']
            if not hmac.compare_digest(bearer(), token) or row['expires'] < time.time():
                raise Invalid('安装回报凭据失效')
            if row['state'] == 'completed':
                return jsonify(ok=True)
            if row['state'] not in ('installing', 'awaiting_report'):
                raise Invalid('任务状态不允许报告完成')
            build = integer(value.get('os_build'), '系统版本', 19041, 99999)
            expected = data['profile']['computer_prefix'] + '-' + digest(data['target']['inventory']['hardware_uuid'])[:8].upper()
            preserved_name = data['source'].get('kind') == 'wim'
            if (value.get('hardware_uuid') != row['device_id']
                    or (not preserved_name and value.get('computer_name') != expected)
                    or (preserved_name and (not isinstance(value.get('computer_name'), str)
                                            or not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', value['computer_name'])))
                    or value.get('image_state') != 'IMAGE_STATE_COMPLETE' or value.get('oobe_done') is not True
                    or (data['source']['family'] == 'windows11') != (build >= 22000)
                    or (preserved_name and build != next(i['build'] for i in data['source']['images']
                                                        if i['index'] == data['profile']['image_index']))):
                raise Invalid('安装后系统、设备身份或 OOBE 状态未通过核对')
            c.execute('UPDATE jobs SET state=?,updated=? WHERE id=?', ('completed', time.time(), identity))
            event(c, 'completed', '安装后客户端报告 OOBE 已结束，系统版本与设备身份匹配；不等于驱动/业务验收', identity)
        return jsonify(ok=True)

    @app.get('/boot.ipxe')
    def boot_script():
        with store.connect() as c:
            url = store.setting(c, 'public_url')
            identity = request.args.get('uuid')
            if not identity:
                script = f'#!ipxe\nisset ${{uuid}} || goto failed\nchain {url}/boot.ipxe?uuid=${{uuid}} || goto failed\nexit\n:failed\necho A valid SMBIOS UUID is required. No deployment was started.\nexit\n'
                return Response(script, mimetype='text/plain')
            try:
                identity = str(uuid.UUID(identity))
                if uuid.UUID(identity).int in (0, (1 << 128)-1):
                    raise ValueError()
            except ValueError:
                return Response('#!ipxe\necho Invalid hardware UUID. No deployment was started.\nexit\n', mimetype='text/plain')
            dev = c.execute('SELECT consumed FROM devices WHERE id=?', (identity,)).fetchone()
            active = c.execute('SELECT id FROM jobs WHERE device_id=? AND state IN (?,?,?,?)', (identity, *ACTIVE)).fetchone()
            if (dev and dev['consumed']) or active:
                return Response('#!ipxe\necho Deployment already authorized. Returning to local boot.\nexit\n', mimetype='text/plain')
        script = f'#!ipxe\nset base {url}\nkernel ${{base}}/boot/wimboot || goto failed\ninitrd ${{base}}/boot/boot.wim boot.wim || goto failed\nboot || goto failed\n:failed\necho Network boot failed - no disk action was performed\nshell\n'
        return Response(script, mimetype='text/plain')

    @app.get('/boot/<name>')
    def boot_file(name):
        if name not in ('wimboot', 'boot.wim', 'BCD', 'boot.sdi'):
            return jsonify(error='文件不存在'), 404
        root = (store.root / 'boot').resolve()
        path = (root / name).resolve()
        if path.parent != root or not path.is_file():
            return jsonify(error='启动文件尚未准备；请先使用 ADK 构建 WinPE'), 404
        return send_file(path, conditional=True)

    register_media_routes(app, store, admin, body, tls_required, bearer, event, create_config, bootstrap_zip)
    host_app.register_blueprint(app)
    return app
