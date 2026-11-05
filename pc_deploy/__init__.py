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
                        integer, inventory, device_report, profile_record, public_url, source_record,
                        target_check, text, partition_target, finalizer_command)
from .storage import Store
from .domain_join import available_name, computer_name, employee_id, join_record
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

    def domain_transport_required(c, joining):
        if secure_request() and urlsplit(store.setting(c, 'public_url')).scheme == 'https':
            return
        if http_allowed() and joining.get('allow_http') is True:
            return
        raise Invalid('自动加域需要 HTTPS；隔离内网可在装机方案中明确允许 HTTP 加域')

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

    def reserved_computer_names(c, domain, exclude=None):
        names = set()
        for row in c.execute('SELECT id,data FROM jobs WHERE state IN (?,?,?,?)', ACTIVE):
            other = json.loads(row['data'])
            if row['id'] != exclude and other.get('domain_join', {}).get('domain') == domain:
                names.add(other['target']['computer_name'])
        return names

    def target_without_telemetry(target):
        return dict(target, inventory={k: v for k, v in target['inventory'].items() if k != 'system_info'})

    def snapshot_target(c, target, profile, source, reserved_names=None):
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
        if profile.get('domain_join'):
            domain_transport_required(c, profile['domain_join'])
            employee = employee_id(target.get('employee_id'))
            reserved = reserved_computer_names(c, profile['domain_join']['domain']) | set(reserved_names or ())
            name = available_name(employee, reserved)
            result.update(employee_id=employee, computer_name=name)
            if reserved_names is not None:
                reserved_names.add(name)
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
                   MIN(CASE WHEN kind='installing' AND message='正在配置系统引导与安装后回报' THEN created END) AS image_applied_at,
                   MIN(CASE WHEN kind='awaiting_report' THEN created END) AS deployment_finished_at,
                   MIN(CASE WHEN kind IN ('domain_join','completed') OR
                       (kind='failed' AND message LIKE 'Windows 已安装，自动加域失败%') THEN created END) AS windows_reported_at,
                   MIN(CASE WHEN kind IN ('completed','failed','cancelled') THEN created END) AS finished_at
            FROM events WHERE job_id IN ({placeholders}) GROUP BY job_id
        """, identities)}

    def completion_display(job, value):
        incoming = value.get('device_info')
        if not isinstance(incoming, dict):
            return False
        fields = ('model', 'manufacturer', 'system_family', 'product_name', 'product_version', 'oem_model')
        clean = {}
        for key in fields:
            raw = incoming.get(key)
            if isinstance(raw, str):
                item = re.sub(r'[\x00-\x1f\x7f]', ' ', raw).strip()[:160]
                if item:
                    clean[key] = item
        before = canonical([job.get('display_info', {}), job.get('system_info', {})])
        job.setdefault('display_info', {}).update(clean)
        report = device_report(incoming.get('system_info'), 'windows')
        if report:
            report['reported_at'] = time.time()
            job['system_info'] = report
        return before != canonical([job['display_info'], job.get('system_info', {})])

    def public_job(row, now, timing):
        data = json.loads(row['data'])
        timing = timing or {}
        display = dict(data['target']['inventory'], **data.get('display_info', {}))
        detail = {key: display[key] for key in ('hardware_uuid', 'ram_bytes', 'firmware', 'architecture',
                  'secure_boot', 'tpm2', 'macs') if key in display}
        detail['disks'] = [dict({key: disk[key] for key in ('number', 'model', 'serial', 'unique_id',
                          'bus', 'size_bytes') if key in disk},
                          partition_count=len(disk['partitions']) if 'partitions' in disk else None)
                          for disk in display.get('disks', [])]
        detail['system_info'] = data.get('system_info') or display.get('system_info', {})
        return dict(id=row['id'], device_id=row['device_id'], serial=data['target']['serial'],
                    model=display.get('model') or data['target']['model'], disk=data['target']['disk'], profile=data['profile']['name'],
                    state=row['state'], state_name=STATES[row['state']], created=row['created'],
                    updated=row['updated'], stale=row['state'] in ACTIVE and now-row['updated'] > 600,
                    progress=data.get('progress'), kind=data['source'].get('kind', 'setup'), review=data.get('review'),
                    domain_join=data.get('domain_join'), computer_name=data['target'].get('computer_name'),
                    installed_at=data.get('installed_at') or timing.get('windows_reported_at'),
                    image_applied_at=timing.get('image_applied_at'),
                    deployment_finished_at=timing.get('deployment_finished_at'),
                    expires_at=row['expires'], device_info=detail,
                    **{k: display.get(k, '') for k in
                       ('manufacturer', 'system_family', 'product_name', 'product_version', 'oem_model')},
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
            settings['http_allowed'] = http_allowed()
            settings['domain_defaults'] = dict(domain='.'.join(re.findall(r'(?:^|,)DC=([^,]+)', host_app.config.get('AD_BASE_DN', ''), re.I)),
                                               ou_path=host_app.config.get('AD_COMPUTER_OU', ''))
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
            joining = join_record(data.get('domain_join'))
            if joining:
                domain_transport_required(c, joining)
                value['domain_join'] = joining
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
            private = dict(password=saved_password, product_key=product_key.upper())
            if joining:
                join_password = data.get('domain_join_password', '')
                old_join = json.loads(old['data']).get('domain_join', {}) if old else {}
                if not join_password and all(old_join.get(k) == joining[k] for k in ('domain', 'username')):
                    join_password = old_secret.get('domain_join_password', '')
                if not isinstance(join_password, str) or not 1 <= len(join_password) <= 128 or any(ord(ch) < 32 for ch in join_password):
                    raise Invalid('请填写加域账号密码；更换域或账号后必须重新填写')
                private['domain_join_password'] = join_password
                value['has_domain_join_password'] = True
            secret = store.encrypt(private)
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
            reserved_names = set()
            chosen = [snapshot_target(c, t, profile, source, reserved_names) for t in targets]
            value = dict(profile_id=profile['id'], profile_revision=profile['revision'],
                         source_revision=source['revision'], targets=chosen)
            identity = str(uuid.uuid4())
            c.execute('DELETE FROM previews WHERE expires < ?', (time.time()-3600,))
            c.execute('INSERT INTO previews VALUES(?,?,?,?,0)',
                      (identity, canonical(value), time.time()+180, session['pc_deploy_session_id']))
        return jsonify(id=identity, profile=profile['name'], source=source['name'], targets=chosen,
                       domain_join=profile.get('domain_join'),
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
            reserved_names = set()
            for before in pv['targets']:
                current = snapshot_target(c, before, profile, source, reserved_names)
                if target_without_telemetry(current) != target_without_telemetry(before):
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
                if profile.get('domain_join'):
                    payload['domain_join'] = dict(state='pending', domain=profile['domain_join']['domain'],
                                                  computer_name=target['computer_name'])
                    if not profile_secret.get('domain_join_password'):
                        raise Invalid('加域方案凭据缺失，请重新保存方案')
                    secret['domain_join_password'] = profile_secret['domain_join_password']
                now = time.time()
                c.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)',
                          (identity, target['device_id'], target['boot_id'], 'queued', canonical(payload),
                           store.encrypt(secret), now, now, now+72*3600))
                event(c, 'queued', '已确认整机 ' + target['serial'] + '，仅处理所选硬盘' +
                      ('；本任务允许内网 HTTP 加域' if profile.get('domain_join', {}).get('allow_http') else ''), identity)
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

    @app.post('/api/jobs/<identity>/review')
    @admin
    def review_job(identity):
        value = body()
        if value.get('physical_confirmed') is not True or value.get('outcome') not in ('installed', 'not_installed'):
            raise Invalid('请现场核对电脑，并明确选择实际安装结果')
        note = value.get('note', '')
        if note:
            note = text(note, '核对备注', maximum=500)
        elif not isinstance(note, str):
            raise Invalid('核对备注必须是文字')
        with store.connect(write=True) as c:
            row, data = load(c, 'jobs', identity)
            if row['state'] != 'failed':
                raise Invalid('只有已失败的任务可以登记人工核对结果')
            previous = data.get('review') or {}
            operator = g.pc_deploy_operator
            if (previous.get('outcome'), previous.get('note'), previous.get('operator')) == (value['outcome'], note, operator):
                return jsonify(ok=True)
            data['review'] = dict(outcome=value['outcome'], note=note, operator=operator, reviewed_at=time.time())
            # Preserve the original failure and finish time; this is an operator observation.
            c.execute('UPDATE jobs SET data=? WHERE id=?', (canonical(data), identity))
            result = '已能进入 Windows' if value['outcome'] == 'installed' else '仍未安装完成'
            event(c, 'review', '人工核对：' + result + '；保留原任务失败记录' + ('。备注：' + note if note else ''), identity)
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
            for name in ('Deploy-Agent.ps1', 'Start.ps1', 'DeviceInfo.ps1'):
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
        payload = body()
        inv = inventory(payload)
        record = dict(inv)
        report = device_report(payload.get('system_info'), 'pe')
        if report:
            record['system_info'] = dict(report, reported_at=time.time())
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
                      (inv['hardware_uuid'], inv['boot_id'], canonical(record), digest(inv), token_hash(token),
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
            record = dict(inv)
            report = device_report(payload.get('system_info'), 'pe')
            if report:
                record['system_info'] = dict(report, reported_at=time.time())
            c.execute('UPDATE devices SET data=?,inventory_hash=?,last_seen=? WHERE id=?',
                      (canonical(record), digest(inv), time.time(), dev['id']))
            if payload.get('registration_only') is True:
                return jsonify(job=None, registration_only=True)
            row = c.execute('SELECT * FROM jobs WHERE device_id=? AND state IN (?,?,?,?)', (dev['id'], *ACTIVE)).fetchone()
            if not row or not store.setting(c, 'enabled', False):
                return jsonify(job=None)
            data = json.loads(row['data'])
            if data.get('domain_join'):
                domain_transport_required(c, data['profile']['domain_join'])
            if row['boot_id'] != dev['boot_id'] or digest(inv) != data['target']['inventory_hash']:
                raise Invalid('设备硬件已变化，请取消旧任务并重新预览')
            if row['state'] not in ('queued', 'preflight') or dev['consumed']:
                return jsonify(job=None)
            if row['expires'] < time.time() or (row['state'] == 'queued' and time.time()-row['created'] > 900):
                raise Invalid('任务已过领取期限，请人工取消后重新确认')
            if row['state'] == 'queued':
                running = sum(not json.loads(item['data']).get('installed_at') for item in
                              c.execute("SELECT data FROM jobs WHERE state IN ('preflight','installing','awaiting_report')"))
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
            if data.get('domain_join'):
                domain_transport_required(c, data['profile']['domain_join'])
                finalizer['domain_join'] = dict(domain=data['domain_join']['domain'],
                                               computer_name=data['target']['computer_name'],
                                               employee_id=data['target']['employee_id'],
                                               allow_http=data['profile']['domain_join'].get('allow_http', False))
                if data['profile']['domain_join'].get('mode') == 'manual':
                    finalizer['domain_join']['mode'] = 'manual'
                    finalizer['expires_at'] = row['expires']
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

    def domain_completion(c, identity, value):
        row, job = load(c, 'jobs', identity)
        domain_transport_required(c, job['profile'].get('domain_join', {}))
        secret = store.decrypt(row['secret'])
        if not hmac.compare_digest(bearer(), secret['finish_token']) or row['expires'] < time.time():
            raise Invalid('安装后任务凭据失效')
        retry_failure = (row['state'] == 'failed' and value.get('stage') == 'failed'
                         and job.get('domain_join', {}).get('state') == 'failed')
        if (row['state'] not in ('installing', 'awaiting_report') and not retry_failure) or not job.get('domain_join'):
            raise Invalid('任务未启用自动加域，或已结束')
        if value.get('hardware_uuid') != row['device_id']:
            raise Invalid('加域设备身份不匹配')
        return row, job, secret

    @app.post('/api/jobs/domain-join/release')
    @admin
    def release_domain_join():
        value = body()
        identities = value.get('job_ids')
        if (not isinstance(identities, list) or not 1 <= len(identities) <= 100
                or any(not isinstance(item, str) for item in identities)
                or len(set(identities)) != len(identities)
                or value.get('restart_confirmed') is not True):
            raise Invalid('请选择待加域任务，并确认已保存设置、允许加域后重启')
        with store.connect(write=True) as c:
            selected = []
            for identity in identities:
                row, job = load(c, 'jobs', identity)
                joining = job.get('domain_join', {})
                if (job['profile'].get('domain_join', {}).get('mode') != 'manual'
                        or row['state'] != 'awaiting_report' or row['expires'] < time.time()
                        or not job.get('installed_at') or joining.get('state') != 'waiting_release'):
                    raise Invalid('所选任务尚未装好、已开始加域或已过期，请刷新后重新选择')
                domain_transport_required(c, job['profile']['domain_join'])
                selected.append((identity, job))
            now = time.time()
            for identity, job in selected:
                if not job['domain_join'].get('released_at'):
                    job['domain_join']['released_at'] = now
                    c.execute('UPDATE jobs SET data=?,updated=? WHERE id=?', (canonical(job), now, identity))
                    event(c, 'domain_join', '管理员已确认设置完成，允许本机改名、加域并重启；等待客户端领取', identity)
        return jsonify(ok=True, count=len(selected))

    @app.post('/api/agent/jobs/<identity>/domain-join/config')
    def domain_join_config(identity):
        value = body()
        with store.connect(write=True) as c:
            row, job, secret = domain_completion(c, identity, value)
            current = job['domain_join']
            if job['profile']['domain_join'].get('mode') == 'manual' and not current.get('released_at'):
                build = integer(value.get('os_build'), '系统版本', 19041, 99999)
                if (value.get('image_state') != 'IMAGE_STATE_COMPLETE' or value.get('oobe_done') is not True
                        or not isinstance(value.get('computer_name'), str)
                        or not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', value['computer_name'])
                        or (job['source']['family'] == 'windows11') != (build >= 22000)
                        or (job['source'].get('kind') == 'wim' and build != next(
                            image['build'] for image in job['source']['images']
                            if image['index'] == job['profile']['image_index']))):
                    raise Invalid('尚未收到匹配本机和系统版本的安装完成回报，不能进入待统一加域')
                if current['state'] not in ('pending', 'waiting_release'):
                    raise Invalid('任务已进入其他加域阶段，禁止重新等待')
                changed = current['state'] != 'waiting_release'
                now = time.time()
                current.update(state='waiting_release', os_installed=True, updated=now)
                job.setdefault('installed_at', now)
                completion_display(job, value)
                c.execute('UPDATE jobs SET state=?,data=?,updated=? WHERE id=?',
                          ('awaiting_report', canonical(job), now, identity))
                if changed:
                    event(c, 'domain_join', 'Windows 安装完成，等待管理员统一加域；可先进行现场设置，当前不会执行加域或额外重启', identity)
                return jsonify(waiting_for_release=True, expires_at=row['expires'])
            password = secret.get('domain_join_password')
            if not password or current['state'] not in ('pending', 'waiting_release', 'checking', 'joining'):
                raise Invalid('加域凭据已回收，禁止重新发起加域')
            if completion_display(job, value):
                c.execute('UPDATE jobs SET data=?,updated=? WHERE id=?', (canonical(job), time.time(), identity))
            result = dict(job['profile']['domain_join'], password=password, join_state=current['state'],
                          computer_name=job['target']['computer_name'], employee_id=job['target']['employee_id'])
        return jsonify(result)

    @app.post('/api/agent/jobs/<identity>/domain-join/name')
    def domain_join_name(identity):
        value = body()
        unavailable = computer_name(value.get('unavailable_name'))
        with store.connect(write=True) as c:
            row, job, _ = domain_completion(c, identity, value)
            current = job['domain_join']
            if job['profile']['domain_join'].get('mode') == 'manual' and not current.get('released_at'):
                raise Invalid('等待管理员统一加域，暂不更改电脑名')
            if current['state'] not in ('pending', 'waiting_release', 'checking'):
                raise Invalid('加域已启动，禁止再次更换电脑名')
            # A lost response may repeat the previous conflict; return the same assigned name.
            if unavailable == current['computer_name']:
                occupied = set(current.get('unavailable_names', []))
                occupied.add(unavailable)
                reserved = reserved_computer_names(c, current['domain'], identity)
                name = available_name(job['target']['employee_id'], occupied | reserved)
                current.update(computer_name=name, unavailable_names=sorted(occupied))
                job['target']['computer_name'] = name
                c.execute('UPDATE jobs SET data=?,updated=? WHERE id=?',
                          (canonical(job), time.time(), identity))
                event(c, 'domain_join', '域内电脑名 '+unavailable+' 已存在，自动改用 '+name+'；未修改已有电脑', identity)
            name = current['computer_name']
        return jsonify(computer_name=name)

    @app.post('/api/agent/jobs/<identity>/domain-join/status')
    def domain_join_status(identity):
        value = body()
        stage = value.get('stage')
        messages = dict(checking='Windows 已安装，正在检查域 DNS 与电脑名',
                        joining='Windows 已安装，正在加入 AD 域',
                        restarting='加域命令已成功，正在重启，等待验证域信任',
                        verified='重启后域身份与安全通道验证通过',
                        failed='Windows 已安装，自动加域失败；不会重新装机或自动再次加域')
        if not isinstance(stage, str) or stage not in messages:
            raise Invalid('加域阶段无效')
        with store.connect(write=True) as c:
            row, job, secret = domain_completion(c, identity, value)
            current = job['domain_join']
            if current['state'] == 'failed':
                return jsonify(ok=True)
            if (job['profile']['domain_join'].get('mode') == 'manual'
                    and not current.get('released_at') and stage != 'failed'):
                raise Invalid('等待管理员统一加域，禁止提前执行加域或重启')
            order = dict(pending=0, waiting_release=0, checking=1, joining=2, restarting=3, verified=4, failed=5)
            if order[stage] < order[current['state']]:
                raise Invalid('旧加域阶段不允许覆盖新结果')
            if stage == 'verified' and (not isinstance(value.get('domain'), str)
                    or value['domain'].lower() != current['domain']
                    or not isinstance(value.get('computer_name'), str)
                    or value['computer_name'].upper() != current['computer_name']
                    or value.get('secure_channel') is not True):
                raise Invalid('加域结果未通过身份与安全通道核对')
            detail = value.get('detail', '')
            if not isinstance(detail, str) or len(detail) > 4000:
                raise Invalid('加域诊断内容格式错误')
            for sensitive in (secret.get('domain_join_password'), secret.get('source_password'), secret.get('local_password')):
                if sensitive:
                    detail = detail.replace(sensitive, '[redacted]')
            detail = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', detail)
            changed = stage != current['state'] or detail != current.get('detail', '')
            completion_display(job, value)
            job.setdefault('installed_at', time.time())
            current.update(state=stage, detail=detail, updated=time.time(), os_installed=True)
            state = 'failed' if stage == 'failed' else 'awaiting_report'
            if stage in ('restarting', 'verified', 'failed'):
                secret.pop('domain_join_password', None)
            c.execute('UPDATE jobs SET state=?,data=?,secret=?,updated=? WHERE id=?',
                      (state, canonical(job), store.encrypt(secret), time.time(), identity))
            if changed:
                event(c, 'failed' if stage == 'failed' else 'domain_join',
                      messages[stage] + ('\n'+detail if detail else ''), identity)
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
            if data.get('domain_join'):
                domain_transport_required(c, data['profile']['domain_join'])
                expected = data['target']['computer_name']
                preserved_name = False
                if (data['domain_join']['state'] != 'verified' or value.get('domain_join_verified') is not True
                        or not isinstance(value.get('domain_name'), str)
                        or value['domain_name'].lower() != data['domain_join']['domain']):
                    raise Invalid('系统已安装，但加域与重启后验证尚未完成')
            if (value.get('hardware_uuid') != row['device_id']
                    or (not preserved_name and value.get('computer_name') != expected)
                    or (preserved_name and (not isinstance(value.get('computer_name'), str)
                                            or not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', value['computer_name'])))
                    or value.get('image_state') != 'IMAGE_STATE_COMPLETE' or value.get('oobe_done') is not True
                    or (data['source']['family'] == 'windows11') != (build >= 22000)
                    or (data['source'].get('kind') == 'wim' and build != next(i['build'] for i in data['source']['images']
                                                        if i['index'] == data['profile']['image_index']))):
                raise Invalid('安装后系统、设备身份或 OOBE 状态未通过核对')
            completion_display(data, value)
            c.execute('UPDATE jobs SET state=?,data=?,updated=? WHERE id=?', ('completed', canonical(data), time.time(), identity))
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
