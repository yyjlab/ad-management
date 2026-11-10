"""AD-side asset delivery. Frozen requests live in SQLite; no PE or asset code is executed."""
import json
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

from flask import jsonify, request

from .deployment import Invalid, canonical, digest, integer, text

PATH = '/api/integrations/ad-deployment/v1/registrations'
INTAKE_PATH = '/api/integrations/ad-deployment/v1/intakes'
CONNECTION_PATH = '/api/integrations/ad-deployment/v1/connection'
BUSES = {'NVMe', 'SATA', 'ATA', 'SAS', 'SCSI', 'RAID', 'MMC'}
AUTH_ERRORS = {'AUTHENTICATION_FAILED', 'FORBIDDEN', 'HTTPS_REQUIRED'}
RETRY_STATES = ('pending', 'retry', 'sending')
PLACEHOLDERS = {'unknown', 'none', 'default string', 'system product name', 'system manufacturer',
                'to be filled by o.e.m.', '未知', '未采集', '未上报'}


def dictionary_error(body, fallback):
    if not isinstance(body, dict) or body.get('code') != 'DEFAULT_DICTIONARY_INVALID':
        return fallback
    # Only show known dictionary errors, never arbitrary receiver text or credentials.
    for label, name in (('公司', '微丰启'), ('位置', '公司'), ('状态', '当前可用')):
        message = f'{label}“{name}”须存在唯一且启用的字典记录；未自动新建'
        if body.get('message') == message:
            return 'asset：' + message
    return fallback


def endpoint_url(value):
    value = text(value, 'asset 地址', 1, 2048)
    try:
        parts = urlsplit(value)
        port = parts.port
        if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or parts.path.rstrip('/') not in ('', PATH, INTAKE_PATH)
                or '\\' in value or any(ch.isspace() for ch in value) or port == 0):
            raise ValueError()
    except ValueError:
        raise Invalid('asset 接收接口只允许 HTTP 或 HTTPS 地址，不能包含账号、查询参数或其他路径') from None
    return urlunsplit((parts.scheme, parts.netloc.lower(), INTAKE_PATH, '', ''))


def receiver_root(endpoint):
    return endpoint.removesuffix(INTAKE_PATH).removesuffix(PATH)


def clean(value, label, maximum=200, required=False):
    if not isinstance(value, str) or value.strip().lower() in PLACEHOLDERS:
        value = ''
    value = re.sub(r'[\x00-\x1f\x7f]', ' ', value).strip()
    if len(value) > maximum:
        raise Invalid(label + '超过接收端长度限制，请核对后另存新登记版本')
    if required and not value:
        raise Invalid(label + '未采集到有效内容，暂不能自动登记')
    return value or None


def asset_display_name(inv):
    def firmware(key):
        value = re.sub(r'[\x00-\x1f\x7f]', ' ', str(inv.get(key) or '')).strip()
        if re.fullmatch(r'unknown|none|not (?:specified|applicable)|default string|system (?:manufacturer|family|product name|version)|to be filled by o\.?e\.?m\.?', value, re.I):
            return ''
        return value
    vendor, family, version = firmware('manufacturer'), firmware('system_family'), firmware('product_version')
    raw = firmware('model') or firmware('product_name') or version or family
    if not raw:
        return None
    code = bool(re.fullmatch(r'[a-z0-9][a-z0-9._-]{2,30}', raw, re.I))
    readable = next((value for value in (firmware('oem_model'), version, firmware('product_name'))
                     if value and value not in (vendor, family) and re.search(r'[A-Za-z\u4e00-\u9fff]', value)
                     and re.search(r'[\s\u4e00-\u9fff]', value)), '')
    known = 'HUAWEI MateBook 14s' if re.match(r'^HKD(?:-|$)', raw, re.I) and (not vendor or re.search(r'huawei|华为', vendor, re.I)) else ''
    main = (readable or known) if code else ''
    main = main or (version if vendor.lower() == 'lenovo' and version else raw)
    parts = [vendor] if vendor and vendor.lower() not in main.lower() else []
    if code and family and family.lower() not in main.lower():
        parts.append(family)
    parts.append(main)
    return clean(' '.join(parts), '资产名称', 160)


def registration_payload(record, category, external_id, intake=False):
    inv = record['inventory']
    cpus = list(dict.fromkeys(filter(None, (clean(row.get('name'), 'CPU')
                    for row in inv.get('cpus', []) if isinstance(row, dict)))))
    memory = inv.get('ram_bytes')
    memory = (format(memory / 1024**3, '.2f').rstrip('0').rstrip('.') + ' GiB'
              if type(memory) is int and memory > 0 else None)
    disks = []
    for disk in inv.get('disks', []):
        if not isinstance(disk, dict) or disk.get('bus') not in BUSES:
            continue
        capacity = disk.get('size_bytes')
        if type(capacity) is not int or not 0 < capacity <= 2**63 - 1:
            raise Invalid('内置物理硬盘容量无效')
        disks.append(dict(model=clean(disk.get('model'), '硬盘型号', 120),
                          capacityBytes=capacity, busType=disk['bus']))
    if len(disks) > 32:
        raise Invalid('内置物理硬盘数量超过接收端限制')
    graphics = [clean(gpu.get('name'), '显卡名称') for gpu in inv.get('gpus', []) if isinstance(gpu, dict)]
    graphics = list(dict.fromkeys(filter(None, graphics)))
    if len(graphics) > 8:
        raise Invalid('显卡数量超过接收端限制')
    captured = record.get('captured_at') or record['updated']
    captured = datetime.fromtimestamp(captured, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    operator = clean(record.get('saved_by'), '登记操作人', 120, True)
    payload = dict(externalRegistrationId=external_id, assetTag=record['asset_tag'], categoryId=category,
                   capturedAt=captured, operator=dict(id=operator, displayName=operator),
                   snapshot=dict(model=clean(inv.get('oem_model') or inv.get('model'), '电脑型号', 120, not intake),
                                 cpu=clean(' / '.join(cpus), 'CPU 汇总'), memory=memory,
                                 internalDisks=disks, graphicsCards=graphics,
                                 manufacturerSerialNumber=clean(inv.get('serial'), 'SN', 160)))
    if intake:
        payload.pop('assetTag')
        payload['name'] = asset_display_name(inv)
    encoded = canonical(payload)
    if len(encoded.encode()) > 32768:
        raise Invalid('资产登记请求超过接收端32KiB上限')
    return encoded


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(endpoint, token, ca_pem, encoded=None):
    """Do not forward the bearer through redirects, environment proxies or unverified TLS."""
    context = ssl.create_default_context()
    if ca_pem:
        context.load_verify_locations(cadata=ca_pem)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(endpoint, data=encoded.encode() if encoded is not None else None,
                                 method='POST' if encoded is not None else 'GET',
                                 headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read(65537)
        if len(content) > 65536:
            raise ValueError('response too large')
        try:
            data = json.loads(content)
        except (ValueError, UnicodeError):
            data = None
        return response.code, data


def post_registration(endpoint, token, ca_pem, encoded):
    return request_json(endpoint, token, ca_pem, encoded)


def probe_connection(endpoint, token, ca_pem):
    return request_json(receiver_root(endpoint) + CONNECTION_PATH, token, ca_pem)


def connection_target(sender, c, value):
    previous = sender.config(c)
    endpoint = endpoint_url(value['endpoint']) if value.get('endpoint') else ''
    secret = sender.secret(c) if endpoint == previous['endpoint'] else {}
    token, ca = value.get('token', ''), value.get('ca_pem', '')
    if not isinstance(token, str) or not isinstance(ca, str):
        raise Invalid('服务凭据和 CA 证书必须是文本')
    if token.strip():
        if not re.fullmatch(r'adp_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}', token.strip()):
            raise Invalid('专用服务凭据格式无效，请使用 asset 签发的 adp_ 凭据')
        secret['token'] = token.strip()
    if value.get('clear_ca') is True:
        secret.pop('ca_pem', None)
    if ca.strip():
        try:
            if len(ca) > 32768 or 'PRIVATE KEY' in ca:
                raise ValueError()
            ssl.create_default_context(cadata=ca.strip())
        except (ssl.SSLError, ValueError):
            raise Invalid('CA 证书格式无效，仅接受公开 PEM 证书') from None
        secret['ca_pem'] = ca.strip()
    return endpoint, secret


class AssetSender:
    def __init__(self, app, store, event):
        self.app, self.store, self.event = app, store, event
        self._lock, self._signal = threading.Lock(), threading.Event()
        self._thread = None
        self.background_allowed = not app.testing
        self.transport = post_registration
        self.status_transport = request_json
        self.probe_transport = probe_connection

    def config(self, c):
        value = self.store.setting(c, 'asset_sync', dict(enabled=False, endpoint='', category_id=None, revision=0))
        if value['endpoint']:
            value['endpoint'] = receiver_root(value['endpoint']) + INTAKE_PATH
        return value

    def secret(self, c):
        encoded = self.store.setting(c, 'asset_sync_secret')
        return self.store.decrypt(encoded) if encoded else {}

    def public_config(self, c):
        config = dict(self.config(c))
        secret = self.secret(c)
        config.update(has_token=bool(secret.get('token')), has_ca=bool(secret.get('ca_pem')),
                      pause=self.store.setting(c, 'asset_sync_pause'))
        return config

    def decorate(self, c, record):
        record = dict(record)
        row = c.execute('SELECT * FROM asset_sync_outbox WHERE device_id=? AND registration_version=?',
                        (record['device_id'], record['version'])).fetchone()
        record['sync_state'] = row['state'] if row else 'waiting_configuration'
        record['sync'] = self.public_row(row) if row else None
        return record

    @staticmethod
    def public_row(row):
        meta = json.loads(row['data'])
        return dict(id=row['id'], state=row['state'], attempts=row['attempts'],
                    next_attempt=row['next_attempt'], updated=row['updated'], endpoint=row['endpoint'],
                    **{key: meta[key] for key in ('result', 'code', 'message') if key in meta})

    def ensure_editable(self, c, identity, tag):
        if c.execute("SELECT 1 FROM asset_sync_outbox WHERE device_id=? AND state IN ('pending','retry','sending','pending_review')",
                     (identity,)).fetchone():
            raise Invalid('此设备正在同步或等待原请求重试，请取得结果后再编辑')
        if c.execute('SELECT 1 FROM asset_sync_outbox WHERE device_id=? AND attempts>0 AND asset_tag<>?',
                     (identity, tag)).fetchone():
            raise Invalid('此设备的资产编号已提交到 asset，不能直接改投另一个编号；请先核对关联资产')

    def auto_save(self, c, device, snapshot):
        identity = device['id']
        previous = c.execute('SELECT * FROM asset_registrations WHERE device_id=?', (identity,)).fetchone()
        # Existing legacy work, particularly successful registrations, must never become new intakes.
        for row in c.execute('SELECT payload,data FROM asset_sync_outbox WHERE device_id=?', (identity,)):
            metadata = json.loads(row['data'])
            if metadata.get('kind') == 'intake' and metadata.get('code') != 'LOCAL_VALIDATION_FAILED':
                return
            if metadata.get('kind') != 'intake' and 'assetTag' in json.loads(row['payload']):
                return
        old = json.loads(previous['data']) if previous else None
        if old and old.get('kind') != 'intake':
            if not self.config(c)['enabled']:
                return
            # A never-submitted draft is safe to send for review, not direct asset creation.
            old = dict(old, asset_tag='')
        now = time.time()
        record = dict(device_id=identity, asset_tag=old.get('asset_tag', '') if old else '',
                      version=previous['version'] + 1 if previous else 1, kind='intake',
                      company='微丰启', location='公司', assigned_to=None, inventory=snapshot,
                      inventory_revision=digest(snapshot), saved_by='pe-auto', updated=now,
                      captured_at=device['last_seen'] or now)
        def normalized(value):
            if isinstance(value, dict):
                return {key: normalized(item) for key, item in value.items()}
            if isinstance(value, list):
                return sorted((normalized(item) for item in value), key=canonical)
            return value
        try:
            prepared = json.loads(registration_payload(record, None, 'fingerprint', intake=True))
            meaningful = dict(snapshot=prepared['snapshot'], name=prepared.get('name'))
        except (Invalid, ValueError, OverflowError):
            meaningful = snapshot
        fingerprint = digest(normalized(meaningful))
        if old and old.get('configuration_hash') == fingerprint:
            self.enqueue(c, old)
            return
        record['configuration_hash'] = fingerprint
        # The legacy NOT NULL UNIQUE column needs a private key until asset assigns a real number.
        tag = record['asset_tag'] or '@intake:' + identity
        c.execute('INSERT INTO asset_registrations VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET '
                  'asset_tag=excluded.asset_tag,version=excluded.version,data=excluded.data,updated=excluded.updated',
                  (identity, tag, record['version'], canonical(record), now))
        self.enqueue(c, record)

    def enqueue(self, c, record):
        config = self.config(c)
        if not config['enabled']:
            return
        if c.execute('SELECT 1 FROM asset_sync_outbox WHERE device_id=? AND registration_version=?',
                     (record['device_id'], record['version'])).fetchone():
            return
        instance = self.store.setting(c, 'asset_sync_instance')
        external_id = 'ad:' + instance + ':' + record['device_id'] + ':' + str(record['version'])
        intake = record.get('kind') == 'intake'
        state, meta = 'pending', {'retry_limit': 8, 'kind': 'intake' if intake else 'registration'}
        try:
            payload = registration_payload(record, config['category_id'], external_id, intake=intake)
        except (Invalid, ValueError, OverflowError):
            payload, state = '{}', 'rejected'
            meta.update(code='LOCAL_VALIDATION_FAILED', message='采集资料不符合接收端要求，请核对型号、配置长度和操作人后保存新版本')
        now = time.time()
        c.execute('INSERT INTO asset_sync_outbox VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (external_id, record['device_id'], record['version'], record['asset_tag'],
                   receiver_root(config['endpoint']) + (INTAKE_PATH if intake else PATH),
                   payload, state, 0, now, 0, '', canonical(meta), now, now, config['revision']))

    def claim(self, now):
        with self.store.connect(write=True) as c:
            config = self.config(c)
            pause = self.store.setting(c, 'asset_sync_pause')
            if not config['enabled'] or pause:
                return None
            row = c.execute("""SELECT * FROM asset_sync_outbox
                WHERE (state IN ('pending','retry','pending_review') AND next_attempt<=?) OR (state='sending' AND lease_until<=?)
                ORDER BY created LIMIT 1""", (now, now)).fetchone()
            if not row:
                return None
            if receiver_root(row['endpoint']) != receiver_root(config['endpoint']):
                meta = json.loads(row['data'])
                meta.update(code='TARGET_CHANGED', message='接收地址已改变，原请求未改投；请核对目标后保存新版本')
                c.execute("UPDATE asset_sync_outbox SET state='blocked',data=?,updated=? WHERE id=?",
                          (canonical(meta), now, row['id']))
                return None
            secret = self.secret(c)
            if not secret.get('token'):
                return None
            claim = secrets.token_hex(16)
            c.execute("UPDATE asset_sync_outbox SET state='sending',attempts=attempts+1,lease_until=?,claim_token=?,updated=? WHERE id=?",
                      (now + 120, claim, now, row['id']))
            return dict(row, claim=claim, attempts=row['attempts'] + 1, config=config, secret=secret)

    @staticmethod
    def outcome(status, body, row):
        intake = json.loads(row.get('data', '{}')).get('kind') == 'intake'
        if intake and isinstance(body, dict) and body.get('result') in ('pending_review', 'approved', 'rejected'):
            result, asset = body['result'], body.get('asset')
            expected = (200, 202) if result == 'pending_review' else (200,)
            valid_asset = (isinstance(asset, dict) and type(asset.get('id')) is int and asset['id'] > 0
                           and type(asset.get('version')) is int and asset['version'] >= 0
                           and isinstance(asset.get('assetTag'), str) and re.fullmatch(r'[0-9]{12}', asset['assetTag']))
            if (status not in expected or body.get('externalRegistrationId') != row['id']
                    or (result == 'approved' and not valid_asset)
                    or (result != 'approved' and asset is not None)):
                return 'blocked', dict(code='RESPONSE_MISMATCH', message='asset 审核结果格式或登记标识不一致'), False
            return result, dict(result=dict(result=result, asset=asset),
                                message='审核已通过' if result == 'approved' else
                                        'asset 已驳回，请在资产系统处理' if result == 'rejected' else '等待 asset 审核'), False
        if intake and 200 <= status < 300:
            return 'blocked', dict(code='INVALID_RESPONSE', message='asset 审核结果不符合约定'), False
        if intake and status == 404:
            return 'retry', dict(code='RECEIVER_NOT_READY', message='asset 审核接口或记录暂未就绪，保留原标识等待重试'), False
        if isinstance(body, dict) and body.get('result') in ('created', 'already_exists', 'configuration_conflict'):
            result = body['result']
            expected = {'created': 201, 'already_exists': 200, 'configuration_conflict': 409}[result]
            asset = body.get('asset')
            if (status != expected or body.get('externalRegistrationId') != row['id']
                    or not isinstance(asset, dict) or asset.get('assetTag') != row['asset_tag']
                    or type(asset.get('id')) is not int or asset['id'] <= 0
                    or type(asset.get('version')) is not int or asset['version'] < 0):
                return 'blocked', dict(code='RESPONSE_MISMATCH', message='接收端返回的登记标识或资产编号不一致，未标记成功'), False
            differences, warnings = body.get('differences'), body.get('warnings')
            if (not isinstance(differences, list) or len(differences) > 32
                    or not isinstance(warnings, list) or len(warnings) > 64):
                return 'blocked', dict(code='INVALID_RESPONSE', message='接收端返回格式不符合约定'), False
            clean_diffs = []
            for difference in differences:
                if not isinstance(difference, dict) or not isinstance(difference.get('field'), str):
                    return 'blocked', dict(code='INVALID_RESPONSE', message='接收端差异格式无效'), False
                clean_diffs.append({key: (str(difference[key])[:2000] if difference.get(key) is not None else None)
                                    for key in ('field', 'existing', 'incoming')})
            result_data = dict(result=result, asset={key: asset[key] for key in ('id', 'assetTag', 'version')},
                               differences=clean_diffs, warnings=[str(warning)[:160] for warning in warnings],
                               replayed=body.get('replayed') is True, observed_at=str(body.get('observedAt', ''))[:40])
            return ('conflict' if result == 'configuration_conflict' else 'synced'), dict(result=result_data), False
        code = body.get('code') if isinstance(body, dict) else None
        code = code if isinstance(code, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', code) else 'HTTP_' + str(status)
        messages = {'AUTHENTICATION_FAILED': '服务凭据无效、已过期或已撤销，请更新联动设置',
                    'HTTPS_REQUIRED': 'asset 接收端要求可信 HTTPS 入口',
                    'INTEGRATION_DISABLED': 'asset 尚未启用 AD 登记接口',
                    'REGISTRATION_NOT_READY': 'asset 登记服务尚未就绪',
                    'SN_SCHEMA_MIGRATION_REQUIRED': 'asset 的 SN 数据库迁移尚未完成',
                    'CATEGORY_INVALID': 'asset 电脑分类 ID 无效，请修正设置后保存新登记版本',
                    'DEFAULT_DICTIONARY_INVALID': 'asset 默认公司、位置或状态字典不符合约定',
                    'IDEMPOTENCY_KEY_REUSED': '外部登记标识与请求内容冲突，已停止重试',
                    'ASSET_NO_LONGER_EXISTS': '上次关联资产已删除或替换，请人工核对',
                    'VALIDATION_FAILED': 'asset 字段校验未通过，请核对配置后保存新版本',
                    'ASSET_RULE_REJECTED': 'asset 现有业务规则拒绝此记录，请在资产系统核对'}
        message = messages.get(code, 'asset 返回 HTTP ' + str(status) + '，请核对接收服务')
        if status == 409:
            message = dictionary_error(body, message)
        retry = (status in (408, 429, 500, 502, 503, 504) or code == 'CONCURRENT_RETRY') and code not in messages
        return ('retry' if retry else 'blocked'), dict(code=code, message=message), code in AUTH_ERRORS or status in (401, 403)

    def process_one(self, now=None):
        now = time.time() if now is None else now
        row = self.claim(now)
        if not row:
            return False
        try:
            meta = json.loads(row['data'])
            if meta.get('poll'):
                status, body = self.status_transport(row['endpoint'] + '/' + quote(row['id'], safe=''),
                                                    row['secret']['token'], row['secret'].get('ca_pem', ''))
            else:
                status, body = self.transport(row['endpoint'], row['secret']['token'],
                                              row['secret'].get('ca_pem', ''), row['payload'])
            state, outcome, pause = self.outcome(status, body, row)
        except (OSError, ValueError, urllib.error.URLError):
            state, outcome, pause = 'retry', dict(code='CONNECTION_FAILED', message='连接或证书校验失败，保留原登记标识等待重试'), False
        with self.store.connect(write=True) as c:
            active = c.execute("SELECT 1 FROM asset_sync_outbox WHERE id=? AND claim_token=? AND state='sending' AND lease_until>?",
                               (row['id'], row['claim'], time.time())).fetchone()
            if not active:
                return True
            meta = json.loads(row['data'])
            current = self.config(c)
            if pause and current['revision'] != row['config']['revision']:
                state, pause = 'retry', False
            meta.update(outcome)
            if meta.get('kind') == 'intake':
                if meta.get('poll'):
                    meta['poll_count'] = meta.get('poll_count', 0) + 1
                if state == 'pending_review':
                    meta.update(poll=True, failures=0)
                    if meta.get('poll_count', 0) >= meta.get('poll_limit', 2880):
                        state = 'attention'
                        meta['message'] = '自动查询已达上限，可按原登记标识继续查询；审核仍在 asset 处理'
                if state == 'retry':
                    meta['failures'] = meta.get('failures', 0) + 1
                if state == 'approved':
                    record_row = c.execute('SELECT * FROM asset_registrations WHERE device_id=? AND version=?',
                                           (row['device_id'], row['registration_version'])).fetchone()
                    tag = meta['result']['asset']['assetTag']
                    collision = c.execute('SELECT 1 FROM asset_registrations WHERE asset_tag=? AND device_id<>?',
                                          (tag, row['device_id'])).fetchone()
                    if record_row and collision:
                        state = 'blocked'
                        meta.update(code='LOCAL_ASSET_TAG_CONFLICT', message='审核编号已关联另一设备，请在 asset 核对')
                    elif record_row:
                        record = json.loads(record_row['data'])
                        record.update(asset_tag=tag, updated=time.time())
                        c.execute('UPDATE asset_registrations SET asset_tag=?,data=?,updated=? WHERE device_id=? AND version=?',
                                  (tag, canonical(record), record['updated'], row['device_id'], row['registration_version']))
            # Never persist receiver-reflected credentials.
            for sensitive in row['secret'].values():
                if sensitive:
                    meta = json.loads(canonical(meta).replace(json.dumps(sensitive)[1:-1], '[redacted]'))
            if state == 'retry' and (meta.get('failures', 0) if meta.get('kind') == 'intake' else row['attempts']) >= meta.get('retry_limit', 8):
                state = 'attention'
                meta.update(message='自动重试已达上限，结果仍待确认；可按原请求重试，不会换登记标识')
            if pause:
                self.store.put(c, 'asset_sync_pause', dict(code=meta.get('code'), message=meta.get('message')))
            delay = min(300, 5 * 2 ** min(row['attempts'] - 1, 6))
            if state == 'pending_review':
                delay = min(300, 30 * 2 ** min(meta.get('poll_count', 0), 4))
            c.execute('UPDATE asset_sync_outbox SET state=?,data=?,next_attempt=?,lease_until=0,claim_token=?,updated=? '
                      'WHERE id=? AND claim_token=?',
                      (state, canonical(meta), now + delay if state in ('retry', 'pending_review') else 0, '', time.time(), row['id'], row['claim']))
            if state not in ('retry', 'pending_review'):
                self.event(c, 'asset_sync', '资产 ' + row['asset_tag'] + ' 同步结果：' + state)
        return True

    def wake(self):
        if not self.background_allowed:
            return
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._loop, name='pc-deploy-asset-sender', daemon=True)
                self._thread.start()
        self._signal.set()

    def _loop(self):
        while True:
            try:
                with self.app.app_context():
                    worked = self.process_one()
            except Exception:
                # A lease preserves the immutable request after unexpected worker failure.
                worked = False
            if not worked:
                self._signal.wait(5)
                self._signal.clear()


def register_asset_sync(app, host_app, store, admin, body, event):
    sender = AssetSender(host_app, store, event)
    host_app.extensions['pc_deploy_asset_sender'] = sender

    @host_app.after_request
    def wake_asset_delivery(response):
        if request.path.startswith('/pc-deploy/') and response.status_code < 400:
            sender.wake()
        return response

    @app.post('/api/asset-sync/settings')
    @admin
    def asset_sync_settings():
        value = body()
        if type(value.get('enabled')) is not bool:
            raise Invalid('自动同步开关必须是布尔值')
        with store.connect(write=True) as c:
            previous = sender.config(c)
            if value.get('revision') != previous['revision'] or type(value.get('revision')) is not int:
                raise Invalid('联动设置已变化，请刷新后重试')
            endpoint, secret = connection_target(sender, c, value)
            category = integer(value.get('category_id'), 'asset 电脑分类 ID', 1, 2**53-1) if value.get('category_id') is not None else None
            if value['enabled'] and not (endpoint and secret.get('token')):
                raise Invalid('开启前请填写 asset 地址和专用服务凭据；分类由 asset 审核确定')
            config = dict(enabled=value['enabled'], endpoint=endpoint, category_id=category,
                          revision=previous['revision']+1)
            store.put(c, 'asset_sync', config)
            store.put(c, 'asset_sync_secret', store.encrypt(secret))
            store.put(c, 'asset_sync_pause', None)
            if store.setting(c, 'asset_sync_instance') is None:
                store.put(c, 'asset_sync_instance', str(uuid.uuid4()))
            for row in list(c.execute("SELECT id,data FROM asset_sync_outbox WHERE state='blocked' AND endpoint IN (?,?)",
                                     (endpoint, receiver_root(endpoint) + PATH))):
                if json.loads(row['data']).get('code') in AUTH_ERRORS | {'HTTP_401', 'HTTP_403'}:
                    c.execute("UPDATE asset_sync_outbox SET state='pending',next_attempt=0 WHERE id=?", (row['id'],))
            if config['enabled']:
                for device in list(c.execute('SELECT * FROM devices')):
                    sender.auto_save(c, device, sender.snapshot(json.loads(device['data'])))
                for row in list(c.execute('SELECT data FROM asset_registrations')):
                    sender.enqueue(c, json.loads(row['data']))
            event(c, 'asset_sync', '更新 asset 联动设置；' + ('自动发送已开启' if config['enabled'] else '已暂停新发送'))
            public = sender.public_config(c)
        return jsonify(ok=True, settings=public)

    @app.post('/api/asset-sync/probe')
    @admin
    def asset_sync_probe():
        value = body()
        with store.connect() as c:
            endpoint, secret = connection_target(sender, c, value)
        if not endpoint or not secret.get('token'):
            raise Invalid('请先填写 asset 地址和专用服务凭据')
        try:
            status, result = sender.probe_transport(endpoint, secret['token'], secret.get('ca_pem', ''))
        except (OSError, ValueError, urllib.error.URLError):
            raise Invalid('无法连接 asset，请核对地址、端口和内网连通性；HTTPS 还需核对证书') from None
        if status != 200:
            hints = {401: '凭据无效、过期或已撤销', 403: '请在 asset 接入设置中允许受信内网 HTTP，或检查权限',
                     404: 'asset 后端尚未更新到支持连接测试的版本', 409: 'asset 的微丰启、公司或当前可用字典不唯一、缺失或停用',
                     503: '请先在 asset 网页启用装机平台接入'}
            message = hints.get(status, 'asset 连接检查返回 HTTP ' + str(status))
            raise Invalid(dictionary_error(result, message) if status == 409 else message)
        if (not isinstance(result, dict) or result.get('receiver') != 'asset-management'
                or result.get('protocolVersion') != 1 or not isinstance(result.get('categories', []), list)
                or len(result.get('categories', [])) > 1000):
            raise Invalid('接收端不是受支持的 asset 接口')
        categories = []
        for choice in result.get('categories', []):
            if (not isinstance(choice, dict) or type(choice.get('id')) is not int or not 0 < choice['id'] <= 2**53-1
                    or not isinstance(choice.get('name'), str) or not 0 < len(choice['name']) <= 160):
                raise Invalid('asset 返回了无效的电脑分类')
            if any(sensitive and sensitive in choice['name'] for sensitive in secret.values()):
                raise Invalid('asset 返回了不可信的分类信息')
            categories.append(dict(id=choice['id'], name=choice['name']))
        return jsonify(ok=True, endpoint=endpoint, categories=categories)

    @app.post('/api/asset-registrations/<identity>/retry')
    @admin
    def retry_asset_registration(identity):
        value = body()
        with store.connect(write=True) as c:
            config = sender.config(c)
            if not config['enabled'] or store.setting(c, 'asset_sync_pause'):
                raise Invalid('请先开启联动并修正服务凭据设置')
            record = c.execute('SELECT version FROM asset_registrations WHERE device_id=?', (identity,)).fetchone()
            if not record or value.get('version') != record['version']:
                raise Invalid('登记记录已变化，请刷新重试')
            row = c.execute('SELECT * FROM asset_sync_outbox WHERE device_id=? AND registration_version=?',
                            (identity, record['version'])).fetchone()
            if (not row or row['state'] not in ('retry','attention','blocked')
                    or receiver_root(row['endpoint']) != receiver_root(config['endpoint'])):
                raise Invalid('此记录不允许按原请求重试；配置差异需核对，地址改变需保存新版本')
            meta = json.loads(row['data'])
            meta['retry_limit'] = row['attempts'] + 8
            if meta.get('kind') == 'intake':
                meta.update(failures=0, retry_limit=8, poll_limit=meta.get('poll_count', 0) + 2880)
            c.execute("UPDATE asset_sync_outbox SET state='pending',next_attempt=0,data=?,updated=? WHERE id=?",
                      (canonical(meta), time.time(), row['id']))
            event(c, 'asset_sync', '资产 ' + row['asset_tag'] + ' 已安排按原登记标识重试')
        return jsonify(ok=True)

    return sender
