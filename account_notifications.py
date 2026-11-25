"""Account notices; plaintext passwords are never saved in delivery records."""
import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlsplit

import ldap3
from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, jsonify, request, send_file, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy.exc import IntegrityError
from pypinyin import lazy_pinyin

MAX_ATTACHMENT = 2 * 1024 * 1024
MAX_TOTAL = 5 * 1024 * 1024
DEFAULT_CC_EMAIL = 'yuanyujie@shunhs.cn'
DOMAIN_DEFAULT_CC_EMAIL = f'{DEFAULT_CC_EMAIL}, liuchongxiang@shunhs.cn'
MAX_CC = 5
DOMAIN_WIFI_NETWORKS = ('WIFI-OA', 'WIFI-Mobile')
PASSWORD_NOTICE = '请妥善保管此密码，请勿向他人透露或转发。'
DOMAIN_TEMPLATE_NAME = '域账号开通'
OLD_DOMAIN_PASSWORD_NOTICE = '此密码为初始密码。登录 Windows 后，请按 Ctrl + Alt + Delete，选择「更改密码」，并尽快设置自己的密码。'
DOMAIN_PASSWORD_NOTICE = (
    '这是您的初始密码。首次登录 Windows 后，请按 Ctrl + Alt + Delete，选择「更改密码」，并尽快设置自己的密码。'
    '如公司策略允许，可在「设置 → 账户 → 登录选项」中设置 PIN；电脑支持时，也可启用人脸或指纹登录。'
)
VPN_TEMPLATE_ID = '8a92f00a-dcb8-4c27-8638-000000000001'
URL_FIELDS = ('login_url', 'tutorial_url', 'download_url')
TEMPLATE_FIELDS = ('name', 'system_name', 'subject', 'intro', *URL_FIELDS, 'password_instruction')
FORM_FIELDS = ('employee_id', 'recipient_name', 'to_email', 'cc_email', 'account', 'notes',
               *URL_FIELDS, 'password_instruction')


class NoticeError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def text(value, limit, required=False, multiline=False):
    if not isinstance(value, str):
        raise NoticeError('字段必须是文本')
    value = value.strip().replace('\r\n', '\n')
    if len(value) > limit or (required and not value):
        raise NoticeError(f'请填写有效内容，最多 {limit} 个字符')
    if any(ord(c) < 32 and not (multiline and c in '\n\t') for c in value) or '\x7f' in value:
        raise NoticeError('字段包含不允许的控制字符')
    return value


def email_address(value):
    value = text(value, 254, True)
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value):
        raise NoticeError('请填写有效的单个收件邮箱')
    return value


def directory_email_status(value):
    try:
        email_address(value)
        return 'valid'
    except NoticeError:
        return 'invalid' if value.strip() else 'missing'


def cc_address_list(value):
    value = text(value, MAX_CC * 256)
    if not value:
        return ''
    parts = value.split(',')
    if len(parts) > MAX_CC:
        raise NoticeError(f'抄送邮箱最多 {MAX_CC} 个，请用英文逗号分隔')
    addresses = {}
    for part in parts:
        try:
            address = email_address(part)
        except NoticeError:
            raise NoticeError('抄送邮箱格式不正确，请用英文逗号分隔') from None
        addresses.setdefault(address.casefold(), address)
    return ', '.join(addresses.values())


def web_url(value):
    value = text(value, 1000)
    if value:
        try:
            parsed = urlsplit(value)
            if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                    parsed.username is not None or parsed.password is not None or
                    any(c.isspace() for c in value)):
                raise ValueError()
            parsed.port
        except ValueError:
            raise NoticeError('链接必须是有效的 HTTP 或 HTTPS 地址') from None
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def suggested_account(name):
    return re.sub(r'[^a-z0-9._-]', '', ''.join(lazy_pinyin(name)).lower())[:120]


def notice_password(value):
    if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise NoticeError('密码最多 128 个字符，不能包含换行或控制字符')
    return value


def domain_template(row):
    return row is not None and row.id != VPN_TEMPLATE_ID and row.name == DOMAIN_TEMPLATE_NAME


def define_models(db):
    class NoticeTemplate(db.Model):
        __tablename__ = 'account_notice_template'
        id = db.Column(db.String(36), primary_key=True)
        name = db.Column(db.String(80), nullable=False)
        system_name = db.Column(db.String(120), nullable=False)
        subject = db.Column(db.String(200), nullable=False)
        intro = db.Column(db.Text, nullable=False)
        login_url = db.Column(db.String(1000), nullable=False, default='')
        tutorial_url = db.Column(db.String(1000), nullable=False, default='')
        download_url = db.Column(db.String(1000), nullable=False, default='')
        password_instruction = db.Column(db.String(500), nullable=False, default='')
        active = db.Column(db.Boolean, nullable=False, default=True)
        version = db.Column(db.Integer, nullable=False, default=1)
        updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    class NoticeAttachment(db.Model):
        __tablename__ = 'account_notice_attachment'
        id = db.Column(db.String(36), primary_key=True)
        template_id = db.Column(db.String(36), db.ForeignKey('account_notice_template.id'), nullable=False, index=True)
        filename = db.Column(db.String(120), nullable=False)
        content = db.Column(db.LargeBinary, nullable=False)
        private_key = db.Column(db.Boolean, nullable=False, default=False)

    class NoticeDelivery(db.Model):
        __tablename__ = 'account_notice_delivery'
        id = db.Column(db.String(36), primary_key=True)
        operator = db.Column(db.String(50), nullable=False)
        request_key = db.Column(db.String(36), nullable=False)
        fingerprint = db.Column(db.String(64), nullable=False)
        snapshot = db.Column(db.Text, nullable=False)
        mode = db.Column(db.String(12), nullable=False)
        to_email = db.Column(db.String(254), nullable=False)
        subject = db.Column(db.String(210), nullable=False)
        status = db.Column(db.String(20), nullable=False, default='sending')
        message = db.Column(db.String(200), nullable=False, default='正在提交邮件服务器')
        created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
        __table_args__ = (db.UniqueConstraint('operator', 'request_key', name='uq_account_notice_request'),)

    return NoticeTemplate, NoticeAttachment, NoticeDelivery


def seed_templates(db, models):
    Template = models[0]
    for ident, name, system in (
        (VPN_TEMPLATE_ID, 'VPN 开通', '公司 VPN'),
        ('8a92f00a-dcb8-4c27-8638-000000000002', '通用账号开通', '业务系统'),
    ):
        if not db.session.get(Template, ident):
            db.session.add(Template(id=ident, name=name, system_name=system,
                subject=f'【账号开通】{system}', intro='您的账号已开通，请按以下信息使用。',
                password_instruction=PASSWORD_NOTICE))


def render_notice(snapshot, test=False, password='', *, domain=False, wifi=None):
    esc = lambda value: html.escape(str(value), quote=True)
    lines = [f"您好，{snapshot['recipient_name']}：", snapshot['intro']]
    if not domain:
        lines.append(f"系统：{snapshot['system_name']}")
    if test:
        lines.insert(0, '测试邮件：本次未向员工发送。')
    rows = [dict(text=line) for line in lines]

    def key_row(label, value, kind=None):
        row = dict(text=f'{label}：{value}')
        if kind:
            row.update(kind=kind, label=label, value=value)
        rows.append(row)

    key_row('登录账号', snapshot['account'], 'credential' if domain else None)
    if password:
        key_row('初始密码', password, 'credential' if domain else None)
    if not domain:
        key_row('密码说明', snapshot['password_instruction'])
    if wifi:
        rows.append(dict(kind='section', text='公司 Wi-Fi'))
        for network, secret in wifi.items():
            key_row(network, secret, 'wifi')
    for key, label, link_text in (
        ('login_url', '登录地址', '打开登录页面'),
        ('tutorial_url', '使用教程', '查看配置教程'),
        ('download_url', '客户端下载', '下载客户端'),
    ):
        if snapshot[key]:
            rows.append(dict(text=f'{label}：', href=snapshot[key], link_text=link_text))
    if snapshot['notes']:
        rows.append(dict(text=snapshot['notes']))
    if domain:
        key_row('密码说明', snapshot['password_instruction'], 'guidance')

    def html_row(row):
        content = esc(row['text'])
        kind = row.get('kind')
        if kind == 'credential':
            return ('<div style="margin:8px 0">'
                    f'<span style="display:block;font-size:12px;font-weight:600;color:#123e76">{esc(row["label"])}</span>'
                    '<strong style="display:inline-block;max-width:100%;box-sizing:border-box;padding:0 6px;'
                    'background-color:#eaf2ff;border-radius:4px;font-size:18px;color:#123e76;font-family:Consolas,monospace;'
                    f'word-break:break-all;white-space:pre-wrap">{esc(row["value"])}</strong></div>')
        if kind == 'wifi':
            return ('<div style="margin:6px 0;padding:9px 14px;background:#eef7f4;border-radius:6px">'
                    f'<span style="display:block;font-size:12px;color:#17483d">{esc(row["label"])}</span>'
                    '<strong style="font-size:15px;color:#17483d;font-family:Consolas,monospace;'
                    f'word-break:break-all;white-space:pre-wrap">{esc(row["value"])}</strong></div>')
        if kind == 'section':
            return f'<h2 style="font-size:15px;margin:20px 0 8px;color:#23473d">{content}</h2>'
        if kind == 'guidance':
            return (f'<h2 style="font-size:14px;margin:16px 0 4px;color:#263449">{esc(row["label"])}</h2>'
                    f'<p style="margin:0 0 10px;white-space:pre-wrap">{esc(row["value"])}</p>')
        if 'href' in row:
            url = esc(row['href'])
            content += (f'<a href="{url}" title="{url}" target="_blank" rel="noopener noreferrer" '
                        f'style="color:#1768dd;text-decoration:underline">{esc(row["link_text"])}</a>')
        return f'<p style="margin:10px 0;white-space:pre-wrap">{content}</p>'

    html_rows = ''.join(map(html_row, rows))
    body = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><body style="margin:0;'
            'padding:24px;background:#f4f7fb;font-family:Arial,Microsoft YaHei,sans-serif;color:#263449">'
            '<div style="max-width:620px;margin:auto;background:white;border:1px solid #dce5ef;'
            'border-radius:8px;overflow:hidden"><div style="padding:20px 24px;background:#1768dd;'
            f'color:white;font-size:20px;font-weight:bold">{esc(snapshot["system_name"])} · 账号开通通知</div>'
            f'<div style="padding:20px 24px;line-height:1.7;overflow-wrap:anywhere">{html_rows}</div>'
            '<div style="padding:14px 24px;border-top:1px solid #e5ebf3;color:#697a91;font-size:12px">'
            'IT 账号通知 · 请勿向无关人员转发账号资料。</div></div></body></html>')
    return '\n\n'.join(row['text'] + row.get('href', '') for row in rows), body, rows


def register_notifications(app, db, models, current_user, touch_session, get_ad_connection, audit,
                           get_setting, set_setting):
    Template, Attachment, Delivery = models
    bp = Blueprint('account_notifications', __name__, url_prefix='/api/admin/account-notifications')
    signer = URLSafeTimedSerializer(app.secret_key, salt='account-notification-preview-v1')

    def initial_password_key(row):
        return f'account_notice_initial_password:{row.id}'

    def wifi_password_key(row, network):
        return f'account_notice_wifi:{row.id}:{network}'

    def template_secret_cipher(setting_key):
        key = hmac.digest(app.secret_key.encode(), setting_key.encode(), 'sha256')
        return Fernet(base64.urlsafe_b64encode(key))

    def save_template_secret(setting_key, password):
        encrypted = template_secret_cipher(setting_key).encrypt(password.encode()).decode('ascii')
        set_setting(setting_key, encrypted)

    def read_template_secret(setting_key, label):
        encrypted = get_setting(setting_key, '')
        try:
            return template_secret_cipher(setting_key).decrypt(encrypted.encode('ascii')).decode() if encrypted else ''
        except (InvalidToken, UnicodeError):
            raise NoticeError(f'{label}无法读取，请在模板中重新保存', 409) from None

    def wifi_credentials(row):
        return {network: password for network in DOMAIN_WIFI_NETWORKS
                if (password := read_template_secret(wifi_password_key(row, network), network + ' 密码'))} if domain_template(row) else {}

    def password_digest(value):
        return hmac.new(app.secret_key.encode(), value.encode(), hashlib.sha256).hexdigest() if value else ''

    def wifi_digest(wifi):
        return password_digest('wifi:' + canonical(wifi)) if wifi else ''

    @bp.before_request
    def authorize():
        user = current_user() if session.get('admin_logged_in') else None
        if not user:
            return jsonify(success=False, message='未登录，请重新登录'), 401
        if user.role != 'super_admin':
            return jsonify(success=False, message='仅超级管理员可管理和发送账号通知'), 403
        touch_session()
        if request.method != 'GET':
            expected = session.get('account_notice_csrf', '')
            supplied = request.headers.get('X-CSRF-Token', '')
            if not expected or not secrets.compare_digest(expected, supplied):
                raise NoticeError('页面已失效，请刷新后重试', 403)
            origin = request.headers.get('Origin')
            if origin and urlsplit(origin).netloc != request.host:
                raise NoticeError('不允许跨站提交', 403)
        if request.content_length and request.content_length > MAX_TOTAL + 65536:
            raise NoticeError('请求内容过大', 413)

    @bp.errorhandler(NoticeError)
    def invalid(error):
        return jsonify(success=False, message=str(error)), error.status

    def data(allowed):
        value = request.get_json(silent=True)
        if not isinstance(value, dict) or set(value) - set(allowed):
            raise NoticeError('请求字段不正确')
        return value

    def get_template(ident):
        row = db.session.get(Template, ident) if isinstance(ident, str) else None
        if not row:
            raise NoticeError('通知模板不存在', 404)
        return row

    def files(row):
        if domain_template(row):
            return []
        return Attachment.query.filter_by(template_id=row.id).order_by(Attachment.id).all()

    def password_instruction(row):
        if domain_template(row):
            return (row.password_instruction if row.password_instruction not in ('', PASSWORD_NOTICE, OLD_DOMAIN_PASSWORD_NOTICE)
                    else DOMAIN_PASSWORD_NOTICE)
        if row.id == VPN_TEMPLATE_ID:
            return row.password_instruction or PASSWORD_NOTICE
        return PASSWORD_NOTICE

    def public_template(row):
        domain_settings = dict(domain_account=True, wifi_configured=[
            network for network in DOMAIN_WIFI_NETWORKS if get_setting(wifi_password_key(row, network), '')
        ]) if domain_template(row) else {}
        return dict(id=row.id, active=row.active, version=row.version,
            **domain_settings,
            **{key: password_instruction(row) if key == 'password_instruction' else getattr(row, key) for key in TEMPLATE_FIELDS},
            attachments=[dict(id=f.id, filename=f.filename, size=len(f.content), private_key=f.private_key) for f in files(row)])

    def public_delivery(row):
        status, message = row.status, row.message
        snapshot = json.loads(row.snapshot)
        if status == 'sending' and datetime.utcnow() - row.created_at > timedelta(minutes=5):
            status = 'unknown'
            message = ('开通结果待确认，请先核对路由器和邮箱，不要重复提交' if snapshot.get('vpn_status') == 'pending'
                       else '发送进程未确认结果，请核对邮箱后决定是否重新发送')
        if snapshot.get('vpn_status') == 'created':
            message = f'VPN 账号 {snapshot["account"]} 创建成功。{message}'
        return dict(id=row.id, operator=row.operator, mode=row.mode, to_email=row.to_email,
            cc_email=snapshot.get('cc_email', '') if row.mode == 'employee' else '',
            subject=row.subject, status=status, message=message,
            created_at=row.created_at.isoformat() + 'Z', snapshot=snapshot)

    @bp.get('/config')
    def config():
        if not session.get('account_notice_csrf'):
            session['account_notice_csrf'] = secrets.token_urlsafe(32)
        ready = all(app.config.get(key) for key in ('MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD'))
        return jsonify(success=True, csrf_token=session['account_notice_csrf'], mail_ready=ready,
                       sender=app.config.get('MAIL_USERNAME', ''), operator=current_user().username,
                       default_cc_email=DEFAULT_CC_EMAIL, password_notice=PASSWORD_NOTICE,
                       domain_default_cc_email=DOMAIN_DEFAULT_CC_EMAIL,
                       vpn_template_id=VPN_TEMPLATE_ID)

    @bp.route('/templates', methods=['GET', 'POST'])
    @bp.route('/templates/<ident>', methods=['POST'])
    def templates(ident=None):
        if request.method == 'GET':
            return jsonify(success=True, templates=[public_template(row) for row in Template.query.order_by(Template.name).all()])
        value = data((*TEMPLATE_FIELDS, 'active', 'version', 'initial_password', 'wifi_passwords'))
        row = get_template(ident) if ident else None
        is_domain = domain_template(row) or (ident != VPN_TEMPLATE_ID and value.get('name') == DOMAIN_TEMPLATE_NAME)
        initial_password = notice_password(value.get('initial_password', ''))
        if initial_password and (not is_domain or len(initial_password.encode()) > 256):
            raise NoticeError('默认初始密码只适用于域账号开通模板，最多 128 个字符且不超过 256 字节')
        wifi = value.get('wifi_passwords', {})
        if not isinstance(wifi, dict) or set(wifi) - set(DOMAIN_WIFI_NETWORKS) or (wifi and not is_domain):
            raise NoticeError('只可为域账号开通模板设置 WIFI-OA 和 WIFI-Mobile 的密码')
        for secret in wifi.values():
            if len(notice_password(secret).encode()) > 256:
                raise NoticeError('Wi-Fi 密码最多 128 个字符且不超过 256 字节')
        cleaned = {}
        for key in TEMPLATE_FIELDS:
            if key == 'password_instruction':
                if is_domain or ident == VPN_TEMPLATE_ID:
                    hint = text(value.get(key, row.password_instruction if row else ''), 500)
                    cleaned[key] = hint or (DOMAIN_PASSWORD_NOTICE if is_domain else PASSWORD_NOTICE)
                else:
                    cleaned[key] = PASSWORD_NOTICE
                continue
            if is_domain and key in URL_FIELDS:
                cleaned[key] = getattr(row, key) if row else ''
                continue
            limit = 4000 if key == 'intro' else 200 if key == 'subject' else 120
            cleaned[key] = web_url(value.get(key, '')) if key in URL_FIELDS else text(
                value.get(key, ''), 80 if key == 'name' else limit,
                required=key in ('name', 'system_name', 'subject', 'intro'), multiline=key == 'intro')
        if is_domain:
            cleaned['name'] = DOMAIN_TEMPLATE_NAME
        active = value.get('active', True)
        if not isinstance(active, bool):
            raise NoticeError('模板启用状态不正确')
        if ident:
            if type(value.get('version')) is not int or value['version'] < 1:
                raise NoticeError('模板版本不正确，请刷新后重试')
            count = Template.query.filter_by(id=ident, version=value.get('version')).update(
                {**cleaned, 'active': active, 'version': row.version + 1, 'updated_at': datetime.utcnow()}, synchronize_session=False)
            if count != 1:
                db.session.rollback()
                raise NoticeError('模板已被修改，请刷新后重试', 409)
        else:
            row = Template(id=str(uuid.uuid4()), active=active, **cleaned)
            db.session.add(row)
        if initial_password:
            save_template_secret(initial_password_key(row), initial_password)
        for network, secret in wifi.items():
            if secret:
                save_template_secret(wifi_password_key(row, network), secret)
        db.session.commit()
        db.session.expire_all()
        audit('保存账号通知模板', 'SYSTEM', f'模板:{row.id}', request.remote_addr)
        return jsonify(success=True, template=public_template(get_template(row.id)))

    @bp.post('/templates/<ident>/initial-password')
    def load_initial_password(ident):
        row = get_template(ident)
        if not domain_template(row) or not row.active:
            raise NoticeError('此模板不提供默认初始密码', 404)
        password = (read_template_secret(initial_password_key(row), '默认初始密码')
                    or os.environ.get('AD_PRECREATE_DEFAULT_PASSWORD', app.config.get('AD_PRECREATE_DEFAULT_PASSWORD', '')))
        response = jsonify(success=True, password=notice_password(password))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @bp.post('/templates/<ident>/attachments')
    def upload(ident):
        row = get_template(ident)
        if domain_template(row):
            raise NoticeError('域账号开通模板不发送附件')
        value = request.files.get('file')
        if not value:
            raise NoticeError('请选择附件')
        name = text(value.filename, 120, True)
        if '/' in name or '\\' in name or not name.lower().endswith(('.ovpn', '.pdf')):
            raise NoticeError('仅支持不含路径的 .ovpn 或 .pdf 附件')
        content = value.stream.read(MAX_ATTACHMENT + 1)
        if not content or len(content) > MAX_ATTACHMENT:
            raise NoticeError('单个附件必须为 1 字节至 2 MiB')
        existing = files(row)
        if len(existing) >= 3 or sum(len(f.content) for f in existing) + len(content) > MAX_TOTAL:
            raise NoticeError('每个模板最多 3 个附件，总大小最多 5 MiB')
        if name.lower().endswith('.pdf') and not content.startswith(b'%PDF-'):
            raise NoticeError('PDF 文件格式不正确')
        if name.lower().endswith('.ovpn') and b'\x00' in content:
            raise NoticeError('OVPN 文件必须是文本配置')
        if Template.query.filter_by(id=row.id, version=row.version).update(
                {'version': row.version + 1}, synchronize_session=False) != 1:
            db.session.rollback()
            raise NoticeError('模板已变更，请刷新后上传', 409)
        db.session.add(Attachment(id=str(uuid.uuid4()), template_id=row.id, filename=name,
                                  content=content, private_key=b'<key>' in content.lower()))
        db.session.commit()
        db.session.expire_all()
        audit('上传账号通知附件', 'SYSTEM', f'模板:{row.id}', request.remote_addr)
        return jsonify(success=True, template=public_template(get_template(ident)))

    @bp.route('/attachments/<ident>', methods=['GET', 'DELETE'])
    def attachment(ident):
        row = db.session.get(Attachment, ident)
        if not row:
            raise NoticeError('附件不存在', 404)
        if request.method == 'GET':
            response = send_file(io.BytesIO(row.content), mimetype='application/octet-stream',
                                 as_attachment=True, download_name=row.filename)
            response.headers['Cache-Control'] = 'no-store'
            return response
        template = get_template(row.template_id)
        if Template.query.filter_by(id=template.id, version=template.version).update(
                {'version': template.version + 1}, synchronize_session=False) != 1:
            db.session.rollback()
            raise NoticeError('模板已变更，请刷新后重试', 409)
        db.session.delete(row)
        db.session.commit()
        audit('移除账号通知附件', 'SYSTEM', f'模板:{template.id}', request.remote_addr)
        return jsonify(success=True)

    @bp.get('/recipients')
    def recipients():
        query = text(request.args.get('q', ''), 80, True)
        if len(query) < 2:
            raise NoticeError('请输入至少 2 个字或字符')
        exact = request.args.get('exact') == '1'
        conn = None
        try:
            conn = get_ad_connection()
            needle = escape_filter_chars(query)
            match = needle if exact else f'*{needle}*'
            conn.search(app.config['AD_BASE_DN'],
                '(&(objectCategory=person)(objectClass=user)(|' +
                ''.join(f'({field}={match})' for field in ('sAMAccountName', 'displayName', 'description', 'cn')) + '))',
                ldap3.SUBTREE, attributes=['sAMAccountName', 'displayName', 'description', 'cn', 'mail', 'department'],
                size_limit=12, time_limit=5)
            if conn.result.get('result') not in (0, 4):
                raise NoticeError('AD 查询失败，请稍后重试', 503)
            result = []
            for entry in conn.entries:
                attrs = entry.entry_attributes_as_dict
                def first(key):
                    values = attrs.get(key, [])
                    return str(values[0]) if values and values[0] is not None else ''
                mail = first('mail').strip()
                email_status = directory_email_status(mail)
                matched_name = next((first(key) for key in ('description', 'displayName', 'cn')
                    if first(key).casefold() == query.casefold()), '') if exact else ''
                name = matched_name or first('description') or first('displayName') or first('cn') or first('sAMAccountName')
                result.append(dict(employee_id=first('sAMAccountName'), name=name, suggested_account=suggested_account(name),
                    email=mail, email_status=email_status, department=first('department')))
            return jsonify(success=True, recipients=result, suggested_account=suggested_account(query),
                           exact=exact, truncated=conn.result.get('result') == 4)
        except NoticeError:
            raise
        except Exception as exc:
            app.logger.warning('账号通知员工查询失败: %s', type(exc).__name__)
            raise NoticeError('无法查询 AD 员工，可手动填写收件信息', 503) from None
        finally:
            if conn is not None:
                try:
                    conn.unbind()
                except Exception:
                    pass

    @bp.post('/recipients/email')
    def save_recipient_email():
        value = data(('template_id', 'employee_id', 'email'))
        template = get_template(value.get('template_id'))
        if not domain_template(template) or not template.active:
            raise NoticeError('仅域账号开通模板支持补全 AD 邮箱')
        employee_id = text(value.get('employee_id', ''), 64, True)
        address = email_address(value.get('email', ''))
        conn = None
        writing = False
        try:
            conn = get_ad_connection()
            conn.search(app.config['AD_BASE_DN'],
                f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={escape_filter_chars(employee_id)}))',
                ldap3.SUBTREE, attributes=['mail'], size_limit=2, time_limit=5)
            result = conn.result.get('result')
            if result == 4 or len(conn.entries) > 1:
                raise NoticeError('无法唯一确认员工域账号，请重新查询', 409)
            if result != 0:
                raise NoticeError('AD 查询失败，未保存邮箱，可手动填写后发送', 503)
            if not conn.entries:
                raise NoticeError('未找到该域账号，未保存邮箱', 404)
            entry = conn.entries[0]
            old_values = [value for value in entry.entry_attributes_as_dict.get('mail', []) if isinstance(value, str)]
            if any(directory_email_status(old) == 'valid' for old in old_values):
                raise NoticeError('该账号已有有效 AD 邮箱，没有覆盖。可仅用手填地址发送本次通知', 409)
            # AD mail is single-valued. Delete only the value we read, then add the new value atomically.
            changes = [(ldap3.MODIFY_DELETE, old_values)] if old_values else []
            changes.append((ldap3.MODIFY_ADD, [address]))
            writing = True
            conn.modify(entry.entry_dn, {'mail': changes})
            result = conn.result.get('result')
            if result in (16, 19, 20):
                raise NoticeError('AD 邮箱可能已被修改，请重新查询，没有覆盖原值', 409)
            if result == 50:
                raise NoticeError('当前 AD 连接没有修改邮箱的权限，仍可使用手填地址发送本次通知', 403)
            if result != 0:
                raise NoticeError('AD 未确认保存邮箱，请重新查询，仍可手动发送本次通知', 503)
        except NoticeError:
            raise
        except Exception as exc:
            app.logger.warning('账号通知保存 AD 邮箱异常: %s', type(exc).__name__)
            message = 'AD 邮箱写入结果未确认，请重新查询' if writing else '无法连接 AD，未保存邮箱'
            raise NoticeError(message, 503) from None
        finally:
            if conn is not None:
                try:
                    conn.unbind()
                except Exception:
                    pass
        message = '邮箱已保存到 AD'
        try:
            audit('补全 AD 邮箱', employee_id, '仅更新 AD 邮箱属性', request.remote_addr)
        except Exception:
            db.session.rollback()
            app.logger.warning('补全 AD 邮箱成功，但审计记录保存失败')
            message += '，但审计记录保存失败'
        return jsonify(success=True, email=address, message=message)

    @bp.post('/preview')
    def preview():
        value = data(('template_id', 'version', 'password', *FORM_FIELDS))
        password = notice_password(value.get('password', ''))
        row = get_template(value.get('template_id'))
        if not row.active or type(value.get('version')) is not int or row.version != value.get('version'):
            raise NoticeError('模板已停用或变更，请重新选择模板', 409)
        snapshot = dict(template_id=row.id, version=row.version, system_name=row.system_name,
                        subject=row.subject, intro=row.intro)
        is_domain = domain_template(row)
        for key in FORM_FIELDS:
            if key == 'password_instruction':
                snapshot[key] = password_instruction(row)
                continue
            raw = value.get(key, '')
            if is_domain and key in URL_FIELDS:
                snapshot[key] = ''
                continue
            if is_domain and key == 'account':
                raw = snapshot['employee_id'] or raw
            if key == 'cc_email':
                snapshot[key] = cc_address_list(raw)
                continue
            snapshot[key] = (email_address(raw) if key == 'to_email' else web_url(raw) if key in URL_FIELDS else
                text(raw, 1000 if key == 'notes' else 64 if key == 'employee_id' else 120,
                     required=key in ('recipient_name', 'account'), multiline=key == 'notes'))
        snapshot['attachments'] = [dict(id=f.id, filename=f.filename, digest=hashlib.sha256(f.content).hexdigest()) for f in files(row)]
        snapshot['password_included'] = bool(password)
        wifi = wifi_credentials(row)
        plain, body, rows = render_notice(snapshot, password=password, domain=is_domain, wifi=wifi)
        token = signer.dumps(dict(operator=current_user().username, snapshot=snapshot,
                                  password_digest=password_digest(password), wifi_digest=wifi_digest(wifi)))
        response = jsonify(success=True, preview_token=token, subject=row.subject, html=body,
                           text=plain, rows=rows, recipient=snapshot['to_email'], cc_email=snapshot['cc_email'])
        response.headers['Cache-Control'] = 'no-store'
        return response

    @bp.post('/send')
    def send():
        value = data(('preview_token', 'request_key', 'mode', 'test_email', 'confirm_text', 'password', 'provision_vpn'))
        if value.get('provision_vpn', False) is not False:
            raise NoticeError('VPN 自动开通已停用，请刷新页面并在路由器后台手动开通。未发送邮件。')
        password = notice_password(value.get('password', ''))
        if value.get('confirm_text') != 'SEND':
            raise NoticeError('请先预览并确认收件人后发送')
        try:
            key = str(uuid.UUID(value.get('request_key', '')))
            signed = signer.loads(value.get('preview_token', ''), max_age=600)
        except (ValueError, TypeError, AttributeError, BadSignature, SignatureExpired):
            raise NoticeError('预览已失效，请重新预览') from None
        operator = current_user().username
        if signed.get('operator') != operator:
            raise NoticeError('预览不属于当前操作人', 403)
        if not hmac.compare_digest(signed.get('password_digest', ''), password_digest(password)):
            raise NoticeError('密码已修改，请重新预览后发送', 409)
        snapshot = signed['snapshot']
        mode = value.get('mode', 'employee')
        if mode not in ('employee', 'test'):
            raise NoticeError('发送方式不正确')
        to = email_address(value.get('test_email', '')) if mode == 'test' else snapshot['to_email']
        cc = snapshot.get('cc_email', '') if mode == 'employee' else ''
        cc_recipients = cc.split(', ') if cc else []
        intent = dict(snapshot=snapshot, mode=mode, to=to, password_digest=password_digest(password))
        if signed.get('wifi_digest'):
            intent['wifi_digest'] = signed['wifi_digest']
        fingerprint = hashlib.sha256(canonical(intent).encode()).hexdigest()
        def replay(row):
            if row.fingerprint != fingerprint:
                raise NoticeError('同一发送标识不能携带不同内容', 409)
            delivery = public_delivery(row)
            return jsonify(success=True, replayed=True, delivery=delivery, message=delivery['message'])
        existing = Delivery.query.filter_by(operator=operator, request_key=key).first()
        if existing:
            return replay(existing)
        template = get_template(snapshot['template_id'])
        if not template.active or template.version != snapshot['version']:
            raise NoticeError('模板或附件已变更，请重新预览', 409)
        wifi = wifi_credentials(template)
        if not hmac.compare_digest(signed.get('wifi_digest', ''), wifi_digest(wifi)):
            raise NoticeError('Wi-Fi 密码已更新，请重新预览后发送', 409)
        attachments = files(template)
        current_files = [dict(id=f.id, filename=f.filename, digest=hashlib.sha256(f.content).hexdigest()) for f in attachments]
        if current_files != snapshot['attachments']:
            raise NoticeError('附件已变更，请重新预览', 409)
        if not all(app.config.get(k) for k in ('MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD')):
            raise NoticeError('现有 SMTP 配置不完整，请联系管理员', 503)
        try:
            sender = email_address(app.config['MAIL_USERNAME'])
            port = int(app.config['MAIL_PORT'])
            if not 1 <= port <= 65535:
                raise ValueError()
        except (NoticeError, ValueError, TypeError):
            raise NoticeError('现有 SMTP 发件邮箱或端口配置不正确', 503) from None
        if Delivery.query.filter(Delivery.operator == operator,
                Delivery.created_at > datetime.utcnow() - timedelta(minutes=1)).count() >= 10:
            raise NoticeError('发送过于频繁，请一分钟后再试', 429)
        row = Delivery(id=str(uuid.uuid4()), operator=operator, request_key=key, fingerprint=fingerprint,
            snapshot=canonical(snapshot), mode=mode, to_email=to,
            subject=('【测试】' if mode == 'test' else '') + snapshot['subject'])
        db.session.add(row)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return replay(Delivery.query.filter_by(operator=operator, request_key=key).one())
        try:
            audit('发送账号通知' if mode == 'employee' else '测试账号通知', (snapshot['employee_id'] or 'MANUAL')[:20],
                  f'记录:{row.id} | 收件:{to}', request.remote_addr)
        except Exception:
            db.session.rollback()
            row.status, row.message = 'failed', '审计记录保存失败，未发送邮件'
            db.session.commit()
            return jsonify(success=False, delivery=public_delivery(row), message=row.message), 500
        plain, body, _ = render_notice(snapshot, mode == 'test', password=password,
                                      domain=domain_template(template), wifi=wifi)
        message = EmailMessage()
        message['From'], message['To'], message['Subject'] = sender, to, row.subject
        if cc:
            message['Cc'] = cc
        message['Message-ID'] = f'<account-notice-{row.id}@{app.config["MAIL_USERNAME"].split("@")[-1]}>'
        message.set_content(plain)
        message.add_alternative(body, subtype='html')
        for file in attachments:
            message.add_attachment(file.content, maintype='application', subtype='octet-stream', filename=file.filename)
        try:
            # SMTP may accept DATA before a disconnect. Never blindly retry an uncertain result.
            with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], port,
                                  timeout=15, context=ssl.create_default_context()) as smtp:
                smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                refused = smtp.send_message(message, to_addrs=list(dict.fromkeys([to, *cc_recipients])))
            if refused:
                rejected = '、'.join(label for match, label in ((to in refused, '收件邮箱'),
                    (any(address in refused for address in cc_recipients), '抄送邮箱')) if match)
                row.status, row.message = 'partial', f'邮件服务器拒绝了{rejected or "部分收件人"}，其余已接受；请核对邮箱，不要直接重复发送'
            else:
                row.status, row.message = 'submitted', '邮件服务器已接受；不代表收件人已收到或阅读'
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPAuthenticationError, smtplib.SMTPDataError,
                smtplib.SMTPSenderRefused, smtplib.SMTPNotSupportedError):
            row.status, row.message = 'failed', '邮件服务器拒绝提交，请核对配置或收件邮箱'
        except (OSError, smtplib.SMTPException):
            row.status, row.message = 'unknown', '连接中断或超时，结果待确认；请先核对邮箱，避免重复发送'
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify(success=False, message='邮件可能已提交，但结果保存失败；请勿直接重复发送'), 503
        delivery = public_delivery(row)
        return jsonify(success=row.status == 'submitted', delivery=delivery, message=delivery['message'])

    @bp.get('/deliveries')
    def deliveries():
        try:
            page = max(1, int(request.args.get('page', '1')))
        except ValueError:
            raise NoticeError('页码不正确') from None
        query = Delivery.query.order_by(Delivery.created_at.desc(), Delivery.id.desc())
        return jsonify(success=True, total=query.count(), page=page,
                       deliveries=[public_delivery(row) for row in query.offset((page - 1) * 20).limit(20)])

    @bp.after_request
    def private(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    app.register_blueprint(bp)
    return bp
