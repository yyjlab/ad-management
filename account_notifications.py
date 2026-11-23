"""Account notices only: no account provisioning and no password delivery."""
import hashlib
import html
import io
import json
import re
import secrets
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlsplit

import ldap3
from flask import Blueprint, jsonify, request, send_file, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy.exc import IntegrityError

MAX_ATTACHMENT = 2 * 1024 * 1024
MAX_TOTAL = 5 * 1024 * 1024
URL_FIELDS = ('login_url', 'tutorial_url', 'download_url')
TEMPLATE_FIELDS = ('name', 'system_name', 'subject', 'intro', *URL_FIELDS, 'password_instruction')
FORM_FIELDS = ('employee_id', 'recipient_name', 'to_email', 'account', 'notes',
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
        ('8a92f00a-dcb8-4c27-8638-000000000001', 'VPN 开通', '公司 VPN'),
        ('8a92f00a-dcb8-4c27-8638-000000000002', '通用账号开通', '业务系统'),
    ):
        if not db.session.get(Template, ident):
            db.session.add(Template(id=ident, name=name, system_name=system,
                subject=f'【账号开通】{system}', intro='您的账号已开通，请按以下信息使用。',
                password_instruction='密码由 IT 单独提供，或使用已约定的现有密码。'))


def render_notice(snapshot, test=False):
    esc = lambda value: html.escape(str(value), quote=True)
    lines = [f"您好，{snapshot['recipient_name']}：", snapshot['intro'],
             f"系统：{snapshot['system_name']}", f"登录账号：{snapshot['account']}",
             f"密码说明：{snapshot['password_instruction']}"]
    for key, label in zip(URL_FIELDS, ('登录地址', '使用教程', '客户端下载')):
        if snapshot[key]:
            lines.append(f'{label}：{snapshot[key]}')
    if snapshot['notes']:
        lines.append(snapshot['notes'])
    if test:
        lines.insert(0, '测试邮件：本次未向员工发送。')
    rows = ''.join(f'<p style="margin:10px 0;white-space:pre-wrap">{esc(line)}</p>' for line in lines)
    body = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><body style="margin:0;'
            'padding:24px;background:#f4f7fb;font-family:Arial,Microsoft YaHei,sans-serif;color:#263449">'
            '<div style="max-width:620px;margin:auto;background:white;border:1px solid #dce5ef;'
            'border-radius:8px;overflow:hidden"><div style="padding:20px 24px;background:#1768dd;'
            f'color:white;font-size:20px;font-weight:bold">{esc(snapshot["system_name"])} · 账号开通通知</div>'
            f'<div style="padding:20px 24px;line-height:1.7;overflow-wrap:anywhere">{rows}</div>'
            '<div style="padding:14px 24px;border-top:1px solid #e5ebf3;color:#697a91;font-size:12px">'
            'IT 账号通知 · 请勿向无关人员转发账号资料。</div></div></body></html>')
    return '\n\n'.join(lines), body


def register_notifications(app, db, models, current_user, touch_session, get_ad_connection, audit):
    Template, Attachment, Delivery = models
    bp = Blueprint('account_notifications', __name__, url_prefix='/api/admin/account-notifications')
    signer = URLSafeTimedSerializer(app.secret_key, salt='account-notification-preview-v1')

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
            raise NoticeError('请求字段不正确；本版不接受或发送明文密码')
        return value

    def get_template(ident):
        row = db.session.get(Template, ident) if isinstance(ident, str) else None
        if not row:
            raise NoticeError('通知模板不存在', 404)
        return row

    def files(row):
        return Attachment.query.filter_by(template_id=row.id).order_by(Attachment.id).all()

    def public_template(row):
        return dict(id=row.id, active=row.active, version=row.version,
            **{key: getattr(row, key) for key in TEMPLATE_FIELDS},
            attachments=[dict(id=f.id, filename=f.filename, size=len(f.content), private_key=f.private_key) for f in files(row)])

    def public_delivery(row):
        status, message = row.status, row.message
        if status == 'sending' and datetime.utcnow() - row.created_at > timedelta(minutes=5):
            status, message = 'unknown', '发送进程未确认结果，请核对邮箱后决定是否重新发送'
        return dict(id=row.id, operator=row.operator, mode=row.mode, to_email=row.to_email,
            subject=row.subject, status=status, message=message,
            created_at=row.created_at.isoformat() + 'Z', snapshot=json.loads(row.snapshot))

    @bp.get('/config')
    def config():
        if not session.get('account_notice_csrf'):
            session['account_notice_csrf'] = secrets.token_urlsafe(32)
        ready = all(app.config.get(key) for key in ('MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD'))
        return jsonify(success=True, csrf_token=session['account_notice_csrf'], mail_ready=ready,
                       sender=app.config.get('MAIL_USERNAME', ''), operator=current_user().username)

    @bp.route('/templates', methods=['GET', 'POST'])
    @bp.route('/templates/<ident>', methods=['POST'])
    def templates(ident=None):
        if request.method == 'GET':
            return jsonify(success=True, templates=[public_template(row) for row in Template.query.order_by(Template.name).all()])
        value = data((*TEMPLATE_FIELDS, 'active', 'version'))
        cleaned = {}
        for key in TEMPLATE_FIELDS:
            limit = 4000 if key == 'intro' else 500 if key == 'password_instruction' else 200 if key == 'subject' else 120
            cleaned[key] = web_url(value.get(key, '')) if key in URL_FIELDS else text(
                value.get(key, ''), 80 if key == 'name' else limit,
                required=key in ('name', 'system_name', 'subject', 'intro'), multiline=key == 'intro')
        active = value.get('active', True)
        if not isinstance(active, bool):
            raise NoticeError('模板启用状态不正确')
        if ident:
            row = get_template(ident)
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
        db.session.commit()
        db.session.expire_all()
        audit('保存账号通知模板', 'SYSTEM', f'模板:{row.id}', request.remote_addr)
        return jsonify(success=True, template=public_template(get_template(row.id)))

    @bp.post('/templates/<ident>/attachments')
    def upload(ident):
        row = get_template(ident)
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
                try:
                    email_address(mail)
                    email_status = 'valid'
                except NoticeError:
                    email_status = 'invalid' if mail else 'missing'
                matched_name = next((first(key) for key in ('description', 'displayName', 'cn')
                    if first(key).casefold() == query.casefold()), '') if exact else ''
                result.append(dict(employee_id=first('sAMAccountName'),
                    name=matched_name or first('description') or first('displayName') or first('cn') or first('sAMAccountName'),
                    email=mail, email_status=email_status, department=first('department')))
            return jsonify(success=True, recipients=result, exact=exact, truncated=conn.result.get('result') == 4)
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

    @bp.post('/preview')
    def preview():
        value = data(('template_id', 'version', *FORM_FIELDS))
        row = get_template(value.get('template_id'))
        if not row.active or type(value.get('version')) is not int or row.version != value.get('version'):
            raise NoticeError('模板已停用或变更，请重新选择模板', 409)
        snapshot = dict(template_id=row.id, version=row.version, system_name=row.system_name,
                        subject=row.subject, intro=row.intro)
        for key in FORM_FIELDS:
            raw = value.get(key, '')
            snapshot[key] = (email_address(raw) if key == 'to_email' else web_url(raw) if key in URL_FIELDS else
                text(raw, 1000 if key == 'notes' else 500 if key == 'password_instruction' else 64 if key == 'employee_id' else 120,
                     required=key in ('recipient_name', 'account', 'password_instruction'), multiline=key == 'notes'))
        snapshot['attachments'] = [dict(id=f.id, filename=f.filename, digest=hashlib.sha256(f.content).hexdigest()) for f in files(row)]
        plain, body = render_notice(snapshot)
        token = signer.dumps(dict(operator=current_user().username, snapshot=snapshot))
        return jsonify(success=True, preview_token=token, subject=row.subject, html=body,
                       text=plain, recipient=snapshot['to_email'])

    @bp.post('/send')
    def send():
        value = data(('preview_token', 'request_key', 'mode', 'test_email', 'confirm_text'))
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
        snapshot = signed['snapshot']
        mode = value.get('mode', 'employee')
        if mode not in ('employee', 'test'):
            raise NoticeError('发送方式不正确')
        to = email_address(value.get('test_email', '')) if mode == 'test' else snapshot['to_email']
        fingerprint = hashlib.sha256(canonical(dict(snapshot=snapshot, mode=mode, to=to)).encode()).hexdigest()
        def replay(row):
            if row.fingerprint != fingerprint:
                raise NoticeError('同一发送标识不能携带不同内容', 409)
            return jsonify(success=True, replayed=True, delivery=public_delivery(row))
        existing = Delivery.query.filter_by(operator=operator, request_key=key).first()
        if existing:
            return replay(existing)
        template = get_template(snapshot['template_id'])
        if not template.active or template.version != snapshot['version']:
            raise NoticeError('模板或附件已变更，请重新预览', 409)
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
        plain, body = render_notice(snapshot, mode == 'test')
        message = EmailMessage()
        message['From'], message['To'], message['Subject'] = sender, to, row.subject
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
                refused = smtp.send_message(message)
                if refused:
                    raise smtplib.SMTPRecipientsRefused(refused)
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
        return jsonify(success=row.status == 'submitted', delivery=public_delivery(row), message=row.message)

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
