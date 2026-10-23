# ============================================================
# 员工自助注册系统 - 主程序
# 功能：员工通过任意邮箱验证，自动在Windows AD里创建账号
#       + 忘记密码：发重置链接到邮箱，点链接设置新密码
# 运行环境：Docker容器（gunicorn启动）
# ============================================================

import os
import random
import string
import smtplib
import re
import secrets
import logging
import json
import hashlib
import hmac
import shutil
import subprocess
import sys
import struct
import uuid
from collections import Counter
from functools import wraps
import threading
import time
import ssl
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

from flask import Flask, request, jsonify, session, Response, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash
import ldap3
from ldap3.core.exceptions import LDAPException
from urllib.parse import urlencode, urlsplit
from dingtalk_auth import DingTalkClient, DingTalkConfig, DingTalkError
from gpo_password_policy import GpoPasswordPolicy, PolicyError, validate_changes as validate_gpo_changes
from gpo_endpoint_policy import GpoEndpointPolicy, validate_policy as validate_endpoint_policy
from ad_precreate import PrecreateDirectory, PrecreateError, account_ids, build_user_attributes, validate_spec
from ad_bulk_delete import (BulkDeleteDirectory, DAYS as BULK_DELETE_DAYS, LIMIT as BULK_DELETE_LIMIT,
                            blocked_reason, snapshot, entry_text as bulk_delete_entry_text)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ============================================================
# 初始化 Flask 应用
# ============================================================
app = Flask(__name__)
app.config.from_object('config.Config')


def ensure_stable_secret_key():
    """
    Gunicorn 多 worker 时必须使用稳定 SECRET_KEY。
    如果配置里用了随机值，每次请求落到不同 worker 会导致后台登录态异常。
    """
    secret_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.flask_secret_key')
    secret = os.environ.get('FLASK_SECRET_KEY') or os.environ.get('SECRET_KEY')
    if not secret:
        if os.path.exists(secret_file):
            with open(secret_file, 'r', encoding='utf-8') as f:
                secret = f.read().strip()
        else:
            secret = secrets.token_urlsafe(48)
            try:
                fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(secret)
            except FileExistsError:
                with open(secret_file, 'r', encoding='utf-8') as f:
                    secret = f.read().strip()
    app.config['SECRET_KEY'] = secret


ensure_stable_secret_key()
app.config.setdefault('SESSION_COOKIE_NAME', 'employee_register_admin_session')
db = SQLAlchemy(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10 per minute"],
    storage_uri="memory://"
)

# ============================================================
# 日志配置
# 三个独立日志文件，都在 app.py 同目录下：
#   register.log → 注册相关操作
#   reset.log    → 重置密码相关操作
#   admin.log    → 管理员后台操作（禁用/删除账号）
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

log_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s',
                                   datefmt='%Y-%m-%d %H:%M:%S')

def make_logger(name, filename):
    """创建独立logger，同时写文件和控制台"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(os.path.join(BASE_DIR, filename), encoding='utf-8')
    fh.setFormatter(log_formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(log_formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

register_logger = make_logger('register', 'register.log')  # 注册日志
reset_logger    = make_logger('reset',    'reset.log')     # 重置密码日志
admin_logger    = make_logger('admin',    'admin.log')     # 管理员操作日志

LOCAL_TZ = ZoneInfo('Asia/Shanghai') if ZoneInfo else None


# ============================================================
# 数据库模型
# ============================================================

class VerificationCode(db.Model):
    """验证码表：每次发送验证码插一条，过期或用过的都算失败"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    employee_id = db.Column(db.String(20), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)


class RegisterLog(db.Model):
    """操作日志表：注册、重置密码，成功失败都记录"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    employee_id = db.Column(db.String(20))
    status = db.Column(db.String(20))      # success / failed / reset_success / reset_failed
    message = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AdminLoginLog(db.Model):
    """后台管理员登录日志：成功失败都记录，便于追踪谁在什么时间登录"""
    id = db.Column(db.Integer, primary_key=True)
    admin_username = db.Column(db.String(50))
    success = db.Column(db.Boolean, default=False)
    message = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AdminActionLog(db.Model):
    """后台高危/管理操作日志：删除、锁定、解锁、改资料、重置密码等"""
    id = db.Column(db.Integer, primary_key=True)
    admin_username = db.Column(db.String(50))
    action = db.Column(db.String(50))
    target_employee_id = db.Column(db.String(20))
    message = db.Column(db.String(300))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AdminUser(db.Model):
    """后台登录用户：超级管理员、管理员、只读用户。"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='readonly')
    permissions = db.Column(db.String(500), default='')
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemSetting(db.Model):
    """后台系统设置，只允许超级管理员修改。"""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(500), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class DingTalkAccount(db.Model):
    """钉钉身份与平台账号的独立对应记录，不关联 AD 域账号。"""
    identity_hash = db.Column(db.String(64), primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('admin_user.id'), unique=True, nullable=False)
    admin_user = db.relationship('AdminUser', backref=db.backref(
        'dingtalk_account', uselist=False, cascade='all, delete-orphan'
    ))
    employee_name = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DingTalkLoginState(db.Model):
    """跨 Gunicorn worker 共用的一次性授权状态。"""
    state_hash = db.Column(db.String(64), primary_key=True)
    browser_hash = db.Column(db.String(64), nullable=False)
    client_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class EmployeeAccountProvision(db.Model):
    """新员工工号发放及AD账号创建记录。"""
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    reservation_token = db.Column(db.String(64), unique=True, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='reserved')
    full_name = db.Column(db.String(80))
    department = db.Column(db.String(80))
    email = db.Column(db.String(120))
    manager_name = db.Column(db.String(80))
    job_title = db.Column(db.String(80))
    note = db.Column(db.String(500))
    message = db.Column(db.String(300))
    created_by = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AdPrecreateBatch(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    request_key = db.Column(db.String(36), nullable=False, unique=True)
    spec = db.Column(db.Text, nullable=False)
    password_mac = db.Column(db.String(64), nullable=False)
    created_by = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    items = db.relationship('AdPrecreateItem', backref='batch', order_by='AdPrecreateItem.employee_id')


class AdPrecreateItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(36), db.ForeignKey('ad_precreate_batch.id'), nullable=False, index=True)
    employee_id = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    message = db.Column(db.String(200), nullable=False, default='待创建')
    attempt_token = db.Column(db.String(32))
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    object_guid = db.Column(db.String(80))
    __table_args__ = (db.UniqueConstraint('batch_id', 'employee_id', name='uq_precreate_batch_account'),)


class AdBulkDeleteBatch(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    request_key = db.Column(db.String(36), nullable=False, unique=True)
    spec = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    items = db.relationship('AdBulkDeleteItem', backref='batch', order_by='AdBulkDeleteItem.employee_id')


class AdBulkDeleteItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(36), db.ForeignKey('ad_bulk_delete_batch.id'), nullable=False, index=True)
    employee_id = db.Column(db.String(20), nullable=False)
    snapshot = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    message = db.Column(db.String(200), nullable=False, default='待复查后删除')
    attempt_token = db.Column(db.String(32))
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    __table_args__ = (db.UniqueConstraint('batch_id', 'employee_id', name='uq_bulk_delete_account'),)


class AdminSessionAudit(db.Model):
    """后台在线审计：记录最后活跃时间，用于判断谁在线。"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    role = db.Column(db.String(20))
    ip_address = db.Column(db.String(50))
    login_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=True)


class PendingApproval(db.Model):
    """危险操作二人审批：删除账号、批量改密等。"""
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(80))
    payload = db.Column(db.Text)
    requested_by = db.Column(db.String(50), nullable=False)
    approved_by = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    message = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    executed_at = db.Column(db.DateTime)


class PasswordExpireReminderLog(db.Model):
    """密码到期提醒日志，避免同一用户同一提醒日重复发送。"""
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(80))
    email = db.Column(db.String(120))
    pwd_last_set = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)
    remind_days = db.Column(db.Integer)
    success = db.Column(db.Boolean, default=False)
    message = db.Column(db.String(300))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SchedulerJobLock(db.Model):
    """自动任务锁：多 worker 同时触发时，保证每天只有一个进程真正执行。"""
    id = db.Column(db.Integer, primary_key=True)
    job_name = db.Column(db.String(80), nullable=False)
    run_date = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='running')
    message = db.Column(db.String(300))
    locked_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    __table_args__ = (db.UniqueConstraint('job_name', 'run_date', name='uq_scheduler_job_date'),)


class PasswordReminderSendLock(db.Model):
    """邮件发送锁：保证同一用户同一提醒节点同一天只发送一次。"""
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), nullable=False)
    remind_days = db.Column(db.Integer, nullable=False)
    send_date = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('employee_id', 'remind_days', 'send_date', name='uq_password_reminder_send_once'),)


class ComputerCheckin(db.Model):
    """客户端登录上报：记录真实用户-计算机最近使用情况。"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    computer_name = db.Column(db.String(80), nullable=False)
    domain = db.Column(db.String(80))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    checkin_count = db.Column(db.Integer, default=0)
    first_checkin_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checkin_at = db.Column(db.DateTime, default=datetime.utcnow)
    raw_payload = db.Column(db.Text)
    __table_args__ = (db.UniqueConstraint('username', 'computer_name', name='uq_computer_checkin_user_computer'),)


class PasswordResetToken(db.Model):
    """密码重置Token表：忘记密码时生成token发到邮箱，点链接时验证"""
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)


def ensure_database_tables():
    """创建数据库表；gunicorn多worker同时启动时，表已存在就跳过。"""
    try:
        db.create_all()
        bootstrap_super_admin()
        set_default_setting('company_name', app.config.get('COMPANY_NAME', '微丰启'))
        set_default_setting('admin_title', app.config.get('ADMIN_TITLE', 'IT管理后台'))
        set_default_setting('admin_session_minutes', app.config.get('ADMIN_SESSION_MINUTES', 10))
        set_default_setting('super_admin_session_minutes', app.config.get('SUPER_ADMIN_SESSION_MINUTES', 480))
        set_default_setting('allow_delete_user', app.config.get('ALLOW_DELETE_USER', 'true'))
        set_default_setting('security_brand', app.config.get('SECURITY_BRAND', '微丰启安全提醒'))
        set_default_setting('security_notice', app.config.get('SECURITY_NOTICE', '为了保障公司账号安全，请及时修改密码，避免影响电脑登录和业务系统访问。'))
        set_default_setting('password_expire_days', app.config.get('PASSWORD_EXPIRE_DAYS', 90))
        set_default_setting('password_reminder_days', app.config.get('PASSWORD_REMINDER_DAYS', '15,7,1'))
        set_default_setting('password_reminder_enabled', app.config.get('PASSWORD_REMINDER_ENABLED', 'true'))
        set_default_setting('password_reminder_batch_size', app.config.get('PASSWORD_REMINDER_BATCH_SIZE', 50))
        set_default_setting('password_reminder_auto_time', app.config.get('PASSWORD_REMINDER_AUTO_TIME', '09:00'))
        set_default_setting('password_reminder_auto_token', app.config.get('PASSWORD_REMINDER_AUTO_TOKEN', secrets.token_urlsafe(32)))
        set_default_setting('client_checkin_token', app.config.get('CLIENT_CHECKIN_TOKEN', secrets.token_urlsafe(32)))
        db.session.commit()
    except OperationalError as e:
        if 'already exists' not in str(e):
            raise
    except IntegrityError:
        db.session.rollback()


# ============================================================
# 工具函数
# ============================================================

def generate_code(length=6):
    """生成6位随机数字验证码"""
    return ''.join(random.choices(string.digits, k=length))


def generate_token():
    """生成64位安全随机token，用于密码重置链接"""
    return secrets.token_hex(32)


def is_valid_employee_id(employee_id):
    """校验工号格式：wfq + 6位数字，例如 wfq101755"""
    return bool(re.match(r'^wfq\d{6}$', employee_id))


def is_valid_ad_account_name(value):
    """允许查询/维护已有AD账号名；生产注册仍使用严格工号规则。"""
    return bool(re.fullmatch(r'[A-Za-z0-9._-]{1,64}', value or ''))


def is_valid_email(email):
    """
    校验邮箱格式，任意邮箱都可以（QQ、163、企业邮均可）
    只检查格式，不限制域名
    """
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email))


def is_valid_chinese_field(value, min_len=1, max_len=5):
    """
    校验姓名/部门字段：仅允许中文，1-5个字
    """
    if not value:
        return False
    if len(value) < min_len or len(value) > max_len:
        return False
    return bool(re.fullmatch(r'[\u4e00-\u9fff]+', value))


def validate_password(password):
    """
    校验密码强度，返回 (是否通过, 错误信息)
    AD要求：8位以上，含大小写字母+数字+特殊符号
    """
    if len(password) < 8:
        return False, '密码至少8位'
    if not re.search(r'[A-Z]', password):
        return False, '密码需包含大写字母'
    if not re.search(r'[a-z]', password):
        return False, '密码需包含小写字母'
    if not re.search(r'\d', password):
        return False, '密码需包含数字'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, '密码需包含特殊字符，如 !@#$%'
    return True, ''


ROLE_PERMISSIONS = {
    'super_admin': [
        'view_user', 'edit_user', 'reset_password', 'lock_user', 'unlock_user', 'disable_user',
        'delete_user', 'view_logs', 'manage_admins', 'system_settings',
        'password_policy', 'view_dashboard', 'view_computers'
    ],
    'admin': [
    'view_user', 'edit_user', 'reset_password', 'lock_user', 'unlock_user', 'disable_user',
        'view_logs', 'view_dashboard', 'view_computers'
    ],
    'readonly': ['view_user', 'view_dashboard']
}


def split_permissions(value):
    if not value:
        return []
    return [p.strip() for p in value.split(',') if p.strip()]


def permissions_for_role(role):
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS['readonly'])


def sanitized_permissions(role, permissions):
    allowed = set(permissions_for_role(role))
    if role == 'admin':
        allowed.add('delete_user')
    cleaned = [p for p in (permissions or []) if p in allowed]
    if role != 'super_admin':
        cleaned = [p for p in cleaned if p != 'password_policy']
    if role == 'readonly':
        cleaned = [p for p in cleaned if p not in ('delete_user', 'edit_user', 'reset_password', 'lock_user', 'unlock_user', 'disable_user', 'view_logs')]
    return cleaned


def user_permissions(user):
    if not user:
        return []
    if user.role == 'super_admin':
        return ROLE_PERMISSIONS['super_admin']
    custom = split_permissions(user.permissions)
    if user.role == 'admin':
        permissions = list(ROLE_PERMISSIONS['admin'])
        if 'delete_user' in custom:
            permissions.append('delete_user')
        return sanitized_permissions(user.role, permissions)
    return sanitized_permissions(user.role, permissions_for_role(user.role))


def config_super_admin_username():
    return app.config.get('SUPER_ADMIN_USERNAME') or app.config.get('ADMIN_USERNAME')


def ensure_current_super_admin(user):
    if user and user.username == config_super_admin_username() and user.role != 'super_admin':
        user.role = 'super_admin'
        user.permissions = ','.join(ROLE_PERMISSIONS['super_admin'])
        user.is_active = True
        db.session.commit()
    return user


def bootstrap_super_admin():
    """从config.py初始化超级管理员；子账户之后都在用户中心维护。"""
    username = config_super_admin_username()
    password = app.config.get('SUPER_ADMIN_PASSWORD') or app.config.get('ADMIN_PASSWORD')
    if not username or not password:
        return

    with db.session.no_autoflush:
        existing = AdminUser.query.filter_by(username=username).first()
    if existing:
        if existing.role != 'super_admin':
            existing.role = 'super_admin'
            existing.permissions = ','.join(ROLE_PERMISSIONS['super_admin'])
            db.session.commit()
        return

    try:
        db.session.add(AdminUser(
            username=username,
            password_hash=generate_password_hash(password),
            role='super_admin',
            permissions=','.join(ROLE_PERMISSIONS['super_admin']),
            created_by='config'
        ))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = AdminUser.query.filter_by(username=username).first()
        if existing and existing.role != 'super_admin':
            existing.role = 'super_admin'
            existing.permissions = ','.join(ROLE_PERMISSIONS['super_admin'])
            db.session.commit()


def get_setting(key, default):
    setting = SystemSetting.query.filter_by(key=key).first()
    return setting.value if setting else default


def set_setting(key, value):
    setting = SystemSetting.query.filter_by(key=key).first()
    if not setting:
        setting = SystemSetting(key=key, value=str(value))
        db.session.add(setting)
    else:
        setting.value = str(value)
        setting.updated_at = datetime.utcnow()


def set_default_setting(key, value):
    with db.session.no_autoflush:
        exists = SystemSetting.query.filter_by(key=key).first()
    if not exists:
        db.session.add(SystemSetting(key=key, value=str(value)))


def get_or_create_setting(key, default_factory):
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting:
        return setting.value
    value = default_factory() if callable(default_factory) else default_factory
    setting = SystemSetting(key=key, value=str(value))
    db.session.add(setting)
    db.session.commit()
    return setting.value


def normalize_checkin_value(value, max_len):
    return str(value or '').strip()[:max_len]


@app.route('/api/client/computer_checkin', methods=['POST'])
@limiter.limit("120 per minute")
def client_computer_checkin():
    """客户端登录脚本上报真实用户-计算机使用关系。"""
    data = request.get_json(silent=True) or {}
    token = normalize_checkin_value(data.get('token') or request.headers.get('X-Checkin-Token'), 200)
    expected_token = get_or_create_setting(
        'client_checkin_token',
        lambda: app.config.get('CLIENT_CHECKIN_TOKEN', secrets.token_urlsafe(32))
    )
    if not expected_token or not secrets.compare_digest(token, expected_token):
        return jsonify({'success': False, 'message': 'token错误'}), 403

    username = normalize_checkin_value(data.get('username'), 50).lower()
    computer_name = normalize_checkin_value(data.get('computer') or data.get('computer_name'), 80).upper()
    domain = normalize_checkin_value(data.get('domain'), 80).upper()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,50}', username):
        return jsonify({'success': False, 'message': '用户名格式不正确'}), 400
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', computer_name):
        return jsonify({'success': False, 'message': '计算机名格式不正确'}), 400

    now = local_now()
    safe_payload = {k: normalize_checkin_value(v, 200) for k, v in data.items() if k != 'token'}
    raw_payload = json.dumps(safe_payload, ensure_ascii=False)

    def upsert_checkin():
        row = ComputerCheckin.query.filter_by(username=username, computer_name=computer_name).first()
        if not row:
            row = ComputerCheckin(
                username=username,
                computer_name=computer_name,
                domain=domain,
                ip_address=request.remote_addr,
                user_agent=normalize_checkin_value(request.headers.get('User-Agent'), 200),
                checkin_count=1,
                first_checkin_at=now,
                last_checkin_at=now,
                raw_payload=raw_payload
            )
            db.session.add(row)
            return
        row.domain = domain
        row.ip_address = request.remote_addr
        row.user_agent = normalize_checkin_value(request.headers.get('User-Agent'), 200)
        row.checkin_count = (row.checkin_count or 0) + 1
        row.last_checkin_at = now
        row.raw_payload = raw_payload

    try:
        upsert_checkin()
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        upsert_checkin()
        db.session.commit()

    return jsonify({'success': True, 'message': '上报成功'})


def current_admin_user():
    username = session.get('admin_username')
    if not username:
        return None
    return ensure_current_super_admin(AdminUser.query.filter_by(username=username, is_active=True).first())


def has_permission(permission):
    user = current_admin_user()
    return bool(user and permission in user_permissions(user))


def is_super_admin_user(user=None):
    user = user or current_admin_user()
    return bool(user and user.role == 'super_admin')


def permission_required(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get('admin_logged_in'):
                return jsonify({'success': False, 'message': '未登录，请重新登录'})
            touch_admin_session()
            if not has_permission(permission):
                return jsonify({'success': False, 'message': '权限不足'})
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def verify_admin_credentials(username, password):
    """保留给旧流程兼容；现在主要用于登录。"""
    user = ensure_current_super_admin(AdminUser.query.filter_by(username=username, is_active=True).first())
    return bool(user and check_password_hash(user.password_hash, password))


def admin_required(fn):
    """后台API统一登录校验。"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({'success': False, 'message': '未登录，请重新登录'})
        touch_admin_session()
        return fn(*args, **kwargs)
    return wrapper


def current_admin_username():
    return session.get('admin_username', 'unknown')


def touch_admin_session():
    username = session.get('admin_username')
    if not username:
        return
    audit = AdminSessionAudit.query.filter_by(username=username).first()
    now = datetime.utcnow()
    if not audit:
        audit = AdminSessionAudit(username=username, role=session.get('admin_role'), ip_address=request.remote_addr)
        db.session.add(audit)
    audit.role = session.get('admin_role')
    audit.ip_address = request.remote_addr
    audit.last_seen_at = now
    audit.is_online = True
    db.session.commit()


def logout_admin_session(username):
    audit = AdminSessionAudit.query.filter_by(username=username).first()
    if audit:
        audit.is_online = False
        audit.last_seen_at = datetime.utcnow()
        db.session.commit()


def mark_admin_login_session(username, role, ip_address):
    now = datetime.utcnow()
    audit = AdminSessionAudit.query.filter_by(username=username).first()
    if not audit:
        audit = AdminSessionAudit(username=username)
        db.session.add(audit)
    audit.role = role
    audit.ip_address = ip_address
    audit.login_at = now
    audit.last_seen_at = now
    audit.is_online = True
    db.session.commit()


def start_admin_login_session(user, message='登录成功'):
    session.clear()
    session['admin_logged_in'] = True
    session['admin_username'] = user.username
    session['admin_role'] = user.role
    session.permanent = True
    timeout_minutes = int(get_setting(
        'super_admin_session_minutes' if user.role == 'super_admin' else 'admin_session_minutes',
        480 if user.role == 'super_admin' else 10
    ))
    app.permanent_session_lifetime = timedelta(minutes=timeout_minutes)
    db.session.add(AdminLoginLog(
        admin_username=user.username, success=True, message=message, ip_address=request.remote_addr
    ))
    db.session.commit()
    mark_admin_login_session(user.username, user.role, request.remote_addr)
    admin_logger.info(f'{message} | 用户名:{user.username} | IP:{request.remote_addr}')


def write_admin_action(action, target_employee_id, message, ip_address, admin_username=None):
    """写管理员操作日志到数据库和 admin.log 文件。"""
    operator = admin_username or current_admin_username()
    db.session.add(AdminActionLog(
        admin_username=operator,
        action=action,
        target_employee_id=target_employee_id,
        message=message,
        ip_address=ip_address
    ))
    db.session.commit()
    admin_logger.warning(
        f"{action} | 操作人:{operator} | 目标:{target_employee_id} | {message} | IP:{ip_address}"
    )


def create_pending_approval(action, target, payload, message):
    approval = PendingApproval(
        action=action,
        target=target,
        payload=json.dumps(payload, ensure_ascii=False),
        requested_by=current_admin_username(),
        message=message
    )
    db.session.add(approval)
    db.session.commit()
    return approval


def validate_approval(approval_id, action):
    approval = PendingApproval.query.get(approval_id)
    if not approval:
        return None, '审批记录不存在'
    if approval.action != action:
        return None, '审批动作不匹配'
    if approval.status != 'approved':
        return None, '该操作还未完成二人审批'
    if approval.approved_by == current_admin_username():
        return None, '批准人不能执行自己批准的操作'
    return approval, ''


def require_yes(data):
    return (data.get('confirm_text') or '').strip().upper() == 'YES'


def parse_json_object(value):
    try:
        parsed = json.loads(value or '{}')
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def utc_now():
    return datetime.utcnow()


def local_now():
    if LOCAL_TZ:
        return datetime.now(LOCAL_TZ).replace(tzinfo=None)
    return datetime.utcnow() + timedelta(hours=8)


def utc_to_local(dt):
    if not dt:
        return None
    if LOCAL_TZ:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo('UTC'))
        return dt.astimezone(LOCAL_TZ).replace(tzinfo=None)
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt + timedelta(hours=8)


def fmt_local_dt(dt):
    local_dt = utc_to_local(dt)
    return local_dt.strftime('%Y-%m-%d %H:%M:%S') if local_dt else ''


def local_day_start_utc(day):
    if LOCAL_TZ:
        local_start = datetime(day.year, day.month, day.day, tzinfo=LOCAL_TZ)
        return local_start.astimezone(ZoneInfo('UTC')).replace(tzinfo=None)
    return datetime.combine(day, datetime.min.time()) - timedelta(hours=8)


def ad_filetime_to_str(value):
    """把AD的Windows FILETIME转换成中国深圳时间。"""
    if not value:
        return None
    raw = str(value)
    if raw in ('0', 'None') or raw.startswith('1601-01-01'):
        return None
    try:
        filetime = int(raw)
        if filetime <= 0:
            return None
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        if dt.year <= 1601:
            return None
        return fmt_local_dt(dt)
    except Exception:
        try:
            dt = value.value.replace(tzinfo=None)
            if dt.year <= 1601:
                return None
            return fmt_local_dt(dt)
        except Exception:
            return raw


def ad_filetime_to_datetime(value):
    """把AD时间转为中国深圳时间的datetime，统计今天登录人数时使用。"""
    if not value:
        return None
    try:
        raw = str(value)
        filetime = int(raw)
        if filetime <= 0:
            return None
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        if dt.year <= 1601:
            return None
        return utc_to_local(dt)
    except Exception:
        try:
            dt = value.value.replace(tzinfo=None)
            if dt.year <= 1601:
                return None
            return utc_to_local(dt)
        except Exception:
            return None


def ad_datetime_to_str(value):
    """把AD普通datetime属性转换成中国深圳时间字符串。"""
    if not value:
        return None
    try:
        dt = value.value
        if isinstance(dt, datetime):
            if dt.year <= 1601:
                return None
            if dt.tzinfo is not None:
                return dt.astimezone(LOCAL_TZ).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S') if LOCAL_TZ else dt.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
            return fmt_local_dt(dt)
    except Exception:
        pass
    text = str(value)
    return None if text.lower() in ('none', '') else text


def latest_ad_logon_datetime(entry):
    candidates = [
        ad_filetime_to_datetime(getattr(entry, 'lastLogon', None)),
        ad_filetime_to_datetime(getattr(entry, 'lastLogonTimestamp', None))
    ]
    candidates = [dt for dt in candidates if dt]
    return max(candidates) if candidates else None


def login_status_from_ad(entry):
    """AD lastLogonTimestamp 可能为空；logonCount 大于 0 时也视为曾登录。"""
    login_count = int(get_entry_text(entry, 'logonCount', '0') or 0)
    last_logon_dt = latest_ad_logon_datetime(entry)
    has_logged = bool(last_logon_dt or login_count > 0)
    last_logon = last_logon_dt.strftime('%Y-%m-%d %H:%M:%S') if last_logon_dt else ('有登录记录但AD未记录时间' if login_count > 0 else '从未登录')
    return has_logged, login_count, last_logon_dt, last_logon


def latest_action_for_target(target, actions):
    return AdminActionLog.query.filter(
        AdminActionLog.target_employee_id == target,
        AdminActionLog.action.in_(actions)
    ).order_by(AdminActionLog.created_at.desc()).first()


def datetime_to_ad_filetime(dt):
    """把datetime转换为AD Windows FILETIME。"""
    return int((dt - datetime(1601, 1, 1)).total_seconds() * 10000000)


def get_domain_password_max_age_days(conn):
    """读取AD默认域密码最大有效期。maxPwdAge是负数100纳秒间隔。"""
    bases = [app.config.get('AD_BASE_DN')]
    try:
        conn.search(
            search_base='',
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=['defaultNamingContext']
        )
        root_base = get_entry_text(conn.entries[0], 'defaultNamingContext') if conn.entries else ''
        if root_base and root_base not in bases:
            bases.insert(0, root_base)
    except Exception:
        pass
    for base in [b for b in bases if b]:
        try:
            conn.search(
                search_base=base,
                search_filter='(objectClass=domainDNS)',
                search_scope=ldap3.BASE,
                attributes=['maxPwdAge']
            )
            if not conn.entries:
                continue
            raw = get_entry_text(conn.entries[0], 'maxPwdAge')
            if not raw:
                continue
            intervals = abs(int(raw))
            if intervals <= 0:
                continue
            return max(1, int(round(intervals / 10_000_000 / 86400)))
        except Exception:
            continue
    return None


def get_user_password_expiry_datetime(entry, max_age_days=None):
    """优先使用AD计算字段，兜底用pwdLastSet + 域密码有效期。"""
    computed = ad_filetime_to_datetime(get_entry_value(entry, 'msDS-UserPasswordExpiryTimeComputed'))
    if computed:
        return computed
    pwd_dt = ad_filetime_to_datetime(get_entry_value(entry, 'pwdLastSet'))
    if pwd_dt and max_age_days:
        return pwd_dt + timedelta(days=max_age_days)
    return None


def infer_password_max_age_days_from_users(conn, sample_size=30):
    """从用户计算到期时间反推密码有效期，用于域策略字段读不到时展示。"""
    try:
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq*)(pwdLastSet>=1))',
            search_scope=ldap3.SUBTREE,
            attributes=['pwdLastSet', 'msDS-UserPasswordExpiryTimeComputed', 'userAccountControl'],
            size_limit=sample_size
        )
        candidates = []
        for entry in conn.entries:
            uac = int(get_entry_text(entry, 'userAccountControl', '512') or 512)
            if bool(uac & 65536):
                continue
            pwd_dt = ad_filetime_to_datetime(get_entry_value(entry, 'pwdLastSet'))
            expire_dt = ad_filetime_to_datetime(get_entry_value(entry, 'msDS-UserPasswordExpiryTimeComputed'))
            if not pwd_dt or not expire_dt:
                continue
            days = round((expire_dt - pwd_dt).total_seconds() / 86400)
            if 1 <= days <= 999:
                candidates.append(days)
        if not candidates:
            return None
        return Counter(candidates).most_common(1)[0][0]
    except Exception as e:
        app.logger.warning(f"反推AD密码有效期失败: {e}")
        return None


def get_effective_password_max_age_days(conn):
    """读取或反推AD密码有效期天数，仅用于展示和兜底计算。"""
    return get_domain_password_max_age_days(conn) or infer_password_max_age_days_from_users(conn)


def can_change_password_from_net_user(employee_id):
    """Use Windows net user output when available; it reflects AD change-password ACL."""
    if not employee_id or not shutil.which('net'):
        return None
    try:
        result = subprocess.run(
            ['net', 'user', employee_id, '/domain'],
            capture_output=True,
            text=True,
            timeout=8,
            errors='ignore'
        )
        output = (result.stdout or '') + (result.stderr or '')
        for line in output.splitlines():
            compact = re.sub(r'\s+', '', line).lower()
            if '用户可以更改密码' in compact or 'usermaychangepassword' in compact:
                if compact.endswith('no') or compact.endswith('否'):
                    return False
                if compact.endswith('yes') or compact.endswith('是'):
                    return True
        return None
    except Exception:
        return None


CHANGE_PASSWORD_GUID = uuid.UUID('ab721a53-1e2f-11d0-9819-00aa0040529b')
AD_SD_FLAGS_DACL_ONLY = b'\x30\x03\x02\x01\x04'
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100


def sid_from_bytes(data, offset):
    """Parse a binary SID from a security descriptor."""
    if offset + 8 > len(data):
        return None, offset
    revision = data[offset]
    sub_count = data[offset + 1]
    authority = int.from_bytes(data[offset + 2:offset + 8], 'big')
    pos = offset + 8
    parts = []
    for _ in range(sub_count):
        if pos + 4 > len(data):
            return None, offset
        parts.append(str(struct.unpack_from('<I', data, pos)[0]))
        pos += 4
    return f"S-{revision}-{authority}" + (('-' + '-'.join(parts)) if parts else ''), pos


def object_guid_from_ace(data, offset):
    if offset + 16 > len(data):
        return None
    return uuid.UUID(bytes_le=data[offset:offset + 16])


def can_change_password_from_sd(sd_value):
    """Return False when AD DACL explicitly denies the Change Password right."""
    if not sd_value:
        return None
    data = bytes(sd_value)
    if len(data) < 20:
        return None
    dacl_offset = struct.unpack_from('<I', data, 16)[0]
    if not dacl_offset or dacl_offset + 8 > len(data):
        return None
    ace_count = struct.unpack_from('<H', data, dacl_offset + 4)[0]
    pos = dacl_offset + 8
    denied_change_password = set()
    for _ in range(ace_count):
        if pos + 4 > len(data):
            break
        ace_type = data[pos]
        ace_size = struct.unpack_from('<H', data, pos + 2)[0]
        ace_end = pos + ace_size
        if ace_size < 8 or ace_end > len(data):
            break
        access_mask = struct.unpack_from('<I', data, pos + 4)[0]
        sid_offset = pos + 8
        object_type = None
        if ace_type in (0x05, 0x06):  # ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE
            if pos + 12 > ace_end:
                pos = ace_end
                continue
            object_flags = struct.unpack_from('<I', data, pos + 8)[0]
            sid_offset = pos + 12
            if object_flags & 0x1:
                object_type = object_guid_from_ace(data, sid_offset)
                sid_offset += 16
            if object_flags & 0x2:
                sid_offset += 16
        sid, _ = sid_from_bytes(data, sid_offset)
        is_change_password_ace = (
            (access_mask & ADS_RIGHT_DS_CONTROL_ACCESS)
            and (object_type is None or object_type == CHANGE_PASSWORD_GUID)
            and sid in ('S-1-1-0', 'S-1-5-10')
        )
        if ace_type in (0x01, 0x06) and is_change_password_ace:
            denied_change_password.add(sid)
        pos = ace_end
    if {'S-1-1-0', 'S-1-5-10'}.issubset(denied_change_password):
        return False
    return True


def can_change_password_from_ad_acl(conn, user_dn):
    """Read AD DACL for the user object. 'User cannot change password' lives in ACL."""
    if not user_dn:
        return None
    try:
        conn.search(
            search_base=user_dn,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=['nTSecurityDescriptor'],
            controls=[('1.2.840.113556.1.4.801', True, AD_SD_FLAGS_DACL_ONLY)]
        )
        if not conn.entries:
            return None
        raw_values = conn.entries[0].entry_raw_attributes.get('nTSecurityDescriptor') or []
        if not raw_values:
            return None
        return can_change_password_from_sd(raw_values[0])
    except Exception as e:
        app.logger.warning(f"读取AD改密权限失败: {e}")
        return None


def is_ad_lockout_value(value):
    """判断AD lockoutTime是否表示当前锁定。"""
    if not value:
        return False
    raw = str(value)
    if raw in ('0', '1601-01-01 00:00:00+00:00', '1601-01-01 00:00:00', 'None'):
        return False
    try:
        return int(raw) > 0
    except Exception:
        return True


def get_entry_value(entry, attr):
    """安全读取ldap3 entry属性，兼容带横杠的AD属性名。"""
    try:
        value = entry[attr]
        if value:
            return value
    except Exception:
        pass
    return getattr(entry, attr, None)


def get_entry_text(entry, attr, default=''):
    """安全读取ldap3 entry属性，避免空字段显示成异常对象。"""
    value = get_entry_value(entry, attr)
    if not value:
        return default
    text = str(value)
    if text.lower() == 'none':
        return default
    return text


def ldap_escape(value):
    return ldap3.utils.conv.escape_filter_chars(value)


def employee_id_to_computer_prefix(employee_id):
    return employee_id.upper().replace('WFQ', 'WFQ', 1)


def computer_search_base():
    return app.config.get('AD_COMPUTER_OU') or app.config['AD_BASE_DN']


def computer_matches_employee(computer_name, employee_id):
    prefix = employee_id_to_computer_prefix(employee_id)
    return bool(re.fullmatch(prefix + r'[A-Za-z]*', computer_name or '', re.IGNORECASE))


def computer_name_to_employee_id(computer_name):
    match = re.fullmatch(r'(WFQ\d{6})[A-Za-z]*', computer_name or '', re.IGNORECASE)
    return match.group(1).lower() if match else ''


def is_infra_computer(name, operating_system, dn):
    text_name = name or ''
    text_os = operating_system or ''
    text_dn = dn or ''
    return (
        text_name.upper().startswith('DC')
        or 'WINDOWS SERVER' in text_os.upper()
        or 'OU=DOMAIN CONTROLLERS' in text_dn.upper()
        or 'CN=DOMAIN CONTROLLERS' in text_dn.upper()
    )


def build_computer_row(entry, known_user_ids=None):
    """Build one AD computer row for management views."""
    known_user_ids = known_user_ids or set()
    uac = int(get_entry_text(entry, 'userAccountControl', '0') or 0)
    has_logged, login_count, last_logon_dt, last_logon = login_status_from_ad(entry)
    name = get_entry_text(entry, 'cn')
    operating_system = get_entry_text(entry, 'operatingSystem')
    dn = get_entry_text(entry, 'distinguishedName')
    today = local_now().date()
    inactive_days = (today - last_logon_dt.date()).days if last_logon_dt else None
    matched_employee_id = computer_name_to_employee_id(name)
    has_matching_user = bool(matched_employee_id and matched_employee_id in known_user_ids)
    is_disabled = bool(uac & 2)
    is_infra = is_infra_computer(name, operating_system, dn)
    inactive_limit = int(get_setting('computer_inactive_days', '7') or 7)
    review_reasons = []
    if not has_logged:
        review_reasons.append('无登录记录')
    elif inactive_days is not None and inactive_days >= inactive_limit:
        review_reasons.append(f'{inactive_limit}天未登录')
    if not has_matching_user:
        review_reasons.append('无对应用户')
    if is_infra:
        review_reasons = ['域控/服务器，不进入清理参考']
    action = latest_action_for_target(name, ['删除计算机', '删除计算机完成', '禁用计算机', '启用计算机'])
    return {
        'name': name,
        'dns_host_name': get_entry_text(entry, 'dNSHostName'),
        'description': get_entry_text(entry, 'description'),
        'operating_system': operating_system,
        'status': '已禁用' if is_disabled else '正常',
        'login_status': '已登录' if has_logged else '未登录',
        'login_count': login_count,
        'last_logon': last_logon,
        'inactive_days': inactive_days,
        'inactive_label': f'{inactive_days}天' if inactive_days is not None else '无登录记录',
        'matched_employee_id': matched_employee_id,
        'matching_user_status': matched_employee_id if has_matching_user else ('域控服务器' if is_infra else '无对应用户'),
        'has_matching_user': has_matching_user,
        'is_infra': is_infra,
        'review_reason': '、'.join(review_reasons) if review_reasons else '正常',
        'password_last_set': ad_filetime_to_str(getattr(entry, 'pwdLastSet', None)) or '',
        'when_created': ad_datetime_to_str(getattr(entry, 'whenCreated', None)) or get_entry_text(entry, 'whenCreated'),
        'when_changed': ad_datetime_to_str(getattr(entry, 'whenChanged', None)) or get_entry_text(entry, 'whenChanged'),
        'dn': dn,
        'operator': action.admin_username if action else '',
        'action': action.action if action else '',
        'reason': action.message if action else ('AD userAccountControl 显示禁用' if is_disabled else ''),
        'action_time': fmt_local_dt(action.created_at) if action else ''
    }


def get_related_computers(conn, employee_id):
    """按工号找关联计算机：WFQ101111、WFQ101111A、WFQ101111b 等。"""
    prefix = employee_id_to_computer_prefix(employee_id)
    conn.search(
        search_base=computer_search_base(),
        search_filter=f'(&(objectCategory=computer)(cn={ldap_escape(prefix)}*))',
        search_scope=ldap3.SUBTREE,
        attributes=[
            'cn', 'dNSHostName', 'distinguishedName', 'description',
            'operatingSystem', 'userAccountControl', 'logonCount',
            'lastLogon', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'whenChanged'
        ]
    )
    computers = []
    for entry in conn.entries:
        name = get_entry_text(entry, 'cn')
        if not computer_matches_employee(name, employee_id):
            continue
        uac = int(get_entry_text(entry, 'userAccountControl', '0') or 0)
        has_logged, login_count, last_logon_dt, last_logon = login_status_from_ad(entry)
        computers.append({
            'name': name,
            'dns_host_name': get_entry_text(entry, 'dNSHostName'),
            'description': get_entry_text(entry, 'description'),
            'operating_system': get_entry_text(entry, 'operatingSystem'),
            'status': '已禁用' if bool(uac & 2) else '正常',
            'login_status': '已登录' if has_logged else '未登录',
            'login_count': login_count,
            'last_logon': last_logon,
            'password_last_set': ad_filetime_to_str(getattr(entry, 'pwdLastSet', None)) or '未知',
            'when_created': get_entry_text(entry, 'whenCreated'),
            'when_changed': get_entry_text(entry, 'whenChanged'),
            'dn': get_entry_text(entry, 'distinguishedName')
        })
    return computers


with app.app_context():
    ensure_database_tables()


def get_ad_connection():
    """
    创建AD的LDAP连接
    636端口SSL加密，validate=0忽略自签证书验证
    """
    tls_config = ldap3.Tls(validate=0)
    server = ldap3.Server(
        app.config['AD_SERVER'],
        port=636,
        use_ssl=True,
        tls=tls_config,
        get_info=ldap3.ALL
    )
    return ldap3.Connection(
        server,
        user=app.config['AD_BIND_USER'],
        password=app.config['AD_BIND_PASSWORD'],
        authentication=ldap3.SIMPLE,
        auto_bind=True
    )


def send_email(to_email, subject, html_body):
    """通用发邮件函数，注册验证码和重置链接都用这个"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to_email
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))
    try:
        s = smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        s.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        s.sendmail(app.config['MAIL_USERNAME'], to_email, msg.as_string())
        s.quit()
        return True
    except Exception as e:
        app.logger.error(f"邮件发送失败: {e}")
        return False


def send_verification_email(to_email, code, employee_id, full_name):
    """发送注册验证码邮件，加上微丰启公司名称"""
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;
                border: 1px solid #eee; border-radius: 8px; overflow: hidden;">
        <div style="background: #1677ff; padding: 20px; text-align: center;">
            <h2 style="color: white; margin: 0;">微丰启 · 员工账号注册</h2>
        </div>
        <div style="padding: 30px;">
            <p>您好，<strong>{full_name}</strong>，</p>
            <p>您正在为工号 <strong>{employee_id}</strong> 注册公司域账号。</p>
            <p>您的验证码是：</p>
            <div style="background: #f5f5f5; padding: 20px; text-align: center;
                        border-radius: 8px; margin: 20px 0;">
                <span style="font-size: 36px; font-weight: bold;
                             letter-spacing: 8px; color: #1677ff;">{code}</span>
            </div>
            <p style="color: #666;">验证码 <strong>5分钟</strong> 内有效，请勿泄露给他人。</p>
            <p style="color: #999; font-size: 12px;">如非本人操作，请忽略此邮件。</p>
        </div>
        <div style="background: #f9f9f9; padding: 12px; text-align: center;
                    font-size: 12px; color: #999;">
            微丰启公司 IT部门 · 此邮件由系统自动发送，请勿回复
        </div>
    </div>
    """
    return send_email(to_email, f'【微丰启】账号注册验证码：{code}', html)


def send_reset_email(to_email, employee_id, reset_link):
    """发送密码重置链接邮件，链接30分钟有效"""
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;
                border: 1px solid #eee; border-radius: 8px; overflow: hidden;">
        <div style="background: #1677ff; padding: 20px; text-align: center;">
            <h2 style="color: white; margin: 0;">微丰启 · 密码重置申请</h2>
        </div>
        <div style="padding: 30px;">
            <p>您好，</p>
            <p>我们收到了工号 <strong>{employee_id}</strong> 的密码重置申请。</p>
            <p>请点击下方按钮重置密码：</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}"
                   style="background: #ff7a00; color: white; padding: 12px 32px;
                          border-radius: 8px; text-decoration: none; font-size: 16px;">
                    点击重置密码
                </a>
            </div>
            <p style="color: #666;">此链接 <strong>30分钟</strong> 内有效，过期需重新申请。</p>
            <p style="color: #999; font-size: 12px;">如非本人操作，请忽略此邮件，账号不会有任何变化。</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">
                如按钮无法点击，请复制以下链接到浏览器：<br>
                <span style="color: #1677ff;">{reset_link}</span>
            </p>
        </div>
        <div style="background: #f9f9f9; padding: 12px; text-align: center;
                    font-size: 12px; color: #999;">
            微丰启公司 IT部门 · 此邮件由系统自动发送，请勿回复
        </div>
    </div>
    """
    return send_email(to_email, '【微丰启】密码重置链接', html)


def send_reset_success_email(to_email, employee_id, full_name):
    """
    密码修改成功后发通知邮件
    只告知修改时间和登录方式，不包含密码内容（安全规范）
    """
    now_str = local_now().strftime('%Y-%m-%d %H:%M:%S')
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;
                border: 1px solid #eee; border-radius: 8px; overflow: hidden;">
        <div style="background: #1677ff; padding: 20px; text-align: center;">
            <h2 style="color: white; margin: 0;">微丰启 · 密码修改成功通知</h2>
        </div>
        <div style="padding: 30px;">
            <p>您好，<strong>{full_name}</strong>，</p>
            <p>您的公司域账号密码已于 <strong>{now_str}</strong> 修改成功。</p>
            <div style="background: #f6ffed; border: 1px solid #b7eb8f;
                        border-radius: 8px; padding: 20px; margin: 20px 0;">
                <p style="margin: 0 0 8px 0;"><strong>✅ 登录信息：</strong></p>
                <p style="margin: 0 0 4px 0;">🖥️ 登录方式：开机后使用域账号登录公司电脑</p>
                <p style="margin: 0 0 4px 0;">👤 登录工号：<strong>{employee_id}</strong></p>
                <p style="margin: 0;">🔑 登录密码：您刚刚设置的新密码</p>
            </div>
            <p style="color: #666;">如非本人操作，请立即联系IT部门处理。</p>
        </div>
        <div style="background: #f9f9f9; padding: 12px; text-align: center;
                    font-size: 12px; color: #999;">
            微丰启公司 IT部门 · 此邮件由系统自动发送，请勿回复
        </div>
    </div>
    """
    return send_email(to_email, '【微丰启】密码修改成功通知', html)

def send_register_success_email(to_email, employee_id, full_name):
    """
    注册成功后发通知邮件
    包含登录信息 + 邮箱提醒（此邮箱用于找回密码）
    """
    now_str = local_now().strftime('%Y-%m-%d %H:%M:%S')
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;
                border: 1px solid #eee; border-radius: 8px; overflow: hidden;">
        <div style="background: #1677ff; padding: 20px; text-align: center;">
            <h2 style="color: white; margin: 0;">微丰启 · 账号注册成功通知</h2>
        </div>
        <div style="padding: 30px;">
            <p>您好，<strong>{full_name}</strong>，</p>
            <p>您的公司域账号已于 <strong>{now_str}</strong> 注册成功，以下是您的登录信息：</p>
            <div style="background: #f6ffed; border: 1px solid #b7eb8f;
                        border-radius: 8px; padding: 20px; margin: 20px 0;">
                <p style="margin: 0 0 8px 0;"><strong>✅ 登录信息：</strong></p>
                <p style="margin: 0 0 4px 0;">🖥️ 登录方式：开机后使用域账号登录公司电脑</p>
                <p style="margin: 0 0 4px 0;">👤 登录工号：<strong>{employee_id}</strong></p>
                <p style="margin: 0;">🔑 登录密码：您刚刚设置的密码</p>
            </div>
            <div style="background: #fff7e6; border: 1px solid #ffd591;
                        border-radius: 8px; padding: 20px; margin: 20px 0;">
                <p style="margin: 0 0 8px 0;"><strong>⚠️ 重要提醒：</strong></p>
                <p style="margin: 0 0 4px 0;">📧 您的找回密码邮箱：<strong>{to_email}</strong></p>
                <p style="margin: 0; color: #d46b08;">此邮箱是您唯一的密码找回方式，请务必牢记并确保可正常收件。如需更换邮箱，请联系IT部门。</p>
            </div>
            <p style="color: #666;">如非本人操作，请立即联系IT部门处理。</p>
        </div>
        <div style="background: #f9f9f9; padding: 12px; text-align: center;
                    font-size: 12px; color: #999;">
            微丰启公司 IT部门 · 此邮件由系统自动发送，请勿回复
        </div>
    </div>
    """
    return send_email(to_email, '【微丰启】账号注册成功通知', html)


def send_password_expire_email(to_email, employee_id, full_name, expire_at, days_left):
    """发送密码到期提醒邮件。"""
    company_name = get_setting('company_name', '微丰启')
    security_brand = get_setting('security_brand', f'{company_name}安全提醒')
    security_notice = get_setting('security_notice', '为了保障公司账号安全，请及时修改密码。')
    reset_url = app.config.get('BASE_URL', '').rstrip('/') + '/reset'
    expire_str = expire_at.strftime('%Y-%m-%d')
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto;
                border: 1px solid #eee; border-radius: 8px; overflow: hidden;">
        <div style="background: #1a1a2e; padding: 20px; text-align: center;">
            <h2 style="color: white; margin: 0;">{security_brand}</h2>
        </div>
        <div style="padding: 28px;">
            <p>您好，<strong>{full_name or employee_id}</strong>，</p>
            <p>您的公司账号 <strong>{employee_id}</strong> 密码将在 <strong>{days_left} 天后</strong> 到期。</p>
            <p>预计到期日期：<strong>{expire_str}</strong></p>
            <div style="background:#fff7e6;border:1px solid #ffd591;border-radius:8px;padding:16px;margin:18px 0;color:#8a4b00;">
                {security_notice}
            </div>
            <p>请尽快打开密码重置页面修改密码：</p>
            <p><a href="{reset_url}" style="background:#1677ff;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;">前往修改密码</a></p>
            <p style="color:#999;font-size:12px;">如您已修改密码，请忽略本邮件。</p>
        </div>
        <div style="background:#f9f9f9;padding:12px;text-align:center;font-size:12px;color:#999;">
            {company_name} IT部门 · 此邮件由系统自动发送，请勿回复
        </div>
    </div>
    """
    return send_email(to_email, f'【{company_name}】密码到期提醒：{days_left}天后到期', html)


def parse_reminder_days():
    days = []
    for item in str(get_setting('password_reminder_days', '15,7,1')).split(','):
        item = item.strip()
        if item.isdigit():
            value = int(item)
            if value not in days:
                days.append(value)
    return sorted(days, reverse=True)


def build_password_expire_rows(conn, max_age_days=None):
    """Return password expiry rows using AD pwdLastSet + real domain maxPwdAge."""
    max_age_days = max_age_days or get_effective_password_max_age_days(conn)
    remind_days = parse_reminder_days()
    today = local_now().date()
    conn.search(
        search_base=app.config['AD_BASE_DN'],
        search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq*))',
        search_scope=ldap3.SUBTREE,
        attributes=[
            'sAMAccountName', 'description', 'mail', 'userAccountControl',
            'pwdLastSet', 'msDS-UserPasswordExpiryTimeComputed',
            'lastLogon', 'lastLogonTimestamp', 'logonCount'
        ]
    )
    rows = []
    for entry in conn.entries:
        employee_id = get_entry_text(entry, 'sAMAccountName')
        full_name = get_entry_text(entry, 'description', employee_id)
        email = get_entry_text(entry, 'mail')
        uac = int(get_entry_text(entry, 'userAccountControl', '512') or 512)
        is_disabled = bool(uac & 2)
        password_never_expires = bool(uac & 65536)
        has_logged, login_count, last_logon_dt, last_logon = login_status_from_ad(entry)
        pwd_dt = ad_filetime_to_datetime(getattr(entry, 'pwdLastSet', None))
        expire_at = None
        days_left = None
        status = '无法计算'
        skip_reason = ''

        if is_disabled:
            skip_reason = '账号已禁用'
        elif password_never_expires:
            skip_reason = '密码永不过期'
        elif not email:
            skip_reason = '未绑定邮箱'
        elif not has_logged:
            skip_reason = '从未登录'
        elif not pwd_dt:
            skip_reason = '无密码修改时间'
        else:
            expire_at = get_user_password_expiry_datetime(entry, max_age_days)
            if not expire_at:
                skip_reason = '未读取到密码到期时间'
                rows.append({
                    'employee_id': employee_id,
                    'full_name': full_name,
                    'email': email or '',
                    'account_status': '已禁用' if is_disabled else '正常',
                    'last_logon': last_logon,
                    'login_count': login_count,
                    'pwd_last_set': pwd_dt.strftime('%Y-%m-%d %H:%M:%S') if pwd_dt else '',
                    'expire_at': '',
                    'days_left': None,
                    'days_left_label': '-',
                    'will_send': False,
                    'skip_reason': skip_reason,
                    'status': '无需发送',
                    'password_never_expires': password_never_expires,
                    'last_reminder_at': '',
                    'last_reminder_result': ''
                })
                continue
            days_left = (expire_at.date() - today).days
            if days_left < 0:
                status = '已到期'
            elif days_left in remind_days:
                status = '即将到期'
            else:
                status = '未到提醒日'

        will_send = bool(not skip_reason and days_left in remind_days)
        if not skip_reason and not will_send:
            skip_reason = '不在提醒天数'
        latest_log = PasswordExpireReminderLog.query.filter_by(
            employee_id=employee_id
        ).order_by(PasswordExpireReminderLog.created_at.desc()).first()
        rows.append({
            'employee_id': employee_id,
            'full_name': full_name,
            'email': email or '',
            'account_status': '已禁用' if is_disabled else '正常',
            'last_logon': last_logon,
            'login_count': login_count,
            'pwd_last_set': pwd_dt.strftime('%Y-%m-%d %H:%M:%S') if pwd_dt else '',
            'expire_at': expire_at.strftime('%Y-%m-%d %H:%M:%S') if expire_at else '',
            'days_left': days_left,
            'days_left_label': f'{days_left}天' if days_left is not None else '-',
            'will_send': will_send,
            'skip_reason': '' if will_send else skip_reason,
            'status': status if (will_send or not skip_reason) else '无需发送',
            'password_never_expires': password_never_expires,
            'last_reminder_at': fmt_local_dt(latest_log.created_at) if latest_log else '',
            'last_reminder_result': latest_log.message if latest_log else ''
        })
    rows.sort(key=lambda row: (row['days_left'] is None, row['days_left'] if row['days_left'] is not None else 999999, row['employee_id']))
    return rows, max_age_days, remind_days




def create_ad_user(
    employee_id, email, password, full_name, department,
    manager_name='', job_title='', note=''
):
    """
    在AD里创建用户账号
    - employee_id: 工号，作为登录名
    - email: 员工邮箱
    - password: 初始密码
    - full_name: 真实姓名，存到description字段
    - department: 部门，存到department字段
    """
    try:
        conn = get_ad_connection()

        # 检查工号是否已存在
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE
        )
        if conn.entries:
            return False, "工号已存在，请联系IT部门"

        user_dn = f"cn={employee_id},{app.config['AD_USER_OU']}"
        attributes = build_user_attributes(employee_id, email, password, full_name, department,
                                           manager_name=manager_name, job_title=job_title, note=note)

        conn.add(user_dn, attributes=attributes)

        if conn.result['result'] == 0:
            conn.unbind()
            return True, "账号创建成功"
        else:
            app.logger.error(f"AD创建用户失败: {conn.result}")
            conn.unbind()
            return False, f"AD创建失败: {conn.result.get('description', '未知错误')}"

    except LDAPException as e:
        app.logger.error(f"LDAP连接异常: {e}")
        return False, "连接AD服务器失败，请联系IT"
    except Exception as e:
        app.logger.error(f"创建AD用户未知错误: {e}")
        return False, "系统错误，请联系IT"


def ad_employee_id_exists(employee_id):
    """检查工号是否已经存在于AD。调用前必须先校验工号格式。"""
    conn = get_ad_connection()
    try:
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={employee_id}))',
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName']
        )
        return bool(conn.entries)
    finally:
        conn.unbind()


EMPLOYEE_ID_SEQUENCE_START = 102179
EMPLOYEE_ID_SEQUENCE_END = 102999
EMPLOYEE_ID_SEQUENCE_LAST_ISSUED_KEY = 'employee_id_sequence_last_issued'
EMPLOYEE_ID_SEQUENCE_DEFAULT_LAST_ISSUED = 102178


def employee_id_sequence_number(employee_id):
    """返回正式新员工序列号；历史随机工号不参与顺序发放。"""
    match = re.fullmatch(r'wfq(102\d{3})', (employee_id or '').strip().lower())
    if not match:
        return None
    number = int(match.group(1))
    if EMPLOYEE_ID_SEQUENCE_START <= number <= EMPLOYEE_ID_SEQUENCE_END:
        return number
    return None


def ad_employee_ids_in_sequence():
    """读取整个域中已使用的新员工序列工号。"""
    conn = get_ad_connection()
    try:
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq102*))',
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName']
        )
        return {
            get_entry_text(entry, 'sAMAccountName').lower()
            for entry in conn.entries
            if employee_id_sequence_number(get_entry_text(entry, 'sAMAccountName')) is not None
        }
    finally:
        conn.unbind()


def reserve_specific_employee_id(employee_id, admin_username, check_ad=True):
    """预留指定工号；数据库唯一约束负责阻止多worker并发重复。"""
    target = EmployeeAccountProvision.query.filter_by(employee_id=employee_id).first()
    if target:
        if target.created_by == admin_username and target.status == 'reserved':
            return target
        raise ValueError('该工号已被使用，请更换工号')
    if check_ad and ad_employee_id_exists(employee_id):
        raise ValueError('该工号已存在于AD，请更换工号')

    existing = EmployeeAccountProvision.query.filter_by(
        created_by=admin_username,
        status='reserved'
    ).order_by(EmployeeAccountProvision.created_at.desc()).first()
    if existing:
        existing.employee_id = employee_id
        existing.reservation_token = secrets.token_hex(24)
        existing.message = '工号已预留'
        try:
            db.session.commit()
            return existing
        except IntegrityError:
            db.session.rollback()
            raise ValueError('该工号刚刚被其他操作占用，请更换工号')

    record = EmployeeAccountProvision(
        employee_id=employee_id,
        reservation_token=secrets.token_hex(24),
        status='reserved',
        message='工号已预留',
        created_by=admin_username
    )
    db.session.add(record)
    try:
        db.session.commit()
        return record
    except IntegrityError:
        db.session.rollback()
        raise ValueError('该工号刚刚被其他操作占用，请更换工号')


def reserve_next_employee_id(admin_username):
    """从 wfq102179 开始按独立游标生成工号，并跳过已占用号码。"""
    for _ in range(12):
        ad_employee_ids = ad_employee_ids_in_sequence()
        setting = SystemSetting.query.filter_by(
            key=EMPLOYEE_ID_SEQUENCE_LAST_ISSUED_KEY
        ).first()
        try:
            last_issued = int(setting.value) if setting else EMPLOYEE_ID_SEQUENCE_DEFAULT_LAST_ISSUED
        except (TypeError, ValueError):
            last_issued = EMPLOYEE_ID_SEQUENCE_DEFAULT_LAST_ISSUED

        existing = EmployeeAccountProvision.query.filter_by(
            created_by=admin_username,
            status='reserved'
        ).order_by(EmployeeAccountProvision.created_at.desc()).first()
        existing_number = employee_id_sequence_number(existing.employee_id) if existing else None
        if (
            existing
            and existing_number == last_issued
            and existing.employee_id.lower() not in ad_employee_ids
        ):
            return existing

        provision_ids = {
            row.employee_id.lower()
            for row in EmployeeAccountProvision.query.with_entities(
                EmployeeAccountProvision.employee_id
            ).all()
            if employee_id_sequence_number(row.employee_id) is not None
        }
        occupied_ids = ad_employee_ids | provision_ids
        next_number = max(last_issued + 1, EMPLOYEE_ID_SEQUENCE_START)
        while (
            next_number <= EMPLOYEE_ID_SEQUENCE_END
            and f'wfq{next_number:06d}' in occupied_ids
        ):
            next_number += 1
        if next_number > EMPLOYEE_ID_SEQUENCE_END:
            raise RuntimeError('wfq102xxx新员工工号序列已用完')
        employee_id = f'wfq{next_number:06d}'
        try:
            record = reserve_specific_employee_id(employee_id, admin_username, check_ad=False)
            set_setting(EMPLOYEE_ID_SEQUENCE_LAST_ISSUED_KEY, next_number)
            db.session.commit()
            return record
        except ValueError:
            continue
    raise RuntimeError('顺序工号生成冲突，请稍后重试')


def reset_ad_password(employee_id, new_password):
    """
    修改AD里已存在用户的密码
    先搜到用户DN，再用MODIFY_REPLACE替换，不需要知道旧密码
    返回 (是否成功, 消息)
    """
    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'description']  # 同时取姓名，发通知邮件用
        )
        if not conn.entries:
            conn.unbind()
            return False, "用户不存在", None

        user_dn = str(conn.entries[0].distinguishedName)
        # 取姓名，发成功通知邮件用；取不到就用工号代替
        full_name = str(conn.entries[0].description) if conn.entries[0].description else employee_id

        unicode_password = ('"%s"' % new_password).encode('utf-16-le')
        conn.modify(user_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [unicode_password])]})

        if conn.result['result'] == 0:
            conn.unbind()
            return True, "密码修改成功", full_name
        else:
            app.logger.error(f"修改AD密码失败: {conn.result}")
            conn.unbind()
            return False, f"密码修改失败: {conn.result.get('description', '未知错误')}", None

    except LDAPException as e:
        app.logger.error(f"重置密码LDAP异常: {e}")
        return False, "连接AD服务器失败，请联系IT", None
    except Exception as e:
        app.logger.error(f"重置密码未知错误: {e}")
        return False, "系统错误，请联系IT", None


def force_password_change_next_login(employee_id):
    """把 AD 用户 pwdLastSet 置 0，并立即反查确认。"""
    conn = get_ad_connection()
    try:
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={ldap_escape(employee_id)})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'pwdLastSet']
        )
        if not conn.entries:
            return False, '用户不存在'

        user_dn = str(conn.entries[0].distinguishedName)
        last_error = '未知错误'
        for pwd_value in (0, '0'):
            conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [pwd_value])]})
            if conn.result['result'] == 0:
                conn.search(
                    search_base=user_dn,
                    search_filter='(objectClass=user)',
                    search_scope=ldap3.BASE,
                    attributes=['pwdLastSet']
                )
                current_value = get_entry_text(conn.entries[0], 'pwdLastSet', '') if conn.entries else ''
                if current_value == '0' or current_value.startswith('1601-01-01'):
                    return True, ''
                return False, f'AD返回成功，但pwdLastSet反查仍为 {current_value or "空"}'
            last_error = conn.result.get('message') or conn.result.get('description') or str(conn.result)
        return False, last_error
    finally:
        conn.unbind()


# ============================================================
# 路由 - API接口（页面由 nginx 静态托管 static/ 目录）
# ============================================================

@app.route('/api/send_code', methods=['POST'])
@limiter.limit("3 per minute")
def send_code():
    """注册：发送邮箱验证码"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    email = data.get('email', '').strip().lower()
    full_name = data.get('full_name', '').strip()
    department = data.get('department', '').strip()
    client_ip = request.remote_addr

    if not is_valid_employee_id(employee_id):
        return jsonify({'success': False, 'message': '工号格式不正确，应为 wfq + 6位数字'})
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': '邮箱格式不正确'})
    if not is_valid_chinese_field(full_name, 1, 5):
        return jsonify({'success': False, 'message': '姓名只能填写中文，1-5个字'})
    if not is_valid_chinese_field(department, 1, 5):
        return jsonify({'success': False, 'message': '部门只能填写中文，1-5个字'})

    # 1分钟内发过就不重复发
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    if VerificationCode.query.filter_by(employee_id=employee_id).filter(
        VerificationCode.created_at > one_minute_ago
    ).first():
        return jsonify({'success': False, 'message': '发送太频繁，请1分钟后再试'})

    code = generate_code()
    db.session.add(VerificationCode(email=email, employee_id=employee_id, code=code))
    db.session.commit()

    # 写日志
    register_logger.info(f"发送验证码 | 工号:{employee_id} | 姓名:{full_name} | 部门:{department} | 邮箱:{email} | IP:{client_ip}")

    if send_verification_email(email, code, employee_id, full_name):
        return jsonify({'success': True, 'message': f'验证码已发送到 {email}'})
    return jsonify({'success': False, 'message': '邮件发送失败，请检查邮箱地址或联系IT'})


@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """注册：提交注册，验证码通过后创建AD账号"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    email = data.get('email', '').strip().lower()
    code = data.get('code', '').strip()
    full_name = data.get('full_name', '').strip()
    department = data.get('department', '').strip()   # 新增：部门
    password = data.get('password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    client_ip = request.remote_addr

    # 基础校验
    if not all([employee_id, email, code, full_name, department, password]):
        return jsonify({'success': False, 'message': '请填写所有必填项'})
    if not is_valid_ad_account_name(employee_id):
        return jsonify({'success': False, 'message': '账号名格式不正确'})
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': '邮箱格式不正确'})
    if password != confirm_password:
        return jsonify({'success': False, 'message': '两次密码不一致'})

    # 姓名校验：1-5个字符
    if not is_valid_chinese_field(full_name, 1, 5):
        return jsonify({'success': False, 'message': '姓名只能填写中文，1-5个字'})

    # 部门校验：1-5个字符
    if not is_valid_chinese_field(department, 1, 5):
        return jsonify({'success': False, 'message': '部门只能填写中文，1-5个字'})

    ok, err = validate_password(password)
    if not ok:
        return jsonify({'success': False, 'message': err})

    # 验证码校验
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    verify_record = VerificationCode.query.filter_by(
        employee_id=employee_id, email=email, code=code, is_used=False
    ).filter(VerificationCode.created_at > five_minutes_ago
    ).order_by(VerificationCode.created_at.desc()).first()

    if not verify_record:
        return jsonify({'success': False, 'message': '验证码错误或已过期，请重新获取'})

    # 创建AD账号
    success, message = create_ad_user(employee_id, email, password, full_name, department)

    # 写数据库日志
    db.session.add(RegisterLog(
        email=email, employee_id=employee_id,
        status='success' if success else 'failed',
        message=message, ip_address=client_ip
    ))
    if success:
        verify_record.is_used = True
    db.session.commit()

    # 写文件日志
    if success:
        register_logger.info(
            f"注册成功 | 工号:{employee_id} | 姓名:{full_name} | "
            f"部门:{department} | 邮箱:{email} | IP:{client_ip}"
        )
        send_register_success_email(email, employee_id, full_name)
    else:
        register_logger.warning(
            f"注册失败 | 工号:{employee_id} | 邮箱:{email} | "
            f"原因:{message} | IP:{client_ip}"
        )

    return jsonify({'success': success, 'message': message})


@app.route('/api/reset/request', methods=['POST'])
@limiter.limit("3 per minute")
def reset_request():
    """忘记密码第一步：验证工号存在，发重置链接到邮箱"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    email = data.get('email', '').strip().lower()
    client_ip = request.remote_addr

    if not is_valid_employee_id(employee_id):
        return jsonify({'success': False, 'message': '工号格式不正确'})
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': '邮箱格式不正确'})

    # 去AD验证工号是否存在，同时取出邮箱做校验
    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName', 'mail']  # 取mail字段用于校验
        )
        if not conn.entries:
            conn.unbind()
            reset_logger.warning(
                f"重置密码-工号不存在 | 工号:{employee_id} | IP:{client_ip}"
            )
            return jsonify({'success': False, 'message': '工号不存在，请确认后重试'})

        # 取AD里存的邮箱
        ad_mail_raw = conn.entries[0].mail
        ad_mail = str(ad_mail_raw).strip().lower() if ad_mail_raw else ''
        conn.unbind()

        # AD邮箱为空：说明IT还没给这个账号绑定邮箱
        if not ad_mail or ad_mail == 'none':
            reset_logger.warning(
                f"重置密码-AD邮箱为空 | 工号:{employee_id} | IP:{client_ip}"
            )
            return jsonify({
                'success': False,
                'message': '您的账号尚未绑定找回密码邮箱，请联系IT管理员（袁玉杰）进行处理'
            })

        # AD有邮箱，但用户填的邮箱对不上
        if ad_mail != email:
            # 分析AD邮箱的后缀，给出针对性提示
            ad_domain = ad_mail.split('@')[-1] if '@' in ad_mail else ''
            reset_logger.warning(
                f"重置密码-邮箱不匹配 | 工号:{employee_id} | "
                f"填写:{email} | AD中:{ad_mail} | IP:{client_ip}"
            )
            return jsonify({
                'success': False,
                'message': f'邮箱不正确，您注册时绑定的邮箱后缀为 @{ad_domain}，请使用该邮箱重试'
            })

    except Exception as e:
        app.logger.error(f"重置查询AD失败: {e}")
        return jsonify({'success': False, 'message': '连接AD失败，请联系IT'})

    # 30分钟内已发过就不重复发
    thirty_minutes_ago = datetime.utcnow() - timedelta(minutes=30)
    if PasswordResetToken.query.filter_by(
        employee_id=employee_id, is_used=False
    ).filter(PasswordResetToken.created_at > thirty_minutes_ago).first():
        return jsonify({'success': False, 'message': '重置链接已发送，请检查邮箱，30分钟内有效'})

    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(minutes=30)
    db.session.add(PasswordResetToken(
        employee_id=employee_id, email=email,
        token=token, expires_at=expires_at
    ))
    db.session.commit()

    reset_link = f"{app.config['BASE_URL']}/reset/confirm?token={token}"
    reset_logger.info(f"申请重置密码 | 工号:{employee_id} | 邮箱:{email} | IP:{client_ip}")

    if send_reset_email(email, employee_id, reset_link):
        return jsonify({'success': True, 'message': f'重置链接已发送到 {email}，30分钟内有效'})
    return jsonify({'success': False, 'message': '邮件发送失败，请联系IT'})


@app.route('/api/reset/verify_token', methods=['POST'])
def verify_token():
    """忘记密码：验证token是否有效，前端页面加载时调用"""
    data = request.get_json()
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'valid': False, 'message': '链接无效'})

    record = PasswordResetToken.query.filter_by(token=token, is_used=False).first()
    if not record:
        return jsonify({'valid': False, 'message': '链接无效或已使用，请重新申请'})
    if datetime.utcnow() > record.expires_at:
        return jsonify({'valid': False, 'message': '链接已过期（30分钟有效），请重新申请'})

    return jsonify({'valid': True, 'employee_id': record.employee_id})


@app.route('/api/reset/confirm', methods=['POST'])
@limiter.limit("5 per minute")
def reset_confirm():
    """忘记密码第二步：验证token，提交新密码，修改AD密码，发成功通知邮件"""
    data = request.get_json()
    token = data.get('token', '').strip()
    new_password = data.get('new_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    client_ip = request.remote_addr

    if not all([token, new_password, confirm_password]):
        return jsonify({'success': False, 'message': '请填写所有必填项'})
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': '两次密码不一致'})

    ok, err = validate_password(new_password)
    if not ok:
        return jsonify({'success': False, 'message': err})

    # 二次验证token
    record = PasswordResetToken.query.filter_by(token=token, is_used=False).first()
    if not record:
        return jsonify({'success': False, 'message': '链接无效或已使用，请重新申请'})
    if datetime.utcnow() > record.expires_at:
        return jsonify({'success': False, 'message': '链接已过期，请重新申请'})

    # 修改AD密码，同时取回姓名用于发通知邮件
    success, message, full_name = reset_ad_password(record.employee_id, new_password)

    # 写数据库日志
    db.session.add(RegisterLog(
        email=record.email, employee_id=record.employee_id,
        status='reset_success' if success else 'reset_failed',
        message=message, ip_address=client_ip
    ))
    if success:
        record.is_used = True
    db.session.commit()

    # 写文件日志
    if success:
        reset_logger.info(
            f"重置密码成功 | 工号:{record.employee_id} | "
            f"邮箱:{record.email} | IP:{client_ip}"
        )
        send_reset_success_email(record.email, record.employee_id, full_name or record.employee_id)
    else:
        reset_logger.warning(
            f"重置密码失败 | 工号:{record.employee_id} | "
            f"原因:{message} | IP:{client_ip}"
        )

    return jsonify({'success': success, 'message': message})




# ============================================================
# 管理员后台 API（页面在 static/admin_login.html、admin_manage.html）
# ============================================================

@app.route('/api/admin/check', methods=['GET'])
def admin_check():
    """检查管理员是否已登录（静态管理页加载时调用）"""
    user = current_admin_user()
    if session.get('admin_logged_in') and not user:
        session.clear()
        return jsonify({'logged_in': False})
    return jsonify({
        'logged_in': bool(session.get('admin_logged_in')),
        'username': session.get('admin_username'),
        'display_name': user.dingtalk_account.employee_name if user and user.dingtalk_account else None,
        'role': user.role if user else None,
        'permissions': user_permissions(user) if user else [],
        'settings': {
            'company_name': get_setting('company_name', '微丰启'),
            'admin_title': get_setting('admin_title', 'IT管理后台')
        }
    })


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """
    管理员登录接口
    连续失败5次，锁定10分钟
    成功后在Session里标记已登录，Session有效期8小时
    """
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    client_ip = request.remote_addr

    user = AdminUser.query.filter_by(username=username, is_active=True).first()

    if user and check_password_hash(user.password_hash, password):
        start_admin_login_session(user)
        return jsonify({'success': True})
    else:
        db.session.add(AdminLoginLog(
            admin_username=username, success=False,
            message='账号或密码错误', ip_address=client_ip
        ))
        db.session.commit()
        admin_logger.warning(f"管理员登录失败 | 用户名:{username} | IP:{client_ip}")
        return jsonify({'success': False, 'message': '账号或密码错误'})


def dingtalk_digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def dingtalk_config():
    config = DingTalkConfig.load(app.config)
    if config is None:
        raise DingTalkError('disabled')
    return config


def begin_dingtalk_login(embedded=False):
    config = dingtalk_config()
    if embedded:
        origin = request.headers.get('Origin')
        callback = urlsplit(config.redirect_uri)
        expected_origin = f'{callback.scheme}://{callback.netloc}'
        if (request.headers.get('X-Requested-With') != 'XMLHttpRequest'
                or (origin and origin != expected_origin)):
            raise DingTalkError('origin')
    previous_browser = session.get('dingtalk_browser')
    if previous_browser:
        DingTalkLoginState.query.filter_by(browser_hash=dingtalk_digest(previous_browser)).delete()
    DingTalkLoginState.query.filter(DingTalkLoginState.expires_at <= datetime.utcnow()).delete()
    browser = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(seconds=config.state_ttl)
    db.session.add(DingTalkLoginState(
        state_hash=dingtalk_digest(state), browser_hash=dingtalk_digest(browser),
        client_hash=dingtalk_digest(config.client_id), expires_at=expires
    ))
    db.session.commit()
    session['dingtalk_browser'] = browser
    return {
        'authorizationUrl': config.authorization_url(state, embedded),
        'redirectUri': config.redirect_uri, 'state': state,
        'expiresAt': int(time.time() * 1000) + config.state_ttl * 1000
    }


def resolve_dingtalk_account(config, union_id, employee_name):
    identity = dingtalk_digest(config.client_id + '\0' + union_id)
    binding = db.session.get(DingTalkAccount, identity)
    if not binding:
        user = AdminUser(
            username='dt_' + identity[:24], password_hash=generate_password_hash(secrets.token_urlsafe(48)),
            role='readonly', permissions='', is_active=True, created_by='dingtalk'
        )
        db.session.add(user)
        db.session.add(DingTalkAccount(
            identity_hash=identity, admin_user=user, employee_name=employee_name
        ))
        try:
            db.session.commit()
            return user
        except IntegrityError:
            # Concurrent first logins must resolve the same identity, never merge by name.
            db.session.rollback()
            binding = db.session.get(DingTalkAccount, identity)
            if not binding:
                raise DingTalkError('account') from None
    user = binding.admin_user
    if not user or not user.is_active:
        raise DingTalkError('account')
    return user


@app.after_request
def protect_dingtalk_response(response):
    if request.path.startswith('/api/admin/dingtalk/'):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route('/api/admin/dingtalk/status', methods=['GET'])
def dingtalk_status():
    try:
        enabled = DingTalkConfig.load(app.config) is not None
    except DingTalkError:
        enabled = False
    return jsonify({'enabled': enabled})


@app.route('/api/admin/dingtalk/login', methods=['GET'])
def dingtalk_login():
    try:
        authorization = begin_dingtalk_login()
        return redirect(authorization['authorizationUrl'])
    except DingTalkError as e:
        return redirect('/admin?' + urlencode({'dingtalkError': str(e)}))


@app.route('/api/admin/dingtalk/qr', methods=['POST'])
def dingtalk_qr():
    try:
        return jsonify(begin_dingtalk_login(embedded=True))
    except DingTalkError:
        return jsonify({'success': False, 'message': '无法初始化钉钉二维码，请检查登录域名和应用配置'}), 400


@app.route('/api/admin/dingtalk/callback', methods=['GET'])
def dingtalk_callback():
    try:
        config = dingtalk_config()
        state = request.args.get('state', '')
        browser = session.pop('dingtalk_browser', '')
        if (len(request.args.getlist('state')) != 1 or not re.fullmatch(r'[A-Za-z0-9_-]{43}', state)
                or not isinstance(browser, str) or not browser):
            raise DingTalkError('state')
        consumed = DingTalkLoginState.query.filter_by(
            state_hash=dingtalk_digest(state), browser_hash=dingtalk_digest(browser),
            client_hash=dingtalk_digest(config.client_id)
        ).filter(DingTalkLoginState.expires_at > datetime.utcnow()).delete(synchronize_session=False)
        db.session.commit()
        if consumed != 1:
            raise DingTalkError('state')
        auth_codes = request.args.getlist('authCode')
        codes = request.args.getlist('code')
        code = request.args.get('authCode') if auth_codes else request.args.get('code')
        if (request.args.get('error') is not None or len(auth_codes) > 1 or len(codes) > 1
                or not code or not code.strip() or len(code) > 2048):
            raise DingTalkError('authorization')
        union_id, employee_name = DingTalkClient(config).employee(code)
        user = resolve_dingtalk_account(config, union_id, employee_name)
        start_admin_login_session(user, '钉钉登录成功')
        return redirect('/admin/manage')
    except Exception as e:
        db.session.rollback()
        reason = str(e) if isinstance(e, DingTalkError) else 'provider'
        app.logger.warning('钉钉登录失败: %s', reason)
        try:
            db.session.add(AdminLoginLog(
                admin_username='dingtalk', success=False,
                message='钉钉登录失败: ' + reason, ip_address=request.remote_addr
            ))
            db.session.commit()
        except (IntegrityError, OperationalError):
            db.session.rollback()
        return redirect('/admin?' + urlencode({'dingtalkError': reason}))


@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    """退出登录，清除Session"""
    username = session.get('admin_username', 'unknown')
    client_ip = request.remote_addr
    admin_logger.info(f"管理员退出登录 | 用户名:{username} | IP:{client_ip}")
    logout_admin_session(username)
    session.clear()
    return jsonify({'success': True})


@app.route('/api/admin/search', methods=['POST'])
@admin_required
@permission_required('view_user')
def admin_search():
    """
    搜索AD用户
    输入工号或姓名/描述，返回姓名、部门、邮箱、账号状态
    未登录直接拒绝
    """
    data = request.get_json()
    query = (data.get('employee_id') or data.get('query') or '').strip()
    client_ip = request.remote_addr

    if not query:
        return jsonify({'success': False, 'message': '请输入工号或姓名'})

    is_account_search = is_valid_ad_account_name(query)
    employee_id = query.lower() if is_account_search else ''
    if not is_account_search and len(query) < 2:
        return jsonify({'success': False, 'message': '姓名查询至少输入 2 个字；工号请填写完整格式，例如 wfq101755'})
    safe_query = ldap_escape(query)
    if is_account_search:
        search_filter = (
            f'(&(objectCategory=person)(objectClass=user)'
            f'(|(sAMAccountName={ldap_escape(employee_id)})(displayName={ldap_escape(query)})))'
        )
    else:
        search_filter = (
            f'(&(objectCategory=person)(objectClass=user)'
            f'(sAMAccountName=wfq*)(description=*{safe_query}*))'
        )

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[
                'sAMAccountName', 'description', 'department', 'mail',
                'userAccountControl', 'distinguishedName', 'badPwdCount',
                'lockoutTime', 'logonCount', 'lastLogon', 'lastLogonTimestamp', 'pwdLastSet',
                'whenCreated', 'whenChanged', 'userPrincipalName', 'displayName', 'manager',
                'info', 'accountExpires', 'msDS-UserPasswordExpiryTimeComputed'
            ]
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': f'未找到 {query} 对应的用户'})

        if not is_account_search and len(conn.entries) > 1:
            matches = []
            for item in conn.entries[:20]:
                matches.append({
                    'employee_id': get_entry_text(item, 'displayName') or get_entry_text(item, 'sAMAccountName'),
                    'full_name': get_entry_text(item, 'description', '未填写'),
                    'department': get_entry_text(item, 'department', '未填写'),
                    'email': get_entry_text(item, 'mail', '未绑定')
                })
            conn.unbind()
            return jsonify({'success': True, 'matches': matches, 'message': '找到多个匹配用户，请选择一个'})

        entry = conn.entries[0]
        employee_id = get_entry_text(entry, 'sAMAccountName').lower()
        # userAccountControl: 512=正常启用, 514=已禁用
        uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 512
        is_disabled = bool(uac & 2)  # 第2位为1表示禁用
        is_locked_by_ad = is_ad_lockout_value(getattr(entry, 'lockoutTime', None))
        lock_count = int(get_entry_text(entry, 'badPwdCount', '0') or 0)
        has_logged, login_count, last_logon_dt, last_logon = login_status_from_ad(entry)

        latest_lock = AdminActionLog.query.filter_by(
            target_employee_id=employee_id,
            action='锁定账号'
        ).order_by(AdminActionLog.created_at.desc()).first()
        latest_disable = latest_action_for_target(employee_id, ['禁用账号', '启用账号'])
        latest_security = latest_action_for_target(employee_id, ['锁定账号', '解锁账号', '禁用账号', '启用账号'])

        if is_disabled and is_locked_by_ad:
            status = '已禁用 + 已锁定'
            lock_reason = latest_lock.message if latest_lock else '账号已禁用且处于锁定状态'
        elif is_disabled and latest_security and latest_security.action == '锁定账号':
            status = '管理员锁定'
            lock_reason = latest_security.message or '管理员手动锁定'
        elif is_disabled:
            status = '已禁用'
            lock_reason = latest_disable.message if latest_disable and latest_disable.action == '禁用账号' else '账号被管理员禁用'
        elif is_locked_by_ad:
            status = '已锁定'
            lock_reason = latest_lock.message if latest_lock else '密码错误次数过多导致AD锁定'
        else:
            status = '正常启用'
            lock_reason = '未锁定'

        password_change_count = RegisterLog.query.filter(
            RegisterLog.employee_id == employee_id,
            RegisterLog.status.in_(['reset_success', 'admin_reset_success'])
        ).count()

        manager_text = get_entry_text(entry, 'info')
        manager_dn = get_entry_text(entry, 'manager')
        manager_name = manager_text or (manager_dn.split(',')[0].replace('CN=', '', 1) if manager_dn else '')
        manager_account = ''
        if manager_dn and not manager_text:
            try:
                conn.search(
                    search_base=manager_dn,
                    search_filter='(objectClass=*)',
                    search_scope=ldap3.BASE,
                    attributes=['sAMAccountName', 'description', 'displayName']
                )
                if conn.entries:
                    manager_entry = conn.entries[0]
                    manager_display = get_entry_text(manager_entry, 'description') or get_entry_text(manager_entry, 'displayName') or get_entry_text(manager_entry, 'sAMAccountName')
                    manager_account = get_entry_text(manager_entry, 'sAMAccountName')
                    manager_name = manager_display
            except Exception:
                pass
        pwd_last_set_dt = ad_filetime_to_datetime(getattr(entry, 'pwdLastSet', None))
        password_never_expires = bool(uac & 65536)
        user_dn = get_entry_text(entry, 'distinguishedName')
        can_change_password = can_change_password_from_ad_acl(conn, user_dn)
        if can_change_password is None:
            can_change_password = can_change_password_from_net_user(employee_id)
        must_change_password = get_entry_text(entry, 'pwdLastSet', '') in ('0', 'None', '')
        password_expire_at = '未知'
        password_days_left = '未知'
        if must_change_password:
            password_expire_at = '下次登录必须改密'
            password_days_left = '0天'
        elif password_never_expires:
            password_expire_at = '永不过期'
            password_days_left = '永不过期'
        elif pwd_last_set_dt:
            max_age_days = get_effective_password_max_age_days(conn)
            expire_dt = get_user_password_expiry_datetime(entry, max_age_days)
            if expire_dt:
                password_expire_at = expire_dt.strftime('%Y-%m-%d %H:%M:%S')
                password_days_left = f'{(expire_dt.date() - local_now().date()).days}天'
            else:
                password_expire_at = '未读取到AD到期时间'
                password_days_left = '未知'

        user_info = {
            'employee_id': get_entry_text(entry, 'displayName') or get_entry_text(entry, 'sAMAccountName'),
            'account_name': get_entry_text(entry, 'sAMAccountName'),
            'full_name':   get_entry_text(entry, 'description', '未填写'),
            'department':  get_entry_text(entry, 'department', '未填写'),
            'email':       get_entry_text(entry, 'mail', '未绑定'),
            'manager':     manager_name or '未填写',
            'manager_account': manager_account,
            'status':      status,
            'is_disabled': is_disabled,
            'is_locked':   is_locked_by_ad or is_disabled,
            'lock_count':  lock_count,
            'lock_reason': lock_reason,
            'login_count': login_count,
            'login_status': '已登录' if has_logged else '未登录',
            'password_change_count': password_change_count,
            'last_logon':  last_logon,
            'password_expire_at': password_expire_at,
            'password_days_left': password_days_left,
            'can_change_password': '未知' if can_change_password is None else ('是' if can_change_password else '否'),
            'password_never_expires': password_never_expires,
            'account_created_at': ad_datetime_to_str(getattr(entry, 'whenCreated', None)) or '未知',
            'last_security_action': {
                'action': latest_security.action if latest_security else '',
                'operator': latest_security.admin_username if latest_security else '',
                'message': latest_security.message if latest_security else '',
                'created_at': fmt_local_dt(latest_security.created_at) if latest_security else ''
            },
            'password_last_set': ad_filetime_to_str(getattr(entry, 'pwdLastSet', None)) or '未知',
            'dn':          user_dn,
            'raw_attributes': {
                'sAMAccountName': get_entry_text(entry, 'sAMAccountName'),
                'userPrincipalName': get_entry_text(entry, 'userPrincipalName'),
                'displayName': get_entry_text(entry, 'displayName'),
                'description': get_entry_text(entry, 'description'),
                'department': get_entry_text(entry, 'department'),
                'mail': get_entry_text(entry, 'mail'),
                'manager': manager_text or manager_dn,
                'userAccountControl': str(uac),
                'badPwdCount': str(lock_count),
                'lockoutTime': get_entry_text(entry, 'lockoutTime', '0'),
                'logonCount': str(login_count),
                'lastLogon': get_entry_text(entry, 'lastLogon', ''),
                'lastLogonTimestamp': get_entry_text(entry, 'lastLogonTimestamp', ''),
                'pwdLastSet': get_entry_text(entry, 'pwdLastSet', ''),
                'accountExpires': get_entry_text(entry, 'accountExpires', ''),
                'whenCreated': get_entry_text(entry, 'whenCreated', ''),
                'whenChanged': get_entry_text(entry, 'whenChanged', ''),
                'distinguishedName': get_entry_text(entry, 'distinguishedName')
            }
        }
        related_computers = get_related_computers(conn, employee_id)
        user_info['computers'] = related_computers
        conn.unbind()

        admin_logger.info(f"搜索用户 | 关键字:{query} | 工号:{employee_id} | IP:{client_ip}")
        return jsonify({'success': True, 'user': user_info})

    except Exception as e:
        app.logger.error(f"管理员搜索AD失败: {e}")
        return jsonify({'success': False, 'message': '连接AD失败，请联系IT'})


def precreate_response(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def precreate_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return precreate_response({'success': False, 'message': '未登录，请重新登录'}, 401)
        try:
            user = current_admin_user()
            if not user or user.role != 'super_admin':
                return precreate_response({'success': False, 'message': '只有超级管理员可以预建账号'}, 403)
            touch_admin_session()
            if request.method != 'GET':
                token = request.headers.get('X-CSRF-Token', '')
                expected = session.get('ad_precreate_csrf', '')
                if not expected or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token) or not secrets.compare_digest(token, expected):
                    raise PrecreateError('页面校验已失效，请重新进入批量预建页面', 403)
                if not request.is_json or (request.content_length or 0) > 32768:
                    raise PrecreateError('请求格式或大小不正确')
            return fn(*args, **kwargs)
        except PrecreateError as error:
            db.session.rollback()
            return precreate_response({'success': False, 'message': str(error)}, error.status)
        except (IntegrityError, OperationalError):
            db.session.rollback()
            return precreate_response({'success': False, 'message': '记录保存暂未完成，请刷新批次核对结果后再继续'}, 503)
        except Exception as error:
            db.session.rollback()
            app.logger.error('预建账号操作失败，异常类型:%s', type(error).__name__)
            return precreate_response({'success': False, 'message': '操作结果未确认，请刷新批次核对结果'}, 500)
    return wrapped


def precreate_password(data=None):
    if data is not None:
        password = data.get('password') if isinstance(data, dict) else None
    else:
        password = os.environ.get('AD_PRECREATE_DEFAULT_PASSWORD', app.config.get('AD_PRECREATE_DEFAULT_PASSWORD', ''))
    valid = isinstance(password, str) and 0 < len(password) <= 256
    valid, message = validate_password(password) if valid else (False, '请填写 1 至 256 位的本批次初始密码')
    if not valid:
        if data is not None:
            raise PrecreateError(message)
        raise PrecreateError('请先在服务器私有配置中设置符合密码规则的 AD_PRECREATE_DEFAULT_PASSWORD', 503)
    return password


def precreate_password_mac(password):
    return hmac.new(str(app.secret_key).encode(), ('ad-precreate:' + password).encode(), hashlib.sha256).hexdigest()


def precreate_signer():
    return URLSafeTimedSerializer(app.secret_key, salt='ad-precreate-preview')


def precreate_audit(action, target, message):
    db.session.add(AdminActionLog(admin_username=current_admin_username(), action=action,
        target_employee_id=target, message=message, ip_address=request.remote_addr))


def precreate_batch_data(batch, include_items=True):
    items = [{'employee_id': row.employee_id, 'status': row.status, 'message': row.message,
              'finished_at': fmt_local_dt(row.finished_at) if row.finished_at else ''} for row in batch.items]
    counts = {key: 0 for key in ('pending', 'processing', 'created', 'skipped', 'failed', 'unknown')}
    counts.update(Counter(row['status'] for row in items))
    result = {'id': batch.id, 'spec': json.loads(batch.spec), 'created_by': batch.created_by,
              'created_at': fmt_local_dt(batch.created_at), 'counts': counts}
    if include_items:
        result['items'] = items
    return result


def get_precreate_batch(batch_id):
    batch = db.session.get(AdPrecreateBatch, batch_id)
    if not batch:
        raise PrecreateError('批次不存在', 404)
    return batch


def check_precreate_batch(batch, data=None):
    spec = json.loads(batch.spec)
    if spec['ou'] != app.config.get('AD_USER_OU'):
        raise PrecreateError('创建 OU 配置已变化，此批次已暂停，请核对后重新预览', 409)
    custom = spec.get('password_source') == 'input' or (isinstance(data, dict) and 'password' in data)
    password = precreate_password(data if isinstance(data, dict) else {}) if custom else precreate_password()
    if not secrets.compare_digest(batch.password_mac, precreate_password_mac(password)):
        raise PrecreateError('密码与本批次预览时不一致，已暂停；续跑请输入该批次原密码，新密码请重新预览建立新批次', 409)
    return spec, password


@app.route('/api/admin/ad-precreate/config', methods=['GET'])
@limiter.exempt
@precreate_required
def ad_precreate_config():
    session.setdefault('ad_precreate_csrf', secrets.token_urlsafe(32))
    try:
        precreate_password()
        password_ready = True
    except PrecreateError:
        password_ready = False
    return precreate_response({'success': True, 'ou': app.config.get('AD_USER_OU', ''),
        'password_ready': password_ready, 'password_input': True, 'csrf_token': session['ad_precreate_csrf']})


@app.route('/api/admin/ad-precreate/password', methods=['POST'])
@limiter.limit('10 per minute')
@precreate_required
def ad_precreate_password():
    password = precreate_password()
    precreate_audit('查看预建初始密码', 'SYSTEM', '查看统一初始密码；未记录密码内容')
    db.session.commit()
    return precreate_response({'success': True, 'password': password})


@app.route('/api/admin/ad-precreate/preview', methods=['POST'])
@limiter.limit('10 per minute')
@precreate_required
def ad_precreate_preview():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise PrecreateError('请求格式不正确')
    spec = validate_spec({key: value for key, value in data.items() if key != 'password'})
    custom = 'password' in data or 'prefix' in spec
    password = precreate_password(data) if custom else precreate_password()
    if custom:
        spec['password_source'] = 'input'
    ou = app.config.get('AD_USER_OU')
    if not isinstance(ou, str) or not ou.strip():
        raise PrecreateError('未配置单个创建使用的 AD_USER_OU', 503)
    spec['ou'] = ou
    ids = account_ids(spec)
    with PrecreateDirectory(app.config, ou) as directory:
        existing = directory.lookup(ids)
    rows = [{'employee_id': value, 'status': 'skipped' if value in existing else 'pending',
             'message': '账号已存在，将跳过且不修改' if value in existing else '可创建'} for value in ids]
    token = precreate_signer().dumps({'spec': spec, 'password_mac': precreate_password_mac(password),
                                    'operator': current_admin_username()})
    return precreate_response({'success': True, 'spec': spec, 'items': rows, 'preview_token': token})


@app.route('/api/admin/ad-precreate/batches', methods=['GET', 'POST'])
@limiter.exempt
@precreate_required
def ad_precreate_batches():
    if request.method == 'GET':
        batches = AdPrecreateBatch.query.order_by(AdPrecreateBatch.created_at.desc()).limit(20).all()
        return precreate_response({'success': True, 'batches': [precreate_batch_data(row, False) for row in batches]})
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get('confirm_text') != 'YES':
        raise PrecreateError('请先预览并确认创建')
    key = data.get('request_key')
    try:
        if not isinstance(key, str) or str(uuid.UUID(key)) != key:
            raise ValueError()
        payload = precreate_signer().loads(data.get('preview_token', ''))
    except (ValueError, TypeError, BadSignature):
        raise PrecreateError('批次请求或预览凭据无效') from None
    if payload.get('operator') != current_admin_username():
        raise PrecreateError('预览不属于当前操作人', 403)
    spec = payload['spec']
    if spec['enabled'] and data.get('confirm_enabled') is not True:
        raise PrecreateError('请确认统一密码且不要求首次改密的账号将立即启用')
    serialized = json.dumps(spec, sort_keys=True, ensure_ascii=False)
    existing = AdPrecreateBatch.query.filter_by(request_key=key).first()
    if existing:
        if existing.created_by != current_admin_username() or existing.spec != serialized or existing.password_mac != payload['password_mac']:
            raise PrecreateError('相同请求标识不能用于不同批次', 409)
        check_precreate_batch(existing, data)
        return precreate_response({'success': True, 'batch': precreate_batch_data(existing)})
    try:
        precreate_signer().loads(data.get('preview_token', ''), max_age=600)
    except SignatureExpired:
        raise PrecreateError('预览已过期，请重新预览', 409) from None
    batch = AdPrecreateBatch(id=str(uuid.uuid4()), request_key=key, spec=serialized,
        password_mac=payload['password_mac'], created_by=current_admin_username())
    check_precreate_batch(batch, data)
    db.session.add(batch)
    batch.items = [AdPrecreateItem(employee_id=value) for value in account_ids(spec)]
    precreate_audit('建立预建批次', batch.id, f"{account_ids(spec)[0]} 至 {account_ids(spec)[-1]}；启用:{spec['enabled']}；不要求首次改密")
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = AdPrecreateBatch.query.filter_by(request_key=key).first()
        if not existing or existing.spec != serialized or existing.created_by != current_admin_username() or existing.password_mac != payload['password_mac']:
            raise PrecreateError('批次请求冲突，请刷新核对', 409) from None
        batch = existing
    return precreate_response({'success': True, 'batch': precreate_batch_data(batch)})


@app.route('/api/admin/ad-precreate/batches/<batch_id>', methods=['GET'])
@limiter.exempt
@precreate_required
def ad_precreate_batch(batch_id):
    return precreate_response({'success': True, 'batch': precreate_batch_data(get_precreate_batch(batch_id))})


@app.route('/api/admin/ad-precreate/batches/<batch_id>/retry', methods=['POST'])
@limiter.exempt
@precreate_required
def ad_precreate_retry(batch_id):
    batch = get_precreate_batch(batch_id)
    check_precreate_batch(batch, request.get_json(silent=True))
    AdPrecreateItem.query.filter_by(batch_id=batch.id).filter(
        AdPrecreateItem.status.in_(['failed', 'unknown'])).update(
            {'status': 'pending', 'message': '待核对并重试', 'attempt_token': None,
             'started_at': None, 'finished_at': None}, synchronize_session=False)
    precreate_audit('重试预建批次', batch.id, '仅重试未确认或失败项，先查询 AD，不修改已有账号')
    db.session.commit()
    db.session.expire_all()
    return precreate_response({'success': True, 'batch': precreate_batch_data(batch)})


def precreate_account_result(account, item, spec, marker):
    expected_dn = f"cn={item.employee_id},{spec['ou']}"
    if account.info != '备注：' + marker:
        return 'skipped', '账号已存在，未修改资料、密码或启用状态'
    if account.dn.casefold() != expected_dn.casefold() or not account.guid or account.enabled != spec['enabled']:
        return 'unknown', '已发现本批次账号，但位置或启用状态不符，请人工核对'
    if item.object_guid and item.object_guid != account.guid:
        return 'unknown', '账号标识已变化，请人工核对'
    return 'created', '已创建并回读确认；' + ('已启用' if spec['enabled'] else '已禁用，待发放时启用')


@app.route('/api/admin/ad-precreate/batches/<batch_id>/step', methods=['POST'])
@limiter.exempt
@precreate_required
def ad_precreate_step(batch_id):
    batch = get_precreate_batch(batch_id)
    spec, password = check_precreate_batch(batch, request.get_json(silent=True))
    cutoff = datetime.utcnow() - timedelta(seconds=180)
    item = next((row for row in batch.items if row.status == 'pending' or
        (row.status == 'processing' and row.started_at and row.started_at < cutoff)), None)
    if not item:
        return precreate_response({'success': True, 'batch': precreate_batch_data(batch),
                                  'waiting': any(row.status == 'processing' for row in batch.items)})
    token = uuid.uuid4().hex
    query = AdPrecreateItem.query.filter_by(id=item.id, status=item.status)
    if item.status == 'processing':
        query = query.filter(AdPrecreateItem.started_at == item.started_at)
    claimed = query.update({'status': 'processing', 'attempt_token': token, 'started_at': datetime.utcnow(),
                            'message': '正在核对和创建'}, synchronize_session=False)
    db.session.commit()
    if claimed != 1:
        db.session.expire_all()
        return precreate_response({'success': True, 'batch': precreate_batch_data(batch), 'waiting': True})
    identity = f'{batch.id}/{item.employee_id}'
    signature = hmac.new(str(app.secret_key).encode(), ('ad-precreate-owner:' + identity).encode(), hashlib.sha256).hexdigest()
    marker = f'预建批次:{identity}:{signature}'
    wrote = False
    account = None
    try:
        with PrecreateDirectory(app.config, spec['ou']) as directory:
            account = directory.lookup([item.employee_id]).get(item.employee_id)
            if not account:
                wrote = True
                rejection = None
                added = None
                try:
                    added = directory.create(item.employee_id, password, spec['full_name'], spec['enabled'], marker)
                except PrecreateError as error:
                    rejection = error
                account = directory.lookup([item.employee_id]).get(item.employee_id)
                if not account:
                    if rejection:
                        raise rejection
                    if added is False:
                        raise PrecreateError('目标 OU 存在同名对象，未修改；请核对 CN 和登录名')
                    raise PrecreateError('创建请求后未查到账号，请先核对 AD', 503)
            status, message = precreate_account_result(account, item, spec, marker)
    except PrecreateError as error:
        status = 'unknown' if wrote and error.status != 400 else 'failed'
        message = str(error)
    finished = AdPrecreateItem.query.filter_by(id=item.id, attempt_token=token, status='processing').update(
        {'status': status, 'message': message, 'finished_at': datetime.utcnow(),
         'object_guid': account.guid if account and status == 'created' else item.object_guid}, synchronize_session=False)
    if finished:
        precreate_audit('批量预建账号', item.employee_id, f'批次:{batch.id}；{message}')
    db.session.commit()
    db.session.expire_all()
    return precreate_response({'success': True, 'batch': precreate_batch_data(batch), 'waiting': False})


def bulk_delete_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return precreate_response({'success': False, 'message': '未登录，请重新登录'}, 401)
        try:
            user = current_admin_user()
            if not user or user.role != 'super_admin' or not has_permission('delete_user'):
                return precreate_response({'success': False, 'message': '只有超级管理员可以批量删除用户'}, 403)
            touch_admin_session()
            if request.method != 'GET':
                if get_setting('allow_delete_user', 'true') != 'true':
                    raise PrecreateError('系统设置已关闭删除 AD 用户功能', 403)
                expected = session.get('ad_bulk_delete_csrf', '')
                token = request.headers.get('X-CSRF-Token', '')
                if not expected or not secrets.compare_digest(expected, token):
                    raise PrecreateError('页面校验已失效，请重新进入批量删除页面', 403)
                if not request.is_json or (request.content_length or 0) > 262144:
                    raise PrecreateError('请求格式或大小不正确')
            return fn(*args, **kwargs)
        except PrecreateError as error:
            db.session.rollback()
            return precreate_response({'success': False, 'message': str(error)}, error.status)
        except (IntegrityError, OperationalError):
            db.session.rollback()
            return precreate_response({'success': False, 'message': '批次记录暂未保存完成，请查看历史批次核对；不要重复删除'}, 503)
        except Exception as error:
            db.session.rollback()
            app.logger.error('批量删除异常，类型:%s', type(error).__name__)
            return precreate_response({'success': False, 'message': '操作结果未确认，已暂停，请查看批次核对'}, 500)
    return wrapped


def bulk_delete_directory(host=None):
    return BulkDeleteDirectory(app.config, host=host or os.getenv('GPO_LDAP_SERVER') or None,
                               ca_file=os.getenv('GPO_LDAP_CA_CERTS_FILE') or None)


def bulk_delete_provenance(names):
    records = AdPrecreateItem.query.filter(AdPrecreateItem.employee_id.in_(names),
        AdPrecreateItem.status == 'created', AdPrecreateItem.object_guid.isnot(None)).all()
    return {row.object_guid: row.employee_id for row in records}


def bulk_delete_source(account, known):
    if known.get(account['guid']) == account['employee_id']:
        return 'precreated'
    return 'unknown' if '预建批次:' in account['info'] else 'ordinary'


def bulk_delete_protected_names():
    bind = str(app.config.get('AD_BIND_USER', '')).lower()
    return {current_admin_username().lower(), bind, bind.rsplit('\\', 1)[-1].split('@', 1)[0]}


def bulk_delete_batch_data(batch):
    items = [{**json.loads(row.snapshot), 'status': row.status, 'message': row.message} for row in batch.items]
    counts = {key: 0 for key in ('pending', 'processing', 'deleted', 'absent', 'skipped', 'failed', 'unknown')}
    counts.update(Counter(row['status'] for row in items))
    return {'id': batch.id, 'spec': json.loads(batch.spec), 'created_by': batch.created_by,
            'created_at': fmt_local_dt(batch.created_at), 'items': items, 'counts': counts}


def get_bulk_delete_batch(batch_id):
    batch = db.session.get(AdBulkDeleteBatch, batch_id)
    if not batch or batch.created_by != current_admin_username():
        raise PrecreateError('批次不存在或不属于当前操作人', 404)
    spec = json.loads(batch.spec)
    if spec['ou'] != app.config.get('AD_USER_OU') or spec['base_dn'] != app.config.get('AD_BASE_DN'):
        raise PrecreateError('目标域或 OU 已变化，批次已暂停，请重新筛选', 409)
    return batch


@app.route('/api/admin/ad-bulk-delete/config', methods=['GET'])
@limiter.exempt
@bulk_delete_required
def ad_bulk_delete_config():
    session.setdefault('ad_bulk_delete_csrf', secrets.token_urlsafe(32))
    return precreate_response({'success': True, 'csrf_token': session['ad_bulk_delete_csrf'],
        'days': BULK_DELETE_DAYS, 'limit': BULK_DELETE_LIMIT, 'ou': app.config.get('AD_USER_OU', ''),
        'enabled': get_setting('allow_delete_user', 'true') == 'true'})


@app.route('/api/admin/ad-bulk-delete/scan', methods=['POST'])
@limiter.limit('5 per minute')
@bulk_delete_required
def ad_bulk_delete_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {'scope', 'prefix'} or data.get('scope') not in ('precreated', 'ordinary'):
        raise PrecreateError('请选择批量预建账号或普通员工账号')
    prefix = data.get('prefix', 'wfq')
    if not isinstance(prefix, str) or not re.fullmatch(r'wfq[0-9]{0,6}', prefix.strip().lower()):
        raise PrecreateError('筛选前缀应为 wfq 或 wfq 加数字')
    if not app.config.get('AD_USER_OU'):
        raise PrecreateError('未配置员工 OU，禁止扫描和删除', 503)
    now = datetime.utcnow()
    rows, permitted = [], []
    with bulk_delete_directory() as directory:
        entries, truncated = directory.candidates(prefix.strip().lower(), now)
        names = [bulk_delete_entry_text(entry, 'sAMAccountName').lower() for entry in entries]
        known = bulk_delete_provenance(names)
        for entry in entries:
            try:
                initial = snapshot(entry)
                source = bulk_delete_source(initial, known)
                if source != data['scope']:
                    if source == 'unknown' and data['scope'] == 'precreated':
                        rows.append({'employee_id': initial['employee_id'], 'name': initial['name'],
                            'can_delete': False, 'message': '存在预建标记但平台创建记录无法核对，禁止删除'})
                    continue
                account, peers = directory.inspect(initial['guid'])
                if not account:
                    continue
                reason = blocked_reason(account, peers, app.config['AD_USER_OU'], bulk_delete_protected_names(), now, directory.protected_groups)
                if bulk_delete_source(account, known) != source:
                    reason = '账号来源发生变化，请重新筛选'
                last = max((row['last_logon'] for row in peers if row['last_logon']), default=None)
                row = {key: account[key] for key in ('employee_id', 'guid', 'dn', 'name', 'department', 'created', 'usn', 'uac')}
                row.update(source=source, last_logon=last, can_delete=not bool(reason), message=reason or '满足 45 天规则，待人工勾选')
                rows.append(row)
                if not reason:
                    permitted.append(row)
            except (PrecreateError, ValueError, KeyError, TypeError, OverflowError) as error:
                rows.append({'employee_id': bulk_delete_entry_text(entry, 'sAMAccountName') or '-',
                    'can_delete': False, 'message': str(error) if isinstance(error, PrecreateError) else '登录记录、组权限或删除保护信息无法完整确认，禁止删除'})
        spec = {'scope': data['scope'], 'ou': app.config['AD_USER_OU'], 'base_dn': app.config['AD_BASE_DN'],
                'controllers': directory.controllers, 'write_host': directory.write_host, 'days': BULK_DELETE_DAYS}
    token = URLSafeTimedSerializer(app.secret_key, salt='ad-bulk-delete-preview').dumps(
        {'operator': current_admin_username(), 'spec': spec, 'items': permitted})
    return precreate_response({'success': True, 'items': rows, 'preview_token': token, 'truncated': truncated,
        'controllers': spec['controllers'], 'days': BULK_DELETE_DAYS})


@app.route('/api/admin/ad-bulk-delete/batches', methods=['GET', 'POST'])
@limiter.exempt
@bulk_delete_required
def ad_bulk_delete_batches():
    if request.method == 'GET':
        batches = AdBulkDeleteBatch.query.filter_by(created_by=current_admin_username()).order_by(AdBulkDeleteBatch.created_at.desc()).limit(20).all()
        return precreate_response({'success': True, 'batches': [bulk_delete_batch_data(row) for row in batches]})
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get('confirm_text') != 'YES' or data.get('acknowledge_recovery') is not True:
        raise PrecreateError('请勾选、预览并输入 YES 确认删除')
    selected = data.get('selected')
    if (not isinstance(selected, list) or not 1 <= len(selected) <= BULK_DELETE_LIMIT or
            any(not isinstance(value, str) for value in selected) or len(set(selected)) != len(selected) or
            type(data.get('confirm_count')) is not int or data['confirm_count'] != len(selected)):
        raise PrecreateError('勾选名单或确认数量不正确')
    try:
        key = data['request_key']
        if not isinstance(key, str) or str(uuid.UUID(key)) != key:
            raise ValueError()
        signer = URLSafeTimedSerializer(app.secret_key, salt='ad-bulk-delete-preview')
        payload = signer.loads(data.get('preview_token', ''))
    except (KeyError, ValueError, TypeError, BadSignature):
        raise PrecreateError('删除预览凭据无效') from None
    if payload['operator'] != current_admin_username():
        raise PrecreateError('预览不属于当前操作人', 403)
    choices = {row['employee_id']: row for row in payload['items']}
    if any(name not in choices for name in selected):
        raise PrecreateError('只能删除预览中允许勾选的账号')
    snapshots = [choices[name] for name in sorted(selected)]
    existing = AdBulkDeleteBatch.query.filter_by(request_key=key).first()
    spec = json.dumps(payload['spec'], sort_keys=True, ensure_ascii=False)
    if existing:
        if (existing.created_by != current_admin_username() or existing.spec != spec or
                [json.loads(row.snapshot) for row in existing.items] != snapshots):
            raise PrecreateError('相同请求标识不能用于不同删除名单', 409)
        return precreate_response({'success': True, 'batch': bulk_delete_batch_data(existing)})
    try:
        signer.loads(data.get('preview_token', ''), max_age=600)
    except SignatureExpired:
        raise PrecreateError('筛选已超过十分钟，请重新筛选并确认', 409) from None
    batch = AdBulkDeleteBatch(id=str(uuid.uuid4()), request_key=key, spec=spec, created_by=current_admin_username())
    batch.items = [AdBulkDeleteItem(employee_id=row['employee_id'], snapshot=json.dumps(row, ensure_ascii=False)) for row in snapshots]
    if payload['spec']['ou'] != app.config.get('AD_USER_OU') or payload['spec']['base_dn'] != app.config.get('AD_BASE_DN'):
        raise PrecreateError('目标域或 OU 已变化，请重新筛选', 409)
    db.session.add(batch)
    precreate_audit('建立批量删除批次', 'BULK_DELETE', f'批次:{batch.id}；数量:{len(snapshots)}；45天未使用；仅删除用户，计算机保留')
    db.session.commit()
    return precreate_response({'success': True, 'batch': bulk_delete_batch_data(batch)})


@app.route('/api/admin/ad-bulk-delete/batches/<batch_id>', methods=['GET'])
@limiter.exempt
@bulk_delete_required
def ad_bulk_delete_batch(batch_id):
    return precreate_response({'success': True, 'batch': bulk_delete_batch_data(get_bulk_delete_batch(batch_id))})


@app.route('/api/admin/ad-bulk-delete/batches/<batch_id>/retry', methods=['POST'])
@limiter.exempt
@bulk_delete_required
def ad_bulk_delete_retry(batch_id):
    batch = get_bulk_delete_batch(batch_id)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get('confirm_text') != 'YES' or data.get('acknowledge_recovery') is not True:
        raise PrecreateError('请确认核对后重试')
    AdBulkDeleteItem.query.filter_by(batch_id=batch.id).filter(AdBulkDeleteItem.status.in_(['failed', 'unknown'])).update(
        {'status': 'pending', 'message': '待重新核对', 'attempt_token': None, 'started_at': None}, synchronize_session=False)
    precreate_audit('重试批量删除', 'BULK_DELETE', f'批次:{batch.id}；重新复查后才允许删除')
    db.session.commit()
    db.session.expire_all()
    return precreate_response({'success': True, 'batch': bulk_delete_batch_data(batch)})


@app.route('/api/admin/ad-bulk-delete/batches/<batch_id>/step', methods=['POST'])
@limiter.exempt
@bulk_delete_required
def ad_bulk_delete_step(batch_id):
    batch = get_bulk_delete_batch(batch_id)
    expired = AdBulkDeleteItem.query.filter_by(batch_id=batch.id, status='processing').filter(
        AdBulkDeleteItem.started_at < datetime.utcnow() - timedelta(seconds=180)).all()
    for row in expired:
        row.status, row.message = 'unknown', '上次请求已中断，请人工确认后点击核对重试'
    if expired:
        db.session.commit()
        return precreate_response({'success': True, 'batch': bulk_delete_batch_data(batch), 'waiting': False})
    item = next((row for row in batch.items if row.status == 'pending'), None)
    if not item:
        return precreate_response({'success': True, 'batch': bulk_delete_batch_data(batch),
            'waiting': any(row.status == 'processing' for row in batch.items)})
    token = uuid.uuid4().hex
    claimed = AdBulkDeleteItem.query.filter_by(id=item.id, status='pending').update(
        {'status': 'processing', 'message': '正在复查域登录与保护状态', 'attempt_token': token, 'started_at': datetime.utcnow()}, synchronize_session=False)
    if claimed:
        precreate_audit('批量删除前复查', item.employee_id, f'批次:{batch.id}；仅用户对象，计算机保留')
    db.session.commit()
    if not claimed:
        db.session.expire_all()
        return precreate_response({'success': True, 'batch': bulk_delete_batch_data(batch), 'waiting': True})
    spec, original = json.loads(batch.spec), json.loads(item.snapshot)
    sent = False
    try:
        with bulk_delete_directory(spec['write_host']) as directory:
            if directory.controllers != spec['controllers'] or directory.write_host != spec['write_host']:
                raise PrecreateError('域控列表已变化，请重新筛选', 409)
            account, peers = directory.inspect(original['guid'])
            if not account:
                status, message = 'absent', '原对象已不存在；未发送删除，不认定为本批次删除成功'
            else:
                reason = blocked_reason(account, peers, spec['ou'], bulk_delete_protected_names(), datetime.utcnow(), directory.protected_groups)
                source = bulk_delete_source(account, bulk_delete_provenance([item.employee_id]))
                if source != spec['scope']:
                    reason = '账号来源已变化，请重新筛选'
                if any(account[key] != original[key] for key in ('employee_id', 'guid', 'dn', 'created', 'usn', 'uac')):
                    reason = '账号自预览后发生变化，已跳过；请重新筛选'
                if reason:
                    status, message = 'skipped', reason
                else:
                    db.session.expire_all()
                    if not is_super_admin_user() or get_setting('allow_delete_user', 'true') != 'true':
                        raise PrecreateError('执行前权限或删除开关已变化，已停止', 403)
                    sent = True
                    removed = directory.delete(account)
                    remaining, _ = directory.inspect(original['guid'])
                    if remaining:
                        status, message = 'unknown', '删除后仍查到原对象，已暂停，请人工核对'
                    elif removed:
                        status, message = 'deleted', '用户已删除并回读确认；所有计算机均保留'
                    else:
                        status, message = 'absent', '原对象已不存在；未重复删除'
    except PrecreateError as error:
        status = 'unknown' if sent and error.status != 400 else 'failed'
        message = str(error)
    finished = AdBulkDeleteItem.query.filter_by(id=item.id, attempt_token=token, status='processing').update(
        {'status': status, 'message': message, 'finished_at': datetime.utcnow()}, synchronize_session=False)
    if finished:
        precreate_audit('批量删除用户', item.employee_id, f'批次:{batch.id}；{message}；姓名:{original["name"]}；部门:{original["department"]}')
    db.session.commit()
    db.session.expire_all()
    return precreate_response({'success': True, 'batch': bulk_delete_batch_data(batch), 'waiting': False})


@app.route('/api/admin/ad-users/reserve-id', methods=['POST'])
@admin_required
@permission_required('edit_user')
def admin_reserve_employee_id():
    """超级管理员按新员工序列生成并预留下一个工号。"""
    user = current_admin_user()
    if not user or user.role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以创建新员工账号'})
    try:
        record = reserve_next_employee_id(current_admin_username())
        return jsonify({
            'success': True,
            'employee_id': record.employee_id,
            'reservation_token': record.reservation_token
        })
    except LDAPException:
        return jsonify({'success': False, 'message': '连接AD失败，无法生成下一个工号'})
    except RuntimeError as e:
        return jsonify({'success': False, 'message': str(e)})
    except Exception as e:
        app.logger.error(f'生成下一个新员工工号失败: {e}')
        return jsonify({'success': False, 'message': '生成工号失败，请联系IT'})


@app.route('/api/admin/ad-users/create', methods=['POST'])
@admin_required
@permission_required('edit_user')
def admin_create_employee_account():
    """使用管理员自定义或顺序生成的工号创建新员工AD账号。"""
    user = current_admin_user()
    if not user or user.role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以创建新员工账号'})

    data = request.get_json(silent=True) or {}
    employee_id = (data.get('employee_id') or '').strip().lower()
    reservation_token = (data.get('reservation_token') or '').strip()
    full_name = (data.get('full_name') or '').strip()
    password = data.get('password') or ''
    department = (data.get('department') or '').strip()
    email = (data.get('email') or '').strip()
    manager_name = (data.get('manager_name') or '').strip()
    job_title = (data.get('job_title') or '').strip()
    note = (data.get('note') or '').strip()
    must_change_next_login = bool(data.get('must_change_next_login', True))
    operator = current_admin_username()

    if not is_valid_employee_id(employee_id):
        return jsonify({'success': False, 'message': '工号格式不正确，应为wfq加6位数字'})

    if reservation_token:
        record = EmployeeAccountProvision.query.filter_by(
            employee_id=employee_id,
            reservation_token=reservation_token
        ).first()
        if not record or record.created_by != operator:
            return jsonify({'success': False, 'message': '工号预留信息已失效，请重新生成'})
    else:
        try:
            record = reserve_specific_employee_id(employee_id, operator)
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)})
        except LDAPException:
            return jsonify({'success': False, 'message': '连接AD失败，无法检查工号'})
        except Exception as e:
            app.logger.error(f'预留自定义工号失败: {e}')
            return jsonify({'success': False, 'message': '检查工号失败，请联系IT'})

    if record.status == 'active':
        return jsonify({
            'success': True,
            'employee_id': record.employee_id,
            'message': f'账号 {record.employee_id} 已创建'
        })
    if not full_name or len(full_name) > 80:
        return jsonify({'success': False, 'message': '请填写员工姓名'})
    password_ok, password_message = validate_password(password)
    if not password_ok:
        return jsonify({'success': False, 'message': password_message})
    if email and not is_valid_email(email):
        return jsonify({'success': False, 'message': '邮箱格式不正确'})
    optional_fields = {
        '部门': (department, 80),
        '直属领导': (manager_name, 80),
        '职位': (job_title, 80),
        '备注': (note, 500)
    }
    for label, (value, max_length) in optional_fields.items():
        if len(value) > max_length:
            return jsonify({'success': False, 'message': f'{label}内容过长'})

    record.full_name = full_name
    record.department = department
    record.email = email
    record.manager_name = manager_name
    record.job_title = job_title
    record.note = note
    record.message = '正在创建AD账号'
    db.session.commit()

    success, message = create_ad_user(
        employee_id, email, password, full_name, department,
        manager_name=manager_name, job_title=job_title, note=note
    )
    if not success:
        record.status = 'reserved'
        record.message = message
        db.session.commit()
        write_admin_action('创建AD用户失败', employee_id, message, request.remote_addr)
        return jsonify({'success': False, 'message': message})

    warning = ''
    if must_change_next_login:
        changed, reason = force_password_change_next_login(employee_id)
        if not changed:
            warning = f'；账号已创建，但下次登录改密设置失败：{reason}'

    record.status = 'active'
    record.message = f'AD账号创建成功{warning}'
    db.session.commit()
    detail = (
        f'姓名:{full_name} | 部门:{department or "未填写"} | '
        f'邮箱:{email or "未填写"} | 下次登录改密:{"是" if must_change_next_login else "否"}'
    )
    write_admin_action('创建AD用户', employee_id, detail, request.remote_addr)
    return jsonify({
        'success': True,
        'employee_id': employee_id,
        'message': f'创建成功：{employee_id} / {full_name}{warning}'
    })


@app.route('/api/admin/disable', methods=['POST'])
@admin_required
@permission_required('disable_user')
def admin_disable():
    """
    禁用AD账号（可恢复）
    把 userAccountControl 的第2位设为1 → 账号禁用，无法登录
    账号数据还在，随时可以重新启用
    """
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    reason = data.get('reason', '').strip()
    client_ip = request.remote_addr
    if not reason:
        return jsonify({'success': False, 'message': '请输入禁用原因'})

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'description', 'userAccountControl']
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        user_dn   = str(conn.entries[0].distinguishedName)
        full_name = str(conn.entries[0].description) if conn.entries[0].description else employee_id

        # 514 = 512(正常账号) + 2(禁用位) = 禁用
        conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [514])]})

        if conn.result['result'] == 0:
            conn.unbind()
            write_admin_action('禁用账号', employee_id, f"姓名:{full_name} | 原因:{reason}", client_ip)
            return jsonify({'success': True, 'message': f'账号 {employee_id}（{full_name}）已禁用'})
        else:
            conn.unbind()
            return jsonify({'success': False, 'message': f'禁用失败：{conn.result.get("description")}'})

    except Exception as e:
        app.logger.error(f"禁用账号失败: {e}")
        return jsonify({'success': False, 'message': '操作失败，请联系IT'})


@app.route('/api/admin/enable', methods=['POST'])
@admin_required
@permission_required('disable_user')
def admin_enable():
    """
    启用AD账号（禁用后可以重新启用）
    把 userAccountControl 改回 512
    """
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    client_ip = request.remote_addr

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'description']
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        user_dn   = str(conn.entries[0].distinguishedName)
        full_name = str(conn.entries[0].description) if conn.entries[0].description else employee_id

        # 512 = 正常启用
        conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [512])]})

        if conn.result['result'] == 0:
            conn.unbind()
            write_admin_action('启用账号', employee_id, f"姓名:{full_name}", client_ip)
            return jsonify({'success': True, 'message': f'账号 {employee_id}（{full_name}）已重新启用'})
        else:
            conn.unbind()
            return jsonify({'success': False, 'message': f'启用失败：{conn.result.get("description")}'})

    except Exception as e:
        app.logger.error(f"启用账号失败: {e}")
        return jsonify({'success': False, 'message': '操作失败，请联系IT'})


@app.route('/api/admin/delete', methods=['POST'])
@admin_required
@permission_required('delete_user')
def admin_delete():
    """
    彻底删除AD用户账号（不可恢复），不删除任何关联计算机对象。
    删除前请确认已禁用或确认离职
    操作记录写入admin.log
    """
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    confirm_text = data.get('confirm_text', '').strip()
    approval_id = data.get('approval_id')
    client_ip = request.remote_addr

    if get_setting('allow_delete_user', 'true') != 'true':
        return jsonify({'success': False, 'message': '系统设置已关闭删除AD用户功能'})
    if confirm_text.upper() != 'YES':
        return jsonify({'success': False, 'message': '请输入 YES 后再删除'})
    approval = None
    if not approval_id and not is_super_admin_user():
        approval = create_pending_approval(
            '删除AD用户',
            employee_id,
            {'employee_id': employee_id, 'confirm_text': 'YES'},
            f'请求删除AD用户 {employee_id}，关联计算机保留'
        )
        write_admin_action('发起删除审批', employee_id, f"审批ID:{approval.id}", client_ip)
        return jsonify({'success': False, 'need_approval': True, 'approval_id': approval.id,
                        'message': f'已创建审批 #{approval.id}，需要另一位有权限的管理员批准后再执行'})

    if approval_id:
        approval, err = validate_approval(approval_id, '删除AD用户')
        if err:
            return jsonify({'success': False, 'message': err})

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={employee_id}))',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'description', 'department']
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        user_dn    = str(conn.entries[0].distinguishedName)
        full_name  = str(conn.entries[0].description) if conn.entries[0].description else employee_id
        department = str(conn.entries[0].department)  if conn.entries[0].department  else '未知'
        # 执行删除
        conn.delete(user_dn)

        if conn.result['result'] == 0:
            conn.unbind()
            if approval:
                approval.status = 'executed'
                approval.executed_at = datetime.utcnow()
                db.session.commit()
            write_admin_action(
                '删除账号',
                employee_id,
                f"姓名:{full_name} | 部门:{department} | 仅删除用户，关联计算机保留",
                client_ip
            )
            msg = f'账号 {employee_id}（{full_name}）已删除，关联计算机已保留'
            return jsonify({'success': True, 'message': msg})
        else:
            conn.unbind()
            return jsonify({'success': False, 'message': f'删除失败：{conn.result.get("description")}'})

    except Exception as e:
        app.logger.error(f"删除账号失败: {e}")
        return jsonify({'success': False, 'message': '操作失败，请联系IT'})


@app.route('/api/admin/update_user', methods=['POST'])
@admin_required
@permission_required('edit_user')
def admin_update_user():
    """修改AD用户基础信息：姓名/描述、部门、邮箱、直属领导。工号不允许修改。"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    new_employee_id = employee_id
    full_name = data.get('full_name', '').strip()
    department = data.get('department', '').strip()
    email = data.get('email', '').strip().lower()
    manager_query = data.get('manager', '').strip()
    clear_manager = bool(data.get('clear_manager'))
    client_ip = request.remote_addr

    if not is_valid_ad_account_name(employee_id):
        return jsonify({'success': False, 'message': '账号名格式不正确，只允许字母、数字、点、下划线和横线'})
    if email and not is_valid_email(email):
        return jsonify({'success': False, 'message': '邮箱格式不正确'})
    if len(manager_query) > 64:
        return jsonify({'success': False, 'message': '直属领导姓名过长'})

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'department', 'mail', 'info', 'manager']
        )
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        current_entry = conn.entries[0]
        user_dn = str(current_entry.distinguishedName)

        changes = {
            'description': [(ldap3.MODIFY_REPLACE, [full_name or new_employee_id])]
        }
        if department:
            changes['department'] = [(ldap3.MODIFY_REPLACE, [department])]
        elif get_entry_text(current_entry, 'department'):
            changes['department'] = [(ldap3.MODIFY_DELETE, [])]
        if email:
            changes['mail'] = [(ldap3.MODIFY_REPLACE, [email])]
        elif get_entry_text(current_entry, 'mail'):
            changes['mail'] = [(ldap3.MODIFY_DELETE, [])]
        manager_label = '未修改'
        if manager_query:
            changes['info'] = [(ldap3.MODIFY_REPLACE, [manager_query])]
            manager_label = manager_query
        elif clear_manager:
            if get_entry_text(current_entry, 'info'):
                changes['info'] = [(ldap3.MODIFY_DELETE, [])]
            if get_entry_text(current_entry, 'manager'):
                changes['manager'] = [(ldap3.MODIFY_DELETE, [])]
            manager_label = '已清空'
        conn.modify(user_dn, changes)

        if conn.result['result'] == 0:
            conn.unbind()
            write_admin_action(
                '修改用户信息',
                employee_id,
                f"姓名:{full_name} | 部门:{department} | 邮箱:{email} | 直属领导:{manager_label}",
                client_ip
            )
            return jsonify({'success': True, 'message': '用户信息已更新'})

        reason = conn.result.get('description', '未知错误')
        conn.unbind()
        return jsonify({'success': False, 'message': f'修改失败：{reason}'})

    except Exception as e:
        app.logger.error(f"修改用户信息失败: {e}")
        return jsonify({'success': False, 'message': '操作失败，请联系IT'})


@app.route('/api/admin/lock', methods=['POST'])
@admin_required
@permission_required('lock_user')
def admin_lock():
    """锁定功能已取消：生产操作统一使用禁用/解锁。"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    write_admin_action('锁定功能已取消', employee_id or '-', '请使用禁用账号；解锁功能仍保留', request.remote_addr)
    return jsonify({'success': False, 'message': '锁定功能已取消，请使用“禁用账号”；解锁功能仍可使用'})


@app.route('/api/admin/unlock', methods=['POST'])
@admin_required
@permission_required('unlock_user')
def admin_unlock():
    """解锁账号：清空AD锁定时间，并清除禁用位。"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    client_ip = request.remote_addr

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'description', 'userAccountControl']
        )
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        entry = conn.entries[0]
        user_dn = str(entry.distinguishedName)
        full_name = str(entry.description) if entry.description else employee_id
        uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 512
        conn.modify(user_dn, {
            'lockoutTime': [(ldap3.MODIFY_REPLACE, [0])],
            'userAccountControl': [(ldap3.MODIFY_REPLACE, [uac & ~2])]
        })

        if conn.result['result'] == 0:
            conn.unbind()
            write_admin_action('解锁账号', employee_id, f"姓名:{full_name}", client_ip)
            return jsonify({'success': True, 'message': f'账号 {employee_id} 已解锁'})

        reason = conn.result.get('description', '未知错误')
        conn.unbind()
        return jsonify({'success': False, 'message': f'解锁失败：{reason}'})
    except Exception as e:
        app.logger.error(f"解锁账号失败: {e}")
        return jsonify({'success': False, 'message': '操作失败，请联系IT'})


@app.route('/api/admin/reset_password', methods=['POST'])
@admin_required
@permission_required('reset_password')
def admin_reset_password():
    """管理员直接重置用户密码。"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    new_password = data.get('new_password', '').strip()
    must_change_next_login = bool(data.get('must_change_next_login'))
    client_ip = request.remote_addr

    ok, err = validate_password(new_password)
    if not ok:
        return jsonify({'success': False, 'message': err})

    success, message, full_name = reset_ad_password(employee_id, new_password)
    if success and must_change_next_login:
        try:
            changed, reason = force_password_change_next_login(employee_id)
            if changed:
                message = '密码已重置，并已要求用户下次登录修改密码'
            else:
                success = False
                message = f'密码已重置，但设置下次登录改密失败：{reason}'
        except Exception as e:
            app.logger.error(f"设置下次登录改密失败: {e}")
            success = False
            message = '密码已重置，但设置下次登录改密失败，请联系IT'

    db.session.add(RegisterLog(
        employee_id=employee_id,
        status='admin_reset_success' if success else 'admin_reset_failed',
        message=message,
        ip_address=client_ip
    ))
    write_admin_action(
        '管理员重置密码',
        employee_id,
        f"姓名:{full_name or employee_id} | 下次登录改密:{'是' if must_change_next_login else '否'} | 结果:{message}",
        client_ip
    )
    return jsonify({'success': success, 'message': message})


@app.route('/api/admin/password_policy', methods=['POST'])
@admin_required
@permission_required('password_policy')
def admin_password_policy():
    """单用户密码策略：下次登录改密、永不过期、不能改密。"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    action = data.get('action', '').strip()
    enabled = bool(data.get('enabled', True))
    client_ip = request.remote_addr
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再执行密码策略'})

    if not is_valid_ad_account_name(employee_id):
        return jsonify({'success': False, 'message': '账号名格式不正确'})

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(sAMAccountName={employee_id})',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'description', 'userAccountControl']
        )
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        entry = conn.entries[0]
        user_dn = str(entry.distinguishedName)
        full_name = str(entry.description) if entry.description else employee_id
        uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 512

        if action == 'must_change_next_login':
            conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]})
            action_name = '设置下次登录改密'
        elif action == 'mark_password_changed_now':
            conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])]})
            action_name = '设置密码修改时间为当前'
        elif action == 'password_never_expires':
            new_uac = (uac | 65536) if enabled else (uac & ~65536)
            conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
            action_name = '开启密码永不过期' if enabled else '关闭密码永不过期'
        elif action == 'cannot_change_password':
            new_uac = (uac | 64) if enabled else (uac & ~64)
            conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
            action_name = '开启用户不能改密' if enabled else '关闭用户不能改密'
        else:
            conn.unbind()
            return jsonify({'success': False, 'message': '未知密码策略操作'})

        if conn.result['result'] == 0:
            conn.unbind()
            write_admin_action(action_name, employee_id, f"姓名:{full_name}", client_ip)
            return jsonify({'success': True, 'message': f'{action_name}成功'})

        reason = conn.result.get('description', '未知错误')
        conn.unbind()
        return jsonify({'success': False, 'message': f'操作失败：{reason}'})
    except Exception as e:
        app.logger.error(f"密码策略操作失败: {e}")
        return jsonify({'success': False, 'message': '操作失败，请联系IT'})


@app.route('/api/admin/password_policy/batch', methods=['POST'])
@admin_required
@permission_required('password_policy')
def admin_password_policy_batch():
    """批量密码策略：只允许超级管理员执行。"""
    data = request.get_json()
    action = data.get('action', '').strip()
    confirm_text = data.get('confirm_text', '').strip()
    approval_id = data.get('approval_id')
    client_ip = request.remote_addr

    if current_admin_user().role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以执行批量密码策略'})
    if confirm_text.upper() != 'YES':
        return jsonify({'success': False, 'message': '请输入 YES 后再执行批量操作'})
    if action not in ['must_change_next_login_all', 'mark_password_changed_now_all']:
        return jsonify({'success': False, 'message': '未知批量操作'})
    if not approval_id:
        approval = create_pending_approval(
            '批量密码策略',
            'ALL',
            {'action': action, 'confirm_text': confirm_text},
            f'请求执行批量密码策略：{action}'
        )
        write_admin_action('发起批量密码策略审批', 'ALL', f"审批ID:{approval.id} | 动作:{action}", client_ip)
        return jsonify({'success': False, 'need_approval': True, 'approval_id': approval.id,
                        'message': f'已创建审批 #{approval.id}，需要另一位有权限的管理员批准后再执行'})

    approval, err = validate_approval(approval_id, '批量密码策略')
    if err:
        return jsonify({'success': False, 'message': err})

    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq*))',
            search_scope=ldap3.SUBTREE,
            attributes=['distinguishedName', 'sAMAccountName']
        )
        target_value = 0 if action == 'must_change_next_login_all' else -1
        action_name = '批量设置下次登录改密' if target_value == 0 else '批量设置密码修改时间为当前'
        ok_count = 0
        fail_count = 0

        for entry in conn.entries:
            user_dn = str(entry.distinguishedName)
            conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [target_value])]})
            if conn.result['result'] == 0:
                ok_count += 1
            else:
                fail_count += 1

        conn.unbind()
        approval.status = 'executed'
        approval.executed_at = datetime.utcnow()
        db.session.commit()
        write_admin_action(action_name, 'ALL', f"成功:{ok_count} | 失败:{fail_count}", client_ip)
        return jsonify({'success': True, 'message': f'{action_name}完成，成功 {ok_count} 个，失败 {fail_count} 个'})
    except Exception as e:
        app.logger.error(f"批量密码策略失败: {e}")
        return jsonify({'success': False, 'message': '批量操作失败，请联系IT'})


@app.route('/api/admin/domain_password_policy', methods=['GET'])
@admin_required
@permission_required('password_policy')
def domain_password_policy_get():
    conn = None
    try:
        conn = get_ad_connection()
        # get_info=ldap3.ALL already loads RootDSE fields outside the AD object schema.
        server_info = conn.server.info
        domain_contexts = server_info.other.get('defaultNamingContext', []) if server_info else []
        domain_dn = domain_contexts[0] if domain_contexts else ''
        if not domain_dn:
            raise ValueError('AD 未返回默认域 DN')
        conn.search(
            search_base=domain_dn,
            search_filter='(objectClass=domainDNS)',
            search_scope=ldap3.BASE,
            attributes=['minPwdLength', 'minPwdAge', 'maxPwdAge', 'pwdHistoryLength', 'pwdProperties']
        )
        if not conn.entries:
            raise ValueError('AD 未返回域密码策略')
        entry = conn.entries[0]

        def policy_integer(attr):
            values = entry[attr].raw_values
            if not values:
                raise ValueError(f'AD 未返回 {attr}')
            return int(values[0])

        min_age = policy_integer('minPwdAge')
        max_age = policy_integer('maxPwdAge')
        properties = policy_integer('pwdProperties')
        return jsonify({
            'success': True,
            'policy': {
                'min_password_length': policy_integer('minPwdLength'),
                'min_age_seconds': abs(min_age) / 10_000_000,
                'max_age_seconds': None if max_age == -(2 ** 63) else abs(max_age) / 10_000_000,
                'max_age_never_expires': max_age == -(2 ** 63),
                'password_history_count': policy_integer('pwdHistoryLength'),
                'complexity_enabled': bool(properties & 1),
                'reversible_encryption_enabled': bool(properties & 16)
            }
        })
    except Exception as e:
        app.logger.warning(f'读取域密码策略失败: {e}')
        return jsonify({'success': False, 'message': '读取 AD 域密码策略失败，请检查 AD 连接或权限'}), 503
    finally:
        if conn:
            conn.unbind()


def get_gpo_ad_connection():
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED,
                     ca_certs_file=os.getenv('GPO_LDAP_CA_CERTS_FILE') or None)
    server = ldap3.Server(os.getenv('GPO_LDAP_SERVER') or app.config['AD_SERVER'],
                          port=636, use_ssl=True, tls=tls, get_info=ldap3.ALL, connect_timeout=10)
    return ldap3.Connection(server, user=app.config['AD_BIND_USER'],
                            password=app.config['AD_BIND_PASSWORD'], authentication=ldap3.SIMPLE,
                            auto_bind=True, receive_timeout=15)


@app.route('/api/admin/domain_password_policy/gpo', methods=['GET', 'POST'])
@app.route('/api/admin/domain_password_policy/gpo/preview', methods=['POST'])
@admin_required
@permission_required('password_policy')
def domain_password_policy_gpo():
    if not is_super_admin_user():
        return jsonify(success=False, message='仅超级管理员可管理域密码策略'), 403
    enabled = os.getenv('GPO_PASSWORD_POLICY_ENABLED', 'false').lower() == 'true'
    writable = os.getenv('GPO_PASSWORD_POLICY_WRITE_ENABLED', 'false').lower() == 'true'
    if not enabled:
        return jsonify(success=request.method == 'GET', enabled=False, writable=False,
                       message='GPO 接入未启用，当前仅展示 AD 域对象策略'), 200 if request.method == 'GET' else 403
    conn = None
    preview = request.path.endswith('/preview')
    try:
        if request.method == 'GET':
            session.setdefault('domain_policy_csrf', secrets.token_urlsafe(32))
        else:
            token = request.headers.get('X-CSRF-Token', '')
            expected = session.get('domain_policy_csrf', '')
            if not expected or not secrets.compare_digest(token, expected):
                raise PolicyError('页面校验已失效，请刷新后重试', 403)
            if not writable:
                raise PolicyError('GPO 写入开关未启用', 403)
            data = request.get_json(silent=True)
            if not isinstance(data, dict) or set(data) - {'revision', 'changes', 'confirm_text'}:
                raise PolicyError('请求格式无效')
            validate_gpo_changes(data.get('changes'))
            if not isinstance(data.get('revision'), str) or not 1 <= len(data['revision']) <= 128:
                raise PolicyError('缺少有效的 GPO 版本，请刷新后重试')
            payload_hash = hashlib.sha256(json.dumps(
                [data.get('revision'), data.get('changes')], sort_keys=True, allow_nan=False
            ).encode()).hexdigest()
            if not preview:
                ticket = session.pop('domain_policy_preview', {})
                if (ticket.get('hash') != payload_hash or time.time() - ticket.get('at', 0) > 300
                        or data.get('confirm_text') != 'YES'):
                    raise PolicyError('请重新预览变更，并输入 YES 确认', 409)
        smb_username = os.getenv('GPO_SMB_USERNAME', '')
        smb_password = os.getenv('GPO_SMB_PASSWORD', '')
        if bool(smb_username) != bool(smb_password):
            raise PolicyError('GPO_SMB_USERNAME 和 GPO_SMB_PASSWORD 必须同时填写或同时留空', 503)
        conn = get_gpo_ad_connection()
        editor = GpoPasswordPolicy(
            conn, os.path.join(app.instance_path, 'gpo_password_policy_backups'),
            guid=os.getenv('GPO_PASSWORD_POLICY_GUID', '31b2f340-016d-11d2-945f-00c04fb984f9'),
            username=smb_username or app.config.get('AD_BIND_USER', ''),
            password=smb_password or app.config.get('AD_BIND_PASSWORD', ''))
        if request.method == 'GET':
            result = editor.read()
        elif preview:
            result = editor.preview(data.get('revision'), data.get('changes'))
            session['domain_policy_preview'] = {'hash': payload_hash, 'at': time.time()}
        else:
            write_admin_action('域密码策略保存开始', editor.guid,
                               json.dumps(data['changes'], ensure_ascii=False), request.remote_addr)
            result = editor.save(data.get('revision'), data.get('changes'))
            result['message'] = '已写入真实 GPO 并回读校验；域控应用或复制可能尚未完成'
            try:
                write_admin_action('域密码策略保存完成', editor.guid,
                                   f"版本:{result['source']['version']} 备份:{result['backup_id']}", request.remote_addr)
            except Exception:
                db.session.rollback()
                app.logger.error('GPO 已保存，但完成审计记录失败，备份:%s', result['backup_id'])
                result['message'] += '；完成审计记录失败，请核查后台日志'
        return jsonify(success=True, enabled=True, writable=writable,
                       csrf_token=session['domain_policy_csrf'], **result)
    except PolicyError as exc:
        app.logger.warning('域密码策略 GPO 操作失败:%s 备份:%s', str(exc), exc.backup_id)
        return jsonify(success=False, message=str(exc), backup_id=exc.backup_id,
                       recovery_required=exc.recovery_required), exc.status
    except Exception as exc:
        db.session.rollback()
        # Authentication/library exception strings may contain sensitive connection details.
        app.logger.warning('域密码策略 GPO 操作失败，异常类型:%s', type(exc).__name__)
        return jsonify(success=False, message='GPO 操作失败，请检查 LDAPS、加密 SMB(445)、账号权限和备份目录'), 503
    finally:
        if conn:
            try:
                conn.unbind()
            except Exception:
                app.logger.warning('GPO 操作后关闭 LDAP 连接失败')


@app.route('/api/admin/gpo-endpoint/<kind>', methods=['GET', 'POST'])
@app.route('/api/admin/gpo-endpoint/<kind>/preview', methods=['POST'])
@admin_required
@permission_required('password_policy')
def gpo_endpoint_policy(kind):
    if not is_super_admin_user():
        return jsonify(success=False, message='仅超级管理员可管理设备组策略'), 403
    if kind not in ('lock', 'usb', 'software'):
        return jsonify(success=False, message='不支持的策略类型'), 404
    enabled = os.getenv('GPO_ENDPOINT_POLICY_ENABLED', 'false').lower() == 'true'
    writable = os.getenv('GPO_ENDPOINT_POLICY_WRITE_ENABLED', 'false').lower() == 'true'
    if not enabled:
        return jsonify(success=request.method == 'GET', enabled=False, writable=False,
                       message='设备组策略接入未启用；尚未读取或修改 AD'), 200 if request.method == 'GET' else 403
    conn = None
    preview = request.path.endswith('/preview')
    csrf_key, preview_key = 'endpoint_policy_csrf', 'endpoint_policy_preview_' + kind
    try:
        if request.method == 'GET':
            session.setdefault(csrf_key, secrets.token_urlsafe(32))
        else:
            expected, token = session.get(csrf_key, ''), request.headers.get('X-CSRF-Token', '')
            if not expected or not secrets.compare_digest(expected, token):
                raise PolicyError('页面校验已失效，请刷新后重试', 403)
            if not writable:
                raise PolicyError('设备组策略写入未启用', 403)
            if not request.is_json or (request.content_length or 0) > 65536:
                raise PolicyError('请求格式或大小无效')
            data = request.get_json(silent=True)
            if not isinstance(data, dict) or set(data) - {'revision', 'policy', 'confirm_text', 'confirm_scope'}:
                raise PolicyError('请求格式无效')
            validate_endpoint_policy(kind, data.get('policy'), os.getenv('GPO_SOFTWARE_SOURCE_ROOT', ''))
            if not isinstance(data.get('revision'), str) or not re.fullmatch('[a-f0-9]{64}', data['revision']):
                raise PolicyError('缺少有效版本，请重新读取 GPO')
            payload_hash = hashlib.sha256(json.dumps([kind, data['revision'], data['policy']],
                sort_keys=True, allow_nan=False).encode()).hexdigest()
            if not preview:
                ticket = session.pop(preview_key, {})
                if (ticket.get('hash') != payload_hash or not 0 <= time.time() - ticket.get('at', 0) <= 300 or
                        data.get('confirm_text') != 'YES' or data.get('confirm_scope') != app.config['AD_BASE_DN']):
                    raise PolicyError('请重新预览，确认全域影响范围并输入 YES', 409)
        guids = {name: os.getenv('GPO_ENDPOINT_' + name.upper() + '_GUID', '').strip('{}').lower()
                 for name in ('lock', 'usb', 'software')}
        password_guid = os.getenv('GPO_PASSWORD_POLICY_GUID', '31b2f340-016d-11d2-945f-00c04fb984f9').strip('{}').lower()
        if (not guids[kind] or guids[kind] == password_guid or
                any(guids[kind] == value for name, value in guids.items() if name != kind)):
            raise PolicyError('三项功能必须配置不同的独立 GPO GUID，不能复用密码策略 GPO', 503)
        smb_username, smb_password = os.getenv('GPO_SMB_USERNAME', ''), os.getenv('GPO_SMB_PASSWORD', '')
        if bool(smb_username) != bool(smb_password):
            raise PolicyError('GPO SMB 账号和密码必须同时填写或同时留空', 503)
        conn = get_gpo_ad_connection()
        editor = GpoEndpointPolicy(conn, os.path.join(app.instance_path, 'gpo_endpoint_backups'),
            kind=kind, guid=guids[kind], domain_dn=app.config['AD_BASE_DN'],
            username=smb_username or app.config.get('AD_BIND_USER', ''),
            password=smb_password or app.config.get('AD_BIND_PASSWORD', ''),
            software_root=os.getenv('GPO_SOFTWARE_SOURCE_ROOT', ''))
        if request.method == 'GET':
            result = editor.read()
        elif preview:
            result = editor.preview(data['revision'], data['policy'])
            session[preview_key] = {'hash': payload_hash, 'at': time.time()}
        else:
            if not is_super_admin_user() or os.getenv('GPO_ENDPOINT_POLICY_WRITE_ENABLED', 'false').lower() != 'true':
                raise PolicyError('写入权限或开关已变化，已停止', 403)
            write_admin_action('设备组策略保存开始', editor.guid,
                json.dumps({'kind': kind, 'policy': data['policy'], 'domain': app.config['AD_BASE_DN']}, ensure_ascii=False), request.remote_addr)
            result = editor.save(data['revision'], data['policy'])
            result['message'] = '已写入真实 GPO 并回读校验；不代表客户端已应用，未执行远程刷新或重启'
            try:
                write_admin_action('设备组策略保存完成', editor.guid,
                    f"类型:{kind} 版本:{result['source']['version']} 备份:{result['backup_id']}", request.remote_addr)
            except Exception:
                db.session.rollback()
                app.logger.error('设备 GPO 已保存，但完成审计记录失败，备份:%s', result['backup_id'])
                result['message'] += '；完成审计记录失败，请核查后台日志'
        response = jsonify(success=True, enabled=True, writable=writable, csrf_token=session[csrf_key],
            domain_dn=app.config['AD_BASE_DN'], **result)
        response.headers['Cache-Control'] = 'no-store'
        return response
    except PolicyError as error:
        db.session.rollback()
        app.logger.warning('设备 GPO 操作失败，类型:%s 备份:%s', kind, error.backup_id)
        return jsonify(success=False, message=str(error), backup_id=error.backup_id,
            recovery_required=error.recovery_required), error.status
    except Exception as error:
        db.session.rollback()
        app.logger.warning('设备 GPO 操作失败，类型:%s 异常:%s', kind, type(error).__name__)
        return jsonify(success=False, message='GPO 操作失败，请检查 LDAPS、加密 SMB(445)、独立 GPO、共享目录及备份权限；不要重复提交'), 503
    finally:
        if conn:
            try:
                conn.unbind()
            except Exception:
                app.logger.warning('设备 GPO 操作后关闭 LDAP 连接失败')


@app.route('/api/admin/password_expire/settings', methods=['GET'])
@admin_required
@permission_required('password_policy')
def password_expire_settings_get():
    domain_max_age_days = None
    try:
        conn = get_ad_connection()
        domain_max_age_days = get_effective_password_max_age_days(conn)
        conn.unbind()
    except Exception as e:
        app.logger.warning(f"读取AD密码有效期失败: {e}")
    fallback_days = int(get_setting('password_expire_days', '90'))
    effective_days = domain_max_age_days
    return jsonify({
        'success': True,
        'settings': {
            'security_brand': get_setting('security_brand', '微丰启安全提醒'),
            'security_notice': get_setting('security_notice', '为了保障公司账号安全，请及时修改密码。'),
            'password_expire_days': str(fallback_days),
            'domain_password_max_age_days': domain_max_age_days,
            'effective_password_expire_days': effective_days,
            'password_reminder_days': get_setting('password_reminder_days', '15,7,1'),
            'password_reminder_enabled': get_setting('password_reminder_enabled', 'true'),
            'password_reminder_batch_size': get_setting('password_reminder_batch_size', '50'),
            'password_reminder_auto_time': get_setting('password_reminder_auto_time', '09:00')
        }
    })


@app.route('/api/admin/password_expire/settings', methods=['POST'])
@admin_required
@permission_required('password_policy')
def password_expire_settings_save():
    data = request.get_json()
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再保存提醒设置'})
    auto_time = data.get('password_reminder_auto_time')
    if auto_time and not valid_hhmm(auto_time):
        return jsonify({'success': False, 'message': '自动发送时间格式不正确'})
    for key in [
        'security_brand', 'security_notice', 'password_expire_days',
        'password_reminder_days', 'password_reminder_enabled',
        'password_reminder_batch_size', 'password_reminder_auto_time'
    ]:
        if key in data:
            set_setting(key, data.get(key))
    db.session.commit()
    write_admin_action('修改密码到期提醒设置', 'SYSTEM', '更新提醒周期和邮件文案', request.remote_addr)
    return jsonify({'success': True, 'message': '密码到期提醒设置已保存'})


@app.route('/api/admin/password_expire/preview', methods=['GET'])
@admin_required
@permission_required('password_policy')
def password_expire_preview():
    """预览密码到期用户清单，不发送邮件。"""
    try:
        conn = get_ad_connection()
        rows, max_age_days, remind_days = build_password_expire_rows(conn)
        conn.unbind()
        counts = {
            'total': len(rows),
            'will_send': sum(1 for row in rows if row['will_send']),
            'expired': sum(1 for row in rows if row['days_left'] is not None and row['days_left'] < 0),
            'skipped': sum(1 for row in rows if not row['will_send'])
        }
        return jsonify({
            'success': True,
            'message': f"预览完成：可发送 {counts['will_send']} 人，未发送任何邮件",
            'max_age_days': max_age_days,
            'remind_days': remind_days,
            'counts': counts,
            'rows': rows
        })
    except Exception as e:
        app.logger.error(f"密码到期提醒预览失败: {e}")
        return jsonify({'success': False, 'message': '预览失败，请联系IT'})


def acquire_scheduler_lock(job_name, run_date):
    lock = SchedulerJobLock(job_name=job_name, run_date=run_date, status='running')
    try:
        db.session.add(lock)
        db.session.commit()
        return lock
    except IntegrityError:
        db.session.rollback()
        return None


def finish_scheduler_lock(lock, status, message):
    if not lock:
        return
    lock.status = status
    lock.message = message[:300] if message else ''
    lock.finished_at = datetime.utcnow()
    db.session.commit()


def acquire_reminder_send_lock(employee_id, remind_days, send_date):
    lock = PasswordReminderSendLock(
        employee_id=employee_id,
        remind_days=remind_days,
        send_date=send_date
    )
    try:
        db.session.add(lock)
        db.session.commit()
        return True
    except IntegrityError:
        db.session.rollback()
        return False


def perform_password_expire_scan(dry_run=False, ip_address='system', operator='system', use_job_lock=False):
    """执行密码到期扫描。dry_run只预览；use_job_lock用于自动任务防重复。"""
    if get_setting('password_reminder_enabled', 'true') != 'true':
        return {
            'success': False,
            'message': '密码到期提醒未启用',
            'sent': 0,
            'skipped': 0,
            'failed': 0,
            'rows': []
        }

    today = local_now().date()
    run_date = today.isoformat()
    job_lock = None
    if use_job_lock:
        job_lock = acquire_scheduler_lock('password_expire_daily', run_date)
        if not job_lock:
            return {
                'success': True,
                'message': f'{run_date} 自动任务已由其他进程执行或正在执行',
                'sent': 0,
                'skipped': 0,
                'failed': 0,
                'rows': []
            }

    batch_size = int(get_setting('password_reminder_batch_size', '50'))
    sent = 0
    skipped = 0
    failed = 0
    try:
        conn = get_ad_connection()
        rows, max_age_days, remind_days = build_password_expire_rows(conn)
        conn.unbind()

        matched = sum(1 for row in rows if row['will_send'])
        if dry_run:
            message = f'预览完成：符合发送条件 {matched} 人，未发送任何邮件。'
            write_admin_action('预览密码到期提醒扫描', 'ALL', f"可发送:{matched} | 总数:{len(rows)} | 有效期:{max_age_days}天", ip_address, admin_username=operator)
            return {
                'success': True,
                'message': message,
                'max_age_days': max_age_days,
                'remind_days': remind_days,
                'counts': {
                    'total': len(rows),
                    'will_send': matched,
                    'skipped': len(rows) - matched,
                    'expired': sum(1 for row in rows if row['days_left'] is not None and row['days_left'] < 0)
                },
                'rows': rows
            }

        for row in rows:
            if sent >= batch_size:
                break
            if not row['will_send']:
                skipped += 1
                continue

            employee_id = row['employee_id']
            full_name = row['full_name']
            email = row['email']
            days_left = row['days_left']
            pwd_dt = datetime.strptime(row['pwd_last_set'], '%Y-%m-%d %H:%M:%S') if row['pwd_last_set'] else None
            expire_at = datetime.strptime(row['expire_at'], '%Y-%m-%d %H:%M:%S') if row['expire_at'] else None

            if not acquire_reminder_send_lock(employee_id, days_left, run_date):
                skipped += 1
                continue

            ok = send_password_expire_email(email, employee_id, full_name, expire_at, days_left)
            db.session.add(PasswordExpireReminderLog(
                employee_id=employee_id,
                full_name=full_name,
                email=email,
                pwd_last_set=pwd_dt,
                expire_at=expire_at,
                remind_days=days_left,
                success=ok,
                message='发送成功' if ok else '邮件发送失败',
                ip_address=ip_address
            ))
            if ok:
                sent += 1
            else:
                failed += 1
            db.session.commit()

        message = f'扫描并发送完成：发送 {sent}，跳过 {skipped}，失败 {failed}'
        write_admin_action('执行密码到期提醒扫描', 'ALL', f"发送:{sent} | 跳过:{skipped} | 失败:{failed}", ip_address, admin_username=operator)
        finish_scheduler_lock(job_lock, 'done', message)
        return {
            'success': True,
            'message': message,
            'sent': sent,
            'skipped': skipped,
            'failed': failed
        }
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"密码到期提醒扫描失败: {e}")
        finish_scheduler_lock(job_lock, 'failed', str(e))
        return {
            'success': False,
            'message': '扫描失败，请联系IT',
            'sent': sent,
            'skipped': skipped,
            'failed': failed,
            'error': str(e)
        }


@app.route('/api/admin/password_expire/run', methods=['POST'])
@admin_required
@permission_required('password_policy')
def password_expire_run():
    """手动执行密码到期提醒扫描；建议生产环境用cron每天调用一次。"""
    data = request.get_json(silent=True) or {}
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再执行扫描'})
    dry_run = bool(data.get('dry_run', False))
    result = perform_password_expire_scan(dry_run=dry_run, ip_address=request.remote_addr, operator=current_admin_username())
    return jsonify(result)


@app.route('/api/admin/password_expire/auto_run', methods=['POST'])
def password_expire_auto_run():
    """自动任务入口：使用数据库锁保证多 worker 只有一个真正执行。"""
    token = request.headers.get('X-Auto-Token') or request.args.get('token') or ''
    expected = get_setting('password_reminder_auto_token', '')
    is_local = request.remote_addr in ('127.0.0.1', '::1', 'localhost')
    if not is_local and (not expected or token != expected):
        return jsonify({'success': False, 'message': '自动任务密钥不正确'}), 403
    result = perform_password_expire_scan(
        dry_run=False,
        ip_address=request.remote_addr,
        operator='system-auto',
        use_job_lock=True
    )
    return jsonify(result), (200 if result.get('success') else 400)


@app.route('/api/admin/password_expire/test', methods=['POST'])
@admin_required
@permission_required('password_policy')
def password_expire_test():
    """给单个登录过的用户测试发送密码到期提醒。"""
    data = request.get_json(silent=True) or {}
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再发送测试邮件'})
    employee_id = data.get('employee_id', '').strip().lower()
    if not is_valid_employee_id(employee_id):
        return jsonify({'success': False, 'message': '工号格式不正确'})

    try:
        conn = get_ad_connection()
        expire_days = get_effective_password_max_age_days(conn)
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter=f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={ldap_escape(employee_id)}))',
            search_scope=ldap3.SUBTREE,
            attributes=[
                'sAMAccountName', 'description', 'mail', 'userAccountControl',
                'pwdLastSet', 'msDS-UserPasswordExpiryTimeComputed',
                'lastLogon', 'lastLogonTimestamp', 'logonCount'
            ]
        )
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '用户不存在'})

        entry = conn.entries[0]
        full_name = get_entry_text(entry, 'description', employee_id)
        email = get_entry_text(entry, 'mail')
        uac = int(get_entry_text(entry, 'userAccountControl', '512') or 512)
        last_logon_dt = latest_ad_logon_datetime(entry)
        login_count = int(get_entry_text(entry, 'logonCount', '0') or 0)
        if bool(uac & 2):
            conn.unbind()
            return jsonify({'success': False, 'message': '该用户已禁用，不发送测试邮件'})
        if not email:
            conn.unbind()
            return jsonify({'success': False, 'message': '该用户没有邮箱，不发送测试邮件'})
        if not last_logon_dt and login_count <= 0:
            conn.unbind()
            return jsonify({'success': False, 'message': '该用户从未登录过，不发送测试邮件'})

        pwd_dt = ad_filetime_to_datetime(getattr(entry, 'pwdLastSet', None))
        if not pwd_dt:
            conn.unbind()
            return jsonify({'success': False, 'message': '该用户没有密码修改时间，不能计算到期日'})
        expire_at = get_user_password_expiry_datetime(entry, expire_days)
        if not expire_at:
            conn.unbind()
            return jsonify({'success': False, 'message': '未读取到该用户密码到期时间，不发送测试邮件'})
        days_left = (expire_at.date() - local_now().date()).days
        ok = send_password_expire_email(email, employee_id, full_name, expire_at, days_left)
        db.session.add(PasswordExpireReminderLog(
            employee_id=employee_id,
            full_name=full_name,
            email=email,
            pwd_last_set=pwd_dt,
            expire_at=expire_at,
            remind_days=days_left,
            success=ok,
            message='测试发送成功' if ok else '测试邮件发送失败',
            ip_address=request.remote_addr
        ))
        db.session.commit()
        conn.unbind()
        write_admin_action('测试发送密码到期提醒', employee_id, f"邮箱:{email} | 剩余天数:{days_left}", request.remote_addr)
        return jsonify({'success': ok, 'message': '测试邮件已发送' if ok else '测试邮件发送失败'})
    except Exception as e:
        app.logger.error(f"测试发送密码到期提醒失败: {e}")
        return jsonify({'success': False, 'message': '测试发送失败，请联系IT'})


@app.route('/api/admin/password_expire/logs', methods=['GET'])
@admin_required
@permission_required('password_policy')
def password_expire_logs():
    rows = PasswordExpireReminderLog.query.order_by(PasswordExpireReminderLog.created_at.desc()).limit(200).all()
    return jsonify({
        'success': True,
        'logs': [{
            'created_at': fmt_local_dt(r.created_at),
            'employee_id': r.employee_id,
            'full_name': r.full_name or '',
            'email': r.email or '',
            'expire_at': r.expire_at.strftime('%Y-%m-%d') if r.expire_at else '',
            'remind_days': r.remind_days,
            'success': bool(r.success),
            'message': r.message or ''
        } for r in rows]
    })


@app.route('/api/admin/settings', methods=['GET'])
@admin_required
@permission_required('system_settings')
def admin_settings_get():
    return jsonify({
        'success': True,
        'settings': {
            'company_name': get_setting('company_name', '微丰启'),
            'admin_title': get_setting('admin_title', 'IT管理后台'),
            'admin_session_minutes': get_setting('admin_session_minutes', '10'),
            'super_admin_session_minutes': get_setting('super_admin_session_minutes', '480'),
            'allow_delete_user': get_setting('allow_delete_user', 'true'),
            'security_brand': get_setting('security_brand', '微丰启安全提醒'),
            'security_notice': get_setting('security_notice', '为了保障公司账号安全，请及时修改密码。')
        }
    })


@app.route('/api/admin/settings', methods=['POST'])
@admin_required
@permission_required('system_settings')
def admin_settings_save():
    data = request.get_json()
    client_ip = request.remote_addr
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再保存系统设置'})
    if current_admin_user().role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以修改系统设置'})

    for key in ['company_name', 'admin_title', 'admin_session_minutes', 'super_admin_session_minutes', 'allow_delete_user', 'security_brand', 'security_notice']:
        if key in data:
            set_setting(key, data.get(key))
    db.session.commit()
    write_admin_action('修改系统设置', 'SYSTEM', '更新后台系统设置', client_ip)
    return jsonify({'success': True, 'message': '系统设置已保存'})


@app.route('/api/admin/users', methods=['GET'])
@admin_required
@permission_required('manage_admins')
def admin_users():
    """返回后台用户列表，密码永远不返回前端。"""
    users = AdminUser.query.options(joinedload(AdminUser.dingtalk_account)).order_by(AdminUser.created_at.desc()).all()
    return jsonify({
        'success': True,
        'roles': ROLE_PERMISSIONS,
        'admins': [{
            'id': u.id,
            'username': u.username,
            'display_name': u.dingtalk_account.employee_name if u.dingtalk_account else None,
            'role': u.role,
            'permissions': user_permissions(u),
            'is_active': bool(u.is_active),
            'created_by': u.created_by or '',
            'created_at': fmt_local_dt(u.created_at)
        } for u in users]
    })


@app.route('/api/admin/users/create', methods=['POST'])
@admin_required
@permission_required('manage_admins')
def admin_user_create():
    """超级管理员创建后台子账户。"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'readonly').strip()
    requested_permissions = data.get('permissions')
    permissions = sanitized_permissions(role, permissions_for_role(role) if requested_permissions is None else requested_permissions)
    client_ip = request.remote_addr
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再创建后台用户'})

    if current_admin_user().role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以创建后台用户'})
    if not re.match(r'^[A-Za-z0-9_.-]{3,30}$', username):
        return jsonify({'success': False, 'message': '用户名只能包含字母、数字、下划线、点和横线，长度3-30位'})
    if len(password) < 8:
        return jsonify({'success': False, 'message': '后台用户密码至少8位'})
    if role == 'super_admin' or role not in ROLE_PERMISSIONS:
        return jsonify({'success': False, 'message': '角色不正确'})
    if AdminUser.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': '用户名已存在'})

    db.session.add(AdminUser(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        permissions=','.join(permissions),
        created_by=current_admin_username()
    ))
    db.session.commit()
    write_admin_action('创建后台用户', username, f"角色:{role}", client_ip)
    return jsonify({'success': True, 'message': '后台用户已创建'})


@app.route('/api/admin/users/update', methods=['POST'])
@admin_required
@permission_required('manage_admins')
def admin_user_update():
    """超级管理员修改后台子账户。"""
    data = request.get_json()
    user_id = data.get('id')
    role = data.get('role', 'readonly').strip()
    requested_permissions = data.get('permissions')
    permissions = sanitized_permissions(role, permissions_for_role(role) if requested_permissions is None else requested_permissions)
    password = data.get('password', '').strip()
    is_active = bool(data.get('is_active', True))
    client_ip = request.remote_addr
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再修改后台用户'})

    if current_admin_user().role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以修改后台用户'})
    user = AdminUser.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '后台用户不存在'})
    if user.role == 'super_admin':
        return jsonify({'success': False, 'message': '超级管理员不能在用户中心修改'})
    if role == 'super_admin' or role not in ROLE_PERMISSIONS:
        return jsonify({'success': False, 'message': '角色不正确'})

    user.role = role
    user.permissions = ','.join(permissions)
    user.is_active = is_active
    if password:
        if len(password) < 8:
            return jsonify({'success': False, 'message': '后台用户密码至少8位'})
        user.password_hash = generate_password_hash(password)
    db.session.commit()
    write_admin_action('修改后台用户', user.username, f"角色:{role} | 启用:{is_active}", client_ip)
    return jsonify({'success': True, 'message': '后台用户已更新'})


@app.route('/api/admin/users/delete', methods=['POST'])
@admin_required
@permission_required('manage_admins')
def admin_user_delete():
    """超级管理员删除后台子账户。"""
    data = request.get_json()
    user_id = data.get('id')
    client_ip = request.remote_addr
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再删除后台用户'})

    if current_admin_user().role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以删除后台用户'})
    user = AdminUser.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '后台用户不存在'})
    if user.role == 'super_admin':
        return jsonify({'success': False, 'message': '不能删除超级管理员'})

    username = user.username
    db.session.delete(user)
    db.session.commit()
    write_admin_action('删除后台用户', username, '删除子账户', client_ip)
    return jsonify({'success': True, 'message': '后台用户已删除'})


@app.route('/api/admin/sessions', methods=['GET'])
@admin_required
@permission_required('manage_admins')
def admin_sessions():
    """后台用户在线审计。"""
    now = utc_now()
    for user in AdminUser.query.all():
        if not AdminSessionAudit.query.filter_by(username=user.username).first():
            audit = AdminSessionAudit(
                username=user.username,
                role=user.role,
                ip_address='',
                is_online=False
            )
            audit.login_at = None
            audit.last_seen_at = None
            db.session.add(audit)
    db.session.commit()
    rows = AdminSessionAudit.query.order_by(AdminSessionAudit.last_seen_at.desc()).all()
    data = []
    for row in rows:
        timeout = int(get_setting('super_admin_session_minutes' if row.role == 'super_admin' else 'admin_session_minutes',
                                  480 if row.role == 'super_admin' else 10))
        online = bool(row.is_online and row.last_seen_at and now - row.last_seen_at <= timedelta(minutes=timeout))
        data.append({
            'username': row.username,
            'role': row.role,
            'ip_address': row.ip_address or '',
            'login_at': fmt_local_dt(row.login_at),
            'last_seen_at': fmt_local_dt(row.last_seen_at),
            'is_online': online
        })
    return jsonify({'success': True, 'sessions': data})


@app.route('/api/admin/approvals', methods=['GET'])
@admin_required
@permission_required('view_logs')
def admin_approvals():
    """审批中心列表。"""
    rows = PendingApproval.query.order_by(PendingApproval.created_at.desc()).limit(200).all()
    return jsonify({
        'success': True,
        'approvals': [{
            'id': r.id,
            'action': r.action,
            'target': r.target or '',
            'requested_by': r.requested_by,
            'approved_by': r.approved_by or '',
            'status': r.status,
            'message': r.message or '',
            'payload': parse_json_object(r.payload),
            'created_at': fmt_local_dt(r.created_at),
            'approved_at': fmt_local_dt(r.approved_at),
            'executed_at': fmt_local_dt(r.executed_at)
        } for r in rows]
    })


@app.route('/api/admin/approvals/approve', methods=['POST'])
@admin_required
def admin_approval_approve():
    """第二个有权限的人批准危险操作。"""
    data = request.get_json()
    approval_id = data.get('id')
    approval = PendingApproval.query.get(approval_id)
    approver = current_admin_user()
    if not approver or approver.role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以批准危险操作'})
    if not approval:
        return jsonify({'success': False, 'message': '审批记录不存在'})
    if approval.status != 'pending':
        return jsonify({'success': False, 'message': '该审批不是待审批状态'})
    if approval.requested_by == current_admin_username():
        return jsonify({'success': False, 'message': '不能审批自己发起的危险操作'})
    approval.status = 'approved'
    approval.approved_by = current_admin_username()
    approval.approved_at = datetime.utcnow()
    db.session.commit()
    write_admin_action('审批危险操作', approval.target or approval.action, f"审批ID:{approval.id} | 动作:{approval.action}", request.remote_addr)
    return jsonify({'success': True, 'message': '审批通过，发起人可继续执行'})


@app.route('/api/admin/approvals/reject', methods=['POST'])
@admin_required
def admin_approval_reject():
    """超级管理员拒绝危险操作审批。"""
    data = request.get_json()
    approval_id = data.get('id')
    reason = (data.get('reason') or '').strip() or '未填写原因'
    approval = PendingApproval.query.get(approval_id)
    approver = current_admin_user()
    if not approver or approver.role != 'super_admin':
        return jsonify({'success': False, 'message': '只有超级管理员可以拒绝危险操作'})
    if not approval:
        return jsonify({'success': False, 'message': '审批记录不存在'})
    if approval.status != 'pending':
        return jsonify({'success': False, 'message': '该审批不是待审批状态'})
    if approval.requested_by == current_admin_username():
        return jsonify({'success': False, 'message': '不能拒绝自己发起的危险操作'})
    approval.status = 'rejected'
    approval.approved_by = current_admin_username()
    approval.approved_at = datetime.utcnow()
    approval.message = f"{approval.message or ''} | 拒绝原因:{reason}"
    db.session.commit()
    write_admin_action('拒绝危险操作', approval.target or approval.action, f"审批ID:{approval.id} | 动作:{approval.action} | 原因:{reason}", request.remote_addr)
    return jsonify({'success': True, 'message': '审批已拒绝'})


@app.route('/api/admin/export/ad_users', methods=['GET'])
@admin_required
@permission_required('view_user')
def admin_export_ad_users():
    """导出AD用户CSV，Excel可直接打开。"""
    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq*))',
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName', 'description', 'department', 'mail', 'userAccountControl', 'logonCount', 'lastLogon', 'lastLogonTimestamp', 'pwdLastSet']
        )
        lines = ['工号,姓名,部门,邮箱,状态,累计登录,最后登录,密码最后修改']
        for entry in conn.entries:
            uac = int(get_entry_text(entry, 'userAccountControl', '512') or 512)
            status = '已禁用' if bool(uac & 2) else '正常'
            cells = [
                get_entry_text(entry, 'sAMAccountName'),
                get_entry_text(entry, 'description'),
                get_entry_text(entry, 'department'),
                get_entry_text(entry, 'mail'),
                status,
                get_entry_text(entry, 'logonCount', '0'),
                (latest_ad_logon_datetime(entry).strftime('%Y-%m-%d %H:%M:%S') if latest_ad_logon_datetime(entry) else '从未登录'),
                ad_filetime_to_str(getattr(entry, 'pwdLastSet', None)) or ''
            ]
            lines.append(','.join('"' + str(c).replace('"', '""') + '"' for c in cells))
        conn.unbind()
        body = '\ufeff' + '\n'.join(lines)
        write_admin_action('导出AD用户', 'ALL', '导出CSV', request.remote_addr)
        return Response(body, mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': 'attachment; filename=ad_users.csv'})
    except Exception as e:
        app.logger.error(f"导出AD用户失败: {e}")
        return jsonify({'success': False, 'message': '导出失败，请联系IT'})


@app.route('/api/admin/computers/stats', methods=['GET'])
@admin_required
@permission_required('view_dashboard')
def admin_computer_stats():
    """统计AD计算机登录情况。"""
    try:
        conn = get_ad_connection()
        conn.search(
            search_base=computer_search_base(),
            search_filter='(objectCategory=computer)',
            search_scope=ldap3.SUBTREE,
            attributes=[
                'cn', 'dNSHostName', 'description', 'operatingSystem',
                'userAccountControl', 'logonCount', 'lastLogon', 'lastLogonTimestamp',
                'pwdLastSet', 'whenCreated', 'whenChanged', 'distinguishedName'
            ]
        )
        computer_entries = list(conn.entries)
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq*))',
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName']
        )
        known_user_ids = {get_entry_text(entry, 'sAMAccountName').lower() for entry in conn.entries}
        logged = []
        today_logged = []
        past_logged = []
        never = []
        stale_computers = []
        disabled_computers = []
        disabled_count = 0
        today = local_now().date()
        inactive_days_limit = int(get_setting('computer_inactive_days', '7') or 7)
        for entry in computer_entries:
            uac = int(get_entry_text(entry, 'userAccountControl', '0') or 0)
            has_logged, login_count, last_logon_dt, last_logon = login_status_from_ad(entry)
            is_disabled = bool(uac & 2)
            name = get_entry_text(entry, 'cn')
            operating_system = get_entry_text(entry, 'operatingSystem')
            dn = get_entry_text(entry, 'distinguishedName')
            inactive_days = (today - last_logon_dt.date()).days if last_logon_dt else None
            matched_employee_id = computer_name_to_employee_id(name)
            has_matching_user = bool(matched_employee_id and matched_employee_id in known_user_ids)
            is_infra = is_infra_computer(name, operating_system, dn)
            review_reasons = []
            if not has_logged:
                review_reasons.append('无登录记录')
            elif inactive_days is not None and inactive_days >= inactive_days_limit:
                review_reasons.append(f'{inactive_days_limit}天未登录')
            if not has_matching_user:
                review_reasons.append('无对应用户')
            if is_infra:
                review_reasons = ['域控/服务器，不进入清理参考']
            action = latest_action_for_target(name, ['禁用计算机', '启用计算机', '删除计算机', '删除计算机完成'])
            row = {
                'name': name,
                'dns_host_name': get_entry_text(entry, 'dNSHostName'),
                'description': get_entry_text(entry, 'description'),
                'operating_system': operating_system,
                'status': '已禁用' if is_disabled else '正常',
                'login_status': '已登录' if has_logged else '未登录',
                'login_count': login_count,
                'last_logon': last_logon,
                'inactive_days': inactive_days,
                'inactive_label': f'{inactive_days}天' if inactive_days is not None else '无登录记录',
                'matched_employee_id': matched_employee_id,
                'matching_user_status': matched_employee_id if has_matching_user else ('域控服务器' if is_infra else '无对应用户'),
                'has_matching_user': has_matching_user,
                'is_infra': is_infra,
                'review_reason': '；'.join(review_reasons),
                'password_last_set': ad_filetime_to_str(getattr(entry, 'pwdLastSet', None)) or '',
                'when_created': get_entry_text(entry, 'whenCreated'),
                'when_changed': get_entry_text(entry, 'whenChanged'),
                'dn': dn,
                'operator': action.admin_username if action else '',
                'action': action.action if action else '',
                'reason': action.message if action else ('AD userAccountControl 显示禁用' if is_disabled else ''),
                'action_time': fmt_local_dt(action.created_at) if action else ''
            }
            if is_disabled:
                disabled_count += 1
                disabled_computers.append(row)
            if not has_logged:
                never.append(row)
            else:
                logged.append(row)
                if last_logon_dt and last_logon_dt.date() == today:
                    today_logged.append(row)
                else:
                    past_logged.append(row)
            if review_reasons and not is_infra:
                stale_computers.append(row)
        conn.unbind()
        logged.sort(key=lambda row: (row.get('login_count') or 0, row.get('last_logon') or ''), reverse=True)
        today_logged.sort(key=lambda row: (row.get('login_count') or 0, row.get('last_logon') or ''), reverse=True)
        past_logged.sort(key=lambda row: (row.get('login_count') or 0, row.get('last_logon') or ''), reverse=True)
        never.sort(key=lambda row: row.get('name') or '')
        stale_computers.sort(key=lambda row: (row.get('inactive_days') is None, row.get('inactive_days') or 0), reverse=True)
        disabled_computers.sort(key=lambda row: row.get('name') or '')
        return jsonify({
            'success': True,
            'stats': {
                'total_computers': len(logged) + len(never),
                'logged_computers_count': len(logged),
                'today_logged_computers_count': len(today_logged),
                'past_logged_computers_count': len(past_logged),
                'never_login_computers_count': len(never),
                'stale_computers_count': len(stale_computers),
                'computer_inactive_days': inactive_days_limit,
                'disabled_computers_count': disabled_count,
                'logged_computers': logged,
                'today_logged_computers': today_logged,
                'past_logged_computers': past_logged,
                'never_login_computers': never,
                'stale_computers': stale_computers,
                'disabled_computers': disabled_computers
            },
            'data_source': '计算机统计来自 AD computer 对象的 logonCount、lastLogon、lastLogonTimestamp、userAccountControl、pwdLastSet；页面按中国深圳时间显示，最后登录取 lastLogon 与 lastLogonTimestamp 中较新的值。'
        })
    except Exception as e:
        app.logger.error(f"统计计算机失败: {e}")
        return jsonify({'success': False, 'message': '统计计算机失败，请联系IT'})


@app.route('/api/admin/computers/by_user', methods=['POST'])
@admin_required
@permission_required('view_user')
def admin_computers_by_user():
    """按员工工号列出关联计算机。"""
    data = request.get_json()
    employee_id = data.get('employee_id', '').strip().lower()
    if not is_valid_employee_id(employee_id):
        return jsonify({'success': False, 'message': '工号格式不正确'})
    try:
        conn = get_ad_connection()
        computers = get_related_computers(conn, employee_id)
        conn.unbind()
        return jsonify({'success': True, 'computers': computers})
    except Exception as e:
        app.logger.error(f"查询关联计算机失败: {e}")
        return jsonify({'success': False, 'message': '查询关联计算机失败，请联系IT'})


@app.route('/api/admin/computers/search', methods=['POST'])
@admin_required
@permission_required('view_computers')
def admin_computer_search():
    """按计算机名精确查询单台AD计算机。"""
    data = request.get_json(silent=True) or {}
    computer_name = data.get('name', '').strip()
    if not computer_name:
        return jsonify({'success': False, 'message': '请输入计算机名'})
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', computer_name):
        return jsonify({'success': False, 'message': '计算机名格式不正确'})
    try:
        conn = get_ad_connection()
        conn.search(
            search_base=computer_search_base(),
            search_filter=f'(&(objectCategory=computer)(cn={ldap_escape(computer_name)}))',
            search_scope=ldap3.SUBTREE,
            attributes=[
                'cn', 'dNSHostName', 'description', 'operatingSystem',
                'userAccountControl', 'logonCount', 'lastLogon', 'lastLogonTimestamp',
                'pwdLastSet', 'whenCreated', 'whenChanged', 'distinguishedName'
            ]
        )
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '未找到对应计算机'})
        entry = conn.entries[0]
        matched_employee_id = computer_name_to_employee_id(get_entry_text(entry, 'cn'))
        known_user_ids = set()
        if matched_employee_id:
            conn.search(
                search_base=app.config['AD_BASE_DN'],
                search_filter=f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={ldap_escape(matched_employee_id)}))',
                search_scope=ldap3.SUBTREE,
                attributes=['sAMAccountName']
            )
            known_user_ids = {get_entry_text(item, 'sAMAccountName').lower() for item in conn.entries}
        row = build_computer_row(entry, known_user_ids)
        conn.unbind()
        return jsonify({'success': True, 'computer': row})
    except Exception as e:
        app.logger.error(f"查询计算机失败: {e}")
        return jsonify({'success': False, 'message': '查询计算机失败，请联系IT'})


def set_computer_disabled_state(disabled):
    data = request.get_json(silent=True) or {}
    computer_name = data.get('name', '').strip()
    computer_dn = data.get('dn', '').strip()
    if not computer_name and not computer_dn:
        return jsonify({'success': False, 'message': '缺少计算机名或DN'})
    if computer_name and not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', computer_name):
        return jsonify({'success': False, 'message': '计算机名格式不正确'})
    try:
        conn = get_ad_connection()
        if computer_dn:
            conn.search(
                search_base=computer_dn,
                search_filter='(objectClass=computer)',
                search_scope=ldap3.BASE,
                attributes=['cn', 'distinguishedName', 'operatingSystem', 'userAccountControl']
            )
        else:
            conn.search(
                search_base=computer_search_base(),
                search_filter=f'(&(objectCategory=computer)(cn={ldap_escape(computer_name)}))',
                search_scope=ldap3.SUBTREE,
                attributes=['cn', 'distinguishedName', 'operatingSystem', 'userAccountControl']
            )
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'message': '计算机不存在'})
        entry = conn.entries[0]
        target_name = get_entry_text(entry, 'cn', computer_name)
        target_dn = get_entry_text(entry, 'distinguishedName')
        if is_infra_computer(target_name, get_entry_text(entry, 'operatingSystem'), target_dn):
            conn.unbind()
            return jsonify({'success': False, 'message': '域控/服务器不允许在后台禁用或启用'})
        uac = int(get_entry_text(entry, 'userAccountControl', '4096') or 4096)
        new_uac = (uac | 2) if disabled else (uac & ~2)
        conn.modify(target_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
        if conn.result['result'] == 0:
            conn.unbind()
            action = '禁用计算机' if disabled else '启用计算机'
            write_admin_action(action, target_name, f"DN:{target_dn}", request.remote_addr)
            return jsonify({'success': True, 'message': f'计算机 {target_name} 已{"禁用" if disabled else "启用"}'})
        reason = conn.result.get('description', '未知错误')
        conn.unbind()
        return jsonify({'success': False, 'message': f'操作失败：{reason}'})
    except Exception as e:
        app.logger.error(f"修改计算机状态失败: {e}")
        return jsonify({'success': False, 'message': '修改计算机状态失败，请联系IT'})


@app.route('/api/admin/computers/disable', methods=['POST'])
@admin_required
@permission_required('disable_user')
def admin_computer_disable():
    return set_computer_disabled_state(True)


@app.route('/api/admin/computers/enable', methods=['POST'])
@admin_required
@permission_required('disable_user')
def admin_computer_enable():
    return set_computer_disabled_state(False)


@app.route('/api/admin/computers/delete', methods=['POST'])
@admin_required
@permission_required('delete_user')
def admin_computer_delete():
    """删除单台AD计算机对象：必须二人审批后执行。"""
    data = request.get_json(silent=True) or {}
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再删除计算机'})
    computer_name = data.get('name', '').strip()
    computer_dn = data.get('dn', '').strip()
    approval_id = data.get('approval_id')
    if not computer_name and not computer_dn:
        return jsonify({'success': False, 'message': '缺少计算机名或DN'})
    if computer_name and not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', computer_name):
        return jsonify({'success': False, 'message': '计算机名格式不正确'})

    target_label = computer_name or computer_dn
    approval = None
    if not approval_id and not is_super_admin_user():
        approval = create_pending_approval(
            '删除计算机',
            target_label,
            {'name': computer_name, 'dn': computer_dn, 'confirm_text': 'YES'},
            f'请求删除计算机 {target_label}'
        )
        write_admin_action('发起删除计算机审批', target_label, f"审批ID:{approval.id}", request.remote_addr)
        return jsonify({'success': False, 'need_approval': True, 'approval_id': approval.id,
                        'message': f'已创建审批 #{approval.id}，需要超级管理员批准后再执行'})

    if approval_id:
        approval, err = validate_approval(approval_id, '删除计算机')
        if err:
            return jsonify({'success': False, 'message': err})

    try:
        conn = get_ad_connection()
        if computer_dn:
            conn.search(
                search_base=computer_dn,
                search_filter='(objectClass=computer)',
                search_scope=ldap3.BASE,
                attributes=['cn', 'distinguishedName', 'operatingSystem']
            )
            if not conn.entries:
                conn.unbind()
                return jsonify({'success': True, 'message': '计算机已不存在'})
            entry = conn.entries[0]
            target_dn = get_entry_text(entry, 'distinguishedName')
            target_name = get_entry_text(entry, 'cn', computer_name or computer_dn.split(',')[0].replace('CN=', '', 1))
            target_os = get_entry_text(entry, 'operatingSystem')
        else:
            conn.search(
                search_base=computer_search_base(),
                search_filter=f'(&(objectCategory=computer)(cn={ldap_escape(computer_name)}))',
                search_scope=ldap3.SUBTREE,
                attributes=['cn', 'distinguishedName', 'operatingSystem']
            )
            if not conn.entries:
                conn.unbind()
                if approval:
                    approval.status = 'executed'
                    approval.executed_at = datetime.utcnow()
                    db.session.commit()
                    write_admin_action('删除计算机完成', computer_name, f"审批ID:{approval.id} | 计算机已不存在，视为完成", request.remote_addr)
                    return jsonify({'success': True, 'message': '计算机已不存在，该审批已标记完成'})
                write_admin_action('删除计算机完成', computer_name, '超级管理员直接执行 | 计算机已不存在，视为完成', request.remote_addr)
                return jsonify({'success': True, 'message': '计算机已不存在'})
            entry = conn.entries[0]
            target_dn = get_entry_text(entry, 'distinguishedName')
            target_name = get_entry_text(entry, 'cn', computer_name)
            target_os = get_entry_text(entry, 'operatingSystem')

        if is_infra_computer(target_name, target_os, target_dn):
            conn.unbind()
            return jsonify({'success': False, 'message': '域控/服务器不允许在后台删除'})

        conn.delete(target_dn)
        if conn.result['result'] == 0:
            conn.unbind()
            if approval:
                approval.status = 'executed'
                approval.executed_at = datetime.utcnow()
                db.session.commit()
            write_admin_action('删除计算机', target_name, f"DN:{target_dn}", request.remote_addr)
            return jsonify({'success': True, 'message': f'计算机 {target_name} 已删除'})
        reason = conn.result.get('description', '未知错误')
        conn.unbind()
        return jsonify({'success': False, 'message': f'删除计算机失败：{reason}'})
    except Exception as e:
        app.logger.error(f"删除计算机失败: {e}")
        return jsonify({'success': False, 'message': '删除计算机失败，请联系IT'})


@app.route('/api/admin/backup/export', methods=['GET'])
@admin_required
@permission_required('system_settings')
def admin_backup_export():
    """导出后台用户、设置和日志。"""
    backup = {
        'exported_at': fmt_local_dt(utc_now()),
        'settings': [{ 'key': s.key, 'value': s.value } for s in SystemSetting.query.all()],
        'admin_users': [{
            'username': u.username,
            'role': u.role,
            'permissions': u.permissions,
            'is_active': u.is_active,
            'created_by': u.created_by,
            'created_at': fmt_local_dt(u.created_at)
        } for u in AdminUser.query.all()],
        'action_logs': [{
            'admin_username': r.admin_username,
            'action': r.action,
            'target_employee_id': r.target_employee_id,
            'message': r.message,
            'ip_address': r.ip_address,
            'created_at': fmt_local_dt(r.created_at)
        } for r in AdminActionLog.query.order_by(AdminActionLog.created_at.desc()).limit(1000).all()]
    }
    write_admin_action('导出系统备份', 'SYSTEM', '导出后台用户/设置/日志', request.remote_addr)
    return jsonify({'success': True, 'backup': backup})


@app.route('/api/admin/backup/restore', methods=['POST'])
@admin_required
@permission_required('system_settings')
def admin_backup_restore():
    """恢复系统设置；后台用户密码不从备份恢复。"""
    data = request.get_json()
    backup = data.get('backup') if isinstance(data, dict) else None
    if not require_yes(data):
        return jsonify({'success': False, 'message': '请输入 YES 后再恢复设置'})
    if not backup:
        return jsonify({'success': False, 'message': '备份内容为空'})
    for item in backup.get('settings', []):
        if item.get('key'):
            set_setting(item.get('key'), item.get('value', ''))
    db.session.commit()
    write_admin_action('恢复系统备份', 'SYSTEM', '恢复系统设置；用户密码不恢复', request.remote_addr)
    return jsonify({'success': True, 'message': '系统设置已恢复，后台用户密码不会从备份恢复'})


@app.route('/api/admin/logs', methods=['GET'])
@admin_required
@permission_required('view_logs')
def admin_logs():
    """日志中心：注册、改密、管理员登录、管理员操作。"""
    def fmt_dt(dt):
        return fmt_local_dt(dt)

    operator = request.args.get('operator', '').strip()
    target = request.args.get('target', '').strip().lower()
    action_filter = request.args.get('action', '').strip()
    start_date = request.args.get('start', '').strip()
    end_date = request.args.get('end', '').strip()

    def apply_time_filter(query, model):
        if start_date:
            try:
                start_day = datetime.strptime(start_date, '%Y-%m-%d').date()
                query = query.filter(model.created_at >= local_day_start_utc(start_day))
            except ValueError:
                pass
        if end_date:
            try:
                end_day = datetime.strptime(end_date, '%Y-%m-%d').date() + timedelta(days=1)
                query = query.filter(model.created_at < local_day_start_utc(end_day))
            except ValueError:
                pass
        return query

    register_query = RegisterLog.query.filter(RegisterLog.status.in_(['success', 'failed']))
    password_query = RegisterLog.query.filter(RegisterLog.status.in_([
        'reset_success', 'reset_failed', 'admin_reset_success', 'admin_reset_failed'
    ]))
    login_query = AdminLoginLog.query
    action_query = AdminActionLog.query

    register_query = apply_time_filter(register_query, RegisterLog)
    password_query = apply_time_filter(password_query, RegisterLog)
    login_query = apply_time_filter(login_query, AdminLoginLog)
    action_query = apply_time_filter(action_query, AdminActionLog)

    if target:
        register_query = register_query.filter(RegisterLog.employee_id.like(f'%{target}%'))
        password_query = password_query.filter(RegisterLog.employee_id.like(f'%{target}%'))
        action_query = action_query.filter(AdminActionLog.target_employee_id.like(f'%{target}%'))
    if operator:
        login_query = login_query.filter(AdminLoginLog.admin_username.like(f'%{operator}%'))
        action_query = action_query.filter(AdminActionLog.admin_username.like(f'%{operator}%'))
    if action_filter:
        action_query = action_query.filter(AdminActionLog.action.like(f'%{action_filter}%'))

    register_rows = register_query.order_by(RegisterLog.created_at.desc()).limit(200).all()
    password_rows = password_query.order_by(RegisterLog.created_at.desc()).limit(200).all()
    login_rows = login_query.order_by(AdminLoginLog.created_at.desc()).limit(200).all()
    action_rows = action_query.order_by(AdminActionLog.created_at.desc()).limit(200).all()

    return jsonify({
        'success': True,
        'logs': {
            'register': [{
                'created_at': fmt_dt(r.created_at),
                'employee_id': r.employee_id or '',
                'email': r.email or '',
                'status': r.status,
                'message': r.message or '',
                'ip_address': r.ip_address or ''
            } for r in register_rows],
            'password': [{
                'created_at': fmt_dt(r.created_at),
                'employee_id': r.employee_id or '',
                'email': r.email or '',
                'status': r.status,
                'message': r.message or '',
                'ip_address': r.ip_address or ''
            } for r in password_rows],
            'login': [{
                'created_at': fmt_dt(r.created_at),
                'admin_username': r.admin_username or '',
                'success': bool(r.success),
                'message': r.message or '',
                'ip_address': r.ip_address or ''
            } for r in login_rows],
            'admin': [{
                'created_at': fmt_dt(r.created_at),
                'admin_username': r.admin_username or '',
                'action': r.action or '',
                'target_employee_id': r.target_employee_id or '',
                'message': r.message or '',
                'ip_address': r.ip_address or ''
            } for r in action_rows]
        }
    })


@app.route('/api/admin/stats', methods=['GET'])
@admin_required
@permission_required('view_dashboard')
def admin_stats():
    """统计AD用户总数、今天登录人数、从未登录人数、锁定/禁用人数。"""
    try:
        conn = get_ad_connection()
        conn.search(
            search_base=app.config['AD_BASE_DN'],
            search_filter='(&(objectCategory=person)(objectClass=user)(sAMAccountName=wfq*))',
            search_scope=ldap3.SUBTREE,
            attributes=[
                'sAMAccountName', 'description', 'department', 'userAccountControl',
                'lastLogon', 'lastLogonTimestamp', 'logonCount', 'lockoutTime'
            ]
        )

        today = local_now().date()
        total_users = 0
        today_login_users = 0
        never_login_users = 0
        locked_or_disabled_users = 0
        locked_users_count = 0
        disabled_users_count = 0
        logged_user_list = []
        today_login_user_list = []
        past_login_user_list = []
        never_login_user_list = []
        locked_or_disabled_user_list = []

        for entry in conn.entries:
            total_users += 1
            employee_id = get_entry_text(entry, 'sAMAccountName')
            full_name = get_entry_text(entry, 'description', '未填写')
            department = get_entry_text(entry, 'department', '未填写')
            uac = int(get_entry_text(entry, 'userAccountControl', '512') or 512)
            is_disabled = bool(uac & 2)
            is_locked = is_ad_lockout_value(getattr(entry, 'lockoutTime', None))
            if is_disabled:
                disabled_users_count += 1
            if is_locked:
                locked_users_count += 1
            if is_disabled or is_locked:
                locked_or_disabled_users += 1

            has_logged, login_count, last_logon_dt, last_logon = login_status_from_ad(entry)
            user_row = {
                'employee_id': employee_id,
                'full_name': full_name,
                'department': department,
                'login_count': login_count,
                'last_logon': last_logon,
                'login_status': '已登录' if has_logged else '未登录'
            }
            if is_disabled or is_locked:
                action = latest_action_for_target(employee_id, ['锁定账号', '禁用账号', '启用账号'])
                locked_or_disabled_user_list.append({
                    **user_row,
                    'account_status': '已禁用 + 已锁定' if is_disabled and is_locked else ('已禁用' if is_disabled else '已锁定'),
                    'lock_count': int(get_entry_text(entry, 'badPwdCount', '0') or 0),
                    'operator': action.admin_username if action else '',
                    'action': action.action if action else '',
                    'reason': action.message if action else ('AD lockoutTime 显示锁定' if is_locked else 'AD userAccountControl 显示禁用'),
                    'action_time': fmt_local_dt(action.created_at) if action else ''
                })
            if not has_logged:
                never_login_users += 1
                never_login_user_list.append(user_row)
            else:
                logged_user_list.append(user_row)
            if last_logon_dt and last_logon_dt.date() == today:
                today_login_users += 1
                today_login_user_list.append(user_row)
            elif has_logged:
                past_login_user_list.append(user_row)

        logged_user_list.sort(key=lambda row: (row.get('login_count') or 0, row.get('last_logon') or ''), reverse=True)
        today_login_user_list.sort(key=lambda row: (row.get('login_count') or 0, row.get('last_logon') or ''), reverse=True)
        past_login_user_list.sort(key=lambda row: (row.get('login_count') or 0, row.get('last_logon') or ''), reverse=True)
        never_login_user_list.sort(key=lambda row: row.get('employee_id') or '')
        locked_or_disabled_user_list.sort(key=lambda row: (row.get('account_status') or '', row.get('employee_id') or ''))
        conn.unbind()
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'today_login_users': today_login_users,
                'past_login_users': max(len(logged_user_list) - today_login_users, 0),
                'never_login_users': never_login_users,
                'locked_or_disabled_users': locked_or_disabled_users,
                'locked_users_count': locked_users_count,
                'disabled_users_count': disabled_users_count,
                'logged_users': logged_user_list,
                'today_login_user_list': today_login_user_list,
                'past_login_user_list': past_login_user_list,
                'never_login_user_list': never_login_user_list,
                'locked_or_disabled_user_list': locked_or_disabled_user_list
            },
            'data_source': '用户统计来自 AD 用户对象的 logonCount、lastLogon、lastLogonTimestamp、userAccountControl、lockoutTime；页面按中国深圳时间显示，最后登录取 lastLogon 与 lastLogonTimestamp 中较新的值。'
        })
    except Exception as e:
        app.logger.error(f"管理员统计AD失败: {e}")
        return jsonify({'success': False, 'message': '统计失败，请联系IT'})


_password_reminder_scheduler_started = False


def valid_hhmm(value):
    return bool(re.fullmatch(r'([01]\d|2[0-3]):[0-5]\d', value or ''))


def password_reminder_scheduler_loop():
    """代码内自动发送循环；多 worker 会同时检查，但数据库锁保证只有一个真正发送。"""
    last_checked_minute = ''
    while True:
        try:
            with app.app_context():
                auto_time = get_setting('password_reminder_auto_time', '09:00')
                if not valid_hhmm(auto_time):
                    auto_time = '09:00'
                now = local_now()
                current_minute = now.strftime('%Y-%m-%d %H:%M')
                if current_minute != last_checked_minute and now.strftime('%H:%M') == auto_time:
                    last_checked_minute = current_minute
                    app.logger.info(f"密码到期自动提醒到点触发: {current_minute}")
                    result = perform_password_expire_scan(
                        dry_run=False,
                        ip_address='scheduler',
                        operator='system-auto',
                        use_job_lock=True
                    )
                    app.logger.info(f"密码到期自动提醒任务结果: {result.get('message')}")
        except Exception as e:
            app.logger.error(f"密码到期自动提醒任务异常: {e}")
        time.sleep(30)


def start_password_reminder_scheduler():
    global _password_reminder_scheduler_started
    if _password_reminder_scheduler_started:
        return
    _password_reminder_scheduler_started = True
    thread = threading.Thread(target=password_reminder_scheduler_loop, daemon=True)
    thread.start()
    app.logger.info("密码到期自动提醒内置定时器已启动")


def run_password_expire_auto_once(force=False):
    """命令行自动任务入口：给 Windows 计划任务/cron 调用。"""
    with app.app_context():
        ensure_database_tables()
        result = perform_password_expire_scan(
            dry_run=False,
            ip_address='scheduler-cli',
            operator='system-auto',
            use_job_lock=not force
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get('success') else 1


if os.environ.get('DISABLE_INTERNAL_PASSWORD_SCHEDULER', '').lower() not in ('1', 'true', 'yes'):
    start_password_reminder_scheduler()
# ============================================================
# 启动入口
# 自动创建数据库表，db文件和app.py在同一目录
# ============================================================
if __name__ == '__main__':
    if '--password-expire-auto-run' in sys.argv:
        sys.exit(run_password_expire_auto_once(force='--force' in sys.argv))

    with app.app_context():
        ensure_database_tables()
        register_logger.info("系统启动，数据库表初始化完成")
    app.run(host='0.0.0.0', port=5000, debug=False)
