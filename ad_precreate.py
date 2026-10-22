"""Validated monthly account ranges and bounded, create-only AD operations."""
from dataclasses import dataclass
import re
import uuid

import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars


class PrecreateError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def validate_spec(data):
    allowed = {'prefix', 'year', 'month', 'start', 'end', 'full_name', 'enabled'}
    if not isinstance(data, dict) or set(data) - allowed:
        raise PrecreateError('只允许设置账号前缀、序号、姓名说明和启用状态')
    identity = {}
    limits = {'start': (0, 99), 'end': (0, 99)}
    if 'prefix' in data:
        prefix = data['prefix']
        if (not isinstance(prefix, str) or not re.fullmatch(r'wfq[0-9]{4}', prefix.strip().lower())
                or 'year' in data or 'month' in data):
            raise PrecreateError('账号前缀应为 wfq 加四位数字，例如 wfq2611；末两位序号单独设置')
        identity['prefix'] = prefix.strip().lower()
    else:
        limits.update({'year': (2000, 2099), 'month': (1, 12)})
    for key, (low, high) in limits.items():
        if type(data.get(key)) is not int or not low <= data[key] <= high:
            raise PrecreateError('年月或序号范围不正确')
    if data['start'] > data['end']:
        raise PrecreateError('起始序号不能大于结束序号')
    name = data.get('full_name', '预建待分配')
    if (not isinstance(name, str) or not name.strip() or len(name.strip()) > 80
            or any(ord(c) < 32 or c in '<>' for c in name)):
        raise PrecreateError('姓名说明须为 1 至 80 个字符，且不能包含控制字符或尖括号')
    enabled = data.get('enabled', False)
    if type(enabled) is not bool:
        raise PrecreateError('启用状态必须为布尔值')
    return {**identity, **{key: data[key] for key in limits}, 'full_name': name.strip(), 'enabled': enabled}


def account_ids(spec):
    prefix = spec['prefix'] if 'prefix' in spec else f"wfq{spec['year'] % 100:02d}{spec['month']:02d}"
    return [f"{prefix}{number:02d}"
            for number in range(spec['start'], spec['end'] + 1)]


def build_user_attributes(employee_id, email, password, full_name, department,
                          manager_name='', job_title='', note='', enabled=True):
    attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'cn': employee_id, 'sAMAccountName': employee_id,
        'userPrincipalName': employee_id + '@wfq.com', 'displayName': employee_id,
        'description': full_name, 'unicodePwd': ('"%s"' % password).encode('utf-16-le'),
        'userAccountControl': '512' if enabled else '514'
    }
    if department:
        attributes['department'] = department
    if email:
        attributes['mail'] = email
    if job_title:
        attributes['title'] = job_title
    notes = []
    if manager_name:
        notes.append(f'直属领导：{manager_name}')
    if note:
        notes.append(f'备注：{note}')
    if notes:
        attributes['info'] = '；'.join(notes)
    return attributes


@dataclass(frozen=True)
class DirectoryAccount:
    employee_id: str
    dn: str
    guid: str
    info: str
    enabled: bool


class PrecreateDirectory:
    def __init__(self, config, ou=None):
        self.config = config
        self.ou = ou or config.get('AD_USER_OU')
        self.connection = None

    def __enter__(self):
        try:
            server = ldap3.Server(self.config['AD_SERVER'], port=636, use_ssl=True,
                                 tls=ldap3.Tls(validate=0), get_info=ldap3.NONE, connect_timeout=8)
            self.connection = ldap3.Connection(server, user=self.config['AD_BIND_USER'],
                password=self.config['AD_BIND_PASSWORD'], authentication=ldap3.SIMPLE,
                auto_bind=True, receive_timeout=10)
            return self
        except (LDAPException, OSError, KeyError):
            raise PrecreateError('无法连接 AD，请检查连接配置和权限', 503) from None

    def __exit__(self, *args):
        if self.connection:
            try:
                self.connection.unbind()
            except (LDAPException, OSError):
                pass

    def lookup(self, employee_ids):
        terms = ''.join(f'(sAMAccountName={escape_filter_chars(value)})' for value in employee_ids)
        try:
            self.connection.search(self.config['AD_BASE_DN'], f'(|{terms})', ldap3.SUBTREE,
                attributes=['sAMAccountName', 'info', 'userAccountControl', 'objectGUID'])
            if self.connection.result.get('result') != 0:
                raise PrecreateError('AD 账号查询失败，未执行创建', 503)
            result = {}
            for entry in self.connection.entries:
                def value(name, default=''):
                    return entry[name].value if name in entry and entry[name].value is not None else default
                raw_guid = value('objectGUID')
                guid = str(uuid.UUID(bytes_le=raw_guid)) if isinstance(raw_guid, bytes) else str(raw_guid)
                account = DirectoryAccount(str(value('sAMAccountName')).lower(), entry.entry_dn,
                    guid, str(value('info')), not bool(int(value('userAccountControl', 2)) & 2))
                result[account.employee_id] = account
            return result
        except (LDAPException, OSError, KeyError, ValueError):
            raise PrecreateError('无法核对 AD 账号状态，请稍后重试', 503) from None

    def create(self, employee_id, password, full_name, enabled, marker):
        attributes = build_user_attributes(employee_id, '', password, full_name, '', note=marker, enabled=enabled)
        try:
            self.connection.add(f'cn={employee_id},{self.ou}', attributes=attributes)
            code = self.connection.result.get('result')
        except (LDAPException, OSError):
            raise PrecreateError('创建请求结果未确认，请先核对 AD，不能直接认定失败', 503) from None
        if code not in (0, 68):
            raise PrecreateError('AD 拒绝创建，请检查密码策略、OU 和权限')
        return code == 0
