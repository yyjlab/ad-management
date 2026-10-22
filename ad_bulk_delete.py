"""Read-before-delete policy for explicitly selected inactive employee accounts."""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import re
import ssl
import struct
import time
import uuid

import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn
from smbprotocol.security_descriptor import AccessDeniedAce, SIDPacket, SMB2CreateSDBuffer

from ad_precreate import PrecreateError

DAYS = 45
LIMIT = 100
ATTRIBUTES = ['sAMAccountName', 'objectClass', 'objectGUID', 'objectSid', 'sAMAccountType',
    'description', 'department', 'whenCreated', 'lastLogon', 'lastLogonTimestamp', 'logonCount',
    'userAccountControl', 'adminCount', 'isCriticalSystemObject', 'servicePrincipalName',
    'primaryGroupID', 'uSNChanged', 'info']


def attribute_values(entry, name):
    return next((values for key, values in entry.entry_raw_attributes.items() if key.lower() == name.lower()), [])


def entry_text(entry, name, default=''):
    values = attribute_values(entry, name)
    value = values[0] if values else default
    return value.decode('utf-8') if isinstance(value, bytes) else str(value)


def utc_time(value, filetime=False):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if filetime:
        number = int(value)
        if number < 0:
            raise ValueError('negative time')
        return datetime(1601, 1, 1) + timedelta(microseconds=number // 10) if number else None
    return datetime.strptime(str(value), '%Y%m%d%H%M%S.0Z')


def dn_parts(value):
    return tuple((key.lower(), part.casefold()) for key, part, _ in parse_dn(value, strip=True))


def in_ou(dn, ou):
    parts, parent = dn_parts(dn), dn_parts(ou)
    return len(parts) > len(parent) and parts[-len(parent):] == parent


def sid_text(value):
    if isinstance(value, bytes):
        sid = SIDPacket()
        if sid.unpack(value):
            raise ValueError('invalid SID')
        return str(sid)
    if not re.fullmatch(r'S-1-(?:[0-9]+-)+[0-9]+', str(value)):
        raise ValueError('invalid SID')
    return str(value)


def deletion_denied(raw):
    if not isinstance(raw, bytes) or not raw:
        raise ValueError('security descriptor unavailable')
    descriptor = SMB2CreateSDBuffer()
    descriptor.unpack(raw)
    acl = descriptor.get_dacl()
    if acl is None:
        raise ValueError('DACL unavailable')
    for ace in acl['aces'].get_value():
        if isinstance(ace, AccessDeniedAce) and ace['mask'].get_value() & 0x10040:
            return True
        if isinstance(ace, bytes):
            # Object/callback ACEs share the header and mask; unknown deny formats fail closed.
            if len(ace) < 8 or ace[0] not in (5, 6, 9, 10, 11, 12, 13, 17, 18, 19):
                raise ValueError('unsupported ACE')
            if ace[0] in (6, 10, 12) and struct.unpack_from('<I', ace, 4)[0] & 0x10040:
                return True
    return False


def snapshot(entry, security=False):
    def value(name, default=None):
        values = attribute_values(entry, name)
        return values[0] if values else default
    guid = value('objectGUID')
    guid = str(uuid.UUID(bytes_le=guid)) if isinstance(guid, bytes) else str(uuid.UUID(str(guid).strip('{}')))
    created = utc_time(entry_text(entry, 'whenCreated'))
    last = [utc_time(value(name, 0), True) for name in ('lastLogon', 'lastLogonTimestamp')]
    last = max((dt for dt in last if dt), default=None)
    data = {'employee_id': entry_text(entry, 'sAMAccountName').lower(), 'guid': guid, 'dn': entry.entry_dn,
        'name': entry_text(entry, 'description'), 'department': entry_text(entry, 'department'),
        'created': created.isoformat(), 'last_logon': last.isoformat() if last else None,
        'logon_count': int(value('logonCount', 0)), 'uac': int(value('userAccountControl')),
        'sam_type': int(value('sAMAccountType')), 'sid': sid_text(value('objectSid')),
        'primary_group': int(value('primaryGroupID')), 'admin_count': int(value('adminCount', 0)),
        'critical': entry_text(entry, 'isCriticalSystemObject', 'false').lower() == 'true',
        'service': bool(attribute_values(entry, 'servicePrincipalName')),
        'classes': [v.decode('utf-8').lower() if isinstance(v, bytes) else str(v).lower() for v in attribute_values(entry, 'objectClass')],
        'usn': entry_text(entry, 'uSNChanged'), 'info': entry_text(entry, 'info')}
    if not data['usn'] or data['logon_count'] < 0:
        raise ValueError('incomplete attributes')
    if security:
        data['groups'] = sorted(sid_text(v) for v in attribute_values(entry, 'tokenGroups'))
        if not data['groups']:
            raise ValueError('group membership unavailable')
        data['delete_denied'] = deletion_denied(value('nTSecurityDescriptor'))
    return data


def blocked_reason(account, peers, ou, protected_names, now, protected_groups=()):
    cutoff = now - timedelta(days=DAYS)
    if not peers:
        return '无法确认所有域控的登录记录'
    if not re.fullmatch(r'wfq[0-9]{6}', account['employee_id']) or not in_ou(account['dn'], ou):
        return '不是目标 OU 内的普通员工账号'
    if ('user' not in account['classes'] or 'computer' in account['classes'] or
            account['sam_type'] != 805306368 or not account['uac'] & 512 or account['uac'] & 0x3800):
        return '不是普通用户对象，禁止批量删除'
    if (account['admin_count'] or account['critical'] or account['service'] or
            account['primary_group'] != 513 or account['employee_id'] in protected_names or account['dn'].casefold() in protected_names or
            int(account['sid'].rsplit('-', 1)[-1]) < 1000):
        return '管理员、绑定账号、服务账号或受保护账号'
    if account.get('delete_denied'):
        return '账号存在删除保护或拒绝删除权限'
    if 'groups' not in account:
        return '无法确认完整组权限，禁止删除'
    if datetime.fromisoformat(account['created']) > cutoff:
        return '创建未满 45 天'
    for peer in peers:
        if not peer.get('groups') or peer.get('delete_denied'):
            return '有域控无法确认组权限，或账号存在删除保护'
        for sid in peer['groups']:
            if sid in protected_groups or (sid.startswith('S-1-5-32-') and sid != 'S-1-5-32-545') or (
                    sid.startswith('S-1-5-21-') and int(sid.rsplit('-', 1)[-1]) in (512, 516, 518, 519, 520, 521, 525, 526, 527)):
                return '属于管理员或受保护安全组'
        if (peer['guid'] != account['guid'] or dn_parts(peer['dn']) != dn_parts(account['dn']) or
                peer['employee_id'] != account['employee_id'] or peer['created'] != account['created'] or peer['sid'] != account['sid']):
            return '域控间账号标识或位置不一致，禁止删除'
        last = datetime.fromisoformat(peer['last_logon']) if peer['last_logon'] else None
        if last and (last > cutoff or last < datetime.fromisoformat(peer['created']) or last > now):
            return '45 天内有域登录记录或登录时间异常'
        if not last and peer['logon_count'] > 0:
            return '存在登录计数但无法确认时间，禁止删除'
        if peer['admin_count'] or peer['critical'] or peer['service'] or peer['primary_group'] != 513 or peer['uac'] != account['uac']:
            return '域控间账号状态不同或账号受保护'
    return ''


class BulkDeleteDirectory:
    def __init__(self, config, host=None, ca_file=None):
        self.config, self.host, self.ca_file = config, host or config['AD_SERVER'], ca_file
        self.stack = ExitStack()
        self.connections = {}
        self.deadline = time.monotonic() + 65

    def check_budget(self):
        if time.monotonic() >= self.deadline:
            raise PrecreateError('安全核对超时，未继续删除；请缩小账号前缀后重新筛选', 503)

    @staticmethod
    def close_connection(conn):
        try:
            conn.unbind()
        except (LDAPException, OSError):
            pass

    def connection(self, host):
        self.check_budget()
        if host not in self.connections:
            try:
                server = ldap3.Server(host, port=636, use_ssl=True, get_info=ldap3.NONE,
                    tls=ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.ca_file), connect_timeout=8)
                conn = ldap3.Connection(server, user=self.config['AD_BIND_USER'], password=self.config['AD_BIND_PASSWORD'],
                    authentication=ldap3.SIMPLE, auto_bind=True, check_names=False, auto_referrals=False, receive_timeout=10)
            except (LDAPException, OSError, ValueError):
                raise PrecreateError('无法安全连接域控；请检查域控 DNS、LDAPS 证书信任和连接权限', 503) from None
            self.connections[host] = conn
            self.stack.callback(self.close_connection, conn)
        return self.connections[host]

    def search(self, conn, base, query, attributes, scope=ldap3.SUBTREE, limit=0, controls=None, partial=False):
        self.check_budget()
        try:
            conn.search(base, query, scope, attributes=attributes, size_limit=limit, controls=controls)
            code = conn.result.get('result')
            if code not in ((0, 4) if partial else (0,)) or any(r.get('type') == 'searchResRef' for r in conn.response):
                raise PrecreateError('域控查询未完整完成，禁止继续删除', 503)
            return list(conn.entries), code == 4
        except (LDAPException, OSError):
            raise PrecreateError('域控查询失败，无法确认登录和保护状态，禁止继续删除', 503) from None

    def __enter__(self):
        try:
            conn = self.connection(self.host)
            entries, _ = self.search(conn, '', '(objectClass=*)', ['dnsHostName', 'defaultNamingContext'], ldap3.BASE)
            if len(entries) != 1 or dn_parts(entry_text(entries[0], 'defaultNamingContext')) != dn_parts(self.config['AD_BASE_DN']):
                raise PrecreateError('连接域与配置不一致，禁止删除', 503)
            self.write_host = entry_text(entries[0], 'dnsHostName').lower()
            self.controllers = self.discover(conn)
            self.primary = self.connection(self.write_host)
            groups, _ = self.search(self.primary, self.config['AD_BASE_DN'],
                '(&(objectClass=group)(|(adminCount=1)(cn=DnsAdmins)(cn=*Admin*)))', ['objectSid'])
            self.protected_groups = {sid_text(attribute_values(row, 'objectSid')[0]) for row in groups}
            return self
        except Exception:
            self.stack.close()
            raise

    def __exit__(self, *args):
        self.stack.close()

    def discover(self, conn):
        entries, _ = self.search(conn, self.config['AD_BASE_DN'],
            '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', ['dNSHostName'])
        domain = '.'.join(v for k, v in dn_parts(self.config['AD_BASE_DN']) if k == 'dc')
        hosts = sorted({entry_text(row, 'dNSHostName').lower() for row in entries if attribute_values(row, 'dNSHostName')})
        if (not hosts or len(hosts) != len(entries) or len(hosts) > 16 or self.write_host not in hosts or
                any(not re.fullmatch(r'[a-z0-9][a-z0-9.-]+', h) or not h.endswith('.' + domain) for h in hosts)):
            raise PrecreateError('无法确认完整域控列表，禁止删除', 503)
        return hosts

    def candidates(self, prefix, now):
        cutoff = now - timedelta(days=DAYS)
        filetime = int((cutoff - datetime(1601, 1, 1)).total_seconds() * 10000000)
        query = ('(&(objectCategory=person)(objectClass=user)(sAMAccountName=' + escape_filter_chars(prefix) + '*)'
            '(whenCreated<=' + cutoff.strftime('%Y%m%d%H%M%S.0Z') + ')(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=' + str(filetime) + ')))')
        entries, partial = self.search(self.primary, self.config['AD_USER_OU'], query,
            ATTRIBUTES, limit=LIMIT + 1, partial=True)
        return entries[:LIMIT], partial or len(entries) > LIMIT

    def inspect(self, guid):
        guid = str(uuid.UUID(guid))
        query = '(objectGUID=' + ''.join('\\%02x' % b for b in uuid.UUID(guid).bytes_le) + ')'
        try:
            peers = []
            for host in [self.write_host] + [h for h in self.controllers if h != self.write_host]:
                conn = self.connection(host)
                rows, _ = self.search(conn, self.config['AD_BASE_DN'], query, ['distinguishedName'])
                if not rows and host == self.write_host:
                    return None, []
                if len(rows) != 1:
                    raise PrecreateError('有域控缺失该账号，无法确认登录情况，禁止删除', 503)
                rows, _ = self.search(conn, rows[0].entry_dn, '(objectClass=*)',
                    ATTRIBUTES + ['tokenGroups', 'nTSecurityDescriptor'], ldap3.BASE,
                    controls=security_descriptor_control(sdflags=4))
                if len(rows) != 1:
                    raise PrecreateError('账号在核对期间变化，禁止删除', 503)
                row = snapshot(rows[0], security=True)
                if row['guid'] != guid:
                    raise PrecreateError('账号标识已变化，禁止删除', 503)
                peers.append(row)
            return peers[0], peers
        except (ValueError, KeyError, TypeError, OverflowError, struct.error):
            raise PrecreateError('账号属性、完整组权限或删除保护信息不完整，禁止删除', 503) from None

    def delete(self, account):
        self.check_budget()
        rows, _ = self.search(self.primary, account['dn'], '(objectClass=*)',
            ATTRIBUTES + ['tokenGroups', 'nTSecurityDescriptor'], ldap3.BASE,
            controls=security_descriptor_control(sdflags=4))
        try:
            fresh = snapshot(rows[0], security=True) if len(rows) == 1 else None
        except (ValueError, KeyError, TypeError, OverflowError, struct.error):
            fresh = None
        fields = ('employee_id', 'guid', 'dn', 'usn', 'uac', 'sid', 'last_logon', 'groups',
                  'admin_count', 'critical', 'service', 'primary_group', 'delete_denied')
        if not fresh or any(fresh[key] != account[key] for key in fields):
            raise PrecreateError('执行前账号再次发生变化，未发送删除；请重新筛选', 409)
        # A GUID target cannot resolve to a replacement account with the same login/DN.
        target = '<GUID=' + str(uuid.UUID(account['guid'])) + '>'
        try:
            self.primary.delete(target)  # No tree-delete controls, no computer or child-object deletion.
            code = self.primary.result.get('result')
        except (LDAPException, OSError):
            raise PrecreateError('删除请求结果未确认，请核对后再重试', 503) from None
        if code not in (0, 32):
            raise PrecreateError('AD 拒绝删除；未解除保护、未删除子对象或计算机')
        return code == 0
