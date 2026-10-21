"""Restricted password-policy editor for one domain-linked security GPO."""

import codecs
import configparser
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path, PureWindowsPath
import re
import ssl
from uuid import UUID, uuid4

import ldap3
from ldap3.utils.dn import parse_dn
import smbclient


DEFAULT_GUID = '31b2f340-016d-11d2-945f-00c04fb984f9'
SECURITY_CSE = '{827d319e-6eac-11d2-a4ea-00c04f79f83a}'
SAM = 'MACHINE\\System\\CurrentControlSet\\Control\\SAM\\'
# API key: (INF section, INF key, boolean or maximum integer value)
FIELDS = {
    'relax_min_password_length_limits': ('Registry Values', SAM + 'RelaxMinimumPasswordLengthLimits', bool),
    'complexity_enabled': ('System Access', 'PasswordComplexity', bool),
    'min_password_length': ('System Access', 'MinimumPasswordLength', 128),
    'min_age_days': ('System Access', 'MinimumPasswordAge', 999),
    'max_age_days': ('System Access', 'MaximumPasswordAge', 999),
    'password_history_count': ('System Access', 'PasswordHistorySize', 24),
    'reversible_encryption_enabled': ('System Access', 'ClearTextPassword', bool),
    'min_password_length_audit': ('Registry Values', SAM + 'MinimumPasswordLengthAudit', 128),
}


class PolicyError(Exception):
    def __init__(self, message, status=400, *, backup_id=None, recovery_required=False):
        super().__init__(message)
        self.status = status
        self.backup_id = backup_id
        self.recovery_required = recovery_required


class IniDocument:
    """Validate as INI, but patch only targeted lines to retain other GPO data."""

    def __init__(self, raw):
        if len(raw) > 4 * 1024 * 1024:
            raise PolicyError('GPO 文件过大，拒绝编辑', 503)
        self.bom = b''
        self.encoding = 'utf-8'
        for bom, encoding in ((codecs.BOM_UTF16_LE, 'utf-16-le'),
                              (codecs.BOM_UTF16_BE, 'utf-16-be'),
                              (codecs.BOM_UTF8, 'utf-8')):
            if raw.startswith(bom):
                self.bom, self.encoding = bom, encoding
                break
        try:
            self.text = raw[len(self.bom):].decode(self.encoding, errors='strict')
            if '\x00' in self.text:
                raise ValueError('NUL')
            self.parser = configparser.ConfigParser(interpolation=None, delimiters=('=',), strict=True)
            self.parser.read_string(self.text)
            sections = self.parser.sections()
            if len({s.casefold() for s in sections}) != len(sections) or self.parser.defaults():
                raise ValueError('ambiguous sections')
        except (UnicodeError, ValueError, configparser.Error) as exc:
            raise PolicyError('GPO 文件编码或 INI 格式不受支持，未作修改', 503) from exc
        self.sections = {s.casefold(): s for s in self.parser.sections()}

    def get(self, section, key):
        actual = self.sections.get(section.casefold())
        return self.parser.get(actual, key, fallback=None) if actual else None

    def patch(self, changes):
        lines = self.text.splitlines(keepends=True)
        newline = '\r\n' if '\r\n' in self.text else '\n'
        for (section, key), value in changes.items():
            current, start, end, found = '', None, len(lines), None
            for index, line in enumerate(lines):
                header = re.fullmatch(r'\s*\[([^\]]+)\]\s*', line.strip())
                if header:
                    if current == section.casefold():
                        end = index
                        break
                    current = header[1].casefold()
                    if current == section.casefold():
                        start = index
                elif current == section.casefold() and '=' in line and not line.lstrip().startswith((';', '#')):
                    if line.split('=', 1)[0].strip().casefold() == key.casefold():
                        found = index
            if found is not None:
                lines[found:found + 1] = [] if value is None else [f'{key} = {value}{newline}']
            elif value is not None:
                if start is None:
                    if lines and not lines[-1].endswith(('\r', '\n')):
                        lines[-1] += newline
                    lines.extend([f'[{section}]{newline}', f'{key} = {value}{newline}'])
                else:
                    if end and not lines[end - 1].endswith(('\r', '\n')):
                        lines[end - 1] += newline
                    lines.insert(end, f'{key} = {value}{newline}')
        result = self.bom + ''.join(lines).encode(self.encoding)
        IniDocument(result)
        return result


def read_policy(raw):
    document, policy = IniDocument(raw), {}
    for name, (section, key, limit) in FIELDS.items():
        value = document.get(section, key)
        if value is None:
            policy[name] = None
            continue
        if section == 'Registry Values':
            match = re.fullmatch(r'4\s*,\s*(\d+)', value)
            if not match:
                raise PolicyError(f'{name} 不是受支持的 DWORD 策略', 503)
            value = match[1]
        try:
            value = int(value)
        except ValueError as exc:
            raise PolicyError(f'{name} 的 GPO 值无效', 503) from exc
        if name == 'max_age_days' and value == -1:
            value = 0
        maximum = 1 if limit is bool else limit
        if not 0 <= value <= maximum:
            raise PolicyError(f'{name} 超出支持范围', 503)
        policy[name] = bool(value) if limit is bool else value
    return policy


def apply_changes(raw, changes):
    validate_changes(changes)
    before = read_policy(raw)
    after = dict(before)
    after.update(changes)
    minimum, maximum = after['min_age_days'], after['max_age_days']
    if minimum is not None and maximum not in (None, 0) and minimum >= maximum:
        raise PolicyError('密码最短使用期限必须小于最长使用期限')
    if (after['min_password_length'] or 0) > 14 and after['relax_min_password_length_limits'] is not True:
        raise PolicyError('超过 14 个字符须先启用放宽最小密码长度限制')
    updates, diff = {}, []
    for name, value in changes.items():
        if value == before[name]:
            continue
        section, key, _ = FIELDS[name]
        serialized = None if value is None else str(int(value))
        if name == 'max_age_days' and value == 0:
            serialized = '-1'
        if section == 'Registry Values' and serialized is not None:
            serialized = '4,' + serialized
        updates[section, key] = serialized
        diff.append({'key': name, 'before': before[name], 'after': value})
    return IniDocument(raw).patch(updates), diff


def validate_changes(changes):
    if not isinstance(changes, dict) or not changes or set(changes) - FIELDS.keys():
        raise PolicyError('只允许修改本页的八项密码策略')
    for name, value in changes.items():
        limit = FIELDS[name][2]
        if value is not None:
            if limit is bool:
                valid = type(value) is bool
            else:
                minimum = 1 if name == 'min_password_length_audit' else 0
                valid = type(value) is int and minimum <= value <= limit
            if not valid:
                raise PolicyError(f'{name} 的类型或范围不正确')


def next_version(version):
    return (version & 0xffff0000) | (((version + 1) & 0xffff) or 1)


def _value(entry, key, default=''):
    values = entry[key].raw_values
    if not values:
        return default
    value = values[0]
    return value.decode('utf-8') if isinstance(value, bytes) else str(value)


class GpoPasswordPolicy:
    def __init__(self, conn, backup_root, *, guid=DEFAULT_GUID, username='', password=''):
        self.conn = conn
        if not conn.server.ssl or not conn.server.tls or conn.server.tls.validate != ssl.CERT_REQUIRED:
            raise PolicyError('GPO 管理必须使用验证域控证书的 LDAPS 连接', 503)
        self.backup_root = Path(backup_root)
        try:
            self.guid = '{' + str(UUID(guid.strip('{}'))).upper() + '}'
        except (ValueError, AttributeError) as exc:
            raise PolicyError('GPO GUID 配置无效', 503) from exc
        contexts = conn.server.info.other.get('defaultNamingContext', []) if conn.server.info else []
        if not contexts:
            raise PolicyError('AD 未返回默认域 DN', 503)
        self.domain_dn = contexts[0]
        self.domain = '.'.join(value for attr, value, _ in parse_dn(self.domain_dn) if attr.casefold() == 'dc')
        self.host = conn.server.host
        if not re.fullmatch(r'[A-Za-z0-9.-]+', self.host) or not re.fullmatch(r'[A-Za-z0-9.-]+', self.domain):
            raise PolicyError('域控或域名称不受支持', 503)
        self.dn = f'CN={self.guid},CN=Policies,CN=System,{self.domain_dn}'
        if not username or not password or not ('@' in username or '\\' in username) or username.upper().startswith('CN='):
            raise PolicyError('SMB 需要 UPN 或 DOMAIN\\user 账号及密码，不能使用 LDAP DN', 503)
        self.username, self.password = username, password

    def metadata(self):
        attrs = ['displayName', 'gPCFileSysPath', 'versionNumber', 'gPCMachineExtensionNames', 'flags', 'gPCWQLFilter']
        if not self.conn.search(self.dn, '(objectClass=groupPolicyContainer)', ldap3.BASE, attributes=attrs) or not self.conn.entries:
            raise PolicyError('读取目标 GPO 失败，请检查 GPO 及 AD 权限', 503)
        entry = self.conn.entries[0]
        path = PureWindowsPath(_value(entry, 'gPCFileSysPath'))
        expected = (self.domain, 'Policies', self.guid)
        if (not path.is_absolute() or path.drive.split('\\')[-1].casefold() != 'sysvol'
                or tuple(part.casefold() for part in path.parts[1:]) != tuple(s.casefold() for s in expected)):
            raise PolicyError('GPO 的 SYSVOL 路径不在允许范围内', 503)
        try:
            version = int(_value(entry, 'versionNumber'))
            flags = int(_value(entry, 'flags', '0'))
            if not 0 <= version <= 0xffffffff:
                raise ValueError('version')
        except ValueError as exc:
            raise PolicyError('GPO 版本无效', 503) from exc
        if flags & 2 or SECURITY_CSE not in _value(entry, 'gPCMachineExtensionNames').casefold():
            raise PolicyError('目标 GPO 未启用计算机安全策略，不能通过此页编辑', 503)
        if _value(entry, 'gPCWQLFilter'):
            raise PolicyError('目标 GPO 带 WMI 筛选，不能作为本页的域默认策略编辑', 503)
        if not self.conn.search(self.domain_dn, '(objectClass=domainDNS)', ldap3.BASE, attributes=['gPLink']):
            raise PolicyError('无法读取域根 GPO 链接', 503)
        link = _value(self.conn.entries[0], 'gPLink') if self.conn.entries else ''
        if not any(dn.casefold() == self.dn.casefold() and not int(options) & 1
                   for dn, options in re.findall(r'\[LDAP://([^;]+);(\d+)\]', link, re.I)):
            raise PolicyError('目标 GPO 未以启用状态链接到域根', 503)
        return {'guid': self.guid, 'name': _value(entry, 'displayName'), 'version': version, 'dc': self.host}

    @contextmanager
    def files(self, writable=False):
        pool = {}
        stack = ExitStack()
        try:
            smbclient.register_session(self.host, username=self.username, password=self.password,
                                       encrypt=True, require_signing=True, auth_protocol='ntlm',
                                       connection_timeout=10, connection_cache=pool)
            base = f'\\\\{self.host}\\SYSVOL\\{self.domain}\\Policies\\{self.guid}'
            handles = [stack.enter_context(smbclient.open_file(base + suffix, mode='r+b' if writable else 'rb',
                       share_access='r', buffering=0, connection_cache=pool)) for suffix in (
                       r'\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf', r'\GPT.ini')]
            yield handles
        finally:
            # Cleanup must not turn an already verified save into a misleading write failure.
            try:
                stack.close()
            except Exception:
                logging.getLogger(__name__).warning('GPO 操作后关闭 SMB 文件句柄失败')
            try:
                smbclient.reset_connection_cache(fail_on_error=False, connection_cache=pool)
            except Exception:
                logging.getLogger(__name__).warning('GPO 操作后关闭 SMB 连接失败')

    def snapshot(self, handles):
        meta = self.metadata()
        raw = []
        for handle in handles:
            handle.seek(0)
            chunks, size = [], 0
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 4 * 1024 * 1024:
                    raise PolicyError('GPO 文件过大，拒绝编辑', 503)
            raw.append(b''.join(chunks))
        try:
            file_version = int(IniDocument(raw[1]).get('General', 'Version'))
        except (TypeError, ValueError) as exc:
            raise PolicyError('GPT.ini 缺少有效版本号', 503) from exc
        if file_version != meta['version'] or self.metadata() != meta:
            raise PolicyError('AD 与 SYSVOL 版本不一致，请待复制完成后刷新', 409)
        revision = hashlib.sha256(json.dumps(meta, sort_keys=True).encode() + b'\x00' + raw[0] + b'\x00' + raw[1]).hexdigest()
        return {'source': meta, 'policy': read_policy(raw[0]), 'revision': revision}, raw

    def read(self):
        with self.files() as handles:
            return self.snapshot(handles)[0]

    def preview(self, revision, changes):
        with self.files() as handles:
            snapshot, raw = self.snapshot(handles)
            self.check_revision(snapshot, revision)
            _, diff = apply_changes(raw[0], changes)
            return dict(snapshot, diff=diff)

    @staticmethod
    def check_revision(snapshot, revision):
        if not isinstance(revision, str) or revision != snapshot['revision']:
            raise PolicyError('策略已变化，请刷新后重新预览', 409)

    def backup(self, snapshot, raw):
        backup_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid4().hex
        folder = self.backup_root / backup_id
        folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name, data in zip(('GptTmpl.inf', 'GPT.ini', 'metadata.json'), (
                *raw, json.dumps(snapshot, ensure_ascii=False, indent=2).encode('utf-8'))):
            descriptor = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
        return backup_id

    def compare_version(self, old, new):
        # LDAP Modify is atomic: deleting an exact old value prevents a stale overwrite.
        if not self.conn.modify(self.dn, {'versionNumber': [
                (ldap3.MODIFY_DELETE, [str(old)]), (ldap3.MODIFY_ADD, [str(new)])]}):
            raise PolicyError('GPO 版本更新失败或发生并发修改', 409)

    @staticmethod
    def replace(handle, data):
        handle.seek(0)
        offset = 0
        while offset < len(data):
            written = handle.write(data[offset:offset + 65536])
            if not written or written < 0:
                raise OSError('short SMB write')
            offset += written
        handle.truncate(len(data))
        handle.flush()

    def save(self, revision, changes):
        with self.files(writable=True) as handles:
            snapshot, raw = self.snapshot(handles)
            self.check_revision(snapshot, revision)
            template, diff = apply_changes(raw[0], changes)
            if not diff:
                raise PolicyError('没有需要保存的变更')
            old = snapshot['source']['version']
            new = next_version(old)
            ini = IniDocument(raw[1]).patch({('General', 'Version'): str(new)})
            backup_id = self.backup(snapshot, raw)
            cas_attempted = False
            try:
                self.replace(handles[0], template)
                cas_attempted = True
                self.compare_version(old, new)
                self.replace(handles[1], ini)
                result, written = self.snapshot(handles)
                if written != [template, ini] or result['source']['version'] != new:
                    raise OSError('GPO readback mismatch')
                return dict(result, backup_id=backup_id, diff=diff)
            except Exception as exc:
                try:
                    current = self.metadata()['version'] if cas_attempted else old
                    if current not in (old, new):
                        raise OSError('concurrent version change')
                    for handle, original in zip(handles, raw):
                        self.replace(handle, original)
                    if current == new:
                        self.compare_version(new, old)
                    restored, original = self.snapshot(handles)
                    if original != raw or restored['revision'] != snapshot['revision']:
                        raise OSError('rollback readback mismatch')
                except Exception as recovery:
                    raise PolicyError('保存结果不确定，自动恢复未完成；请暂停编辑并按备份人工核查', 503,
                                      backup_id=backup_id, recovery_required=True) from recovery
                raise PolicyError('保存失败，已回读确认恢复为保存前内容；请刷新后重试', 503,
                                  backup_id=backup_id) from exc
