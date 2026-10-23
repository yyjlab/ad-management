"""Narrow, versioned editors for three explicitly configured domain-root GPOs."""

import codecs
import errno
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path, PureWindowsPath
import re
import ssl
import struct
from uuid import UUID, uuid4, uuid5
import xml.etree.ElementTree as ET

import ldap3
from ldap3.utils.dn import parse_dn
import smbclient

from gpo_password_policy import IniDocument, PolicyError, GpoPasswordPolicy, _value, next_version

MAX_FILE = 4 * 1024 * 1024
IDLE_KEY = r'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'
USB_KEY = r'Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
POL_HEADER = b'PReg\x01\x00\x00\x00'
PATHS = {
    'lock': [r'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'],
    'usb': [r'Machine\Registry.pol'],
    'software': [r'User\Preferences\Files\Files.xml', r'User\Preferences\Shortcuts\Shortcuts.xml',
                 r'User\Preferences\ADManagementSoftware.json'],
}
EXTENSIONS = {
    'lock': [('{827D319E-6EAC-11D2-A4EA-00C04F79F83A}', '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}')],
    'usb': [('{35378EAC-683F-11D2-A89A-00C04FBBCFA2}', '{D02B1F72-3407-48AE-BA88-E8213C6761F1}')],
    'software': [('{00000000-0000-0000-0000-000000000000}', '{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}',
                  '{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}'),
                 ('{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}', '{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}'),
                 ('{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}', '{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}')],
}
XML_TYPES = {
    'Files': ('File', '{215B2E53-57CE-475C-80FE-9EEC14635851}', '{50BE44C8-567A-4ED1-B1D0-9234FE1F38AF}'),
    'Shortcuts': ('Shortcut', '{872ECB34-B2EC-401B-A585-D32574AA90EE}', '{4F2F7C55-2790-433E-8127-0739D1CFA327}'),
}


def dn_tuple(value):
    return tuple((key.casefold(), part.casefold()) for key, part, _ in parse_dn(value, strip=True))


def parse_pol(raw):
    if raw is None:
        return []
    if len(raw) > MAX_FILE or not raw.startswith(POL_HEADER):
        raise PolicyError('Registry.pol 文件头或大小无效，未作修改', 503)
    offset, entries = 8, []
    try:
        def take(marker):
            nonlocal offset
            if raw[offset:offset + len(marker)] != marker:
                raise ValueError('delimiter')
            offset += len(marker)

        def text():
            nonlocal offset
            start = offset
            while raw[offset:offset + 2] != b'\x00\x00':
                offset += 2
                if offset >= len(raw):
                    raise ValueError('unterminated string')
            value = raw[start:offset].decode('utf-16-le', errors='strict')
            offset += 2
            return value

        while offset < len(raw):
            start = offset
            take(b'[\x00')
            key = text()
            take(b';\x00')
            name = text()
            take(b';\x00')
            kind = struct.unpack_from('<I', raw, offset)[0]
            offset += 4
            take(b';\x00')
            size = struct.unpack_from('<I', raw, offset)[0]
            offset += 4
            take(b';\x00')
            if size > len(raw) - offset:
                raise ValueError('size')
            data = raw[offset:offset + size]
            offset += size
            take(b']\x00')
            entries.append((key, name, kind, data, raw[start:offset]))
        return entries
    except (ValueError, UnicodeError, struct.error) as exc:
        raise PolicyError('Registry.pol 格式不完整，未作修改', 503) from exc


def pol_dword(key, name, value):
    return (b'[\x00' + (key + '\x00').encode('utf-16-le') + b';\x00' +
            (name + '\x00').encode('utf-16-le') + b';\x00' + struct.pack('<I', 4) + b';\x00' +
            struct.pack('<I', 4) + b';\x00' + struct.pack('<I', value) + b']\x00')


def usb_values(raw):
    values = {}
    for key, name, kind, data, _ in parse_pol(raw):
        if key.casefold() != USB_KEY.casefold():
            continue
        if name.startswith('**'):
            raise PolicyError('U盘策略含删除或安全描述符指令，请先在 GPMC 核对', 503)
        if name.casefold() not in ('deny_read', 'deny_write'):
            continue
        if name.casefold() in values or kind != 4 or len(data) != 4:
            raise PolicyError('U盘策略值重复或不是 DWORD', 503)
        number = struct.unpack('<I', data)[0]
        if number not in (0, 1):
            raise PolicyError('U盘策略值不受支持', 503)
        values[name.casefold()] = number
    return values


def read_usb(raw):
    values = usb_values(raw)
    pair = (values.get('deny_read'), values.get('deny_write'))
    return {'mode': {(None, None): 'undefined', (0, 0): 'allow', (0, 1): 'readonly', (1, 1): 'deny'}.get(pair, 'custom')}


def patch_usb(raw, mode):
    usb_values(raw)
    entries = parse_pol(raw)
    kept = [original for key, name, _, _, original in entries if not
            (key.casefold() == USB_KEY.casefold() and name.casefold() in ('deny_read', 'deny_write'))]
    if mode != 'undefined':
        read, write = {'allow': (0, 0), 'readonly': (0, 1), 'deny': (1, 1)}[mode]
        kept.extend((pol_dword(USB_KEY, 'Deny_Read', read), pol_dword(USB_KEY, 'Deny_Write', write)))
    return POL_HEADER + b''.join(kept)


def xml_document(raw, name):
    if raw is None:
        return ET.Element(name, {'clsid': XML_TYPES[name][1]})
    if len(raw) > MAX_FILE or re.search(br'<!\s*(?:DOCTYPE|ENTITY)', raw.replace(b'\x00', b''), re.I):
        raise PolicyError('首选项 XML 含不受支持的声明或过大', 503)
    try:
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        root = ET.fromstring(raw, parser=parser)
    except ET.ParseError as exc:
        raise PolicyError('首选项 XML 无效，未作修改', 503) from exc
    if root.tag != name or root.get('clsid', '').upper() != XML_TYPES[name][1] or root.get('disabled', '0') != '0':
        raise PolicyError('首选项类型不匹配或已整体禁用，请先在 GPMC 核对', 503)
    return root


def source_path(value, root):
    if not isinstance(value, str) or not isinstance(root, str) or not root:
        raise PolicyError('先配置可信的软件共享根目录 GPO_SOFTWARE_SOURCE_ROOT')
    def parts(path):
        if not re.fullmatch(r'\\\\[A-Za-z0-9][A-Za-z0-9.-]*\\[^\\/:*?"<>|\x00-\x1f]+(?:\\[^\\/:*?"<>|\x00-\x1f]+)*', path):
            raise PolicyError('软件来源必须是可信共享目录内的 UNC 路径')
        values = path[2:].split('\\')
        if any(p in ('.', '..') or p.endswith((' ', '.')) for p in values) or '%' in path:
            raise PolicyError('软件路径含不安全字符')
        return values
    child, parent = parts(value), parts(root.rstrip('\\'))
    if len(child) <= len(parent) or [p.casefold() for p in child[:len(parent)]] != [p.casefold() for p in parent]:
        raise PolicyError('软件不在配置的可信共享根目录内')
    if not child[-1].lower().endswith('.exe') or len(value) > 240:
        raise PolicyError('首版仅支持单个独立 EXE，路径最多 240 字符')
    return value


def validate_policy(kind, policy, software_root=''):
    if not isinstance(policy, dict):
        raise PolicyError('策略格式无效')
    if kind == 'lock':
        if set(policy) != {'seconds'} or (policy['seconds'] is not None and
                (type(policy['seconds']) is not int or not 0 <= policy['seconds'] <= 599940)):
            raise PolicyError('锁屏时间须为 0～599940 的整数秒；未配置使用空值')
    elif kind == 'usb':
        if set(policy) != {'mode'} or policy['mode'] not in ('undefined', 'allow', 'readonly', 'deny'):
            raise PolicyError('请选择未配置、允许读写、只读或禁止读写')
    elif kind == 'software':
        if set(policy) != {'enabled', 'source', 'name'} or type(policy['enabled']) is not bool:
            raise PolicyError('软件配置格式无效')
        if not isinstance(policy['source'], str) or not isinstance(policy['name'], str):
            raise PolicyError('软件名称和来源须为文字')
        if policy['enabled']:
            source_path(policy['source'], software_root)
            if not re.fullmatch(r'[\w\u4e00-\u9fff .-]{1,40}', policy['name']) or policy['name'].endswith((' ', '.')):
                raise PolicyError('软件名称限 1～40 个汉字、字母、数字、空格、点、横线或下划线')
        elif policy != {'enabled': False, 'source': '', 'name': ''}:
            raise PolicyError('停止下发时请清空软件配置；不会删除客户端已复制的 EXE')
    else:
        raise PolicyError('不支持的策略类型', 404)


def extension_list(original, additions):
    groups = re.findall(r'\[((?:\{[0-9A-Fa-f-]{36}\}){2,})\]', original)
    if ''.join('[' + group + ']' for group in groups) != original:
        raise PolicyError('GPO 扩展列表格式无效', 503)
    merged = {}
    for group in groups:
        ids = re.findall(r'\{[0-9A-Fa-f-]{36}\}', group)
        for value in ids:
            UUID(value.strip('{}'))
        merged.setdefault(ids[0].upper(), set()).update(v.upper() for v in ids[1:])
    for group in additions:
        merged.setdefault(group[0], set()).update(group[1:])
    return ''.join('[' + first + ''.join(sorted(rest)) + ']' for first, rest in sorted(merged.items()))


def workstation_filter(value):
    # One query only; reject additional clauses rather than inferring a safe filter.
    match = re.fullmatch(r'1;3;10;([0-9]+);WQL;root\\CIMv2;([^;]+);', value, re.I)
    return bool(match and int(match[1]) == len(match[2]) and re.fullmatch(
        r'\s*SELECT\s+\*\s+FROM\s+Win32_OperatingSystem\s+WHERE\s+ProductType\s*=\s*1\s*', match[2], re.I))


class GpoEndpointPolicy:
    def __init__(self, conn, backup_root, *, kind, guid, domain_dn, username, password,
                 scope='workstations', software_root=''):
        if kind not in PATHS or scope != 'workstations':
            raise PolicyError('GPO 类型或设备范围配置无效', 503)
        if not conn.server.ssl or not conn.server.tls or conn.server.tls.validate != ssl.CERT_REQUIRED:
            raise PolicyError('必须通过验证域控证书的 LDAPS 管理 GPO', 503)
        try:
            self.guid = '{' + str(UUID(guid.strip('{}'))).upper() + '}'
        except (ValueError, AttributeError) as exc:
            raise PolicyError('请配置本功能独立的 GPO GUID', 503) from exc
        if self.guid in ('{31B2F340-016D-11D2-945F-00C04FB984F9}', '{6AC1786C-016F-11D2-945F-00C04FB984F9}'):
            raise PolicyError('不得使用默认域策略或默认域控策略', 503)
        actual = conn.server.info.other.get('defaultNamingContext', []) if conn.server.info else []
        if not actual or dn_tuple(actual[0]) != dn_tuple(domain_dn):
            raise PolicyError('连接的 AD 域与配置不一致', 503)
        if not username or not password or not ('@' in username or '\\' in username):
            raise PolicyError('SMB 需要 UPN 或 DOMAIN\\user 账号', 503)
        self.conn, self.kind, self.scope = conn, kind, scope
        self.domain_dn, self.backup_root = domain_dn, Path(backup_root)
        self.domain = '.'.join(part for key, part in dn_tuple(domain_dn) if key == 'dc')
        self.host = conn.server.host
        if not re.fullmatch(r'[A-Za-z0-9.-]+', self.host) or not re.fullmatch(r'[A-Za-z0-9.-]+', self.domain):
            raise PolicyError('域控主机名或域名称无效', 503)
        self.dn = f'CN={self.guid},CN=Policies,CN=System,{domain_dn}'
        self.base = f'\\\\{self.host}\\SYSVOL\\{self.domain}\\Policies\\{self.guid}'
        self.username, self.password, self.software_root = username, password, software_root
        self.extension_attr = 'gPCUserExtensionNames' if kind == 'software' else 'gPCMachineExtensionNames'
        self.conn.auto_referrals = False

    def search(self, base, query, attributes, scope=ldap3.BASE):
        self.conn.search(base, query, scope, attributes=attributes)
        if self.conn.result.get('result') != 0 or any(row.get('type') == 'searchResRef' for row in self.conn.response):
            raise PolicyError('域控查询未完整完成，禁止操作 GPO', 503)
        return list(self.conn.entries)

    def metadata(self):
        rows = self.search(self.dn, '(objectClass=groupPolicyContainer)',
            ['displayName', 'gPCFileSysPath', 'versionNumber', 'flags', 'gPCWQLFilter',
             'gPCMachineExtensionNames', 'gPCUserExtensionNames', 'uSNChanged'])
        if len(rows) != 1:
            raise PolicyError('找不到本功能 GPO，请先创建独立 GPO 并链接到域根', 503)
        row = rows[0]
        path = PureWindowsPath(_value(row, 'gPCFileSysPath'))
        if (not path.is_absolute() or path.drive.split('\\')[-1].casefold() != 'sysvol' or
                tuple(p.casefold() for p in path.parts[1:]) != (self.domain.casefold(), 'policies', self.guid.casefold())):
            raise PolicyError('SYSVOL 路径不在本域指定 GPO 内', 503)
        try:
            version, flags = int(_value(row, 'versionNumber')), int(_value(row, 'flags'))
        except ValueError as exc:
            raise PolicyError('GPO 版本或启用状态无效', 503) from exc
        if not 0 <= version <= 0xffffffff or not 0 <= flags <= 3 or flags & (1 if self.kind == 'software' else 2):
            raise PolicyError('GPO 对应配置已禁用或版本无效', 503)
        links = self.search(self.domain_dn, '(objectClass=domainDNS)', ['gPLink'])
        root_links = _value(links[0], 'gPLink') if len(links) == 1 else ''
        if not any(dn_tuple(dn) == dn_tuple(self.dn) and not int(options) & 1
                   for dn, options in re.findall(r'\[LDAP://([^;]+);([0-3])\]', root_links, re.I)):
            raise PolicyError('本功能 GPO 未以启用状态链接到域根', 503)
        wmi = _value(row, 'gPCWQLFilter')
        query = ''
        if self.scope == 'workstations':
            match = re.fullmatch(r'\[([^;]+);(\{[0-9A-Fa-f-]{36}\});0\]', wmi)
            if not match or match[1].casefold() != self.domain.casefold():
                raise PolicyError('办公电脑范围要求 GPO 绑定仅限 ProductType=1 的 WMI 筛选；不会自动扩大到服务器', 503)
            filters = self.search(f'CN={match[2]},CN=SOM,CN=WMIPolicy,CN=System,{self.domain_dn}',
                                  '(objectClass=msWMI-Som)', ['msWMI-Parm2'])
            query = _value(filters[0], 'msWMI-Parm2') if len(filters) == 1 else ''
            if not workstation_filter(query):
                raise PolicyError('WMI 筛选不是单一办公电脑筛选，禁止写入', 503)
        extensions = {key: _value(row, key) for key in ('gPCMachineExtensionNames', 'gPCUserExtensionNames')}
        extension_list(extensions[self.extension_attr], ())
        return {'guid': self.guid, 'name': _value(row, 'displayName'), 'version': version,
                'dc': self.host, 'domain': self.domain, 'scope': self.scope, 'flags': flags,
                'root_links': root_links, 'wmi': wmi, 'wmi_query': query, **extensions}

    @contextmanager
    def files(self, writable=False):
        cache, stack, handles = {}, ExitStack(), {}
        try:
            smbclient.register_session(self.host, username=self.username, password=self.password,
                encrypt=True, require_signing=True, auth_protocol='ntlm', connection_timeout=10, connection_cache=cache)
            # GPT.ini is the publication marker and must already exist in a real GPO.
            handles['GPT.ini'] = stack.enter_context(smbclient.open_file(self.base + '\\GPT.ini',
                mode='r+b' if writable else 'rb', share_access='r', buffering=0, connection_cache=cache))
            for name in PATHS[self.kind]:
                try:
                    handles[name] = stack.enter_context(smbclient.open_file(self.base + '\\' + name,
                        mode='r+b' if writable else 'rb', share_access='r', buffering=0, connection_cache=cache))
                except OSError as error:
                    if isinstance(error, FileNotFoundError) or error.errno == errno.ENOENT:
                        handles[name] = None
                    else:
                        raise
            yield handles, stack, cache
        finally:
            try:
                stack.close()
            except Exception:
                logging.getLogger(__name__).warning('设备 GPO 操作后关闭 SMB 文件失败')
            try:
                smbclient.reset_connection_cache(fail_on_error=False, connection_cache=cache)
            except Exception:
                logging.getLogger(__name__).warning('设备 GPO 操作后关闭 SMB 会话失败')

    def read_files(self, handles):
        result = {}
        for name, handle in handles.items():
            if handle is None:
                result[name] = None
                continue
            handle.seek(0)
            chunks, size = [], 0
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE:
                    raise PolicyError('GPO 文件过大，禁止编辑', 503)
                chunks.append(chunk)
            result[name] = b''.join(chunks)
        return result

    def read_values(self, raw):
        if self.kind == 'lock':
            value = IniDocument(raw[PATHS['lock'][0]] or b'[Unicode]\r\nUnicode=yes\r\n').get('Registry Values', IDLE_KEY)
            if value is None:
                return {'seconds': None}
            match = re.fullmatch(r'4\s*,\s*([0-9]+)', value)
            if not match or not 0 <= int(match[1]) <= 599940:
                raise PolicyError('当前锁屏策略不是受支持的 DWORD 秒数', 503)
            return {'seconds': int(match[1])}
        if self.kind == 'usb':
            return read_usb(raw[PATHS['usb'][0]])
        roots = [xml_document(raw[name], tag) for name, tag in zip(PATHS['software'][:2], ('Files', 'Shortcuts'))]
        manifest = raw[PATHS['software'][2]]
        if manifest is None:
            ids = self.software_ids()
            if any(child.get('uid', '').upper() in ids.values() for root in roots for child in root):
                raise PolicyError('软件首选项存在但清单缺失，禁止覆盖，请核对备份', 503)
            return {'enabled': False, 'source': '', 'name': ''}
        try:
            policy = json.loads(manifest)
            validate_policy('software', policy, self.software_root)
        except (ValueError, UnicodeError, TypeError) as exc:
            raise PolicyError('平台软件清单无效，禁止覆盖', 503) from exc
        expected = self.software_files(raw, policy, policy)
        ids = self.software_ids()
        def owned(root):
            result = []
            for child in root:
                if child.get('uid', '').upper() in ids.values():
                    child.attrib.pop('changed', None)
                    result.append(ET.tostring(child, encoding='utf-8'))
            return result
        for root, name in zip(roots, PATHS['software'][:2]):
            if owned(root) != owned(ET.fromstring(expected[name])):
                raise PolicyError('软件清单与实际首选项不一致，请在 GPMC 和备份中核对后再编辑', 409)
        return policy

    def snapshot(self, handles):
        source = self.metadata()
        raw = self.read_files(handles)
        try:
            version = int(IniDocument(raw['GPT.ini']).get('General', 'Version'))
        except (ValueError, TypeError) as exc:
            raise PolicyError('GPT.ini 缺少有效版本', 503) from exc
        if version != source['version'] or self.metadata() != source:
            raise PolicyError('AD 与 SYSVOL 版本或策略范围发生变化，请刷新后重试', 409)
        policy = self.read_values(raw)
        digest = hashlib.sha256(json.dumps(source, sort_keys=True).encode())
        for name, data in sorted(raw.items()):
            digest.update(name.encode() + b'\x00' + (b'absent' if data is None else b'present' + data))
        return {'source': source, 'policy': policy, 'revision': digest.hexdigest()}, raw

    def software_ids(self):
        namespace = UUID(self.guid.strip('{}'))
        return {key: '{' + str(uuid5(namespace, 'ad-management-' + key)).upper() + '}' for key in ('file', 'desktop')}

    def software_files(self, raw, policy, previous):
        roots = [xml_document(raw[name], tag) for name, tag in zip(PATHS['software'][:2], ('Files', 'Shortcuts'))]
        namespace = UUID(self.guid.strip('{}'))
        ids = self.software_ids()
        suffix = namespace.hex[:12]
        local = f'%LocalAppDataDir%\\AD-{suffix}.exe'
        label = f'AD-{suffix}'
        for root in roots:
            for child in list(root):
                if child.get('uid', '').upper() in ids.values():
                    root.remove(child)
        def item(root, tag, key, properties):
            element = ET.SubElement(root, tag, {'clsid': XML_TYPES[root.tag][2], 'name': label,
                'status': label, 'image': '2', 'changed': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                'uid': ids[key], 'userContext': '1', 'removePolicy': '0'})
            ET.SubElement(element, 'Properties', properties)
        if policy['enabled']:
            item(roots[0], 'File', 'file', {'action': 'U', 'fromPath': policy['source'], 'targetPath': local,
                'readOnly': '0', 'archive': '1', 'hidden': '0', 'suppress': '0'})
        for key, folder in (('desktop', '%DesktopDir%'),):
            active = policy['enabled']
            item(roots[1], 'Shortcut', key, {'action': 'U' if active else 'D', 'targetType': 'FILESYSTEM',
                'targetPath': local, 'shortcutPath': folder + '\\' + label, 'arguments': '', 'startIn': '%LocalAppDataDir%',
                'iconPath': local, 'iconIndex': '0', 'window': '1', 'shortcutKey': '0', 'pidl': '',
                'comment': policy['name'] if policy['enabled'] else ''})
        result = {name: ET.tostring(root, encoding='utf-8', xml_declaration=True)
                  for name, root in zip(PATHS['software'][:2], roots)}
        result[PATHS['software'][2]] = json.dumps(policy, ensure_ascii=False, sort_keys=True).encode('utf-8')
        return result

    def changes(self, raw, policy, before):
        validate_policy(self.kind, policy, self.software_root)
        if policy == before:
            raise PolicyError('没有需要保存的变更')
        if self.kind == 'lock':
            name = PATHS['lock'][0]
            original = raw[name] if raw[name] is not None else codecs.BOM_UTF16_LE + (
                '[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1\r\n').encode('utf-16-le')
            value = None if policy['seconds'] is None else '4,' + str(policy['seconds'])
            result = {name: IniDocument(original).patch({('Registry Values', IDLE_KEY): value})}
        elif self.kind == 'usb':
            name = PATHS['usb'][0]
            result = {name: patch_usb(raw[name], policy['mode'])}
        else:
            result = self.software_files(raw, policy, before)
        return result

    def read(self):
        with self.files() as (handles, _, _):
            return self.snapshot(handles)[0]

    def preview(self, revision, policy):
        with self.files() as (handles, _, _):
            state, raw = self.snapshot(handles)
            GpoPasswordPolicy.check_revision(state, revision)
            self.changes(raw, policy, state['policy'])
            return dict(state, after=policy)

    def backup(self, state, raw):
        backup_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid4().hex
        folder = self.backup_root / backup_id
        folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        files = {f'{index}.bin': value for index, value in enumerate(raw.values()) if value is not None}
        files['metadata.json'] = json.dumps({'snapshot': state, 'files': [
            {'path': name, 'backup': f'{index}.bin' if value is not None else None}
            for index, (name, value) in enumerate(raw.items())]}, ensure_ascii=False).encode('utf-8')
        for name, data in files.items():
            descriptor = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
        return backup_id

    def compare_metadata(self, old, new):
        changes = {}
        for key in ('versionNumber', self.extension_attr):
            before, after = old[key], new[key]
            if before != after:
                changes[key] = ([(ldap3.MODIFY_DELETE, [before])] if before != '' else []) + [(ldap3.MODIFY_ADD, [after])]
        if not self.conn.modify(self.dn, changes):
            raise PolicyError('GPO 版本或扩展发生并发变化，已拒绝发布', 409)

    def save(self, revision, policy):
        with self.files(writable=True) as (handles, stack, cache):
            state, raw = self.snapshot(handles)
            GpoPasswordPolicy.check_revision(state, revision)
            updates = self.changes(raw, policy, state['policy'])
            old_version = state['source']['version']
            new_version = (((((old_version >> 16) + 1) & 0xffff) or 1) << 16) | (old_version & 0xffff) if self.kind == 'software' else next_version(old_version)
            old = {'versionNumber': str(old_version), self.extension_attr: state['source'][self.extension_attr]}
            new = {'versionNumber': str(new_version), self.extension_attr: extension_list(old[self.extension_attr], EXTENSIONS[self.kind])}
            updates['GPT.ini'] = IniDocument(raw['GPT.ini']).patch({('General', 'Version'): str(new_version)})
            backup_id = self.backup(state, raw)
            touched, created, cas_attempted = [], [], False
            try:
                for name, data in updates.items():
                    if name == 'GPT.ini':
                        continue
                    if handles[name] is None:
                        parent = self.base + '\\' + str(PureWindowsPath(name).parent)
                        smbclient.makedirs(parent, exist_ok=True, connection_cache=cache)
                        handles[name] = stack.enter_context(smbclient.open_file(self.base + '\\' + name,
                            mode='x+b', share_access='r', buffering=0, connection_cache=cache))
                        created.append(name)
                    touched.append(name)
                    GpoPasswordPolicy.replace(handles[name], data)
                if self.metadata() != state['source']:
                    raise PolicyError('保存期间 GPO 范围或内容发生变化', 409)
                cas_attempted = True
                self.compare_metadata(old, new)
                touched.append('GPT.ini')
                GpoPasswordPolicy.replace(handles['GPT.ini'], updates['GPT.ini'])
                result, readback = self.snapshot(handles)
                if result['policy'] != policy or any(readback[name] != data for name, data in updates.items()):
                    raise OSError('GPO readback mismatch')
                return dict(result, backup_id=backup_id)
            except Exception as error:
                try:
                    current = self.metadata()
                    actual = {'versionNumber': str(current['version']), self.extension_attr: current[self.extension_attr]}
                    if actual not in (old, new):
                        raise OSError('another writer published')
                    for name in reversed(touched):
                        if name == 'GPT.ini':
                            continue
                        if name in created:
                            handles[name].close()
                            handles[name] = None
                            smbclient.remove(self.base + '\\' + name, connection_cache=cache)
                        else:
                            GpoPasswordPolicy.replace(handles[name], raw[name])
                    if cas_attempted and actual == new:
                        self.compare_metadata(new, old)
                    if 'GPT.ini' in touched:
                        GpoPasswordPolicy.replace(handles['GPT.ini'], raw['GPT.ini'])
                    if isinstance(error, OSError) and error.errno == errno.EEXIST:
                        raise OSError('concurrent file creation requires manual verification')
                    restored, restored_raw = self.snapshot(handles)
                    if restored_raw != raw or restored['revision'] != state['revision']:
                        raise OSError('rollback mismatch')
                except Exception as recovery:
                    raise PolicyError('保存结果不确定，自动恢复未完成；请按备份人工核查并暂停写入', 503,
                        backup_id=backup_id, recovery_required=True) from recovery
                raise PolicyError('保存失败，已回读确认恢复为保存前内容，请刷新后重试', 503, backup_id=backup_id) from error
