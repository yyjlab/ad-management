"""Validation and Windows Setup documents. This module never touches a disk."""
import base64
import hashlib
import ipaddress
import json
import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

NAMESPACE = 'urn:schemas-microsoft-com:unattend'
WCM = 'http://schemas.microsoft.com/WMIConfig/2002/State'
ET.register_namespace('', NAMESPACE)
ET.register_namespace('wcm', WCM)
SAFE_BUSES = {'NVMe', 'SATA', 'SAS', 'SCSI', 'ATA', 'RAID'}
ACTIVE = ('queued', 'preflight', 'installing', 'awaiting_report')
TERMINAL = ('completed', 'failed', 'cancelled')
STATES = {
    'queued': '等待领取', 'preflight': '安装前检查', 'installing': 'Windows 安装中',
    'awaiting_report': '等待安装后回报', 'completed': '安装后已回报',
    'failed': '失败，需核对', 'cancelled': '已取消',
}
ERRORS = {
    'PREFLIGHT': '安装前检查未通过，未启动安装程序',
    'SOURCE': '安装源、凭据或文件校验失败，未启动安装程序',
    'DISK_CHANGED': '硬盘信息发生变化，已停止',
    'SETUP': 'Windows Setup 返回错误，请检查目标电脑的安装日志',
    'NETWORK': '部署网络连接失败，请检查目标电脑',
}


class Invalid(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def text(value, name, minimum=1, maximum=120):
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise Invalid(f'{name}长度必须为 {minimum}–{maximum} 个字符')
    value = value.strip()
    if any(ord(c) < 32 for c in value):
        raise Invalid(f'{name}包含控制字符')
    return value


def integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise Invalid(f'{name}必须为 {minimum}–{maximum} 之间的整数')
    return value


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-fA-F0-9]{64}', value):
        raise Invalid('必须提供完整的 SHA-256 校验值')
    return value.lower()


def public_url(value):
    value = text(value, '平台地址', maximum=240).rstrip('/')
    p = urlsplit(value)
    if p.username or p.password or p.query or p.fragment or p.path not in ('', '/pc-deploy') or not p.hostname:
        raise Invalid('平台地址只能使用协议、主机、端口及 /pc-deploy，不能含其他路径或凭据')
    try:
        local = ipaddress.ip_address(p.hostname).is_loopback
    except ValueError:
        local = p.hostname == 'localhost'
    if p.scheme != 'https' and not (p.scheme == 'http' and local):
        raise Invalid('远程客户端必须使用 HTTPS；HTTP 只允许本机预览')
    if not re.fullmatch(r'[A-Za-z0-9.:\[\]-]+', p.netloc):
        raise Invalid('平台地址包含不支持的字符')
    try:
        p.port
    except ValueError as exc:
        raise Invalid('端口无效') from exc
    return value if p.path else value + '/pc-deploy'


def unc_path(value):
    value = text(value, '安装源 UNC 路径', maximum=240).rstrip('\\')
    if not re.fullmatch(r'\\\\[A-Za-z0-9.-]+\\[A-Za-z0-9_$.-]+(?:\\[^"<>|?*\x00-\x1f]+)*', value):
        raise Invalid(r'请填写完整 UNC 路径，例如 \\fileserver\install\Win11')
    if any(p in ('.', '..') or p.endswith((' ', '.')) for p in value[2:].split('\\')):
        raise Invalid('安装源路径不能包含目录跳转或歧义目录名')
    return value


def source_record(data):
    if not isinstance(data, dict):
        raise Invalid('安装源清单必须是 JSON 对象')
    filename = data.get('image_file', 'sources\\install.wim')
    if filename not in ('sources\\install.wim', 'sources\\install.esd'):
        raise Invalid('首版只支持原版安装源中的 install.wim 或 install.esd')
    family = data.get('family')
    if family not in ('windows11', 'windows10'):
        raise Invalid('仅支持 Windows 11 / Windows 10')
    images = data.get('images')
    if not isinstance(images, list) or not 1 <= len(images) <= 50:
        raise Invalid('请导入安装源检测脚本生成的镜像索引清单')
    cleaned, seen = [], set()
    for image in images:
        if not isinstance(image, dict):
            raise Invalid('镜像索引清单格式错误')
        index = integer(image.get('index'), '镜像索引', 1, 100)
        if index in seen:
            raise Invalid('镜像索引重复')
        seen.add(index)
        build = integer(image.get('build'), 'Windows 内部版本', 19041, 99999)
        if (family == 'windows11') != (build >= 22000):
            raise Invalid('系统类型与镜像内部版本不一致')
        if image.get('architecture') != 'amd64':
            raise Invalid('首版仅支持 x64（amd64）镜像')
        language = image.get('language', 'zh-CN')
        if language not in ('zh-CN', 'en-US'):
            raise Invalid('首版支持简体中文或英语安装源')
        cleaned.append(dict(index=index, name=text(image.get('name'), '镜像名称'),
                            build=build, architecture='amd64', language=language))
    user = text(data.get('smb_user'), '安装源只读账号', maximum=120)
    if not re.fullmatch(r'[A-Za-z0-9_.$@\\-]+', user):
        raise Invalid('安装源账号请使用 DOMAIN\\user 或 user@domain 格式')
    if '@' not in user and '\\' not in user:
        raise Invalid('安装源账号必须包含域或文件服务器名称')
    return dict(name=text(data.get('name'), '安装源名称'), path=unc_path(data.get('path')),
                family=family, image_file=filename, images=cleaned,
                image_sha256=sha256(data.get('image_sha256')),
                setup_sha256=sha256(data.get('setup_sha256')), smb_user=user)


def profile_record(data, source):
    index = integer(data.get('image_index'), '镜像索引', 1, 100)
    if index not in {v['index'] for v in source['images']}:
        raise Invalid('所选镜像索引不在安装源中')
    username = text(data.get('username'), '本地管理员名称', maximum=20)
    reserved = {'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount', 'system', 'krbtgt'}
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,19}', username) or username.lower() in reserved:
        raise Invalid('本地账号请用英文字母开头，不能使用 Windows 保留账号名')
    prefix = text(data.get('computer_prefix', 'PC'), '计算机名前缀', maximum=6).upper()
    if not re.fullmatch(r'[A-Z][A-Z0-9-]{0,5}', prefix):
        raise Invalid('计算机名前缀只能使用英文字母、数字和连字符')
    size = integer(data.get('system_gib', 0), '系统盘容量', 0, 4096)
    if size and size < 80:
        raise Invalid('独立 C 盘至少 80 GiB；0 表示不创建数据分区')
    return dict(name=text(data.get('name'), '方案名称'), source_id=source['id'], image_index=index,
                username=username, computer_prefix=prefix, system_gib=size)


def inventory(data):
    if not isinstance(data, dict):
        raise Invalid('设备清单格式错误')
    try:
        identity = str(uuid.UUID(str(data.get('hardware_uuid', ''))))
        boot = str(uuid.UUID(str(data.get('boot_id', ''))))
        if uuid.UUID(identity).int in (0, (1 << 128) - 1):
            raise ValueError()
    except ValueError as exc:
        raise Invalid('硬件 UUID 或本次启动 ID 无效') from exc
    disks = data.get('disks')
    if not isinstance(disks, list) or not 1 <= len(disks) <= 32:
        raise Invalid('必须能识别至少一块硬盘；缺少存储驱动时不能下发')
    clean, keys, numbers = [], set(), set()
    for d in disks:
        if not isinstance(d, dict):
            raise Invalid('硬盘清单格式错误')
        if any(d.get(k) is not None and not isinstance(d.get(k), str) for k in ('serial', 'unique_id', 'bus', 'model')):
            raise Invalid('硬盘身份字段必须是字符串')
        serial = str(d.get('serial') or '').strip()[:120]
        unique = str(d.get('unique_id') or '').strip()[:200]
        number = integer(d.get('number'), '硬盘编号', 0, 255)
        if number in numbers:
            raise Invalid('硬盘编号重复')
        numbers.add(number)
        size = integer(d.get('size_bytes'), '硬盘容量', 1, 2**63 - 1)
        key = digest(dict(serial=serial, unique_id=unique, size_bytes=size))
        if key in keys:
            raise Invalid('硬盘身份不唯一，不能安全选盘')
        keys.add(key)
        bus = str(d.get('bus') or 'Unknown')
        allowed = bus in SAFE_BUSES and bool(serial or unique) and size >= 64 * 1024**3
        allowed = allowed and d.get('read_only') is False and d.get('offline') is False
        clean.append(dict(key=key, number=number, serial=serial, unique_id=unique,
                          size_bytes=size, bus=bus, model=str(d.get('model') or '')[:120],
                          read_only=d.get('read_only') is not False,
                          offline=d.get('offline') is not False, eligible=allowed))
    macs = data.get('macs', [])
    if not isinstance(macs, list) or len(macs) > 8 or not all(isinstance(m, str) and re.fullmatch(r'[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}', m) for m in macs):
        raise Invalid('网卡 MAC 清单格式错误')
    return dict(hardware_uuid=identity, boot_id=boot, model=text(data.get('model', 'Unknown'), '机型'),
                serial=text(data.get('serial', 'Unknown'), '整机序列号'),
                firmware=data.get('firmware') if data.get('firmware') in ('UEFI', 'BIOS') else 'Unknown',
                architecture=data.get('architecture') if data.get('architecture') == 'amd64' else 'unsupported',
                ram_bytes=integer(data.get('ram_bytes'), '内存容量', 1, 2**63 - 1),
                secure_boot=data.get('secure_boot') is True, tpm2=data.get('tpm2') is True,
                macs=sorted(macs),
                disks=sorted(clean, key=lambda d: d['number']))


def target_check(device, disk_key, profile):
    if device['firmware'] != 'UEFI' or device['architecture'] != 'amd64':
        raise Invalid('首版只允许 UEFI x64 电脑；不会自动关闭 Secure Boot 或切换 BIOS 模式')
    if device['ram_bytes'] < 4 * 1024**3:
        raise Invalid('内存小于 4 GiB，停止下发')
    matches = [d for d in device['disks'] if d['key'] == disk_key]
    if len(matches) != 1 or not matches[0]['eligible']:
        raise Invalid('目标盘无效：外置盘、未知总线、只读盘或身份不明确的盘禁止下发')
    disk = matches[0]
    available = disk['size_bytes'] // 1024**2 - 260 - 16 - 1100 - 32
    if available < 60 * 1024 or (profile['system_gib'] and available < profile['system_gib'] * 1024 + 1024):
        raise Invalid('目标盘容量不足以创建所选分区方案')
    return disk


def node(parent, tag, value=None, **attrs):
    e = ET.SubElement(parent, f'{{{NAMESPACE}}}{tag}', attrs)
    if value is not None:
        e.text = str(value)
    return e


def component(settings, name):
    return node(settings, 'component', name=name, processorArchitecture='amd64',
                publicKeyToken='31bf3856ad364e35', language='neutral', versionScope='nonSxS')


def finalizer_command(config):
    script = (Path(__file__).parent / 'agent' / 'Finalize.ps1').read_text(encoding='utf-8-sig')
    script_b64 = base64.b64encode(script.encode()).decode()
    config_b64 = base64.b64encode(canonical(config).encode()).decode()
    # Only constant code and base64-encoded JSON enter the command, never user shell syntax.
    bootstrap = f"""$ErrorActionPreference='Stop'
$p=Join-Path $env:ProgramData 'PCDeploy\\{config['job_id']}'
New-Item -ItemType Directory -Path $p -Force | Out-Null
& icacls.exe $p /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){{throw 'Cannot protect finalizer directory'}}
[IO.File]::WriteAllBytes((Join-Path $p 'Finalize.ps1'),[Convert]::FromBase64String('{script_b64}'))
[IO.File]::WriteAllBytes((Join-Path $p 'config.json'),[Convert]::FromBase64String('{config_b64}'))
$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$p+'\\Finalize.ps1"')
$t=New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'PCDeploy-{config['job_id']}' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'PCDeploy-{config['job_id']}'
"""
    command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + base64.b64encode(bootstrap.encode('utf-16le')).decode()
    if len(command) > 30000:
        raise Invalid('安装回报配置过大，不能安全写入应答文件')
    return command


def answer_file(device, disk, profile, source, password, finalizer, product_key=None):
    target_check(device, disk['key'], profile)
    root = ET.Element(f'{{{NAMESPACE}}}unattend')
    pe = node(root, 'settings', **{'pass': 'windowsPE'})
    language = next(i['language'] for i in source['images'] if i['index'] == profile['image_index'])
    international = component(pe, 'Microsoft-Windows-International-Core-WinPE')
    node(node(international, 'SetupUILanguage'), 'UILanguage', language)
    for k in ('InputLocale', 'SystemLocale', 'UILanguage', 'UserLocale'):
        node(international, k, language)
    setup = component(pe, 'Microsoft-Windows-Setup')
    userdata = node(setup, 'UserData')
    node(userdata, 'AcceptEula', 'true')
    key = node(userdata, 'ProductKey')
    if product_key:
        node(key, 'Key', product_key)
    node(key, 'WillShowUI', 'Never')
    config = node(setup, 'DiskConfiguration')
    target = node(config, 'Disk', **{f'{{{WCM}}}action': 'add'})
    node(target, 'DiskID', disk['number'])
    node(target, 'WillWipeDisk', 'true')
    creates, modifies = node(target, 'CreatePartitions'), node(target, 'ModifyPartitions')
    available = disk['size_bytes'] // 1024**2 - 260 - 16 - 1100 - 32
    windows_size = profile['system_gib'] * 1024 if profile['system_gib'] else available
    partitions = [('EFI', 260, 'FAT32', 'System', None), ('MSR', 16, None, None, None),
                  ('Primary', windows_size, 'NTFS', 'Windows', 'C'),
                  ('Primary', 1100, 'NTFS', 'Recovery', None)]
    if profile['system_gib']:
        partitions.append(('Primary', None, 'NTFS', 'Data', 'D'))
    for i, (kind, size, fmt, label, letter) in enumerate(partitions, 1):
        create = node(creates, 'CreatePartition', **{f'{{{WCM}}}action': 'add'})
        node(create, 'Order', i)
        node(create, 'Type', kind)
        node(create, 'Size' if size else 'Extend', size if size else 'true')
        if fmt:
            modify = node(modifies, 'ModifyPartition', **{f'{{{WCM}}}action': 'add'})
            node(modify, 'Order', i)
            node(modify, 'PartitionID', i)
            node(modify, 'Format', fmt)
            node(modify, 'Label', label)
            if letter:
                node(modify, 'Letter', letter)
            if label == 'Recovery':
                node(modify, 'TypeID', 'de94bba4-06d1-4d40-a16a-bfd50179d6ac')
    node(config, 'WillShowUI', 'OnError')
    osimage = node(node(setup, 'ImageInstall'), 'OSImage')
    install_from = node(osimage, 'InstallFrom')
    node(install_from, 'Path', source['path'] + '\\' + source['image_file'])
    metadata = node(install_from, 'MetaData', **{f'{{{WCM}}}action': 'add'})
    node(metadata, 'Key', '/IMAGE/INDEX')
    node(metadata, 'Value', profile['image_index'])
    install_to = node(osimage, 'InstallTo')
    node(install_to, 'DiskID', disk['number'])
    node(install_to, 'PartitionID', 3)
    node(osimage, 'WillShowUI', 'OnError')
    special = node(root, 'settings', **{'pass': 'specialize'})
    shell = component(special, 'Microsoft-Windows-Shell-Setup')
    node(shell, 'ComputerName', profile['computer_prefix'] + '-' + digest(device['hardware_uuid'])[:8].upper())
    node(shell, 'TimeZone', 'China Standard Time')
    run = node(component(special, 'Microsoft-Windows-Deployment'), 'RunSynchronous')
    cmd = node(run, 'RunSynchronousCommand', **{f'{{{WCM}}}action': 'add'})
    node(cmd, 'Order', 1)
    node(cmd, 'Path', finalizer_command(finalizer))
    node(cmd, 'Description', 'Register one-time deployment completion report')
    oobe = node(root, 'settings', **{'pass': 'oobeSystem'})
    lang = component(oobe, 'Microsoft-Windows-International-Core')
    for k in ('InputLocale', 'SystemLocale', 'UILanguage', 'UserLocale'):
        node(lang, k, language)
    shell = component(oobe, 'Microsoft-Windows-Shell-Setup')
    account = node(node(node(shell, 'UserAccounts'), 'LocalAccounts'), 'LocalAccount', **{f'{{{WCM}}}action': 'add'})
    node(account, 'Name', profile['username'])
    node(account, 'Group', 'Administrators')
    pw = node(account, 'Password')
    node(pw, 'Value', base64.b64encode((password + 'Password').encode('utf-16le')).decode())
    node(pw, 'PlainText', 'false')
    o = node(shell, 'OOBE')
    for k in ('HideEULAPage', 'HideOEMRegistrationScreen', 'HideOnlineAccountScreens', 'HideWirelessSetupInOOBE'):
        node(o, k, 'true')
    node(o, 'ProtectYourPC', 1)
    ET.indent(root)
    return ET.tostring(root, encoding='utf-8', xml_declaration=True).decode()
