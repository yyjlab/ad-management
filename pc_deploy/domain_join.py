"""Validation for optional post-install domain join. No directory writes happen here."""
import re
from ipaddress import ip_address

from .deployment import Invalid, text


def employee_id(value):
    value = text(value, '员工工号', maximum=14).upper()
    if not re.fullmatch(r'[A-Z0-9](?:[A-Z0-9-]{0,12}[A-Z0-9])?', value):
        raise Invalid('工号须为 1–14 位字母、数字或连字符，不能以连字符开头或结尾')
    return value


def computer_name(value):
    name = text(value, '电脑名', maximum=15).upper()
    if not re.fullmatch(r'[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?', name) or name.isdecimal():
        raise Invalid('电脑名须为 1–15 位字母、数字或连字符，不能全为数字')
    return name


def name_candidates(value):
    base = employee_id(value)
    # Purely numeric employee IDs stay unchanged; only their Windows name gains a letter.
    return ([] if base.isdecimal() else [base]) + [base + chr(letter) for letter in range(65, 91)]


def available_name(value, reserved):
    blocked = {name.upper() for name in reserved}
    for candidate in name_candidates(value):
        if candidate not in blocked:
            return candidate
    raise Invalid('该工号的电脑名及 A–Z 后缀均已占用，请人工核对；不会覆盖已有电脑')


def join_record(value):
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get('enabled'), bool):
        raise Invalid('请明确选择是否在安装后自动加域')
    if not value['enabled']:
        return None
    allow_http = value.get('allow_http', False)
    if not isinstance(allow_http, bool):
        raise Invalid('请明确选择是否允许内网 HTTP 加域')
    mode = value.get('mode', 'automatic')
    if mode not in ('automatic', 'manual'):
        raise Invalid('请选择安装后自动加域或平台统一加域')
    domain = text(value.get('domain'), 'AD 域 DNS 名称', maximum=253).lower()
    labels = domain.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in labels):
        raise Invalid('请填写完整 AD 域 DNS 名称，不能填写网页地址或 IP')
    try:
        ip_address(domain)
    except ValueError:
        pass
    else:
        raise Invalid('AD 域名不能填写 IP')
    user = text(value.get('username'), 'AD 加域账号', maximum=120)
    if not re.fullmatch(r'(?:[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+|[A-Za-z0-9._$-]+@[A-Za-z0-9.-]+)', user):
        raise Invalid('加域账号请填写 DOMAIN\\user 或 user@domain')
    ou = value.get('ou_path', '')
    if not isinstance(ou, str):
        raise Invalid('目标 OU 格式错误')
    ou = ou.strip()
    if ou:
        ou = text(ou, '目标 OU', maximum=500)
        suffix = ','.join('DC='+part for part in labels)
        if (not ou.lower().endswith(','+suffix.lower())
                or not re.fullmatch(r'(?:(?:OU|CN)=[^,\\+<>=;"]{1,64},)+(?:DC=[a-z0-9-]+,)*DC=[a-z0-9-]+', ou, re.I)):
            raise Invalid('目标 OU 必须属于所填域；此处支持普通 OU / CN 名称，不支持转义名称')
    result = dict(domain=domain, username=user, ou_path=ou)
    if allow_http:
        result['allow_http'] = True
    if mode == 'manual':
        result['mode'] = mode
    return result
