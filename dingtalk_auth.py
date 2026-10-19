"""DingTalk authorization and enterprise membership verification."""

import json
import os
from dataclasses import dataclass, field
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CALLBACK_PATH = '/api/admin/dingtalk/callback'
AUTHORIZE_URL = 'https://login.dingtalk.com/oauth2/auth'


class DingTalkError(Exception):
    pass


@dataclass(frozen=True)
class DingTalkConfig:
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    state_ttl: int
    timeout: int

    @classmethod
    def load(cls, config):
        def setting(name, default=''):
            return os.environ.get(name, config.get(name, default))

        if str(setting('DINGTALK_LOGIN_ENABLED', False)).lower() not in ('true', '1', 'yes'):
            return None
        try:
            client_id = str(setting('DINGTALK_LOGIN_CLIENT_ID') or '').strip()
            secret = str(setting('DINGTALK_LOGIN_CLIENT_SECRET') or '').strip()
            redirect_uri = str(setting('DINGTALK_LOGIN_REDIRECT_URI') or '').strip()
            uri = urlsplit(redirect_uri)
            ttl = int(setting('DINGTALK_LOGIN_STATE_TTL_SECONDS', 600))
            timeout = int(setting('DINGTALK_LOGIN_TIMEOUT_SECONDS', 10))
            if (not client_id or not secret or uri.scheme not in ('http', 'https')
                    or not uri.hostname or uri.username or uri.password or uri.query or uri.fragment
                    or uri.path != CALLBACK_PATH or '\\' in redirect_uri
                    or any(c.isspace() for c in redirect_uri) or not 60 <= ttl <= 1800
                    or not 1 <= timeout <= 30):
                raise ValueError()
            uri.port
            return cls(client_id, secret, redirect_uri, ttl, timeout)
        except (ValueError, TypeError):
            raise DingTalkError('configuration') from None

    def authorization_url(self, state, embedded=False):
        params = {
            'client_id': self.client_id, 'response_type': 'code', 'scope': 'openid',
            'prompt': 'consent', 'redirect_uri': self.redirect_uri, 'state': state
        }
        if embedded:
            params['iframe'] = 'true'
        return AUTHORIZE_URL + '?' + urlencode(params)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DingTalkClient:
    def __init__(self, config):
        self.config = config
        self.opener = build_opener(_NoRedirect())

    def _request(self, url, body=None, headers=None):
        request = Request(
            url, data=json.dumps(body).encode('utf-8') if body is not None else None,
            headers={'Accept': 'application/json', 'Content-Type': 'application/json', **(headers or {})}
        )
        try:
            with self.opener.open(request, timeout=self.config.timeout) as response:
                payload = response.read(65537)
            if len(payload) > 65536:
                raise ValueError()
            result = json.loads(payload)
            if not isinstance(result, dict):
                raise ValueError()
            return result
        except (URLError, OSError, ValueError):
            # Provider responses/exceptions can contain credentials; discard their details.
            raise DingTalkError('provider') from None

    @staticmethod
    def _text(data, key, max_length=4096):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > max_length:
            raise DingTalkError('provider')
        return value

    @staticmethod
    def _member_result(data):
        if type(data.get('errcode')) is not int or data['errcode'] != 0 or not isinstance(data.get('result'), dict):
            raise DingTalkError('membership')
        return data['result']

    def employee(self, code):
        token = self._request('https://api.dingtalk.com/v1.0/oauth2/userAccessToken', {
            'clientId': self.config.client_id, 'clientSecret': self.config.client_secret,
            'code': code, 'grantType': 'authorization_code'
        })
        user = self._request('https://api.dingtalk.com/v1.0/contact/users/me', headers={
            'x-acs-dingtalk-access-token': self._text(token, 'accessToken')
        })
        union_id = self._text(user, 'unionId', 256)
        app_token = self._request('https://api.dingtalk.com/v1.0/oauth2/accessToken', {
            'appKey': self.config.client_id, 'appSecret': self.config.client_secret
        })
        query = urlencode({'access_token': self._text(app_token, 'accessToken')})
        member = self._member_result(self._request(
            'https://oapi.dingtalk.com/topapi/user/getbyunionid?' + query, {'unionid': union_id}
        ))
        if type(member.get('contact_type')) is not int or member['contact_type'] != 0:
            raise DingTalkError('membership')
        user_id = self._text(member, 'userid', 256)
        detail = self._member_result(self._request(
            'https://oapi.dingtalk.com/topapi/v2/user/get?' + query,
            {'userid': user_id, 'language': 'zh_CN'}
        ))
        if (detail.get('userid') != user_id or detail.get('active') is not True
                or detail.get('unionid', union_id) != union_id):
            raise DingTalkError('membership')
        return union_id, self._text(detail, 'name', 80).strip()
