import importlib
import logging
import os
import sys
import types
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from dingtalk_auth import DingTalkClient, DingTalkConfig, DingTalkError


class DingTalkLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = types.ModuleType('config')
        config.Config = type('Config', (), {
            'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite://',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False, 'RATELIMIT_ENABLED': False
        })
        with patch.dict(sys.modules, {'config': config}), patch.dict(os.environ, {
            'FLASK_SECRET_KEY': 'isolated-test-session-key', 'DISABLE_INTERNAL_PASSWORD_SCHEDULER': 'true'
        }), patch('logging.FileHandler', return_value=logging.NullHandler()):
            cls.platform = importlib.import_module('app')
        sys.modules['app'] = cls.platform

    def setUp(self):
        self.env = patch.dict(os.environ, {
            'DINGTALK_LOGIN_ENABLED': 'true', 'DINGTALK_LOGIN_CLIENT_ID': 'test-client',
            'DINGTALK_LOGIN_CLIENT_SECRET': 'test-secret',
            'DINGTALK_LOGIN_REDIRECT_URI': 'http://ad.wfq.test/api/admin/dingtalk/callback',
            'DINGTALK_LOGIN_STATE_TTL_SECONDS': '600', 'DINGTALK_LOGIN_TIMEOUT_SECONDS': '10'
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.context = self.platform.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.platform.db.drop_all()
        self.platform.db.create_all()
        self.addCleanup(self.platform.db.session.remove)
        self.client = self.platform.app.test_client()
        self.provider = patch.object(self.platform.DingTalkClient, 'employee', return_value=('union-1', '张三'))
        self.employee = self.provider.start()
        self.addCleanup(self.provider.stop)
        self.ldap_patch = patch.object(self.platform, 'get_ad_connection', side_effect=AssertionError('must not contact AD'))
        self.ldap = self.ldap_patch.start()
        self.addCleanup(self.ldap_patch.stop)

    def begin(self, client=None):
        response = (client or self.client).get('/api/admin/dingtalk/login')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn('test-secret', response.location)
        url = urlsplit(response.location)
        self.assertEqual(url.netloc, 'login.dingtalk.com')
        params = parse_qs(url.query)
        self.assertNotIn('iframe', params)
        self.assertEqual(params['redirect_uri'], ['http://ad.wfq.test/api/admin/dingtalk/callback'])
        return params['state'][0]

    def callback(self, state, client=None, **kwargs):
        return (client or self.client).get('/api/admin/dingtalk/callback', query_string={
            'state': state, 'authCode': 'test-code', **kwargs
        })

    def test_status_and_disabled_configuration_expose_no_credentials(self):
        self.assertEqual(self.client.get('/api/admin/dingtalk/status').json, {'enabled': True})
        os.environ['DINGTALK_LOGIN_ENABLED'] = 'false'
        self.assertEqual(self.client.get('/api/admin/dingtalk/status').json, {'enabled': False})
        self.assertIn('dingtalkError=disabled', self.client.get('/api/admin/dingtalk/login').location)
        self.assertEqual(self.platform.DingTalkLoginState.query.count(), 0)

    def test_first_login_creates_only_readonly_platform_user_with_audit(self):
        self.assertEqual(self.callback(self.begin()).location, '/admin/manage')
        user = self.platform.AdminUser.query.one()
        self.assertEqual(user.role, 'readonly')
        self.assertEqual(user.permissions, '')
        self.assertTrue(user.username.startswith('dt_'))
        check = self.client.get('/api/admin/check').json
        self.assertTrue(check['logged_in'])
        self.assertEqual(check['display_name'], '张三')
        self.assertEqual(check['permissions'], ['view_user', 'view_dashboard'])
        self.assertEqual(self.platform.AdminLoginLog.query.one().message, '钉钉登录成功')
        self.assertTrue(self.platform.AdminSessionAudit.query.one().is_online)
        self.assertEqual(self.platform.DingTalkLoginState.query.count(), 0)
        self.ldap.assert_not_called()

    def test_state_cannot_be_replayed_even_with_old_signed_cookie(self):
        state = self.begin()
        cookie_name = self.platform.app.config['SESSION_COOKIE_NAME']
        old_cookie = self.client.get_cookie(cookie_name).value
        self.callback(state)
        self.client.set_cookie(cookie_name, old_cookie)
        self.assertIn('dingtalkError=state', self.callback(state).location)
        self.employee.assert_called_once()

    def test_another_browser_cannot_consume_state(self):
        state = self.begin()
        other = self.platform.app.test_client()
        self.assertIn('dingtalkError=state', self.callback(state, client=other).location)
        self.employee.assert_not_called()
        self.assertEqual(self.callback(state).location, '/admin/manage')

    def test_expired_or_refreshed_state_never_contacts_provider(self):
        old = self.begin()
        fresh = self.begin()
        self.assertNotEqual(old, fresh)
        self.assertIsNone(self.platform.db.session.get(self.platform.DingTalkLoginState, self.platform.dingtalk_digest(old)))
        record = self.platform.DingTalkLoginState.query.one()
        record.expires_at = datetime.utcnow() - timedelta(seconds=1)
        self.platform.db.session.commit()
        self.assertIn('dingtalkError=state', self.callback(fresh).location)
        self.employee.assert_not_called()

    def test_callback_accepts_code_aliases_and_prefers_auth_code(self):
        cases = (
            ([('authCode', 'auth-code')], 'auth-code'),
            ([('code', 'legacy-code')], 'legacy-code'),
            ([('code', 'same-code'), ('authCode', 'same-code')], 'same-code'),
            ([('code', 'other-code'), ('authCode', 'auth-code')], 'auth-code'),
        )
        for params, expected in cases:
            with self.subTest(params=params):
                self.employee.reset_mock()
                response = self.client.get('/api/admin/dingtalk/callback', query_string=[
                    ('state', self.begin()), *params
                ])
                self.assertEqual(response.location, '/admin/manage')
                self.employee.assert_called_once_with(expected)
        self.ldap.assert_not_called()

    def test_duplicate_code_parameters_and_authorization_denial_are_rejected(self):
        cases = (
            [],
            [('authCode', 'one'), ('authCode', 'two')],
            [('code', 'one'), ('code', 'two')],
            [('authCode', 'valid'), ('code', 'same'), ('code', 'same')],
            [('authCode', 'same'), ('authCode', 'same'), ('code', 'valid')],
            [('authCode', ''), ('code', 'valid')],
            [('authCode', ' '), ('code', 'valid')],
            [('authCode', 'x' * 2049), ('code', 'valid')],
            [('code', '')],
            [('code', ' ')],
            [('code', 'x' * 2049)],
            [('authCode', 'valid'), ('code', 'other'), ('error', 'access_denied')],
        )
        for params in cases:
            with self.subTest(params=params):
                response = self.client.get('/api/admin/dingtalk/callback', query_string=[
                    ('state', self.begin()), *params
                ])
                self.assertIn('dingtalkError=authorization', response.location)
        self.employee.assert_not_called()
        self.assertEqual(self.platform.AdminUser.query.count(), 0)

    def test_dual_alias_callback_still_requires_single_use_state(self):
        state = self.begin()
        cookie_name = self.platform.app.config['SESSION_COOKIE_NAME']
        old_cookie = self.client.get_cookie(cookie_name).value
        self.assertIn('dingtalkError=state', self.client.get('/api/admin/dingtalk/callback', query_string=[
            ('state', state), ('state', state), ('authCode', 'test-code'), ('code', 'other-code')
        ]).location)
        self.employee.assert_not_called()
        self.client.set_cookie(cookie_name, old_cookie)
        self.assertEqual(self.callback(state, code='other-code').location, '/admin/manage')
        self.client.set_cookie(cookie_name, old_cookie)
        self.assertIn('dingtalkError=state', self.callback(state, code='other-code').location)
        self.employee.assert_called_once_with('test-code')

    def test_member_failure_never_creates_account(self):
        self.employee.side_effect = DingTalkError('membership')
        self.assertIn('dingtalkError=membership', self.callback(self.begin()).location)
        self.assertEqual(self.platform.AdminUser.query.count(), 0)
        self.assertFalse(self.client.get('/api/admin/check').json['logged_in'])
        self.assertFalse(self.platform.AdminLoginLog.query.one().success)

    def test_deleting_platform_user_removes_binding_without_touching_ad(self):
        self.callback(self.begin())
        self.platform.db.session.delete(self.platform.AdminUser.query.one())
        self.platform.db.session.commit()
        self.assertEqual(self.platform.DingTalkAccount.query.count(), 0)
        self.client.post('/api/admin/logout')
        self.assertEqual(self.callback(self.begin()).location, '/admin/manage')
        self.assertEqual(self.platform.AdminUser.query.one().role, 'readonly')
        self.ldap.assert_not_called()

    def test_same_name_is_not_merged_and_repeat_login_keeps_existing_role(self):
        existing = self.platform.AdminUser(username='张三', password_hash='unused', role='super_admin')
        self.platform.db.session.add(existing)
        self.platform.db.session.commit()
        self.callback(self.begin())
        binding = self.platform.DingTalkAccount.query.one()
        self.assertNotEqual(binding.admin_user_id, existing.id)
        binding.admin_user.role = 'admin'
        self.platform.db.session.commit()
        self.client.post('/api/admin/logout')
        self.callback(self.begin())
        self.assertEqual(self.client.get('/api/admin/check').json['role'], 'admin')
        self.assertEqual(self.platform.AdminUser.query.count(), 2)
        self.assertEqual(self.employee.call_count, 2)

    def test_disabled_account_cannot_login_or_be_recreated(self):
        self.callback(self.begin())
        user = self.platform.AdminUser.query.one()
        user.is_active = False
        self.platform.db.session.commit()
        self.client.post('/api/admin/logout')
        self.assertIn('dingtalkError=account', self.callback(self.begin()).location)
        self.assertFalse(self.client.get('/api/admin/check').json['logged_in'])
        self.assertEqual(self.platform.AdminUser.query.count(), 1)

    def test_local_password_login_and_logout_still_work(self):
        user = self.platform.AdminUser(username='local-admin', role='super_admin',
            password_hash=self.platform.generate_password_hash('local-test-password'))
        self.platform.db.session.add(user)
        self.platform.db.session.commit()
        self.assertFalse(self.client.post('/api/admin/login', json={'username': user.username, 'password': 'wrong'}).json['success'])
        self.assertTrue(self.client.post('/api/admin/login', json={'username': user.username, 'password': 'local-test-password'}).json['success'])
        self.assertEqual(self.client.get('/api/admin/check').json['role'], 'super_admin')
        users = self.client.get('/api/admin/users').json
        self.assertTrue(users['success'])
        self.assertIsNone(users['admins'][0]['display_name'])
        self.client.post('/api/admin/logout')
        self.assertFalse(self.client.get('/api/admin/check').json['logged_in'])

    def test_qr_requires_same_origin_header_and_does_not_create_user(self):
        self.assertEqual(self.client.post('/api/admin/dingtalk/qr').status_code, 400)
        self.assertEqual(self.client.post('/api/admin/dingtalk/qr', headers={
            'X-Requested-With': 'XMLHttpRequest', 'Origin': 'https://wrong.test'
        }).status_code, 400)
        response = self.client.post('/api/admin/dingtalk/qr', headers={
            'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://ad.wfq.test'
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(parse_qs(urlsplit(response.json['authorizationUrl']).query)['iframe'], ['true'])
        self.assertEqual(self.platform.AdminUser.query.count(), 0)
        self.employee.assert_not_called()


class DingTalkProviderTests(unittest.TestCase):
    def setUp(self):
        self.config = DingTalkConfig('client', 'secret', 'https://ad.test/api/admin/dingtalk/callback', 600, 10)

    def test_configuration_rejects_bad_callback_and_secret_is_not_printed(self):
        self.assertNotIn('secret', repr(self.config))
        with patch.dict(os.environ, {'DINGTALK_LOGIN_ENABLED': 'true', 'DINGTALK_LOGIN_CLIENT_ID': 'client',
                'DINGTALK_LOGIN_CLIENT_SECRET': 'secret', 'DINGTALK_LOGIN_REDIRECT_URI': 'https://ad.test/other'}):
            with self.assertRaises(DingTalkError):
                DingTalkConfig.load({})

    def responses(self):
        return [{'accessToken': 'user-token'}, {'unionId': 'union'}, {'accessToken': 'enterprise-token'},
            {'errcode': 0, 'result': {'userid': 'employee', 'contact_type': 0}},
            {'errcode': 0, 'result': {'userid': 'employee', 'unionid': 'union', 'active': True, 'name': '张三'}}]

    def test_employee_uses_user_identity_and_enterprise_membership(self):
        client = DingTalkClient(self.config)
        with patch.object(client, '_request', side_effect=self.responses()) as request:
            self.assertEqual(client.employee('code'), ('union', '张三'))
            self.assertEqual(request.call_args_list[0].args[1]['grantType'], 'authorization_code')
            self.assertEqual(request.call_args_list[1].kwargs['headers']['x-acs-dingtalk-access-token'], 'user-token')
            self.assertIn('enterprise-token', request.call_args_list[3].args[0])

    def test_external_or_inactive_members_are_rejected(self):
        for kind in ('external', 'inactive'):
            responses = self.responses()
            if kind == 'external':
                responses[3]['result']['contact_type'] = 1
            else:
                responses[4]['result']['active'] = False
            client = DingTalkClient(self.config)
            with self.subTest(kind=kind), patch.object(client, '_request', side_effect=responses):
                with self.assertRaisesRegex(DingTalkError, 'membership'):
                    client.employee('code')

    def test_provider_errors_do_not_expose_tokens_or_secret(self):
        client = DingTalkClient(self.config)
        with patch.object(client.opener, 'open', side_effect=OSError('secret token provider details')):
            with self.assertRaisesRegex(DingTalkError, '^provider$'):
                client.employee('code')


if __name__ == '__main__':
    unittest.main()
