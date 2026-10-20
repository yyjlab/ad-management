import importlib
import logging
import os
import sys
import types
import unittest
from unittest.mock import patch

import ldap3
from ldap3.core.exceptions import LDAPAttributeError


class DomainPasswordPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = types.ModuleType('config')
        config.Config = type('Config', (), {
            'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite://',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False, 'RATELIMIT_ENABLED': False
        })
        with patch.dict(sys.modules, {'config': config}), patch.dict(os.environ, {
            'FLASK_SECRET_KEY': 'isolated-test-session-key',
            'DISABLE_INTERNAL_PASSWORD_SCHEDULER': 'true'
        }), patch('logging.FileHandler', return_value=logging.NullHandler()):
            cls.platform = importlib.import_module('app')
        sys.modules['app'] = cls.platform

    def setUp(self):
        self.context = self.platform.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.platform.db.drop_all()
        self.platform.db.create_all()
        self.addCleanup(self.platform.db.session.remove)
        self.user = self.platform.AdminUser(
            username='policy-reader', password_hash='unused', role='super_admin'
        )
        self.platform.db.session.add(self.user)
        self.platform.db.session.commit()
        self.client = self.platform.app.test_client()
        with self.client.session_transaction() as session:
            session['admin_logged_in'] = True
            session['admin_username'] = self.user.username
            session['admin_role'] = self.user.role

        server = ldap3.Server('ad.test', get_info=ldap3.OFFLINE_AD_2012_R2)
        self.conn = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC, read_only=True)
        self.domain_dn = server.info.other['defaultNamingContext'][0]
        self.attributes = {
            'objectClass': ['top', 'domain', 'domainDNS'],
            'minPwdLength': 8, 'minPwdAge': -864000000000,
            'maxPwdAge': -155520000000000, 'pwdHistoryLength': 12,
            'pwdProperties': 17
        }
        self.conn.strategy.add_entry(self.domain_dn, self.attributes)
        self.conn.bind()
        self.connection_patch = patch.object(self.platform, 'get_ad_connection', return_value=self.conn)
        self.get_connection = self.connection_patch.start()
        self.addCleanup(self.connection_patch.stop)
        self.search_patch = patch.object(self.conn, 'search', wraps=self.conn.search)
        self.search = self.search_patch.start()
        self.addCleanup(self.search_patch.stop)
        self.unbind_patch = patch.object(self.conn, 'unbind', wraps=self.conn.unbind)
        self.unbind = self.unbind_patch.start()
        self.addCleanup(self.unbind_patch.stop)

    def get_policy(self):
        return self.client.get('/api/admin/domain_password_policy')

    def replace_attributes(self, validate=True, **values):
        self.attributes.update(values)
        del self.conn.strategy.entries[self.domain_dn]
        self.conn.strategy.add_entry(self.domain_dn, self.attributes, validate=validate)

    def test_ad_schema_reproduces_original_rootdse_error(self):
        with self.assertRaisesRegex(LDAPAttributeError, 'invalid attribute type defaultNamingContext'):
            self.conn.search('', '(objectClass=*)', ldap3.BASE, attributes=['defaultNamingContext'])

    def test_reads_cached_domain_and_real_raw_policy_values(self):
        response = self.get_policy()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'success': True, 'policy': {
            'min_password_length': 8, 'min_age_seconds': 86400,
            'max_age_seconds': 180 * 86400, 'max_age_never_expires': False,
            'password_history_count': 12, 'complexity_enabled': True,
            'reversible_encryption_enabled': True
        }})
        self.search.assert_called_once_with(
            search_base=self.domain_dn, search_filter='(objectClass=domainDNS)',
            search_scope=ldap3.BASE,
            attributes=['minPwdLength', 'minPwdAge', 'maxPwdAge', 'pwdHistoryLength', 'pwdProperties']
        )
        self.assertTrue(self.conn.check_names)
        self.assertTrue(self.conn.read_only)
        self.unbind.assert_called_once()

    def test_zero_values_are_preserved(self):
        self.replace_attributes(minPwdAge=0, pwdHistoryLength=0, pwdProperties=0)
        response = self.get_policy()
        self.assertEqual(response.status_code, 200)
        policy = response.json['policy']
        self.assertEqual(policy['min_age_seconds'], 0)
        self.assertEqual(policy['password_history_count'], 0)
        self.assertFalse(policy['complexity_enabled'])
        self.assertFalse(policy['reversible_encryption_enabled'])

    def test_never_expiring_max_age(self):
        # AD's never-expire sentinel exceeds the mock timedelta validator.
        self.replace_attributes(validate=False, maxPwdAge=-(2 ** 63))
        response = self.get_policy()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['policy']['max_age_never_expires'])
        self.assertIsNone(response.json['policy']['max_age_seconds'])

    def test_missing_server_info_or_domain_does_not_search_empty_base(self):
        for info in (None, types.SimpleNamespace(other={})):
            with self.subTest(info=info), patch.object(self.conn.server, '_dsa_info', info):
                response = self.get_policy()
                self.assertEqual(response.status_code, 503)
                self.assertFalse(response.json['success'])
        self.search.assert_not_called()
        self.assertEqual(self.unbind.call_count, 2)

    def test_missing_policy_values_fail_and_close_connection(self):
        self.replace_attributes(minPwdAge=[])
        response = self.get_policy()
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json['success'])
        self.unbind.assert_called_once()

    def test_missing_domain_entry_fails_and_closes_connection(self):
        del self.conn.strategy.entries[self.domain_dn]
        response = self.get_policy()
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json['success'])
        self.unbind.assert_called_once()

    def test_unauthenticated_or_readonly_user_cannot_query_ad(self):
        self.user.role = 'readonly'
        self.platform.db.session.commit()
        self.assertFalse(self.get_policy().json['success'])
        with self.client.session_transaction() as session:
            session.clear()
        self.assertFalse(self.get_policy().json['success'])
        self.get_connection.assert_not_called()


if __name__ == '__main__':
    unittest.main()
