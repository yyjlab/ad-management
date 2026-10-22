import json
import os
import time
import unittest
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import ldap3
from ldap3.core.exceptions import LDAPException
from sqlalchemy.exc import OperationalError

from ad_precreate import (DirectoryAccount, PrecreateDirectory, PrecreateError,
                         account_ids, build_user_attributes, validate_spec)
import test_domain_password_policy as domain_tests


PASSWORD = 'IsolatedTestPassword1!'
OU = 'OU=用户,DC=wfq,DC=com'


class PrecreateHelpersTests(unittest.TestCase):
    def test_editable_prefix_and_two_digit_suffix(self):
        spec = validate_spec({'prefix': ' WFQ2612 ', 'start': 0, 'end': 99})
        self.assertEqual(spec['prefix'], 'wfq2612')
        self.assertEqual((account_ids(spec)[0], account_ids(spec)[-1], len(account_ids(spec))),
                         ('wfq261200', 'wfq261299', 100))
        self.assertEqual(account_ids({**spec, 'prefix': 'wfq2701', 'start': 9, 'end': 10}),
                         ['wfq270109', 'wfq270110'])

    def test_monthly_ranges_and_defaults(self):
        spec = validate_spec({'year': 2026, 'month': 11, 'start': 0, 'end': 99})
        ids = account_ids(spec)
        self.assertEqual((ids[0], ids[-1], len(ids)), ('wfq261100', 'wfq261199', 100))
        self.assertFalse(spec['enabled'])
        self.assertEqual(spec['full_name'], '预建待分配')
        self.assertEqual(account_ids({**spec, 'month': 12})[-1], 'wfq261299')
        self.assertEqual(account_ids({**spec, 'year': 2027, 'month': 1})[0], 'wfq270100')

    def test_attribute_mapping_preserves_single_create_defaults(self):
        attrs = build_user_attributes('wfq261100', 'a@example.test', PASSWORD, '张三', 'IT',
                                      manager_name='李四', job_title='运维', note='test')
        self.assertEqual(attrs['cn'], 'wfq261100')
        self.assertEqual(attrs['displayName'], 'wfq261100')
        self.assertEqual(attrs['description'], '张三')
        self.assertEqual(attrs['unicodePwd'], ('"' + PASSWORD + '"').encode('utf-16-le'))
        self.assertEqual(attrs['userAccountControl'], '512')
        self.assertEqual(attrs['info'], '直属领导：李四；备注：test')
        self.assertNotIn('pwdLastSet', attrs)
        self.assertNotIn(PASSWORD, attrs['info'])
        self.assertEqual(build_user_attributes('wfq261101', '', PASSWORD, '张三', '', enabled=False)['userAccountControl'], '514')

    def test_directory_timeouts_and_errors_do_not_expose_secrets(self):
        config = {'AD_SERVER': 'dc.test', 'AD_BIND_USER': 'bind', 'AD_BIND_PASSWORD': PASSWORD, 'AD_USER_OU': OU}
        connection = MagicMock()
        with patch('ad_precreate.ldap3.Server') as server, patch('ad_precreate.ldap3.Connection', return_value=connection) as factory:
            with PrecreateDirectory(config) as directory:
                connection.add.side_effect = LDAPException(PASSWORD)
                with self.assertRaises(PrecreateError) as caught:
                    directory.create('wfq261100', PASSWORD, '张三', False, 'marker')
                self.assertNotIn(PASSWORD, str(caught.exception))
                self.assertEqual(factory.call_args.kwargs['receive_timeout'], 10)
                self.assertEqual(server.call_args.kwargs['connect_timeout'], 8)
            connection.unbind.assert_called_once()

    def test_real_ldap_entry_lookup_and_failed_search(self):
        server = ldap3.Server('dc.test', get_info=ldap3.OFFLINE_AD_2012_R2)
        conn = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC)
        dn = 'CN=wfq261100,' + OU
        guid = uuid.uuid4()
        conn.strategy.add_entry(dn, {'objectClass': ['user'], 'sAMAccountName': 'wfq261100',
            'info': '备注：marker', 'userAccountControl': 514, 'objectGUID': guid.bytes_le})
        conn.bind()
        directory = PrecreateDirectory({'AD_BASE_DN': 'DC=wfq,DC=com'}, OU)
        directory.connection = conn
        account = directory.lookup(['wfq261100'])['wfq261100']
        self.assertFalse(account.enabled)
        self.assertIn(str(guid), account.guid)
        self.assertEqual(account.info, '备注：marker')
        with patch.object(conn, 'search', side_effect=LDAPException(PASSWORD)):
            with self.assertRaises(PrecreateError) as caught:
                directory.lookup(['wfq261100'])
            self.assertNotIn(PASSWORD, str(caught.exception))
        conn.unbind()


class PrecreateApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        domain_tests.DomainPasswordPolicyTests.setUpClass.__func__(cls)

    def setUp(self):
        self.context = self.platform.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.platform.db.drop_all()
        self.platform.db.create_all()
        self.addCleanup(self.platform.db.session.remove)
        self.user = self.platform.AdminUser(username='precreate-admin', password_hash='unused', role='super_admin')
        self.platform.db.session.add(self.user)
        self.platform.db.session.commit()
        self.env = patch.dict(os.environ, {'AD_PRECREATE_DEFAULT_PASSWORD': PASSWORD})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.config = patch.dict(self.platform.app.config, {'AD_USER_OU': OU, 'AD_BASE_DN': 'DC=wfq,DC=com'})
        self.config.start()
        self.addCleanup(self.config.stop)
        self.client = self.platform.app.test_client()
        with self.client.session_transaction() as session:
            session['admin_logged_in'] = True
            session['admin_username'] = self.user.username
            session['admin_role'] = 'super_admin'
        response = self.client.get('/api/admin/ad-precreate/config')
        self.headers = {'X-CSRF-Token': response.json['csrf_token']}
        self.records = {}
        self.directory = MagicMock()
        self.directory.__enter__.return_value = self.directory
        self.directory.lookup.side_effect = lambda ids: {value: self.records[value] for value in ids if value in self.records}
        self.directory.create.side_effect = self.create_record
        self.directory_patch = patch.object(self.platform, 'PrecreateDirectory', return_value=self.directory)
        self.directory_factory = self.directory_patch.start()
        self.addCleanup(self.directory_patch.stop)
        self.spec = {'year': 2026, 'month': 11, 'start': 0, 'end': 2, 'full_name': '预建待分配', 'enabled': False}
        self.custom_spec = {'prefix': 'wfq2612', 'start': 0, 'end': 2, 'full_name': '预建待分配', 'enabled': False}

    def create_record(self, account, password, name, enabled, marker):
        self.records[account] = DirectoryAccount(account, 'CN=' + account + ',' + OU,
            str(uuid.uuid4()), '备注：' + marker, enabled)
        return True

    def post(self, path, data=None):
        return self.client.post('/api/admin/ad-precreate/' + path, json=data or {}, headers=self.headers)

    def begin(self, spec=None, request_key=None, password=None):
        secret = {'password': password} if password is not None else {}
        preview = self.post('preview', {**(spec or self.spec), **secret})
        self.assertEqual(preview.status_code, 200, preview.json)
        payload = {'preview_token': preview.json['preview_token'], 'request_key': request_key or str(uuid.uuid4()),
                   'confirm_text': 'YES', 'confirm_enabled': (spec or self.spec)['enabled'], **secret}
        result = self.post('batches', payload)
        self.assertEqual(result.status_code, 200, result.json)
        return result.json['batch'], payload

    def step(self, batch, password=None):
        response = self.post('batches/' + batch['id'] + '/step', {'password': password} if password is not None else {})
        self.assertEqual(response.status_code, 200, response.json)
        return response.json['batch']

    def test_configuration_and_history_do_not_expose_password(self):
        response = self.client.get('/api/admin/ad-precreate/config')
        self.assertTrue(response.json['password_ready'])
        self.assertEqual(response.json['ou'], OU)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn(PASSWORD, response.get_data(as_text=True))
        response = self.post('password')
        self.assertEqual(response.json['password'], PASSWORD)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn(PASSWORD, self.platform.AdminActionLog.query.one().message)

    def test_new_tables_can_be_added_without_changing_existing_data(self):
        self.platform.db.session.add(self.platform.AdminActionLog(admin_username='old', action='old', message='preserved'))
        self.platform.db.session.commit()
        self.platform.AdPrecreateItem.__table__.drop(self.platform.db.engine)
        self.platform.AdPrecreateBatch.__table__.drop(self.platform.db.engine)
        self.platform.ensure_database_tables()
        self.assertEqual(self.platform.AdminUser.query.one().username, 'precreate-admin')
        self.assertEqual(self.platform.AdminActionLog.query.one().message, 'preserved')
        self.assertEqual(self.platform.AdPrecreateBatch.query.count(), 0)
        self.assertEqual(self.platform.AdPrecreateItem.query.count(), 0)

    def test_authentication_and_actual_role_are_required_for_every_endpoint(self):
        paths = ['config', 'batches', 'batches/missing']
        posts = ['password', 'preview', 'batches', 'batches/missing/step', 'batches/missing/retry']
        for role in ('readonly', 'admin'):
            self.user.role = role
            self.platform.db.session.commit()
            for path in paths:
                self.assertEqual(self.client.get('/api/admin/ad-precreate/' + path).status_code, 403)
            for path in posts:
                self.assertEqual(self.post(path).status_code, 403)
        other = self.platform.app.test_client()
        self.assertEqual(other.get('/api/admin/ad-precreate/config').status_code, 401)
        self.directory_factory.assert_not_called()

    def test_mutations_require_csrf(self):
        for path in ('password', 'preview', 'batches', 'batches/missing/step', 'batches/missing/retry'):
            response = self.client.post('/api/admin/ad-precreate/' + path, json=self.spec)
            self.assertEqual(response.status_code, 403)
        self.directory_factory.assert_not_called()

    def test_missing_password_disables_creation_and_reveal(self):
        os.environ['AD_PRECREATE_DEFAULT_PASSWORD'] = ''
        self.assertFalse(self.client.get('/api/admin/ad-precreate/config').json['password_ready'])
        self.assertEqual(self.post('preview', self.spec).status_code, 503)
        self.assertEqual(self.post('password').status_code, 503)
        self.directory_factory.assert_not_called()

    def test_invalid_or_extra_fields_are_rejected_before_ad_access(self):
        for changes in ({'year': True}, {'year': 2100}, {'year': '2026'}, {'month': 13}, {'start': -1},
                        {'end': 100}, {'start': 2, 'end': 1}, {'full_name': ''}, {'full_name': 'x\n'}, {'full_name': '<img src=x>'},
                        {'enabled': 'false'}, {'ou': 'OU=Administrators'},
                        {'must_change_next_login': False}):
            with self.subTest(changes=changes):
                self.assertEqual(self.post('preview', {**self.spec, **changes}).status_code, 400)
        self.directory_factory.assert_not_called()

    def test_invalid_prefixes_and_passwords_are_rejected_before_ad_access(self):
        for prefix in ('', 'wfq261100', 'wfq26', 'other26', 'wfq26*1', 'wfq２６１１', 'wfq2611,OU=x'):
            self.assertEqual(self.post('preview', {**self.custom_spec, 'prefix': prefix, 'password': PASSWORD}).status_code, 400)
        for password in ('', 'weak', None, True, ['Password'], 'A' * 257):
            self.assertEqual(self.post('preview', {**self.custom_spec, 'password': password}).status_code, 400)
        for extra in ({'year': 2026}, {'month': 11}, {'password_source': 'input'}):
            self.assertEqual(self.post('preview', {**self.custom_spec, 'password': PASSWORD, **extra}).status_code, 400)
        self.assertEqual(self.post('preview', self.custom_spec).status_code, 400)
        self.directory_factory.assert_not_called()

    def test_custom_password_works_without_env_and_remains_out_of_storage_and_responses(self):
        os.environ['AD_PRECREATE_DEFAULT_PASSWORD'] = ''
        config = self.client.get('/api/admin/ad-precreate/config').json
        self.assertTrue(config['password_input'])
        self.assertFalse(config['password_ready'])
        batch, payload = self.begin(self.custom_spec, password=PASSWORD)
        result = self.step(batch, PASSWORD)
        self.assertEqual(result['counts']['created'], 1)
        self.assertEqual(self.directory.create.call_args.args[:2], ('wfq261200', PASSWORD))
        self.assertNotIn(PASSWORD, json.dumps(payload['preview_token']))
        for response in (self.client.get('/api/admin/ad-precreate/batches'),
                         self.client.get('/api/admin/ad-precreate/batches/' + batch['id'])):
            self.assertNotIn(PASSWORD, response.get_data(as_text=True))
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        stored = self.platform.AdPrecreateBatch.query.one()
        self.assertNotIn(PASSWORD, stored.spec)
        self.assertNotIn(PASSWORD, stored.password_mac)
        with self.client.session_transaction() as session:
            self.assertNotIn(PASSWORD, str(dict(session)))
        for log in self.platform.AdminActionLog.query.all():
            self.assertNotIn(PASSWORD, log.message)

    def test_custom_batch_requires_original_password_for_create_resume_and_retry(self):
        batch, payload = self.begin(self.custom_spec, password=PASSWORD)
        path = 'batches/' + batch['id']
        for operation in ('step', 'retry'):
            self.assertEqual(self.post(path + '/' + operation).status_code, 400)
            self.assertEqual(self.post(path + '/' + operation, {'password': 'DifferentTestPassword2!'}).status_code, 409)
        self.assertEqual(self.post('batches', {**payload, 'password': 'DifferentTestPassword2!'}).status_code, 409)
        self.directory.create.assert_not_called()
        os.environ['AD_PRECREATE_DEFAULT_PASSWORD'] = 'DifferentEnvPassword3!'
        result = self.step(batch, PASSWORD)
        self.assertEqual(result['counts']['created'], 1)
        self.assertEqual(self.directory.create.call_args.args[1], PASSWORD)
        self.assertEqual(self.post(path + '/retry', {'password': PASSWORD}).status_code, 200)
        self.assertEqual(self.step(batch, PASSWORD)['counts']['created'], 2)

    def test_password_change_after_preview_does_not_create_a_batch(self):
        preview = self.post('preview', {**self.custom_spec, 'password': PASSWORD}).json
        payload = {'preview_token': preview['preview_token'], 'request_key': str(uuid.uuid4()),
                   'confirm_text': 'YES', 'password': 'DifferentTestPassword2!'}
        self.assertEqual(self.post('batches', payload).status_code, 409)
        self.assertEqual(self.platform.AdPrecreateBatch.query.count(), 0)
        self.directory.create.assert_not_called()

    def test_each_custom_batch_keeps_its_own_password_and_skips_existing_accounts(self):
        first, _ = self.begin(self.custom_spec, password=PASSWORD)
        self.step(first, PASSWORD)
        other_password = 'AnotherTestPassword2!'
        second, _ = self.begin(self.custom_spec, password=other_password)
        self.assertEqual(self.step(second, other_password)['counts']['skipped'], 1)
        self.assertEqual(self.step(second, other_password)['counts']['created'], 1)
        self.assertEqual(self.directory.create.call_args.args[:2], ('wfq261201', other_password))
        self.assertEqual(self.directory.create.call_count, 2)
        self.assertEqual(self.records['wfq261200'].info.split('/')[0], '备注：预建批次:' + first['id'])

    def test_legacy_batches_can_resume_with_entered_original_password_without_env(self):
        batch, _ = self.begin()
        os.environ['AD_PRECREATE_DEFAULT_PASSWORD'] = ''
        self.assertEqual(self.step(batch, PASSWORD)['counts']['created'], 1)

    def test_custom_prefix_preview_matches_saved_batch(self):
        batch, _ = self.begin({**self.custom_spec, 'prefix': 'wfq2701', 'start': 98, 'end': 99}, password=PASSWORD)
        self.assertEqual([item['employee_id'] for item in batch['items']], ['wfq270198', 'wfq270199'])
        self.assertEqual(batch['spec']['prefix'], 'wfq2701')
        self.assertEqual(batch['spec']['password_source'], 'input')

    def test_preview_is_readonly_and_shows_existing_accounts(self):
        self.records['wfq261100'] = DirectoryAccount('wfq261100', 'CN=old,' + OU, 'old', '', True)
        result = self.post('preview', self.spec).json
        self.assertEqual([row['status'] for row in result['items']], ['skipped', 'pending', 'pending'])
        self.directory.create.assert_not_called()
        self.assertEqual(self.platform.AdPrecreateBatch.query.count(), 0)
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_batch_creation_is_idempotent_and_does_not_write_ad(self):
        batch, payload = self.begin()
        self.assertEqual(self.post('batches', payload).json['batch']['id'], batch['id'])
        self.assertEqual(self.platform.AdPrecreateBatch.query.count(), 1)
        self.assertEqual(self.platform.AdPrecreateItem.query.count(), 3)
        self.directory.create.assert_not_called()
        preview = self.post('preview', {**self.spec, 'month': 12}).json
        self.assertEqual(self.post('batches', {**payload, 'preview_token': preview['preview_token']}).status_code, 409)

    def test_expired_or_tampered_preview_cannot_start_a_batch(self):
        preview = self.post('preview', self.spec).json
        signer = self.platform.precreate_signer()
        decoded = signer.loads(preview['preview_token'])
        timestamp_signer = signer.make_signer()
        with patch.object(timestamp_signer, 'get_timestamp', return_value=int(time.time()) - 601), \
                patch.object(signer, 'make_signer', return_value=timestamp_signer):
            preview['preview_token'] = signer.dumps(decoded)
        payload = {'preview_token': preview['preview_token'], 'request_key': str(uuid.uuid4()), 'confirm_text': 'YES'}
        self.assertEqual(self.post('batches', payload).status_code, 409)
        self.assertEqual(self.post('batches', {**payload, 'preview_token': preview['preview_token'] + 'bad'}).status_code, 400)
        self.assertEqual(self.platform.AdPrecreateBatch.query.count(), 0)

    def test_immediate_enable_requires_explicit_confirmation(self):
        preview = self.post('preview', {**self.spec, 'enabled': True}).json
        payload = {'preview_token': preview['preview_token'], 'request_key': str(uuid.uuid4()), 'confirm_text': 'YES'}
        self.assertEqual(self.post('batches', payload).status_code, 400)
        response = self.post('batches', {**payload, 'confirm_enabled': True})
        batch = self.step(response.json['batch'])
        self.assertEqual(batch['counts']['created'], 1)
        self.assertTrue(self.directory.create.call_args.args[3])

    def test_create_readback_history_and_repeated_steps_never_recreate(self):
        batch, _ = self.begin()
        for _ in range(4):
            batch = self.step(batch)
        self.assertEqual(batch['counts']['created'], 3)
        self.assertEqual(self.directory.create.call_count, 3)
        self.assertTrue(all(not call.args[3] for call in self.directory.create.call_args_list))
        self.assertTrue(all(call.args[2] == '预建待分配' for call in self.directory.create.call_args_list))
        history = self.client.get('/api/admin/ad-precreate/batches').get_data(as_text=True)
        self.assertNotIn(PASSWORD, history)
        for log in self.platform.AdminActionLog.query.all():
            self.assertNotIn(PASSWORD, log.message)

    def test_existing_accounts_are_skipped_without_any_modification(self):
        old = DirectoryAccount('wfq261100', 'CN=old,OU=Other,DC=wfq,DC=com', 'old', '', True)
        self.records['wfq261100'] = old
        batch, _ = self.begin()
        batch = self.step(batch)
        self.assertEqual(batch['counts']['skipped'], 1)
        self.assertEqual(self.records['wfq261100'], old)
        self.directory.create.assert_not_called()

    def test_existing_cn_with_different_login_is_reported_without_overwrite(self):
        batch, _ = self.begin()
        self.directory.create.side_effect = None
        self.directory.create.return_value = False
        result = self.step(batch)
        self.assertEqual(result['counts']['failed'], 1)
        self.assertIn('同名对象', result['items'][0]['message'])
        self.assertFalse(self.records)

    def test_separate_overlapping_batches_do_not_claim_each_others_accounts(self):
        first, _ = self.begin()
        self.step(first)
        second, _ = self.begin()
        result = self.step(second)
        self.assertEqual(result['counts']['skipped'], 1)
        self.assertEqual(self.directory.create.call_count, 1)

    def test_timeout_after_success_is_reconciled_without_second_add(self):
        def create(*args):
            self.create_record(*args)
            raise PrecreateError('结果未确认', 503)
        self.directory.create.side_effect = create
        batch, _ = self.begin()
        result = self.step(batch)
        self.assertEqual(result['counts']['created'], 1)
        self.assertEqual(self.directory.create.call_count, 1)

    def test_unknown_readback_requires_explicit_retry_and_does_not_add_twice(self):
        batch, _ = self.begin()
        reads = 0
        def lookup(ids):
            nonlocal reads
            reads += 1
            if reads == 2:
                raise PrecreateError('回读暂不可用', 503)
            return {value: self.records[value] for value in ids if value in self.records}
        self.directory.lookup.side_effect = lookup
        result = self.step(batch)
        self.assertEqual(result['counts']['unknown'], 1)
        self.directory.lookup.side_effect = lambda ids: {value: self.records[value] for value in ids if value in self.records}
        self.post('batches/' + batch['id'] + '/retry')
        result = self.step(batch)
        self.assertEqual(result['counts']['created'], 1)
        self.assertEqual(self.directory.create.call_count, 1)

    def test_guessed_batch_marker_does_not_claim_an_existing_account(self):
        batch, _ = self.begin()
        account = 'wfq261100'
        self.records[account] = DirectoryAccount(account, 'CN=' + account + ',' + OU, 'old',
            '备注：预建批次:' + batch['id'] + '/' + account, False)
        result = self.step(batch)
        self.assertEqual(result['counts']['skipped'], 1)
        self.directory.create.assert_not_called()

    def test_single_creation_and_original_sequence_remain_unchanged(self):
        connection = MagicMock()
        connection.entries = []
        connection.result = {'result': 0}
        with patch.object(self.platform, 'get_ad_connection', return_value=connection):
            success, _ = self.platform.create_ad_user('wfq102179', '', PASSWORD, '张三', '')
        self.assertTrue(success)
        attrs = connection.add.call_args.kwargs['attributes']
        self.assertEqual(attrs['userAccountControl'], '512')
        self.assertEqual(attrs['description'], '张三')
        self.assertNotIn('pwdLastSet', attrs)
        batch, _ = self.begin()
        with patch.object(self.platform, 'ad_employee_ids_in_sequence', return_value=set()):
            record = self.platform.reserve_next_employee_id(self.user.username)
        self.assertEqual(record.employee_id, 'wfq102179')
        self.assertEqual([row.employee_id for row in self.platform.AdPrecreateItem.query.all()],
                         ['wfq261100', 'wfq261101', 'wfq261102'])

    def test_partial_failure_continues_and_only_failed_items_are_retried(self):
        def create(*args):
            if args[0] == 'wfq261100':
                raise PrecreateError('AD 拒绝创建')
            return self.create_record(*args)
        self.directory.create.side_effect = create
        batch, _ = self.begin()
        for _ in range(3):
            batch = self.step(batch)
        self.assertEqual((batch['counts']['created'], batch['counts']['failed']), (2, 1))
        preserved = dict(self.records)
        self.directory.create.side_effect = self.create_record
        self.post('batches/' + batch['id'] + '/retry')
        batch = self.step(batch)
        self.assertEqual(batch['counts']['created'], 3)
        self.assertTrue(all(self.records[key] == value for key, value in preserved.items()))

    def test_password_or_ou_change_stops_pending_writes(self):
        batch, _ = self.begin()
        os.environ['AD_PRECREATE_DEFAULT_PASSWORD'] = 'OtherTestPassword2!'
        self.assertEqual(self.post('batches/' + batch['id'] + '/step').status_code, 409)
        os.environ['AD_PRECREATE_DEFAULT_PASSWORD'] = PASSWORD
        with patch.dict(self.platform.app.config, {'AD_USER_OU': 'OU=other,DC=wfq,DC=com'}):
            self.assertEqual(self.post('batches/' + batch['id'] + '/step').status_code, 409)
        self.directory.create.assert_not_called()

    def test_processing_lease_prevents_reentry_and_can_resume_after_interruption(self):
        batch, _ = self.begin()
        row = self.platform.AdPrecreateItem.query.first()
        row.status = 'processing'; row.started_at = datetime.utcnow()
        self.platform.db.session.commit()
        # Other pending rows are allowed, but the in-flight row must not be submitted again.
        self.step(batch)
        self.assertNotEqual(self.directory.create.call_args.args[0], row.employee_id)
        row.started_at = datetime.utcnow() - timedelta(minutes=4)
        self.platform.db.session.commit()
        self.step(batch)
        self.assertEqual(self.directory.create.call_args.args[0], row.employee_id)

    def test_audit_commit_failure_can_be_reconciled_from_ad_marker(self):
        batch, _ = self.begin()
        real_commit = self.platform.db.session.commit
        calls = 0
        def commit():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OperationalError('test', {}, RuntimeError('unavailable'))
            return real_commit()
        with patch.object(self.platform.db.session, 'commit', side_effect=commit):
            response = self.post('batches/' + batch['id'] + '/step')
        self.assertEqual(response.status_code, 503)
        row = self.platform.AdPrecreateItem.query.first()
        self.assertEqual(row.status, 'processing')
        row.started_at = datetime.utcnow() - timedelta(minutes=4)
        real_commit()
        batch = self.step(batch)
        self.assertEqual(batch['counts']['created'], 1)
        self.assertEqual(self.directory.create.call_count, 1)


if __name__ == '__main__':
    unittest.main()
