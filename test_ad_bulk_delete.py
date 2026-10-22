import copy
from datetime import datetime, timedelta
import json
import ssl
import time
import unittest
import uuid
from unittest.mock import MagicMock, patch

import ldap3
from ldap3.core.exceptions import LDAPException
from smbprotocol.security_descriptor import AccessAllowedAce, AccessDeniedAce, AclPacket, SIDPacket, SMB2CreateSDBuffer

from ad_bulk_delete import BulkDeleteDirectory, blocked_reason, deletion_denied, snapshot
from ad_precreate import PrecreateError
import test_domain_password_policy as domain_tests

OU = 'OU=用户,DC=wfq,DC=com'
BASE = 'DC=wfq,DC=com'
DOMAIN_SID = 'S-1-5-21-11-22-33'
NOW = datetime(2026, 10, 22, 10, 0, 0)


def account(name='wfq260800', now=NOW):
    return {'employee_id': name, 'guid': str(uuid.uuid4()), 'dn': 'CN=' + name + ',' + OU,
        'name': '预建待分配', 'department': 'IT', 'created': (now - timedelta(days=100)).isoformat(),
        'last_logon': (now - timedelta(days=60)).isoformat(), 'logon_count': 1, 'uac': 514,
        'sam_type': 805306368, 'sid': DOMAIN_SID + '-1100', 'primary_group': 513, 'admin_count': 0,
        'critical': False, 'service': False, 'classes': ['top', 'person', 'user'], 'usn': '100',
        'info': '', 'groups': [DOMAIN_SID + '-513', 'S-1-5-32-545'], 'delete_denied': False}


def descriptor(deny=False):
    sid = SIDPacket(); sid.from_string('S-1-1-0')
    ace = AccessDeniedAce() if deny else AccessAllowedAce()
    ace['mask'] = 0x10040 if deny else 0x20000
    ace['sid'] = sid
    acl = AclPacket(); acl['aces'] = [ace]
    sd = SMB2CreateSDBuffer(); sd.set_dacl(acl)
    return sd.pack()


def entry_for(row):
    def sid_bytes(value):
        sid = SIDPacket(); sid.from_string(value)
        return sid.pack()
    server = ldap3.Server('mock.test', get_info=ldap3.NONE)
    conn = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC, check_names=False)
    conn.strategy.add_entry(row['dn'], {'objectClass': row['classes'], 'sAMAccountName': row['employee_id'],
        'objectGUID': uuid.UUID(row['guid']).bytes_le, 'objectSid': sid_bytes(row['sid']), 'sAMAccountType': row['sam_type'],
        'description': row['name'], 'department': row['department'],
        'whenCreated': datetime.fromisoformat(row['created']).strftime('%Y%m%d%H%M%S.0Z'),
        'lastLogon': int((datetime.fromisoformat(row['last_logon']) - datetime(1601, 1, 1)).total_seconds() * 10000000) if row['last_logon'] else 0,
        'lastLogonTimestamp': 0, 'logonCount': row['logon_count'], 'userAccountControl': row['uac'],
        'adminCount': row['admin_count'], 'primaryGroupID': 513, 'uSNChanged': row['usn'], 'info': row['info'],
        'tokenGroups': [sid_bytes(sid) for sid in row['groups']], 'nTSecurityDescriptor': descriptor(row['delete_denied'])})
    conn.bind(); conn.search(row['dn'], '(objectClass=*)', ldap3.BASE, attributes=ldap3.ALL_ATTRIBUTES)
    return conn.entries[0]


class BulkDeletePolicyTests(unittest.TestCase):
    def test_exact_45_day_boundary_and_never_logged_in(self):
        row = account()
        row['created'] = row['last_logon'] = (NOW - timedelta(days=45)).isoformat()
        self.assertEqual(blocked_reason(row, [row], OU, set(), NOW), '')
        row['last_logon'] = (NOW - timedelta(days=45) + timedelta(seconds=1)).isoformat()
        self.assertTrue(blocked_reason(row, [row], OU, set(), NOW))
        row['last_logon'] = None; row['logon_count'] = 0
        self.assertEqual(blocked_reason(row, [row], OU, set(), NOW), '')
        row['created'] = (NOW - timedelta(days=44)).isoformat()
        self.assertTrue(blocked_reason(row, [row], OU, set(), NOW))

    def test_every_dc_and_unknown_login_data_must_be_checked(self):
        row = account(); peer = copy.deepcopy(row)
        peer['last_logon'] = (NOW - timedelta(days=1)).isoformat()
        self.assertTrue(blocked_reason(row, [row, peer], OU, set(), NOW))
        peer['last_logon'] = None
        self.assertTrue(blocked_reason(row, [row, peer], OU, set(), NOW))
        peer['guid'] = str(uuid.uuid4())
        self.assertTrue(blocked_reason(row, [row, peer], OU, set(), NOW))
        self.assertTrue(blocked_reason(row, [], OU, set(), NOW))

    def test_admin_service_computer_and_accidental_deletion_protection(self):
        for changes in ({'employee_id': 'Administrator'}, {'classes': ['user', 'computer']}, {'uac': 8192},
                        {'admin_count': 1}, {'critical': True}, {'service': True}, {'primary_group': 512},
                        {'sid': DOMAIN_SID + '-500'}, {'groups': [DOMAIN_SID + '-512']},
                        {'groups': ['S-1-5-32-544']}, {'groups': []}, {'delete_denied': True},
                        {'dn': 'CN=wfq260800,OU=Other,' + BASE}):
            row = {**account(), **changes}
            with self.subTest(changes=changes):
                self.assertTrue(blocked_reason(row, [row], OU, set(), NOW))
        row = account()
        self.assertTrue(blocked_reason(row, [row], OU, {row['employee_id']}, NOW))
        row['groups'].append(DOMAIN_SID + '-1500')
        self.assertTrue(blocked_reason(row, [row], OU, set(), NOW, {DOMAIN_SID + '-1500'}))

    def test_real_ldap_entry_and_existing_security_descriptor_parser(self):
        row = account()
        result = snapshot(entry_for(row), security=True)
        self.assertEqual(result['guid'], row['guid'])
        self.assertEqual(result['created'], row['created'])
        self.assertEqual(result['last_logon'], row['last_logon'])
        self.assertEqual(result['groups'], row['groups'])
        self.assertFalse(deletion_denied(descriptor()))
        self.assertTrue(deletion_denied(descriptor(True)))
        with self.assertRaises(ValueError): deletion_denied(None)

    def test_delete_targets_only_original_guid_without_tree_controls(self):
        directory = BulkDeleteDirectory({'AD_SERVER': 'dc01.wfq.com'})
        directory.primary = MagicMock(); directory.primary.result = {'result': 0}
        row = account()
        directory.search = MagicMock(return_value=([entry_for(row)], False))
        self.assertTrue(directory.delete(row))
        directory.primary.delete.assert_called_once_with('<GUID=' + row['guid'] + '>')
        directory.primary.result = {'result': 66}
        with self.assertRaises(PrecreateError): directory.delete(row)
        directory.primary.delete.side_effect = LDAPException('hidden-bind-secret')
        with self.assertRaises(PrecreateError) as caught: directory.delete(row)
        self.assertNotIn('hidden-bind-secret', str(caught.exception))

    def test_final_read_detects_changes_without_sending_delete(self):
        directory = BulkDeleteDirectory({'AD_SERVER': 'dc01.wfq.com'})
        directory.primary = MagicMock(); row = account()
        updated = {**row, 'usn': '101'}
        directory.search = MagicMock(return_value=([entry_for(updated)], False))
        with self.assertRaises(PrecreateError): directory.delete(row)
        directory.primary.delete.assert_not_called()

    def test_connections_verify_tls_disable_referrals_and_have_deadlines(self):
        config = {'AD_SERVER': 'dc01.wfq.com', 'AD_BIND_USER': 'bind', 'AD_BIND_PASSWORD': 'isolated-test-secret'}
        directory = BulkDeleteDirectory(config, ca_file='test-ca.pem')
        with patch('ad_bulk_delete.ldap3.Tls') as tls, patch('ad_bulk_delete.ldap3.Server') as server, \
                patch('ad_bulk_delete.ldap3.Connection') as connection:
            directory.connection('dc01.wfq.com')
            self.assertEqual(tls.call_args.kwargs['validate'], ssl.CERT_REQUIRED)
            self.assertFalse(connection.call_args.kwargs['auto_referrals'])
            self.assertFalse(connection.call_args.kwargs['check_names'])
            self.assertEqual(connection.call_args.kwargs['receive_timeout'], 10)
            self.assertEqual(server.call_args.kwargs['connect_timeout'], 8)
        directory.deadline = 0
        with self.assertRaises(PrecreateError): directory.connection('dc02.wfq.com')

    def test_inspect_reads_every_dc_by_guid_and_fetches_security_with_base_scope(self):
        row = account(); directory = BulkDeleteDirectory({'AD_SERVER': 'dc01.wfq.com', 'AD_BASE_DN': BASE})
        directory.write_host = 'dc01.wfq.com'; directory.controllers = ['dc01.wfq.com', 'dc02.wfq.com']
        directory.connection = MagicMock(side_effect=lambda host: host)
        scopes = []
        def search(conn, base, query, attributes, scope=ldap3.SUBTREE, **kwargs):
            scopes.append((conn, scope, attributes))
            return [entry_for(row)], False
        directory.search = MagicMock(side_effect=search)
        result, peers = directory.inspect(row['guid'])
        self.assertEqual(result['guid'], row['guid']); self.assertEqual(len(peers), 2)
        self.assertEqual({host for host, scope, attrs in scopes}, set(directory.controllers))
        self.assertTrue(all(scope == ldap3.BASE for host, scope, attrs in scopes if 'tokenGroups' in attrs))
        directory.search.side_effect = lambda conn, *args, **kwargs: ([], False) if conn == 'dc02.wfq.com' else ([entry_for(row)], False)
        with self.assertRaises(PrecreateError): directory.inspect(row['guid'])

    def test_incomplete_search_referrals_and_missing_dc_list_fail_closed(self):
        directory = BulkDeleteDirectory({'AD_SERVER': 'dc01.wfq.com', 'AD_BASE_DN': BASE})
        conn = MagicMock(); conn.result = {'result': 4}; conn.response = []; conn.entries = []
        with self.assertRaises(PrecreateError): directory.search(conn, BASE, '(objectClass=*)', [])
        self.assertEqual(directory.search(conn, BASE, '(objectClass=*)', [], partial=True), ([], True))
        conn.result = {'result': 0}; conn.response = [{'type': 'searchResRef'}]
        with self.assertRaises(PrecreateError): directory.search(conn, BASE, '(objectClass=*)', [])
        directory.write_host = 'dc01.wfq.com'; directory.search = MagicMock(return_value=([], False))
        with self.assertRaises(PrecreateError): directory.discover(conn)


class BulkDeleteApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        domain_tests.DomainPasswordPolicyTests.setUpClass.__func__(cls)

    def setUp(self):
        self.context = self.platform.app.app_context(); self.context.push()
        self.addCleanup(self.context.pop)
        self.platform.db.drop_all(); self.platform.db.create_all()
        self.addCleanup(self.platform.db.session.remove)
        self.user = self.platform.AdminUser(username='bulk-delete-admin', password_hash='unused', role='super_admin')
        self.platform.db.session.add(self.user)
        self.platform.set_setting('allow_delete_user', 'true'); self.platform.db.session.commit()
        self.settings = patch.dict(self.platform.app.config, {'AD_USER_OU': OU, 'AD_BASE_DN': BASE, 'AD_BIND_USER': 'administrator@wfq.com'})
        self.settings.start(); self.addCleanup(self.settings.stop)
        self.client = self.platform.app.test_client()
        with self.client.session_transaction() as session:
            session.update(admin_logged_in=True, admin_username=self.user.username, admin_role='super_admin')
        config = self.client.get('/api/admin/ad-bulk-delete/config')
        self.headers = {'X-CSRF-Token': config.json['csrf_token']}
        self.rows = {row['guid']: row for row in [account(now=datetime.utcnow().replace(microsecond=0)), account('wfq260801', datetime.utcnow().replace(microsecond=0))]}
        first = next(iter(self.rows.values()))
        batch = self.platform.AdPrecreateBatch(id=str(uuid.uuid4()), request_key=str(uuid.uuid4()), spec='{}', password_mac='unused', created_by='other-admin')
        batch.items = [self.platform.AdPrecreateItem(employee_id=first['employee_id'], status='created', object_guid=first['guid'])]
        self.platform.db.session.add(batch); self.platform.db.session.commit()
        self.directory = MagicMock(); self.directory.__enter__.return_value = self.directory
        self.directory.controllers = ['dc01.wfq.com', 'dc02.wfq.com']; self.directory.write_host = 'dc01.wfq.com'
        self.directory.protected_groups = set()
        self.directory.candidates.side_effect = lambda prefix, now: ([entry_for(row) for row in self.rows.values()], False)
        self.directory.inspect.side_effect = lambda guid: (copy.deepcopy(self.rows.get(guid)), [copy.deepcopy(self.rows[guid])]) if guid in self.rows else (None, [])
        self.directory.delete.side_effect = lambda row: self.rows.pop(row['guid']) is not None
        factory = patch.object(self.platform, 'bulk_delete_directory', return_value=self.directory)
        self.factory = factory.start(); self.addCleanup(factory.stop)

    def post(self, path, data=None):
        return self.client.post('/api/admin/ad-bulk-delete/' + path, json={} if data is None else data, headers=self.headers)

    def begin(self, scope='precreated'):
        preview = self.post('scan', {'scope': scope, 'prefix': 'wfq'})
        self.assertEqual(preview.status_code, 200, preview.json)
        selected = [row['employee_id'] for row in preview.json['items'] if row['can_delete']]
        payload = {'preview_token': preview.json['preview_token'], 'selected': selected, 'confirm_count': len(selected),
                   'confirm_text': 'YES', 'acknowledge_recovery': True, 'request_key': str(uuid.uuid4())}
        result = self.post('batches', payload)
        self.assertEqual(result.status_code, 200, result.json)
        return result.json['batch'], payload

    def step(self, batch):
        result = self.post('batches/' + batch['id'] + '/step')
        self.assertEqual(result.status_code, 200, result.json)
        return result.json['batch']

    def test_scope_uses_creation_guid_proof_and_scan_never_deletes(self):
        for scope, name in (('precreated', 'wfq260800'), ('ordinary', 'wfq260801')):
            result = self.post('scan', {'scope': scope}).json
            self.assertEqual([row['employee_id'] for row in result['items']], [name])
            self.assertTrue(result['items'][0]['can_delete'])
        self.directory.delete.assert_not_called()
        self.assertEqual(self.platform.AdBulkDeleteBatch.query.count(), 0)

    def test_permissions_actual_role_csrf_and_global_switch_apply_to_all_writes(self):
        posts = ['scan', 'batches', 'batches/missing/step', 'batches/missing/retry']
        for path in posts:
            result = self.client.post('/api/admin/ad-bulk-delete/' + path, json={})
            self.assertEqual(result.status_code, 403)
        for role in ('readonly', 'admin'):
            self.user.role = role; self.platform.db.session.commit()
            for path in posts: self.assertEqual(self.post(path).status_code, 403)
            self.assertEqual(self.client.get('/api/admin/ad-bulk-delete/config').status_code, 403)
        self.user.role = 'super_admin'; self.platform.set_setting('allow_delete_user', 'false'); self.platform.db.session.commit()
        for path in posts: self.assertEqual(self.post(path).status_code, 403)
        self.assertFalse(self.client.get('/api/admin/ad-bulk-delete/config').json['enabled'])
        self.assertEqual(self.platform.app.test_client().get('/api/admin/ad-bulk-delete/config').status_code, 401)
        self.factory.assert_not_called()

    def test_blocked_uncertain_or_recent_login_accounts_cannot_be_selected(self):
        row = next(iter(self.rows.values()))
        row['last_logon'] = datetime.utcnow().isoformat()
        preview = self.post('scan', {'scope': 'precreated'}).json
        self.assertFalse(preview['items'][0]['can_delete'])
        payload = {'preview_token': preview['preview_token'], 'selected': [row['employee_id']], 'confirm_count': 1,
                   'confirm_text': 'YES', 'acknowledge_recovery': True, 'request_key': str(uuid.uuid4())}
        self.assertEqual(self.post('batches', payload).status_code, 400)
        self.directory.inspect.side_effect = PrecreateError('DC unavailable', 503)
        self.assertFalse(self.post('scan', {'scope': 'precreated'}).json['items'][0]['can_delete'])
        self.directory.delete.assert_not_called()

    def test_confirmation_selection_count_expiry_tampering_and_idempotency(self):
        batch, payload = self.begin()
        self.assertEqual(self.post('batches', payload).json['batch']['id'], batch['id'])
        for changes in ({'confirm_text': ''}, {'acknowledge_recovery': False}, {'confirm_count': 2},
                        {'selected': []}, {'selected': ['Administrator']}, {'selected': ['wfq260800', 'wfq260800']},
                        {'preview_token': payload['preview_token'] + 'bad'}):
            self.assertEqual(self.post('batches', {**payload, **changes}).status_code, 400)
        signer = self.platform.URLSafeTimedSerializer(self.platform.app.secret_key, salt='ad-bulk-delete-preview')
        original = signer.loads(payload['preview_token'])
        with patch.object(signer.signer, 'get_timestamp', return_value=int(time.time()) - 601):
            expired = signer.dumps(original)
        self.assertEqual(self.post('batches', {**payload, 'request_key': str(uuid.uuid4()), 'preview_token': expired}).status_code, 409)
        self.assertEqual(self.platform.AdBulkDeleteBatch.query.count(), 1)
        self.directory.delete.assert_not_called()

    def test_only_selected_user_is_deleted_and_repeated_step_does_not_delete_again(self):
        batch, _ = self.begin()
        other = copy.deepcopy(next(row for row in self.rows.values() if row['employee_id'] == 'wfq260801'))
        result = self.step(batch)
        self.assertEqual(result['counts']['deleted'], 1)
        self.assertIn('计算机', result['items'][0]['message'])
        self.assertEqual(self.rows[other['guid']], other)
        self.assertEqual(self.step(batch)['counts']['deleted'], 1)
        self.assertEqual(self.directory.delete.call_count, 1)
        self.assertEqual(self.platform.AdPrecreateItem.query.one().status, 'created')
        self.assertTrue(self.platform.AdminActionLog.query.filter_by(action='批量删除用户').count())

    def test_changed_account_recent_login_privilege_or_source_is_skipped_before_delete(self):
        for changes in ({'usn': '101'}, {'last_logon': datetime.utcnow().isoformat()}, {'admin_count': 1},
                        {'groups': [DOMAIN_SID + '-512']}, {'dn': 'CN=wfq260800,OU=Other,' + BASE}):
            batch, _ = self.begin()
            row = next(row for row in self.rows.values() if row['employee_id'] == 'wfq260800')
            old = copy.deepcopy(row); row.update(changes)
            self.assertEqual(self.step(batch)['counts']['skipped'], 1)
            row.clear(); row.update(old)
        batch, _ = self.begin()
        self.platform.AdPrecreateItem.query.one().object_guid = str(uuid.uuid4()); self.platform.db.session.commit()
        self.assertEqual(self.step(batch)['counts']['skipped'], 1)
        self.directory.delete.assert_not_called()

    def test_original_guid_missing_never_deletes_a_replacement_with_same_name(self):
        batch, _ = self.begin()
        row = self.rows.pop(batch['items'][0]['guid'])
        replacement = {**row, 'guid': str(uuid.uuid4())}; self.rows[replacement['guid']] = replacement
        self.assertEqual(self.step(batch)['counts']['absent'], 1)
        self.assertIn(replacement['guid'], self.rows)
        self.directory.delete.assert_not_called()

    def test_unknown_delete_is_paused_and_explicit_retry_reconciles_without_second_delete(self):
        batch, _ = self.begin()
        def interrupted(row):
            self.rows.pop(row['guid'])
            raise PrecreateError('result unknown', 503)
        self.directory.delete.side_effect = interrupted
        self.assertEqual(self.step(batch)['counts']['unknown'], 1)
        path = 'batches/' + batch['id'] + '/retry'
        self.assertEqual(self.post(path).status_code, 400)
        self.assertEqual(self.post(path, {'confirm_text': 'YES', 'acknowledge_recovery': True}).status_code, 200)
        self.assertEqual(self.step(batch)['counts']['absent'], 1)
        self.assertEqual(self.directory.delete.call_count, 1)

    def test_unreachable_or_changed_dc_blocks_delete_and_pending_lease_never_repeats(self):
        batch, _ = self.begin()
        self.directory.inspect.side_effect = PrecreateError('DC unreachable', 503)
        self.assertEqual(self.step(batch)['counts']['failed'], 1)
        self.directory.delete.assert_not_called()
        row = self.platform.AdBulkDeleteItem.query.one()
        row.status = 'processing'; row.started_at = datetime.utcnow() - timedelta(minutes=4)
        self.platform.db.session.commit()
        self.assertEqual(self.step(batch)['counts']['unknown'], 1)
        self.directory.delete.assert_not_called()

    def test_batch_and_preview_cannot_be_taken_over_by_another_operator(self):
        batch, payload = self.begin()
        user = self.platform.AdminUser(username='other-super', password_hash='unused', role='super_admin')
        self.platform.db.session.add(user); self.platform.db.session.commit()
        with self.client.session_transaction() as session: session['admin_username'] = user.username
        self.assertEqual(self.post('batches', payload).status_code, 403)
        self.assertEqual(self.post('batches/' + batch['id'] + '/step').status_code, 404)
        self.directory.delete.assert_not_called()

    def test_global_switch_is_rechecked_immediately_before_delete(self):
        batch, _ = self.begin()
        real_inspect = self.directory.inspect.side_effect
        def changed(guid):
            self.platform.set_setting('allow_delete_user', 'false'); self.platform.db.session.commit()
            return real_inspect(guid)
        self.directory.inspect.side_effect = changed
        self.assertEqual(self.step(batch)['counts']['failed'], 1)
        self.directory.delete.assert_not_called()

    def test_audit_commit_failure_cannot_cause_an_automatic_second_delete(self):
        batch, _ = self.begin()
        real_commit = self.platform.db.session.commit
        calls = 0
        def commit():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise self.platform.OperationalError('test', {}, RuntimeError('unavailable'))
            return real_commit()
        with patch.object(self.platform.db.session, 'commit', side_effect=commit):
            result = self.post('batches/' + batch['id'] + '/step')
        self.assertEqual(result.status_code, 503)
        self.assertEqual(self.directory.delete.call_count, 1)
        row = self.platform.AdBulkDeleteItem.query.one()
        self.assertEqual(row.status, 'processing')
        row.started_at = datetime.utcnow() - timedelta(minutes=4); real_commit()
        self.assertEqual(self.step(batch)['counts']['unknown'], 1)
        self.post('batches/' + batch['id'] + '/retry', {'confirm_text': 'YES', 'acknowledge_recovery': True})
        self.assertEqual(self.step(batch)['counts']['absent'], 1)
        self.assertEqual(self.directory.delete.call_count, 1)

    def test_new_tables_preserve_existing_platform_and_precreate_records(self):
        self.platform.AdBulkDeleteItem.__table__.drop(self.platform.db.engine)
        self.platform.AdBulkDeleteBatch.__table__.drop(self.platform.db.engine)
        self.platform.ensure_database_tables()
        self.assertEqual(self.platform.AdminUser.query.one().username, 'bulk-delete-admin')
        self.assertEqual(self.platform.AdPrecreateItem.query.one().employee_id, 'wfq260800')
        self.assertEqual(self.platform.AdBulkDeleteBatch.query.count(), 0)

    def test_invalid_inputs_and_unverified_precreate_marker_do_not_allow_deletion(self):
        for data in ([], None, {'scope': 'all'}, {'scope': 'ordinary', 'prefix': '*'},
                     {'scope': 'ordinary', 'prefix': 'wfq)(objectClass=*)'}, {'scope': 'ordinary', 'days': 1}):
            self.assertEqual(self.post('scan', data).status_code, 400)
        row = next(row for row in self.rows.values() if row['employee_id'] == 'wfq260801')
        row['info'] = '备注：预建批次:unconfirmed'
        result = self.post('scan', {'scope': 'precreated'}).json
        uncertain = next(item for item in result['items'] if item['employee_id'] == row['employee_id'])
        self.assertFalse(uncertain['can_delete'])
        self.directory.delete.assert_not_called()


if __name__ == '__main__':
    unittest.main()
