import codecs
import io
import json
import os
import ssl
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ldap3

import gpo_password_policy as gpo
import test_domain_password_policy as domain_tests


TEMPLATE = ('; keep this comment\r\n[Unicode]\r\nUnicode=yes\r\n[System Access]\r\n'
            'MinimumPasswordAge = 1\r\nMaximumPasswordAge = 180\r\nMinimumPasswordLength = 8\r\n'
            'PasswordComplexity = 1\r\nPasswordHistorySize = 0\r\nClearTextPassword = 0\r\n'
            'LockoutBadCount = 5\r\n[Kerberos Policy]\r\nMaxTicketAge = 10\r\n'
            '[Registry Values]\r\nMACHINE\\Other\\Setting=4,7\r\n'
            '[Privilege Rights]\r\nSeBackupPrivilege = *S-1-5-32-544\r\n')
RAW = codecs.BOM_UTF16_LE + TEMPLATE.encode('utf-16-le')


class ParserTests(unittest.TestCase):
    def test_preserves_unrelated_data_encoding_and_zero(self):
        raw, diff = gpo.apply_changes(RAW, {'min_age_days': 0, 'password_history_count': 24})
        self.assertTrue(raw.startswith(codecs.BOM_UTF16_LE))
        expected = TEMPLATE.replace('MinimumPasswordAge = 1', 'MinimumPasswordAge = 0').replace(
            'PasswordHistorySize = 0', 'PasswordHistorySize = 24')
        self.assertEqual(raw, codecs.BOM_UTF16_LE + expected.encode('utf-16-le'))
        self.assertEqual(len(diff), 2)
        self.assertEqual(gpo.read_policy(raw)['min_age_days'], 0)

    def test_never_expire_uses_protocol_sentinel(self):
        raw, _ = gpo.apply_changes(RAW, {'max_age_days': 0})
        self.assertEqual(gpo.IniDocument(raw).get('System Access', 'MaximumPasswordAge'), '-1')
        self.assertEqual(gpo.read_policy(raw)['max_age_days'], 0)

    def test_undefined_removes_only_targeted_key(self):
        raw, _ = gpo.apply_changes(RAW, {'complexity_enabled': None})
        self.assertIsNone(gpo.read_policy(raw)['complexity_enabled'])
        self.assertIn('LockoutBadCount = 5', raw.decode('utf-16'))

    def test_registry_settings_are_dword_and_can_be_removed(self):
        raw, _ = gpo.apply_changes(RAW, {'relax_min_password_length_limits': True,
                                       'min_password_length': 32, 'min_password_length_audit': 40})
        self.assertIn(gpo.SAM + 'RelaxMinimumPasswordLengthLimits = 4,1', raw.decode('utf-16'))
        self.assertEqual(gpo.read_policy(raw)['min_password_length_audit'], 40)
        raw, _ = gpo.apply_changes(raw, {'min_password_length_audit': None})
        self.assertIsNone(gpo.read_policy(raw)['min_password_length_audit'])

    def test_strict_whitelist_and_cross_field_validation(self):
        invalid = [[], {}, {'LockoutBadCount': 0}, {'min_age_days': True}, {'min_age_days': 1.0},
                   {'min_age_days': '1'}, {'min_password_length': -1}, {'password_history_count': 25},
                   {'complexity_enabled': 'false'}, {'complexity_enabled': 1}, {'max_age_days': 1},
                   {'min_password_length': 15}, {'min_password_length': 129}, {'min_password_length_audit': 0}]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(gpo.PolicyError):
                gpo.apply_changes(RAW, changes)

    def test_noop_does_not_rewrite_file(self):
        raw, diff = gpo.apply_changes(RAW, {'min_password_length': 8})
        self.assertEqual((raw, diff), (RAW, []))

    def test_utf8_and_case_insensitive_ini(self):
        raw = b'[system access]\nminimumPasswordLength=8\n'
        new, _ = gpo.apply_changes(raw, {'min_password_length': 9})
        self.assertEqual(gpo.read_policy(new)['min_password_length'], 9)

    def test_ambiguous_malformed_or_unsupported_file_is_rejected(self):
        for raw in (b'[System Access]\nPasswordComplexity=1\npasswordcomplexity=0',
                    b'[System Access]\n[system access]\n', b'\xffbroken', b'[X]\nKey=\x00',
                    b'[System Access]\nPasswordComplexity=2',
                    b'[Registry Values]\n' + (gpo.SAM + 'MinimumPasswordLengthAudit=1,5').encode()):
            with self.subTest(raw=raw), self.assertRaises(gpo.PolicyError):
                gpo.read_policy(raw)

    def test_version_preserves_user_component_and_wraps_to_one(self):
        self.assertEqual(gpo.next_version(0x12340001), 0x12340002)
        self.assertEqual(gpo.next_version(0x1234ffff), 0x12340001)


class MemoryFile(io.BytesIO):
    def close(self):
        pass


class EditorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ad-gpo-test-')
        self.addCleanup(self.temporary.cleanup)
        self.conn = ldap3.Connection(ldap3.Server('dc.test', use_ssl=True, tls=ldap3.Tls(validate=ssl.CERT_REQUIRED),
                                                get_info=ldap3.OFFLINE_AD_2012_R2),
                                    client_strategy=ldap3.MOCK_SYNC)
        self.domain = self.conn.server.info.other['defaultNamingContext'][0]
        self.guid = '{' + gpo.DEFAULT_GUID.upper() + '}'
        self.dn = f'CN={self.guid},CN=Policies,CN=System,{self.domain}'
        self.gpo_attrs = {
            'objectClass': ['top', 'container', 'groupPolicyContainer'], 'cn': self.guid,
            'displayName': 'Default Domain Policy', 'versionNumber': 0x12340001, 'flags': 0,
            'gPCMachineExtensionNames': '[' + gpo.SECURITY_CSE + '{803e14a0-b4fb-11d0-a0d0-00a0c90f574b}]',
            'gPCFileSysPath': f'\\\\AD2012.LAB\\sysvol\\AD2012.LAB\\Policies\\{self.guid}',
        }
        self.conn.strategy.add_entry(self.dn, self.gpo_attrs)
        self.conn.strategy.add_entry(self.domain, {'objectClass': ['top', 'domain', 'domainDNS'],
                                                 'gPLink': f'[LDAP://{self.dn};0]'})
        self.conn.bind()
        self.addCleanup(self.conn.unbind)
        self.editor = gpo.GpoPasswordPolicy(self.conn, self.temporary.name, username='test@AD2012.LAB', password='test-only')
        self.handles = [MemoryFile(RAW), MemoryFile(b'[General]\r\nVersion=305397761\r\nDisplayName=keep\r\n')]
        self.register = patch.object(gpo.smbclient, 'register_session').start()
        self.open = patch.object(gpo.smbclient, 'open_file', side_effect=lambda path, **kw:
                                 self.handles[1 if path.endswith('GPT.ini') else 0]).start()
        self.reset = patch.object(gpo.smbclient, 'reset_connection_cache').start()
        self.addCleanup(patch.stopall)

    def test_reads_real_schema_metadata_and_requires_encryption(self):
        result = self.editor.read()
        self.assertEqual(result['source']['name'], 'Default Domain Policy')
        self.assertEqual(result['policy']['min_password_length'], 8)
        self.register.assert_called_once()
        self.assertTrue(self.register.call_args.kwargs['encrypt'])
        self.assertTrue(self.register.call_args.kwargs['require_signing'])
        for call in self.open.call_args_list:
            self.assertTrue(call.args[0].startswith('\\\\dc.test\\SYSVOL\\AD2012.LAB\\Policies\\'))
            self.assertEqual(call.kwargs['mode'], 'rb')
            self.assertEqual(call.kwargs['share_access'], 'r')
        self.reset.assert_called_once()

    def test_preview_makes_no_writes_or_backups(self):
        before = [h.getvalue() for h in self.handles]
        snapshot = self.editor.read()
        result = self.editor.preview(snapshot['revision'], {'min_age_days': 0})
        self.assertEqual(result['diff'], [{'key': 'min_age_days', 'before': 1, 'after': 0}])
        self.assertEqual([h.getvalue() for h in self.handles], before)
        self.assertEqual(list(Path(self.temporary.name).iterdir()), [])

    def test_save_backs_up_and_updates_both_versions(self):
        snapshot = self.editor.read()
        result = self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertEqual(result['source']['version'], 0x12340002)
        self.assertEqual(result['policy']['min_age_days'], 0)
        backup = Path(self.temporary.name) / result['backup_id']
        self.assertEqual((backup / 'GptTmpl.inf').read_bytes(), RAW)
        self.assertEqual(json.loads((backup / 'metadata.json').read_text())['revision'], snapshot['revision'])
        self.assertIn(b'DisplayName=keep', self.handles[1].getvalue())
        self.assertEqual(self.open.call_args.kwargs['mode'], 'r+b')

    def test_stale_revision_and_mismatched_versions_fail_before_write(self):
        with self.assertRaises(gpo.PolicyError) as error:
            self.editor.save('stale', {'min_age_days': 0})
        self.assertEqual(error.exception.status, 409)
        self.handles[1] = MemoryFile(b'[General]\nVersion=0\n')
        with self.assertRaises(gpo.PolicyError) as error:
            self.editor.read()
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(list(Path(self.temporary.name).iterdir()), [])

    def test_backup_failure_prevents_remote_writes(self):
        snapshot = self.editor.read()
        with patch.object(self.editor, 'backup', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertEqual(self.handles[0].getvalue(), RAW)
        self.assertEqual(self.editor.read()['revision'], snapshot['revision'])

    def test_exact_old_value_modify_rejects_stale_version_atomically(self):
        with self.assertRaises(gpo.PolicyError):
            self.editor.compare_version(123, 124)
        self.assertEqual(self.editor.metadata()['version'], 0x12340001)

    def test_each_write_boundary_rolls_back(self):
        for failure_index in (1, 2):
            with self.subTest(failure_index=failure_index):
                snapshot = self.editor.read()
                replace = self.editor.replace
                count = 0

                def fail_once(handle, data):
                    nonlocal count
                    count += 1
                    if count == failure_index:
                        handle.seek(0)
                        handle.write(b'partial')
                        raise OSError('write interrupted')
                    return replace(handle, data)

                with patch.object(self.editor, 'replace', side_effect=fail_once), self.assertRaises(gpo.PolicyError) as error:
                    self.editor.save(snapshot['revision'], {'min_age_days': 0})
                self.assertFalse(error.exception.recovery_required)
                self.assertIsNotNone(error.exception.backup_id)
                self.assertEqual(self.editor.read()['revision'], snapshot['revision'])

    def test_uncertain_ldap_commit_is_detected_and_restored(self):
        snapshot = self.editor.read()
        original = self.editor.compare_version
        count = 0

        def commit_then_timeout(old, new):
            nonlocal count
            original(old, new)
            count += 1
            if count == 1:
                raise TimeoutError('reply lost')

        with patch.object(self.editor, 'compare_version', side_effect=commit_then_timeout), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertFalse(error.exception.recovery_required)
        self.assertEqual(self.editor.read()['revision'], snapshot['revision'])

    def test_failed_recovery_is_explicit(self):
        snapshot = self.editor.read()
        with patch.object(self.editor, 'replace', side_effect=OSError('offline')), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertTrue(error.exception.recovery_required)
        self.assertIsNotNone(error.exception.backup_id)

    def test_untrusted_paths_disabled_unlinked_or_uninitialized_gpo_fail(self):
        for changes in ({'gPCFileSysPath': '\\\\evil\\other\\AD2012.LAB\\Policies\\' + self.guid},
                        {'flags': 2}, {'gPCMachineExtensionNames': ''}, {'gPCWQLFilter': 'untrusted'}):
            with self.subTest(changes=changes):
                attrs = dict(self.gpo_attrs, **changes)
                del self.conn.strategy.entries[self.dn]
                self.conn.strategy.add_entry(self.dn, attrs)
                with self.assertRaises(gpo.PolicyError):
                    self.editor.read()
        del self.conn.strategy.entries[self.dn]
        self.conn.strategy.add_entry(self.dn, self.gpo_attrs)
        self.conn.modify(self.domain, {'gPLink': [(ldap3.MODIFY_REPLACE, [f'[LDAP://{self.dn};1]'])]})
        with self.assertRaises(gpo.PolicyError):
            self.editor.read()

    def test_dn_credentials_rejected_before_smb_authentication(self):
        with self.assertRaises(gpo.PolicyError):
            gpo.GpoPasswordPolicy(self.conn, self.temporary.name, username='CN=Administrator,CN=Users', password='test')
        self.register.assert_not_called()

    def test_chunked_smb_read_and_write_preserve_complete_template(self):
        class ChunkedFile(MemoryFile):
            def read(self, size=-1):
                return super().read(min(size, 37))

            def write(self, data):
                return super().write(data[:23])

        large = RAW + ('; unrelated data retained\r\n' * 5000).encode('utf-16-le')
        self.handles[0] = ChunkedFile(large)
        snapshot = self.editor.read()
        result = self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertEqual(result['policy']['min_age_days'], 0)
        self.assertEqual(self.handles[0].getvalue(), large.replace('MinimumPasswordAge = 1'.encode('utf-16-le'),
                                                                                'MinimumPasswordAge = 0'.encode('utf-16-le')))

    def test_non_ldaps_connection_is_rejected(self):
        self.conn.server.ssl = False
        with self.assertRaises(gpo.PolicyError):
            gpo.GpoPasswordPolicy(self.conn, self.temporary.name, username='test@AD2012.LAB', password='test')
        self.register.assert_not_called()

    def test_unverified_ldaps_connection_is_rejected(self):
        self.conn.server.tls = ldap3.Tls(validate=ssl.CERT_NONE)
        with self.assertRaises(gpo.PolicyError):
            gpo.GpoPasswordPolicy(self.conn, self.temporary.name, username='test@AD2012.LAB', password='test')
        self.register.assert_not_called()

    def test_concurrent_ldap_change_does_not_get_overwritten_by_rollback(self):
        snapshot = self.editor.read()

        def concurrent_change(old, new):
            self.conn.modify(self.dn, {'versionNumber': [(ldap3.MODIFY_REPLACE, [str(new + 1)])]})
            raise OSError('concurrent edit')

        with patch.object(self.editor, 'compare_version', side_effect=concurrent_change), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertTrue(error.exception.recovery_required)
        self.assertEqual(self.editor.metadata()['version'], 0x12340003)

    def test_post_write_readback_mismatch_restores_original(self):
        snapshot = self.editor.read()
        original = self.editor.snapshot
        calls = 0

        def mismatched(handles):
            nonlocal calls
            calls += 1
            result, raw = original(handles)
            return (result, [b'mismatch', raw[1]]) if calls == 2 else (result, raw)

        with patch.object(self.editor, 'snapshot', side_effect=mismatched), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(snapshot['revision'], {'min_age_days': 0})
        self.assertFalse(error.exception.recovery_required)
        self.assertEqual(self.editor.read()['revision'], snapshot['revision'])

    def test_cleanup_failure_does_not_mask_verified_save_or_original_error(self):
        snapshot = self.editor.read()
        with patch.object(gpo.smbclient, 'reset_connection_cache', side_effect=OSError('disconnect')):
            result = self.editor.save(snapshot['revision'], {'min_age_days': 0})
            self.assertEqual(result['policy']['min_age_days'], 0)
            self.assertIsNotNone(result['backup_id'])
            with self.assertRaises(gpo.PolicyError) as error:
                self.editor.preview('stale', {'min_age_days': 2})
            self.assertEqual(error.exception.status, 409)


class GpoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        domain_tests.DomainPasswordPolicyTests.setUpClass.__func__(cls)
        cls.original_connector = staticmethod(cls.platform.get_gpo_ad_connection)

    def setUp(self):
        domain_tests.DomainPasswordPolicyTests.setUp(self)
        self.env = patch.dict(os.environ, {'GPO_PASSWORD_POLICY_ENABLED': 'true',
                                          'GPO_PASSWORD_POLICY_WRITE_ENABLED': 'true',
                                          'GPO_SMB_USERNAME': '', 'GPO_SMB_PASSWORD': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.get_connection = patch.object(self.platform, 'get_gpo_ad_connection', return_value=self.conn).start()
        self.factory = patch.object(self.platform, 'GpoPasswordPolicy').start()
        self.addCleanup(patch.stopall)
        self.editor = self.factory.return_value
        self.editor.guid = gpo.DEFAULT_GUID
        self.result = {'source': {'name': 'Test', 'guid': gpo.DEFAULT_GUID, 'version': 1, 'dc': 'dc.test'},
                       'policy': gpo.read_policy(RAW), 'revision': 'revision'}
        self.editor.read.return_value = self.result
        self.editor.preview.return_value = dict(self.result, diff=[{'key': 'min_age_days', 'before': 1, 'after': 0}])
        self.editor.save.return_value = dict(self.result, backup_id='test-backup')
        self.url = '/api/admin/domain_password_policy/gpo'
        self.payload = {'revision': 'revision', 'changes': {'min_age_days': 0}}

    def headers(self):
        response = self.client.get(self.url)
        return {'X-CSRF-Token': response.json['csrf_token']}

    def test_disabled_feature_has_no_ad_or_smb_calls(self):
        with patch.dict(os.environ, {'GPO_PASSWORD_POLICY_ENABLED': 'false'}):
            response = self.client.get(self.url)
            self.assertFalse(response.json['enabled'])
            self.assertEqual(self.client.post(self.url, json={}).status_code, 403)
        self.get_connection.assert_not_called()
        self.factory.assert_not_called()

    def test_read_only_config_rejects_preview_and_save(self):
        headers = self.headers()
        with patch.dict(os.environ, {'GPO_PASSWORD_POLICY_WRITE_ENABLED': 'false'}):
            for url in (self.url, self.url + '/preview'):
                self.assertEqual(self.client.post(url, json=self.payload, headers=headers).status_code, 403)
        self.editor.save.assert_not_called()

    def test_csrf_preview_and_exact_confirmation_are_required(self):
        self.assertEqual(self.client.post(self.url, json=self.payload).status_code, 403)
        headers = self.headers()
        self.assertEqual(self.client.post(self.url, json=dict(self.payload, confirm_text='YES'), headers=headers).status_code, 409)
        self.assertTrue(self.client.post(self.url + '/preview', json=self.payload, headers=headers).json['success'])
        self.assertEqual(self.client.post(self.url, json=dict(self.payload, confirm_text='yes'), headers=headers).status_code, 409)
        self.editor.save.assert_not_called()

    def test_success_requires_matching_preview_and_records_audit(self):
        headers = self.headers()
        self.client.post(self.url + '/preview', json=self.payload, headers=headers)
        response = self.client.post(self.url, json=dict(self.payload, confirm_text='YES'), headers=headers)
        self.assertTrue(response.json['success'])
        self.editor.save.assert_called_once_with('revision', {'min_age_days': 0})
        self.assertEqual(self.platform.AdminActionLog.query.count(), 2)
        self.assertEqual(self.client.post(self.url, json=dict(self.payload, confirm_text='YES'), headers=headers).status_code, 409)

    def test_tampered_or_expired_preview_is_rejected(self):
        headers = self.headers()
        self.client.post(self.url + '/preview', json=self.payload, headers=headers)
        changed = dict(self.payload, changes={'min_age_days': 2}, confirm_text='YES')
        self.assertEqual(self.client.post(self.url, json=changed, headers=headers).status_code, 409)
        self.client.post(self.url + '/preview', json=self.payload, headers=headers)
        with patch.object(self.platform.time, 'time', return_value=10**12):
            response = self.client.post(self.url, json=dict(self.payload, confirm_text='YES'), headers=headers)
        self.assertFalse(response.json['success'])
        self.editor.save.assert_not_called()

    def test_audit_intent_failure_prevents_save(self):
        headers = self.headers()
        self.client.post(self.url + '/preview', json=self.payload, headers=headers)
        with patch.object(self.platform, 'write_admin_action', side_effect=OSError('audit unavailable')):
            response = self.client.post(self.url, json=dict(self.payload, confirm_text='YES'), headers=headers)
        self.assertEqual(response.status_code, 503)
        self.editor.save.assert_not_called()

    def test_completion_audit_failure_does_not_claim_remote_write_failed(self):
        headers = self.headers()
        self.client.post(self.url + '/preview', json=self.payload, headers=headers)
        with patch.object(self.platform, 'write_admin_action', side_effect=[None, OSError('audit unavailable')]):
            response = self.client.post(self.url, json=dict(self.payload, confirm_text='YES'), headers=headers)
        self.assertTrue(response.json['success'])
        self.assertIn('审计记录失败', response.json['message'])

    def test_recovery_status_and_errors_do_not_leak_credentials(self):
        self.editor.read.side_effect = RuntimeError('password=secret')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('secret', response.get_data(as_text=True))
        self.editor.read.side_effect = gpo.PolicyError('需核查备份', 503, backup_id='backup', recovery_required=True)
        response = self.client.get(self.url)
        self.assertTrue(response.json['recovery_required'])
        self.assertEqual(response.json['backup_id'], 'backup')

    def test_non_super_admin_and_logged_out_cannot_use_gpo(self):
        self.user.role = 'readonly'
        self.platform.db.session.commit()
        self.assertFalse(self.client.get(self.url).json['success'])
        with self.client.session_transaction() as session:
            session.clear()
        self.assertFalse(self.client.get(self.url).json['success'])
        self.factory.assert_not_called()

    def test_malformed_changes_fail_before_ad_connection(self):
        headers = self.headers()
        self.get_connection.reset_mock()
        for changes in (None, [], {}, {'unknown': True}, {'min_age_days': True}, {'complexity_enabled': 1}):
            with self.subTest(changes=changes):
                response = self.client.post(self.url + '/preview', json={'revision': 'revision', 'changes': changes}, headers=headers)
                self.assertEqual(response.status_code, 400)
        self.get_connection.assert_not_called()

    def test_gpo_connection_verifies_certificate_without_changing_existing_connector(self):
        # Call the real helper despite the API-test network stub.
        with patch.dict(os.environ, {'GPO_LDAP_SERVER': 'dc.example.test', 'GPO_LDAP_CA_CERTS_FILE': ''}), \
                patch.dict(self.platform.app.config, {'AD_BIND_USER': 'test@example.test', 'AD_BIND_PASSWORD': 'test-only'}), \
                patch.object(self.platform.ldap3, 'Connection') as connection:
            self.original_connector()
            server = connection.call_args.args[0]
            self.assertEqual(server.host, 'dc.example.test')
            self.assertTrue(server.ssl)
            self.assertEqual(server.tls.validate, ssl.CERT_REQUIRED)
            self.assertEqual(connection.call_args.kwargs['receive_timeout'], 15)

    def test_partial_smb_credentials_fail_without_authentication_attempt(self):
        for credentials in ({'GPO_SMB_USERNAME': 'other@test', 'GPO_SMB_PASSWORD': ''},
                            {'GPO_SMB_USERNAME': '', 'GPO_SMB_PASSWORD': 'test-only'}):
            with patch.dict(os.environ, credentials):
                self.assertEqual(self.client.get(self.url).status_code, 503)
        self.get_connection.assert_not_called()
        self.factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
