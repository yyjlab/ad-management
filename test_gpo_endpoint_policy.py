import codecs
import errno
import io
import json
import os
import ssl
import struct
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID
import xml.etree.ElementTree as ET

import ldap3
from smbprotocol.exceptions import SMBOSError
from smbprotocol.header import NtStatus

import gpo_endpoint_policy as gpo
import test_domain_password_policy as domain_tests

GUID = '11111111-2222-4333-8444-555555555555'
FILTER_GUID = '{88888888-7777-4666-8555-444444444444}'
QUERY = 'SELECT * FROM Win32_OperatingSystem WHERE ProductType = 1'
FILTER = f'1;3;10;{len(QUERY)};WQL;root\\CIMv2;{QUERY};'
ROOT = r'\\files.test\Software'
SOFTWARE = {'enabled': True, 'name': 'Test App', 'source': ROOT + r'\app.exe'}


class FormatTests(unittest.TestCase):
    def test_registry_roundtrip_keeps_unrelated_binary_and_utf16(self):
        unrelated = gpo.pol_dword('Other\\设置', 'Other', 123)
        raw = gpo.POL_HEADER + unrelated
        for mode in ('readonly', 'deny', 'allow', 'undefined'):
            raw = gpo.patch_usb(raw, mode)
            self.assertEqual(gpo.read_usb(raw)['mode'], mode)
            self.assertIn(unrelated, raw)
        self.assertEqual(raw, gpo.POL_HEADER + unrelated)

    def test_real_removable_disk_class_and_dword_values(self):
        self.assertIn('53f5630d', gpo.USB_KEY)
        raw = gpo.patch_usb(None, 'readonly')
        records = gpo.parse_pol(raw)
        self.assertEqual([(r[1], r[2], struct.unpack('<I', r[3])[0]) for r in records],
                         [('Deny_Read', 4, 0), ('Deny_Write', 4, 1)])
        self.assertNotIn(b'USBSTOR', raw)

    def test_malformed_registry_duplicate_and_control_entries_fail_closed(self):
        one = gpo.pol_dword(gpo.USB_KEY, 'Deny_Read', 1)
        for raw in (b'', b'PReg' + b'\x00' * 4, gpo.POL_HEADER + one[:-1],
                    gpo.POL_HEADER + one + one,
                    gpo.POL_HEADER + gpo.pol_dword(gpo.USB_KEY, '**DelVals', 1),
                    gpo.POL_HEADER + gpo.pol_dword(gpo.USB_KEY, 'Deny_Read', 99)):
            with self.subTest(raw=raw), self.assertRaises(gpo.PolicyError):
                gpo.read_usb(raw)
        self.assertEqual(gpo.read_usb(gpo.POL_HEADER + one)['mode'], 'custom')

    def test_strict_policy_whitelist_and_types(self):
        cases = [('lock', {'seconds': True}), ('lock', {'seconds': 600.0}), ('lock', {'seconds': -1}),
                 ('lock', {'seconds': 599941}), ('usb', {'mode': 'custom'}), ('software', dict(SOFTWARE, launch=True)),
                 ('software', dict(SOFTWARE, name='bad&name')), ('software', dict(SOFTWARE, source=r'\\evil.test\Software\app.exe'))]
        for kind, value in cases:
            with self.subTest(value=value), self.assertRaises(gpo.PolicyError):
                gpo.validate_policy(kind, value, ROOT)
        for value in (None, 0, 1, 901, 599940):
            gpo.validate_policy('lock', {'seconds': value})
        gpo.validate_policy('software', SOFTWARE, ROOT)

    def test_source_path_rejects_traversal_urls_devices_and_share_prefix_confusion(self):
        for value in (ROOT + r'\..\app.exe', ROOT + r'\x.\app.exe', ROOT + r'\x%PATH%\app.exe',
                      ROOT + r'Other\app.exe', ROOT + r'\app.exe:stream', r'C:\app.exe',
                      'https://evil.test/app.exe', r'\\files.test\Software\*.exe', r'\\?\C:\app.exe', ROOT + r'\app.zip'):
            with self.subTest(value=value), self.assertRaises(gpo.PolicyError):
                gpo.source_path(value, ROOT)

    def test_xml_rejects_entities_and_preserves_other_items(self):
        for raw in (b'<Other/>', b'<!DOCTYPE Files [<!ENTITY x "bad">]><Files/>',
                    codecs.BOM_UTF16_LE + '<!DOCTYPE Files><Files/>'.encode('utf-16-le')):
            with self.assertRaises(gpo.PolicyError):
                gpo.xml_document(raw, 'Files')
        root = gpo.xml_document(None, 'Files')
        ET.SubElement(root, 'File', {'uid': '{OTHER}', 'name': 'keep'})
        root = gpo.xml_document(ET.tostring(root), 'Files')
        self.assertEqual(root.find('File').get('name'), 'keep')

    def test_wmi_must_be_exact_workstation_query_and_lengths(self):
        self.assertTrue(gpo.workstation_filter(FILTER))
        for value in (FILTER.replace('= 1', '= 2'), FILTER + FILTER, FILTER.replace(f';{len(QUERY)};', ';999;'),
                      FILTER.replace('ProductType = 1', 'ProductType = 1 OR 1=1'), ''):
            self.assertFalse(gpo.workstation_filter(value))

    def test_extension_merge_preserves_existing_and_adds_correct_client_and_tool_ids(self):
        old = '[{35378eac-683f-11d2-a89a-00c04fbbcfa2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
        merged = gpo.extension_list(old, gpo.EXTENSIONS['software'])
        self.assertIn('35378EAC', merged)
        for group in gpo.EXTENSIONS['software']:
            for value in group:
                self.assertIn(value, merged)
        self.assertEqual(gpo.extension_list(merged, gpo.EXTENSIONS['software']), merged)
        with self.assertRaises(gpo.PolicyError):
            gpo.extension_list('garbage', ())


class MemoryFile(io.BytesIO):
    def close(self):
        pass


class EditorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ad-endpoint-gpo-')
        self.addCleanup(self.temp.cleanup)
        self.conn = ldap3.Connection(ldap3.Server('dc.test', use_ssl=True,
            tls=ldap3.Tls(validate=ssl.CERT_REQUIRED), get_info=ldap3.OFFLINE_AD_2012_R2), client_strategy=ldap3.MOCK_SYNC)
        self.domain = self.conn.server.info.other['defaultNamingContext'][0]
        self.guid = '{' + GUID.upper() + '}'
        self.dn = f'CN={self.guid},CN=Policies,CN=System,{self.domain}'
        self.attrs = {'objectClass': ['top', 'container', 'groupPolicyContainer'], 'cn': self.guid,
            'displayName': 'Endpoint test', 'versionNumber': 0x12340001, 'flags': 0,
            'gPCFileSysPath': f'\\\\AD2012.LAB\\SYSVOL\\AD2012.LAB\\Policies\\{self.guid}',
            'gPCWQLFilter': '[ad2012.lab;' + FILTER_GUID + ';0]'}
        self.conn.strategy.add_entry(self.dn, self.attrs)
        self.conn.strategy.add_entry(self.domain, {'objectClass': ['top', 'domain', 'domainDNS'], 'gPLink': f'[LDAP://{self.dn};0]'})
        self.filter_dn = f'CN={FILTER_GUID},CN=SOM,CN=WMIPolicy,CN=System,{self.domain}'
        self.conn.strategy.add_entry(self.filter_dn, {'objectClass': ['top', 'msWMI-Som'], 'msWMI-Parm2': FILTER})
        self.conn.bind()
        self.addCleanup(self.conn.unbind)
        self.editor = self.make_editor('lock')
        self.store = {self.editor.base + '\\GPT.ini': MemoryFile(b'[General]\r\nVersion=305397761\r\nOther=keep\r\n')}
        self.register = patch.object(gpo.smbclient, 'register_session').start()
        self.open = patch.object(gpo.smbclient, 'open_file', side_effect=self.open_file).start()
        self.mkdir = patch.object(gpo.smbclient, 'makedirs').start()
        self.remove = patch.object(gpo.smbclient, 'remove', side_effect=lambda path, **kw: self.store.pop(path)).start()
        self.reset = patch.object(gpo.smbclient, 'reset_connection_cache').start()
        self.addCleanup(patch.stopall)

    def make_editor(self, kind, **extra):
        return gpo.GpoEndpointPolicy(self.conn, self.temp.name, kind=kind, guid=GUID,
            domain_dn=self.domain, username='publisher@ad2012.lab', password='test-only', software_root=ROOT, **extra)

    def open_file(self, path, mode='rb', **kwargs):
        if mode == 'x+b':
            if path in self.store:
                raise FileExistsError(path)
            self.store[path] = MemoryFile()
        if path not in self.store:
            raise FileNotFoundError(path)
        return self.store[path]

    def test_read_is_readonly_and_checks_true_root_link_wmi_and_tls(self):
        result = self.editor.read()
        self.assertEqual(result['policy'], {'seconds': None})
        self.assertEqual(result['source']['scope'], 'workstations')
        self.assertTrue(all(call.kwargs['mode'] == 'rb' for call in self.open.call_args_list))
        self.mkdir.assert_not_called()
        self.remove.assert_not_called()
        self.assertTrue(self.register.call_args.kwargs['encrypt'])
        self.assertTrue(self.register.call_args.kwargs['require_signing'])

    def test_real_smb_missing_file_error_is_supported_but_permission_errors_are_not_absence(self):
        original = self.open_file
        def missing(path, **kwargs):
            try:
                return original(path, **kwargs)
            except FileNotFoundError:
                raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)
        with patch.object(gpo.smbclient, 'open_file', side_effect=missing):
            self.assertEqual(self.editor.read()['policy'], {'seconds': None})
        def denied(path, **kwargs):
            if not path.endswith('GPT.ini'):
                raise SMBOSError(NtStatus.STATUS_ACCESS_DENIED, path)
            return original(path, **kwargs)
        with patch.object(gpo.smbclient, 'open_file', side_effect=denied), self.assertRaises(SMBOSError):
            self.editor.read()
        self.mkdir.assert_not_called()

    def test_lock_save_preserves_other_security_settings_and_user_version(self):
        raw = codecs.BOM_UTF16_LE + ('[Registry Values]\r\nOther=4,9\r\n[System Access]\r\nMinimumPasswordLength=8\r\n').encode('utf-16-le')
        self.store[self.editor.base + '\\' + gpo.PATHS['lock'][0]] = MemoryFile(raw)
        before = self.editor.read()
        result = self.editor.save(before['revision'], {'seconds': 900})
        self.assertEqual(result['source']['version'], 0x12340002)
        self.assertEqual(result['policy']['seconds'], 900)
        template = self.store[self.editor.base + '\\' + gpo.PATHS['lock'][0]].getvalue()
        self.assertIn('MinimumPasswordLength=8', template.decode('utf-16'))
        self.assertIn('Other=4,9', template.decode('utf-16'))
        self.assertIn(gpo.EXTENSIONS['lock'][0][0], result['source']['gPCMachineExtensionNames'])
        self.assertTrue((gpo.Path(self.temp.name) / result['backup_id'] / 'metadata.json').is_file())

    def test_new_usb_file_and_preview_have_correct_publication_version(self):
        self.editor = self.make_editor('usb')
        before = self.editor.read()
        preview = self.editor.preview(before['revision'], {'mode': 'readonly'})
        self.assertEqual(preview['after'], {'mode': 'readonly'})
        self.assertEqual(len(self.store), 1)
        result = self.editor.save(before['revision'], {'mode': 'readonly'})
        self.assertEqual(result['policy'], {'mode': 'readonly'})
        self.assertEqual(result['source']['version'], 0x12340002)
        self.assertFalse(any('USBSTOR' in path for path in self.store))

    def test_software_writes_gpp_copy_and_desktop_only_in_user_context(self):
        self.editor = self.make_editor('software')
        before = self.editor.read()
        result = self.editor.save(before['revision'], SOFTWARE)
        self.assertEqual(result['source']['version'], 0x12350001)
        raw = {name: self.store[self.editor.base + '\\' + name].getvalue() for name in gpo.PATHS['software']}
        file = ET.fromstring(raw[gpo.PATHS['software'][0]]).find('File')
        shortcut = ET.fromstring(raw[gpo.PATHS['software'][1]]).find('Shortcut')
        self.assertEqual(file.get('userContext'), '1')
        self.assertEqual(file.find('Properties').get('fromPath'), SOFTWARE['source'])
        self.assertTrue(file.find('Properties').get('targetPath').startswith('%LocalAppDataDir%'))
        self.assertEqual(shortcut.get('userContext'), '1')
        self.assertTrue(shortcut.find('Properties').get('shortcutPath').startswith('%DesktopDir%'))
        self.assertEqual(shortcut.find('Properties').get('arguments'), '')
        self.assertNotIn(b'Startup', b''.join(raw.values()))
        self.assertFalse(any(path.endswith('.exe') for path in self.store))
        disabled = self.editor.save(result['revision'], {'enabled': False, 'source': '', 'name': ''})
        roots = [ET.fromstring(self.store[self.editor.base + '\\' + path].getvalue()) for path in gpo.PATHS['software'][:2]]
        self.assertEqual(len(roots[0]), 0)
        self.assertEqual(roots[1].find('Shortcut/Properties').get('action'), 'D')
        self.assertEqual(disabled['policy']['enabled'], False)

    def test_software_preserves_other_preference_items_and_rejects_out_of_band_owned_changes(self):
        self.editor = self.make_editor('software')
        files = gpo.xml_document(None, 'Files')
        ET.SubElement(files, 'File', {'uid': '{OTHER}', 'name': 'Keep other preference'})
        file_path = self.editor.base + '\\' + gpo.PATHS['software'][0]
        self.store[file_path] = MemoryFile(ET.tostring(files))
        before = self.editor.read()
        self.editor.save(before['revision'], SOFTWARE)
        files = ET.fromstring(self.store[file_path].getvalue())
        self.assertEqual(files.find("File[@uid='{OTHER}']").get('name'), 'Keep other preference')
        managed = next(child for child in files if child.get('uid') != '{OTHER}')
        managed.find('Properties').set('fromPath', r'\\evil.test\public\bad.exe')
        self.store[file_path] = MemoryFile(ET.tostring(files))
        with self.assertRaises(gpo.PolicyError):
            self.editor.read()

    def test_new_file_creation_race_never_overwrites_another_writer(self):
        before = self.editor.read()
        original = self.open_file
        created_path = self.editor.base + '\\' + gpo.PATHS['lock'][0]
        def race(path, **kwargs):
            if path == created_path and kwargs['mode'] == 'x+b':
                self.store[path] = MemoryFile(b'other writer')
                raise OSError(errno.EEXIST, 'other writer created it')
            return original(path, **kwargs)
        with patch.object(gpo.smbclient, 'open_file', side_effect=race), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(before['revision'], {'seconds': 60})
        self.assertTrue(error.exception.recovery_required)
        self.assertEqual(self.store[created_path].getvalue(), b'other writer')

    def test_user_version_wrap_keeps_computer_version(self):
        self.editor = self.make_editor('software')
        version = 0xffff1234
        self.conn.modify(self.dn, {'versionNumber': [(ldap3.MODIFY_REPLACE, [str(version)])]})
        self.store[self.editor.base + '\\GPT.ini'] = MemoryFile(f'[General]\r\nVersion={version}\r\n'.encode())
        before = self.editor.read()
        result = self.editor.save(before['revision'], SOFTWARE)
        self.assertEqual(result['source']['version'], 0x00011234)

    def test_builtin_gpo_wrong_domain_unsafe_tls_and_all_device_scope_are_blocked(self):
        for guid in ('31b2f340-016d-11d2-945f-00c04fb984f9', '6ac1786c-016f-11d2-945f-00c04fb984f9'):
            with self.assertRaises(gpo.PolicyError):
                gpo.GpoEndpointPolicy(self.conn, self.temp.name, kind='lock', guid=guid,
                    domain_dn=self.domain, username='user@test', password='test')
        with self.assertRaises(gpo.PolicyError):
            self.make_editor('lock', scope='all')
        self.conn.server.tls.validate = ssl.CERT_NONE
        with self.assertRaises(gpo.PolicyError):
            self.make_editor('lock')

    def test_missing_root_link_wmi_server_query_and_disabled_configuration_fail_closed(self):
        for changes in ({'gPCWQLFilter': ''}, {'flags': '2'}, {'gPCFileSysPath': r'\\evil\share\x'}):
            self.conn.modify(self.dn, {key: [(ldap3.MODIFY_REPLACE, [value])] for key, value in changes.items()})
            with self.assertRaises(gpo.PolicyError):
                self.editor.read()
            self.conn.modify(self.dn, {key: [(ldap3.MODIFY_REPLACE,
                self.attrs[key] if isinstance(self.attrs[key], list) else [self.attrs[key]])] for key in changes})
        self.conn.modify(self.filter_dn, {'msWMI-Parm2': [(ldap3.MODIFY_REPLACE, [FILTER.replace('= 1', '= 2')])]})
        with self.assertRaises(gpo.PolicyError):
            self.editor.read()
        self.conn.modify(self.filter_dn, {'msWMI-Parm2': [(ldap3.MODIFY_REPLACE, [FILTER])]})
        self.conn.modify(self.domain, {'gPLink': [(ldap3.MODIFY_REPLACE, [f'[LDAP://{self.dn};1]'])]})
        with self.assertRaises(gpo.PolicyError):
            self.editor.read()

    def test_stale_revision_version_mismatch_and_noop_do_not_write(self):
        before = self.editor.read()
        with self.assertRaises(gpo.PolicyError):
            self.editor.save('stale', {'seconds': 60})
        with self.assertRaises(gpo.PolicyError):
            self.editor.save(before['revision'], {'seconds': None})
        self.assertEqual(len(self.store), 1)
        self.conn.modify(self.dn, {'versionNumber': [(ldap3.MODIFY_REPLACE, ['99'])]})
        with self.assertRaises(gpo.PolicyError):
            self.editor.read()

    def test_write_failure_rolls_back_created_files_and_exact_metadata(self):
        before = self.editor.read()
        real = self.editor.compare_metadata
        with patch.object(self.editor, 'compare_metadata', side_effect=OSError('before LDAP publication')):
            with self.assertRaises(gpo.PolicyError) as error:
                self.editor.save(before['revision'], {'seconds': 900})
        self.assertFalse(error.exception.recovery_required)
        self.assertEqual(self.editor.read()['revision'], before['revision'])
        self.assertEqual(len(self.store), 1)
        self.assertTrue(error.exception.backup_id)
        self.assertIsNotNone(real)

    def test_failure_after_publication_restores_old_version_and_files(self):
        before = self.editor.read()
        original = gpo.GpoPasswordPolicy.replace
        failed = False
        def replace(handle, data):
            nonlocal failed
            if data.startswith(b'[General]') and b'305397762' in data and not failed:
                failed = True
                raise OSError('publication marker write failed')
            return original(handle, data)
        with patch.object(gpo.GpoPasswordPolicy, 'replace', side_effect=replace), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(before['revision'], {'seconds': 900})
        self.assertFalse(error.exception.recovery_required)
        self.assertEqual(self.editor.read()['revision'], before['revision'])

    def test_rollback_failure_is_explicit_and_returns_backup(self):
        before = self.editor.read()
        with patch.object(self.editor, 'compare_metadata', side_effect=OSError('failed')), \
                patch.object(gpo.smbclient, 'remove', side_effect=OSError('cannot restore')), self.assertRaises(gpo.PolicyError) as error:
            self.editor.save(before['revision'], {'seconds': 900})
        self.assertTrue(error.exception.recovery_required)
        self.assertTrue(error.exception.backup_id)

    def test_cleanup_error_does_not_turn_verified_save_into_failure(self):
        before = self.editor.read()
        with patch.object(gpo.smbclient, 'reset_connection_cache', side_effect=OSError('cleanup')):
            result = self.editor.save(before['revision'], {'seconds': 600})
        self.assertEqual(result['policy']['seconds'], 600)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        domain_tests.DomainPasswordPolicyTests.setUpClass.__func__(cls)

    def setUp(self):
        domain_tests.DomainPasswordPolicyTests.setUp(self)
        self.env = patch.dict(os.environ, {'GPO_ENDPOINT_POLICY_ENABLED': 'true',
            'GPO_ENDPOINT_POLICY_WRITE_ENABLED': 'true', 'GPO_ENDPOINT_LOCK_GUID': GUID,
            'GPO_ENDPOINT_USB_GUID': '22222222-3333-4444-8555-666666666666',
            'GPO_ENDPOINT_SOFTWARE_GUID': '33333333-4444-4555-8666-777777777777',
            'GPO_SOFTWARE_SOURCE_ROOT': ROOT, 'GPO_SMB_USERNAME': '', 'GPO_SMB_PASSWORD': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.config = patch.dict(self.platform.app.config, {'AD_BASE_DN': self.domain_dn})
        self.config.start()
        self.addCleanup(self.config.stop)
        self.connect = patch.object(self.platform, 'get_gpo_ad_connection', return_value=self.conn).start()
        self.factory = patch.object(self.platform, 'GpoEndpointPolicy').start()
        self.addCleanup(patch.stopall)
        self.editor = self.factory.return_value
        self.editor.guid = GUID
        self.state = {'source': {'name': 'Test', 'guid': GUID, 'version': 1, 'dc': 'dc.test', 'scope': 'workstations'},
            'policy': {'seconds': 300}, 'revision': 'a' * 64}
        self.editor.read.return_value = self.state
        self.editor.preview.return_value = dict(self.state, after={'seconds': 900})
        self.editor.save.return_value = dict(self.state, policy={'seconds': 900}, backup_id='backup-test')
        self.url = '/api/admin/gpo-endpoint/lock'
        self.payload = {'revision': 'a' * 64, 'policy': {'seconds': 900}}

    def headers(self):
        return {'X-CSRF-Token': self.client.get(self.url).json['csrf_token']}

    def preview(self, headers):
        return self.client.post(self.url + '/preview', json=self.payload, headers=headers)

    def save(self, headers, **extra):
        payload = dict(self.payload, confirm_text='YES', confirm_scope=self.domain_dn)
        payload.update(extra)
        return self.client.post(self.url, json=payload, headers=headers)

    def test_disabled_feature_and_readonly_flags_never_write(self):
        with patch.dict(os.environ, {'GPO_ENDPOINT_POLICY_ENABLED': 'false'}):
            self.assertFalse(self.client.get(self.url).json['enabled'])
            self.assertEqual(self.client.post(self.url, json={}).status_code, 403)
        self.connect.assert_not_called()
        headers = self.headers()
        with patch.dict(os.environ, {'GPO_ENDPOINT_POLICY_WRITE_ENABLED': 'false'}):
            self.assertEqual(self.preview(headers).status_code, 403)
            self.assertEqual(self.save(headers).status_code, 403)
        self.editor.save.assert_not_called()

    def test_preview_yes_and_exact_domain_scope_required(self):
        self.assertEqual(self.save({}).status_code, 403)
        headers = self.headers()
        self.assertEqual(self.save(headers).status_code, 409)
        self.assertTrue(self.preview(headers).json['success'])
        self.assertEqual(self.save(headers, confirm_scope='other-domain').status_code, 409)
        self.preview(headers)
        self.assertEqual(self.save(headers, confirm_text='yes').status_code, 409)
        self.editor.save.assert_not_called()

    def test_save_audit_and_replay_protection(self):
        headers = self.headers()
        self.preview(headers)
        response = self.save(headers)
        self.assertTrue(response.json['success'])
        self.assertIn('不代表客户端已应用', response.json['message'])
        self.assertEqual(self.platform.AdminActionLog.query.count(), 2)
        self.assertEqual(self.save(headers).status_code, 409)
        self.assertEqual(self.editor.save.call_count, 1)

    def test_usb_software_routes_and_preview_tickets_are_separate(self):
        headers = self.headers()
        self.preview(headers)
        for kind, policy in (('usb', {'mode': 'readonly'}), ('software', SOFTWARE)):
            url = '/api/admin/gpo-endpoint/' + kind
            payload = {'revision': 'a' * 64, 'policy': policy}
            confirmed = dict(payload, confirm_text='YES', confirm_scope=self.domain_dn)
            self.assertEqual(self.client.post(url, json=confirmed, headers=headers).status_code, 409)
            response = self.client.post(url + '/preview', json=payload, headers=headers)
            self.assertTrue(response.json['success'])
            response = self.client.post(url, json=confirmed, headers=headers)
            self.assertTrue(response.json['success'])
            self.editor.save.assert_called_with('a' * 64, policy)
            self.assertEqual(self.factory.call_args.kwargs['kind'], kind)
        self.assertTrue(self.save(headers).json['success'])

    def test_tamper_and_expiry_are_rejected(self):
        headers = self.headers()
        self.preview(headers)
        self.assertEqual(self.save(headers, policy={'seconds': 60}).status_code, 409)
        self.preview(headers)
        with self.client.session_transaction() as session:
            ticket = dict(session['endpoint_policy_preview_lock'])
            ticket['at'] -= 301
            session['endpoint_policy_preview_lock'] = ticket
        self.assertEqual(self.save(headers).status_code, 409)
        self.editor.save.assert_not_called()

    def test_non_superadmin_role_changes_cannot_write(self):
        headers = self.headers()
        self.preview(headers)
        self.user.role = 'admin'
        self.platform.db.session.commit()
        self.assertFalse(self.save(headers).json['success'])
        self.editor.save.assert_not_called()

    def test_duplicate_or_missing_gpo_and_partial_credentials_fail_before_connect(self):
        for change in ({'GPO_ENDPOINT_LOCK_GUID': ''}, {'GPO_ENDPOINT_USB_GUID': GUID}, {'GPO_PASSWORD_POLICY_GUID': GUID},
                       {'GPO_SMB_USERNAME': 'test@domain', 'GPO_SMB_PASSWORD': ''}):
            with patch.dict(os.environ, change):
                self.assertEqual(self.client.get(self.url).status_code, 503)
        self.connect.assert_not_called()

    def test_malformed_inputs_never_reach_ad(self):
        headers = self.headers()
        self.connect.reset_mock()
        for policy in (None, [], {}, {'seconds': True}, {'seconds': '900'}, {'seconds': 599941}):
            response = self.client.post(self.url + '/preview', json=dict(self.payload, policy=policy), headers=headers)
            self.assertEqual(response.status_code, 400)
        self.connect.assert_not_called()

    def test_audit_failure_prevents_gpo_mutation_and_secrets_are_not_returned(self):
        headers = self.headers()
        self.preview(headers)
        with patch.object(self.platform, 'write_admin_action', side_effect=OSError('secret=password')):
            response = self.save(headers)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('secret=password', response.get_data(as_text=True))
        self.editor.save.assert_not_called()

    def test_uncertain_recovery_is_reported_and_not_automatically_retried(self):
        headers = self.headers()
        self.preview(headers)
        self.editor.save.side_effect = gpo.PolicyError('需按备份核查', 503, backup_id='backup-test', recovery_required=True)
        response = self.save(headers)
        self.assertTrue(response.json['recovery_required'])
        self.assertEqual(response.json['backup_id'], 'backup-test')
        self.assertEqual(self.save(headers).status_code, 409)
        self.assertEqual(self.editor.save.call_count, 1)


if __name__ == '__main__':
    unittest.main()
