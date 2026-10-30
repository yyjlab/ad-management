import base64
import copy
import io
import json
import secrets
import tempfile
import time
import unittest
import uuid
import xml.etree.ElementTree as ET
import zipfile

from types import SimpleNamespace
from flask import Flask, session
from pc_deploy import register_pc_deploy, token_hash
from pc_deploy.deployment import (Invalid, NAMESPACE, answer_file, canonical, digest, inventory,
                        public_url, source_record, target_check, unc_path)


def machine(number=3, serial='TEST-LAPTOP-001', hardware=None, bus='NVMe'):
    return dict(hardware_uuid=hardware or str(uuid.uuid4()), boot_id=str(uuid.uuid4()),
                model='Test workstation', serial=serial, firmware='UEFI', architecture='amd64',
                ram_bytes=16*1024**3, secure_boot=True, tpm2=True, macs=['02:11:22:33:44:55'],
                disks=[dict(number=number, serial='TEST-SSD-001', unique_id='test-unique-disk',
                            model='Test SSD', size_bytes=512*1024**3, bus=bus, read_only=False, offline=False)])


def install_source():
    return dict(name='Test Windows 11', path=r'\\test-fileserver\install\win11', family='windows11',
                image_file='sources\\install.wim', image_sha256='a'*64, setup_sha256='b'*64,
                smb_user=r'TEST-FILESERVER\deploy-read', password='Test-only-share-secret',
                images=[dict(index=6, name='Windows 11 Pro', build=26100, architecture='amd64', language='zh-CN')])


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='pcdeploy-test-')
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY='isolated-pc-deploy-test-key',
                               PC_DEPLOY_DATA_DIR=self.directory.name)
        register_pc_deploy(self.app,
            lambda: SimpleNamespace(username=session.get('admin_username'), role=session.get('admin_role')),
            lambda: None)
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s.update(admin_logged_in=True, admin_username='test-super-admin', admin_role='super_admin')
        self.csrf = self.client.get('/pc-deploy/api/session').json['csrf']
        self.client.get('/pc-deploy/api/dashboard')
        self.store = self.app.extensions['pc_deploy_store']
        self.enrollment = secrets.token_urlsafe(40)
        with self.store.connect(write=True) as c:
            c.execute('INSERT INTO enrollments VALUES(?,?,0)', (token_hash(self.enrollment), time.time()+3600))

    def tearDown(self):
        self.directory.cleanup()

    def post(self, path, data=None, token=None, method='POST'):
        headers = {'X-CSRF-Token': self.csrf}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        return self.client.open(path, method=method, json=data or {}, headers=headers)

    def register(self, value=None):
        value = value or machine()
        r = self.post('/pc-deploy/api/agent/register', value, self.enrollment)
        self.assertEqual(r.status_code, 200, r.json)
        return value, r.json

    def fixtures(self, value=None):
        inv, reg = self.register(value)
        s = self.post('/pc-deploy/api/sources', install_source())
        self.assertEqual(s.status_code, 200, s.json)
        p = self.post('/pc-deploy/api/profiles', dict(name='Test profile', source_id=s.json['id'], image_index=6,
                      username='ITSetup', password='Test-only-local-password', system_gib=128, computer_prefix='TEST'))
        self.assertEqual(p.status_code, 200, p.json)
        return inv, reg, s.json['id'], p.json['id']

    def preview(self, inv, profile):
        return self.post('/pc-deploy/api/jobs/preview', dict(profile_id=profile,
                         targets=[dict(device_id=inv['hardware_uuid'], disk_key=inventory(inv)['disks'][0]['key'])]))

    def enable(self, enabled=True):
        with self.store.connect(write=True) as c:
            self.store.put(c, 'enabled', enabled)
            self.store.put(c, 'public_url', 'https://deploy.test/pc-deploy')

    def queued(self):
        inv, reg, source, profile = self.fixtures()
        pv = self.preview(inv, profile)
        self.assertEqual(pv.status_code, 200, pv.json)
        self.enable()
        commit = self.post('/pc-deploy/api/jobs/commit', dict(preview_id=pv.json['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(commit.status_code, 200, commit.json)
        return inv, reg, commit.json['ids'][0]

    def test_default_is_read_only_and_empty(self):
        d = self.client.get('/pc-deploy/api/dashboard').json
        self.assertFalse(d['settings']['enabled'])
        self.assertEqual(d['devices'], [])
        self.assertEqual(d['jobs'], [])
        self.assertFalse(any(d['boot_files'].values()))

    def test_admin_authentication_required(self):
        client = self.app.test_client()
        self.assertEqual(client.get('/pc-deploy/api/dashboard').status_code, 401)
        self.assertEqual(client.post('/pc-deploy/api/sources', json=install_source()).status_code, 401)

    def test_csrf_required(self):
        self.assertEqual(self.client.post('/pc-deploy/api/sources', json=install_source()).status_code, 403)

    def test_foreign_origin_rejected(self):
        r = self.client.post('/pc-deploy/api/sources', json=install_source(),
                             headers={'X-CSRF-Token':self.csrf, 'Origin':'https://hostile.test'})
        self.assertEqual(r.status_code, 403)

    def test_preview_cannot_be_reused_after_ad_session_changes(self):
        inv, _, _, profile = self.fixtures()
        preview_id = self.preview(inv, profile).json['id']
        self.enable()
        with self.client.session_transaction() as s:
            s.pop('pc_deploy_session_id')
            s.pop('pc_deploy_csrf')
        self.csrf = self.client.get('/pc-deploy/api/session').json['csrf']
        result = self.post('/pc-deploy/api/jobs/commit', dict(preview_id=preview_id,
            confirmation='YES', physical_confirmed=True))
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'], [])


    def test_invalid_registration_token(self):
        self.assertEqual(self.post('/pc-deploy/api/agent/register', machine(), 'invalid-but-long-enough-token').status_code, 400)

    def test_expired_registration_token(self):
        with self.store.connect(write=True) as c:
            c.execute('UPDATE enrollments SET expires=0')
        self.assertEqual(self.post('/pc-deploy/api/agent/register', machine(), self.enrollment).status_code, 400)

    def test_registration_retry_is_idempotent(self):
        inv, reg = self.register()
        second = self.post('/pc-deploy/api/agent/register', inv, self.enrollment)
        self.assertEqual(second.json, reg)

    def test_new_boot_revokes_old_agent_session(self):
        inv, reg = self.register()
        inv['boot_id'] = str(uuid.uuid4())
        self.post('/pc-deploy/api/agent/register', inv, self.enrollment)
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', inv, reg['token']).status_code, 400)

    def test_no_automatic_task_for_new_machine(self):
        inv, reg = self.register()
        self.enable()
        self.assertIsNone(self.post('/pc-deploy/api/agent/poll', inv, reg['token']).json['job'])

    def test_preview_does_not_queue(self):
        inv, _, _, profile = self.fixtures()
        self.assertEqual(self.preview(inv, profile).status_code, 200)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'], [])

    def test_disabled_gate_blocks_commit(self):
        inv, _, _, profile = self.fixtures()
        pv = self.preview(inv, profile).json
        r = self.post('/pc-deploy/api/jobs/commit', dict(preview_id=pv['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'], [])

    def test_commit_requires_yes_and_physical_confirmation(self):
        inv, _, _, profile = self.fixtures()
        pv = self.preview(inv, profile).json
        self.enable()
        for values in ({'confirmation':'YES'}, {'confirmation':'yes','physical_confirmed':True}):
            self.assertEqual(self.post('/pc-deploy/api/jobs/commit', dict(preview_id=pv['id'], **values)).status_code, 400)

    def test_expired_preview_rejected(self):
        inv, _, _, profile = self.fixtures()
        pv = self.preview(inv, profile).json
        with self.store.connect(write=True) as c:
            c.execute('UPDATE previews SET expires=0')
        self.enable()
        self.assertEqual(self.post('/pc-deploy/api/jobs/commit', dict(preview_id=pv['id'],confirmation='YES',physical_confirmed=True)).status_code,400)

    def test_profile_edit_invalidates_preview(self):
        inv, _, _, profile = self.fixtures()
        pv = self.preview(inv, profile).json
        with self.store.connect(write=True) as c:
            row = c.execute('SELECT data FROM profiles WHERE id=?', (profile,)).fetchone()
            d = json.loads(row['data']); d['revision'] = 'changed'
            c.execute('UPDATE profiles SET data=? WHERE id=?',(canonical(d), profile))
        self.enable()
        self.assertEqual(self.post('/pc-deploy/api/jobs/commit',dict(preview_id=pv['id'],confirmation='YES',physical_confirmed=True)).status_code,400)

    def test_disk_change_invalidates_preview(self):
        inv, reg, _, profile = self.fixtures()
        pv = self.preview(inv, profile).json
        inv['disks'][0]['serial'] = 'A-DIFFERENT-DISK'
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.enable()
        self.assertEqual(self.post('/pc-deploy/api/jobs/commit',dict(preview_id=pv['id'],confirmation='YES',physical_confirmed=True)).status_code,400)

    def test_offline_machine_rejected(self):
        inv, _, _, profile = self.fixtures()
        with self.store.connect(write=True) as c:
            c.execute('UPDATE devices SET last_seen=0')
        self.assertEqual(self.preview(inv, profile).status_code,400)

    def test_usb_disk_rejected(self):
        inv, _, _, profile = self.fixtures(machine(bus='USB'))
        self.assertEqual(self.preview(inv, profile).status_code,400)

    def test_missing_tpm_blocks_windows11(self):
        m = machine(); m['tpm2'] = False
        inv, _, _, profile = self.fixtures(m)
        self.assertEqual(self.preview(inv, profile).status_code,400)

    def test_explicit_multidisk_selection_only(self):
        m = machine(number=7)
        m['disks'].append(dict(m['disks'][0], number=0, serial='OTHER-DISK', unique_id='other', bus='SATA'))
        inv, _, _, profile = self.fixtures(m)
        result = self.post('/pc-deploy/api/jobs/preview', dict(profile_id=profile, targets=[dict(device_id=inv['hardware_uuid'])]))
        self.assertEqual(result.status_code,400)
        result = self.preview(inv, profile)
        # The fixture has been sorted by number; preview selects exactly the supplied key.
        self.assertEqual(len(result.json['targets']),1)

    def test_double_commit_and_duplicate_task_blocked(self):
        inv, _, job = self.queued()
        profile = self.client.get('/pc-deploy/api/dashboard').json['profiles'][0]['id']
        self.assertEqual(self.preview(inv, profile).status_code,400)
        with self.store.connect() as c:
            pv = c.execute('SELECT id FROM previews').fetchone()['id']
        self.assertEqual(self.post('/pc-deploy/api/jobs/commit',dict(preview_id=pv,confirmation='YES',physical_confirmed=True)).status_code,400)

    def test_new_boot_with_active_job_is_blocked(self):
        inv, _, _ = self.queued()
        inv['boot_id'] = str(uuid.uuid4())
        self.assertEqual(self.post('/pc-deploy/api/agent/register', inv, self.enrollment).status_code,400)

    def test_gate_off_stops_new_authorization(self):
        inv, reg, job = self.queued()
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', inv, reg['token']).json['job']['id'],job)
        self.enable(False)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code,400)

    def test_cancelled_preflight_cannot_start(self):
        inv, reg, job = self.queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.assertEqual(self.post(f'/pc-deploy/api/jobs/{job}/cancel').status_code,200)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code,400)

    def test_start_requires_matching_frozen_inventory(self):
        inv, reg, job = self.queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        inv['disks'][0]['number'] = 0
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code,400)

    def test_actual_job_response_and_no_replay(self):
        inv, reg, job = self.queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        r = self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        self.assertEqual(r.status_code,200,r.json)
        root = ET.fromstring(r.json['answer_xml'])
        disks = root.findall('.//u:DiskConfiguration/u:Disk', {'u':NAMESPACE})
        self.assertEqual(len(disks),1)
        self.assertEqual(disks[0].findtext('u:DiskID',namespaces={'u':NAMESPACE}), '3')
        self.assertNotIn('Test-only-local-password',r.json['answer_xml'])
        self.assertNotIn('Test-only-share-secret',r.json['answer_xml'])
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code,400)
        self.assertEqual(self.post(f'/pc-deploy/api/jobs/{job}/cancel').status_code,400)

    def test_installed_report_is_required_for_success(self):
        inv, reg, job = self.queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/event', {'stage':'awaiting_report'},reg['token'])
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['state'],'awaiting_report')
        with self.store.connect() as c:
            row=c.execute('SELECT secret FROM jobs WHERE id=?',(job,)).fetchone()
        token=self.store.decrypt(row['secret'])['finish_token']
        report=dict(hardware_uuid=inv['hardware_uuid'],computer_name='TEST-'+digest(inv['hardware_uuid'])[:8].upper(),
                    os_build=26100,image_state='IMAGE_STATE_COMPLETE',oobe_done=True)
        bad=dict(report,oobe_done=False)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/finish',bad,token).status_code,400)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/finish',report,reg['token']).status_code,400)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/finish',report,token).status_code,200)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['state'],'completed')
        self.assertIsNone(self.post('/pc-deploy/api/agent/poll',inv,reg['token']).json['job'])

    def test_dashboard_never_exposes_passwords_or_tokens(self):
        _, reg, _ = self.queued()
        raw=self.client.get('/pc-deploy/api/dashboard').text
        for value in ('Test-only-local-password','Test-only-share-secret',reg['token'],self.enrollment):
            self.assertNotIn(value,raw)
        with self.store.connect() as c:
            secrets_in_db=[r['secret'] for r in c.execute('SELECT secret FROM sources')]
        self.assertNotIn('Test-only-share-secret',''.join(secrets_in_db))

    def test_bootstrap_is_scoped_and_expiring(self):
        self.enable(False)
        response=self.post('/pc-deploy/api/bootstrap')
        self.assertEqual(response.status_code,200)
        with zipfile.ZipFile(io.BytesIO(response.data)) as z:
            cfg=json.loads(z.read('config.json'))
            self.assertTrue(cfg['server_url'].startswith('https://'))
            self.assertLess(cfg['expires_at']-time.time(),86401)
            self.assertIn('Build-WinPE.ps1',z.namelist())
            self.assertNotIn('admin_password',cfg)

    def test_boot_file_allowlist(self):
        self.assertEqual(self.client.get('/pc-deploy/boot/secret.key').status_code,404)
        self.assertEqual(self.client.get('/pc-deploy/boot/wimboot').status_code,404)
        self.assertIn('#!ipxe',self.client.get('/pc-deploy/boot.ipxe').text)

    def test_gate_cannot_enable_with_http(self):
        r=self.post('/pc-deploy/api/settings',dict(public_url='http://127.0.0.1:8090',concurrency=2,
                   ca_pem='',enabled=True,confirmation='ENABLE',isolated_network_confirmed=True))
        self.assertEqual(r.status_code,400)

    def test_reconcile_does_not_send_retry(self):
        inv,reg,job=self.queued()
        self.post('/pc-deploy/api/agent/poll',inv,reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start',inv,reg['token'])
        self.assertEqual(self.post(f'/pc-deploy/api/jobs/{job}/reconcile',dict(confirmation='CHECKED')).status_code,200)
        profile=self.client.get('/pc-deploy/api/dashboard').json['profiles'][0]['id']
        self.assertEqual(self.preview(inv,profile).status_code,400)

    def test_https_required_outside_unit_mode(self):
        self.app.testing=False
        try:
            r=self.post('/pc-deploy/api/agent/register',machine(),self.enrollment)
            self.assertEqual(r.status_code,400)
            self.assertIn('HTTPS',r.json['error'])
        finally:
            self.app.testing=True

    def test_bootstrap_rejects_loopback_http_configuration(self):
        self.assertEqual(self.post('/pc-deploy/api/bootstrap').status_code,400)

    def test_active_jobs_prevent_endpoint_change(self):
        self.queued()
        r=self.post('/pc-deploy/api/settings',dict(public_url='https://different.test',ca_pem='',concurrency=2,
                    enabled=False))
        self.assertEqual(r.status_code,400)
        self.assertIn('未结束',r.json['error'])

    def test_batch_creation_is_atomic(self):
        inv,_,_,profile=self.fixtures()
        other,reg=self.register(machine(serial='TEST-LAPTOP-002'))
        targets=[dict(device_id=i['hardware_uuid'],disk_key=inventory(i)['disks'][0]['key']) for i in (inv,other)]
        pv=self.post('/pc-deploy/api/jobs/preview',dict(profile_id=profile,targets=targets)).json
        other['disks'][0]['unique_id']='changed-after-preview'
        self.post('/pc-deploy/api/agent/poll',other,reg['token'])
        self.enable()
        r=self.post('/pc-deploy/api/jobs/commit',dict(preview_id=pv['id'],confirmation='YES',physical_confirmed=True))
        self.assertEqual(r.status_code,400)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'],[])

    def test_job_cannot_be_started_by_another_machine(self):
        inv,reg,job=self.queued()
        self.post('/pc-deploy/api/agent/poll',inv,reg['token'])
        other,other_reg=self.register(machine(serial='TEST-OTHER'))
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start',other,other_reg['token']).status_code,400)

    def test_queue_concurrency_is_enforced(self):
        inv,reg,job=self.queued()
        other,other_reg=self.register(machine(serial='TEST-OTHER'))
        profile=self.client.get('/pc-deploy/api/dashboard').json['profiles'][0]['id']
        pv=self.preview(other,profile).json
        self.post('/pc-deploy/api/jobs/commit',dict(preview_id=pv['id'],confirmation='YES',physical_confirmed=True))
        with self.store.connect(write=True) as c:
            self.store.put(c,'concurrency',1)
        self.assertEqual(self.post('/pc-deploy/api/agent/poll',inv,reg['token']).json['job']['id'],job)
        self.assertIsNone(self.post('/pc-deploy/api/agent/poll',other,other_reg['token']).json['job'])

    def test_json_shape_errors_are_reported(self):
        for change in ({'macs':None},{'disks':[None]},{'disks':'not-a-list'}):
            r=self.post('/pc-deploy/api/agent/register',dict(machine(),**change),self.enrollment)
            self.assertEqual(r.status_code,400,r.text)

    def test_profile_invalid_id_is_reported(self):
        self.assertEqual(self.post('/pc-deploy/api/profiles',dict(source_id=['invalid'])).status_code,400)

    def test_remote_admin_http_is_rejected(self):
        self.app.testing=False
        try:
            r=self.client.get('/pc-deploy/api/session',environ_overrides={'REMOTE_ADDR':'192.0.2.15'})
            self.assertEqual(r.status_code,403)
        finally:
            self.app.testing=True


    def test_password_not_replaced_when_edit_field_blank(self):
        _,_,source,_=self.fixtures()
        updated=install_source();updated['password']=''
        self.assertEqual(self.post('/pc-deploy/api/sources/'+source,updated,method='PUT').status_code,200)
        with self.store.connect() as c:
            encrypted=c.execute('SELECT secret FROM sources WHERE id=?',(source,)).fetchone()['secret']
        self.assertEqual(self.store.decrypt(encrypted),'Test-only-share-secret')

    def test_ipxe_initial_script_passes_smbios_uuid(self):
        script=self.client.get('/pc-deploy/boot.ipxe').text
        self.assertIn('uuid=${uuid}',script)
        self.assertNotIn('/boot/wimboot',script)

    def test_unknown_valid_machine_can_boot_winpe(self):
        script=self.client.get('/pc-deploy/boot.ipxe?uuid='+str(uuid.uuid4())).text
        self.assertIn('/boot/wimboot',script)

    def test_invalid_uuid_never_boots_deployment(self):
        script=self.client.get('/pc-deploy/boot.ipxe?uuid=invalid').text
        self.assertNotIn('/boot/wimboot',script)
        self.assertIn('exit',script)

    def test_queued_or_started_machine_does_not_loop_into_winpe(self):
        inv,reg,job=self.queued()
        script=self.client.get('/pc-deploy/boot.ipxe?uuid='+inv['hardware_uuid']).text
        self.assertIn('Returning to local boot',script)
        self.assertNotIn('/boot/wimboot',script)
        self.assertEqual(self.post('/pc-deploy/api/devices/'+inv['hardware_uuid']+'/rearm',dict(confirmation='CHECKED')).status_code,400)

    def test_rearm_revokes_old_session_and_does_not_queue(self):
        inv,reg=self.register()
        with self.store.connect(write=True) as c:
            c.execute('UPDATE devices SET consumed=1 WHERE id=?',(inv['hardware_uuid'],))
        script=self.client.get('/pc-deploy/boot.ipxe?uuid='+inv['hardware_uuid']).text
        self.assertNotIn('/boot/wimboot',script)
        self.assertEqual(self.post('/pc-deploy/api/devices/'+inv['hardware_uuid']+'/rearm',dict(confirmation='CHECKED')).status_code,200)
        self.assertEqual(self.post('/pc-deploy/api/agent/poll',inv,reg['token']).status_code,400)
        self.assertIn('/boot/wimboot',self.client.get('/pc-deploy/boot.ipxe?uuid='+inv['hardware_uuid']).text)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'],[])

    def test_installation_key_is_protected_and_can_be_removed(self):
        _,_,source,profile=self.fixtures()
        values=dict(name='Test profile',source_id=source,image_index=6,username='ITSetup',
                    system_gib=128,computer_prefix='TEST',product_key='AAAAA-BBBBB-CCCCC-DDDDD-EEEEE')
        self.assertEqual(self.post('/pc-deploy/api/profiles/'+profile,values,method='PUT').status_code,200)
        d=self.client.get('/pc-deploy/api/dashboard')
        self.assertNotIn(values['product_key'],d.text)
        self.assertTrue(d.json['profiles'][0]['has_product_key'])
        values.update(product_key='',clear_product_key=True)
        self.assertEqual(self.post('/pc-deploy/api/profiles/'+profile,values,method='PUT').status_code,200)
        self.assertFalse(self.client.get('/pc-deploy/api/dashboard').json['profiles'][0]['has_product_key'])


class ValidationTests(unittest.TestCase):
    def test_dangerous_urls_rejected(self):
        for url in ('http://deploy.test','https://user:pass@deploy.test','https://deploy.test/path',
                    'https://deploy.test?x=1','file:///c:/windows','https://deploy.test\nreboot'):
            with self.subTest(url=url),self.assertRaises(Invalid): public_url(url)

    def test_local_preview_and_https(self):
        self.assertEqual(public_url('http://127.0.0.1:8090'),'http://127.0.0.1:8090/pc-deploy')
        self.assertEqual(public_url('https://deploy.test/'),'https://deploy.test/pc-deploy')

    def test_unc_traversal_rejected(self):
        for value in ('C:\\Windows',r'\\host\share\..\other',r'\\host\share\test";reboot'):
            with self.subTest(value=value),self.assertRaises(Invalid): unc_path(value)

    def test_unknown_and_external_buses_are_never_eligible(self):
        for bus in ('USB','SD','MMC','iSCSI','Unknown','File Backed Virtual'):
            with self.subTest(bus=bus): self.assertFalse(inventory(machine(bus=bus))['disks'][0]['eligible'])

    def test_missing_disk_identity_rejected(self):
        m=machine();m['disks'][0].update(serial='',unique_id='')
        self.assertFalse(inventory(m)['disks'][0]['eligible'])

    def test_duplicate_disks_rejected(self):
        m=machine();m['disks'].append(copy.deepcopy(m['disks'][0]))
        with self.assertRaises(Invalid): inventory(m)

    def test_unknown_safety_flags_fail_closed(self):
        m=machine();del m['disks'][0]['read_only']
        self.assertFalse(inventory(m)['disks'][0]['eligible'])

    def test_insufficient_partition_space_rejected(self):
        m=inventory(machine());p={'system_gib':1024}
        with self.assertRaises(Invalid): target_check(m,m['disks'][0]['key'],p)

    def test_family_build_mismatch_rejected(self):
        s=install_source();s['family']='windows10'
        with self.assertRaises(Invalid):source_record(s)

    def test_correct_windows10_source(self):
        s=install_source();s['family']='windows10';s['images'][0]['build']=19045
        self.assertEqual(source_record(s)['family'],'windows10')

    def test_malformed_image_entry_is_rejected(self):
        s=install_source();s['images']=[None]
        with self.assertRaises(Invalid):source_record(s)

    def test_boolean_disk_number_is_rejected(self):
        m=machine();m['disks'][0]['number']=False
        with self.assertRaises(Invalid):inventory(m)

    def test_recovery_and_data_partitions_only_on_chosen_disk(self):
        inv=inventory(machine(number=7))
        profile=dict(name='Test',image_index=6,system_gib=128,username='ITSetup',computer_prefix='TEST')
        source=source_record(install_source())
        finalizer=dict(job_id=str(uuid.uuid4()),server_url='https://deploy.test',hardware_uuid=inv['hardware_uuid'],
                       token='test-only-completion-token',ca_pem='')
        xml=answer_file(inv,inv['disks'][0],profile,source,'Test-only-password',finalizer)
        root=ET.fromstring(xml);ns={'u':NAMESPACE}
        self.assertEqual([n.text for n in root.findall('.//u:DiskID',ns)],['7','7'])
        self.assertEqual(len(root.findall('.//u:CreatePartition',ns)),5)
        self.assertEqual(root.findtext('.//u:CreatePartition[u:Order="3"]/u:Size',namespaces=ns),'131072')
        self.assertEqual(root.findtext('.//u:CreatePartition[u:Order="5"]/u:Extend',namespaces=ns),'true')
        self.assertIsNone(root.find('.//u:UserData/u:ProductKey/u:Key',ns))
        self.assertEqual(root.findtext('.//u:UserData/u:ProductKey/u:WillShowUI',namespaces=ns),'Never')



class AdIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_domain_password_policy import DomainPasswordPolicyTests
        DomainPasswordPolicyTests.setUpClass.__func__(cls)

    def setUp(self):
        self.context = self.platform.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.platform.db.drop_all()
        self.platform.db.create_all()
        self.addCleanup(self.platform.db.session.remove)
        self.user = self.platform.AdminUser(username='deployment-admin', password_hash='unused', role='super_admin')
        self.platform.db.session.add(self.user)
        self.platform.db.session.commit()
        self.directory = tempfile.TemporaryDirectory(prefix='ad-pc-integration-')
        self.addCleanup(self.directory.cleanup)
        from unittest.mock import patch
        self.config = patch.dict(self.platform.app.config, {'PC_DEPLOY_DATA_DIR': self.directory.name})
        self.config.start()
        self.addCleanup(self.config.stop)
        old_store = self.platform.app.extensions.pop('pc_deploy_store', None)
        def restore_store():
            self.platform.app.extensions.pop('pc_deploy_store', None)
            if old_store is not None:
                self.platform.app.extensions['pc_deploy_store'] = old_store
        self.addCleanup(restore_store)
        self.client = self.platform.app.test_client()
        with self.client.session_transaction() as s:
            s.update(admin_logged_in=True, admin_username=self.user.username, admin_role='super_admin')

    def test_existing_login_opens_module_without_second_password(self):
        with self.client.get('/pc-deploy/') as response:
            self.assertEqual(response.status_code, 200)
        info = self.client.get('/pc-deploy/api/session')
        self.assertEqual(info.status_code, 200)
        self.assertEqual(info.json['username'], self.user.username)
        self.assertNotIn('password', info.json)
        self.assertEqual(self.client.get('/api/admin/check').json['username'], self.user.username)
        for route in ('login', 'setup', 'logout'):
            self.assertEqual(self.client.post('/pc-deploy/api/' + route, json={}).status_code, 404)

    def test_all_other_roles_and_disabled_users_are_denied(self):
        for role in ('admin', 'readonly'):
            self.user.role = role
            self.platform.db.session.commit()
            self.assertEqual(self.client.get('/pc-deploy/').status_code, 403)
            self.assertEqual(self.client.get('/pc-deploy/api/session').status_code, 403)
            self.assertEqual(self.client.post('/pc-deploy/api/sources', json={}).status_code, 403)
        self.user.role = 'super_admin'
        self.user.is_active = False
        self.platform.db.session.commit()
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').status_code, 401)
        self.assertNotIn('pc_deploy_store', self.platform.app.extensions)

    def test_ad_logout_invalidates_module_and_redirects_page(self):
        self.assertEqual(self.client.get('/pc-deploy/api/session').status_code, 200)
        self.assertTrue(self.client.post('/api/admin/logout').json['success'])
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').status_code, 401)
        self.assertEqual(self.client.get('/pc-deploy/').headers['Location'], '/admin')

    def test_settings_keep_ad_config_and_database_independent(self):
        def table_names():
            with self.platform.db.engine.connect() as connection:
                return set(connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").scalars())
        before_tables = table_names()
        before_cookie_name = self.platform.app.config['SESSION_COOKIE_NAME']
        info = self.client.get('/pc-deploy/api/session').json
        response = self.client.post('/pc-deploy/api/settings', json={
            'public_url': 'https://ad.example.test', 'concurrency': 2, 'enabled': False,
            'ca_pem': ''}, headers={'X-CSRF-Token': info['csrf']})
        self.assertEqual(response.status_code, 200, response.json)
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        self.assertEqual(dashboard['settings']['public_url'], 'https://ad.example.test/pc-deploy')
        self.assertFalse(dashboard['settings']['enabled'])
        self.assertIn('[' + self.user.username + ']', dashboard['events'][0]['message'])
        self.assertEqual(table_names(), before_tables)
        self.assertEqual(self.platform.app.config['SESSION_COOKIE_NAME'], before_cookie_name)

    def test_bootstrap_and_agent_urls_keep_module_prefix(self):
        info = self.client.get('/pc-deploy/api/session').json
        self.client.post('/pc-deploy/api/settings', json={
            'public_url': 'https://ad.example.test/pc-deploy', 'concurrency': 2, 'enabled': False},
            headers={'X-CSRF-Token': info['csrf']})
        result = self.client.post('/pc-deploy/api/bootstrap', json={}, headers={'X-CSRF-Token': info['csrf']})
        self.assertEqual(result.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
            config = json.loads(archive.read('config.json'))
            self.assertEqual(config['server_url'], 'https://ad.example.test/pc-deploy')
            self.assertIn("$uri.AbsolutePath -cne '/pc-deploy'", archive.read('Deploy-Agent.ps1').decode())
        anonymous = self.platform.app.test_client()
        register = anonymous.post('/pc-deploy/api/agent/register', json=machine(),
            headers={'Authorization': 'Bearer ' + config['enrollment_token']})
        self.assertEqual(register.status_code, 200, register.json)
        script = anonymous.get('/pc-deploy/boot.ipxe?uuid=' + register.json['device_id']).text
        self.assertIn('https://ad.example.test/pc-deploy', script)
        self.assertNotIn('https://ad.example.test/boot', script)

    def test_untrusted_proxy_header_cannot_bypass_https(self):
        self.platform.app.testing = False
        self.addCleanup(setattr, self.platform.app, 'testing', True)
        options = {'environ_overrides': {'REMOTE_ADDR': '192.0.2.10'},
                   'headers': {'X-Forwarded-Proto': 'https'}}
        self.assertEqual(self.client.get('/pc-deploy/api/session', **options).status_code, 403)
        self.platform.app.config['PC_DEPLOY_TRUST_PROXY'] = True
        self.addCleanup(self.platform.app.config.pop, 'PC_DEPLOY_TRUST_PROXY', None)
        self.assertEqual(self.client.get('/pc-deploy/api/session', **options).status_code, 200)

    def test_request_limit_only_applies_to_deployment_module(self):
        info = self.client.get('/pc-deploy/api/session').json
        response = self.client.post('/pc-deploy/api/sources', data='x' * (256 * 1024 + 1),
            content_type='application/json', headers={'X-CSRF-Token': info['csrf']})
        self.assertEqual(response.status_code, 413)
        self.assertIsNone(self.platform.app.config['MAX_CONTENT_LENGTH'])
        self.assertEqual(self.client.get('/api/admin/check').status_code, 200)

    def test_public_url_rejects_unrelated_paths(self):
        self.assertEqual(public_url('https://ad.example.test/pc-deploy/'), 'https://ad.example.test/pc-deploy')
        for url in ('https://ad.example.test/admin', 'https://ad.example.test/pc-deploy/../admin',
                    'https://ad.example.test/pc-deploy?token=secret'):
            with self.subTest(url=url), self.assertRaises(Invalid):
                public_url(url)

    def test_four_workers_share_one_complete_persistent_key(self):
        import subprocess
        import sys
        from pathlib import Path
        from pc_deploy.storage import Store
        code = ('import hashlib,sys; from pc_deploy.storage import Store; '
                's=Store(sys.argv[1]); print(hashlib.sha256(s.key).hexdigest())')
        workers = [subprocess.Popen([sys.executable, '-B', '-c', code, self.directory.name],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
        fingerprints = []
        for worker in workers:
            stdout, stderr = worker.communicate(timeout=30)
            self.assertEqual(worker.returncode, 0, stderr)
            fingerprints.append(stdout.strip())
        self.assertEqual(len(set(fingerprints)), 1)
        saved = Store(self.directory.name)
        encrypted = saved.encrypt('test-only-worker-secret')
        self.assertEqual(Store(self.directory.name).decrypt(encrypted), 'test-only-worker-secret')
        self.assertFalse(list(Path(self.directory.name).glob('.key-*')))

if __name__ == '__main__':
    unittest.main(verbosity=2)
