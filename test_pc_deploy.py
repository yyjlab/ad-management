import base64
import copy
import gzip
import re
from pathlib import Path
import io
import os
import subprocess
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
from pc_deploy.deployment import finalizer_command
from pc_deploy.deployment import (Invalid, NAMESPACE, answer_file, canonical, digest, inventory,
                        public_url, source_record, target_check, unc_path)


def decoded_bootstrap(command):
    launcher = base64.b64decode(command.rsplit(' ', 1)[1]).decode('utf-16le')
    packed = re.search(r"\$deploymentBootstrap='([^']+)'", launcher)
    return gzip.decompress(base64.b64decode(packed.group(1))).decode() if packed else launcher


def bootstrap_files(bootstrap):
    packed = re.search(r"\$deploymentFiles='([^']+)'", bootstrap)
    return json.loads(gzip.decompress(base64.b64decode(packed.group(1))))


def bootstrap_config(bootstrap):
    if '$deploymentFiles=' in bootstrap:
        return json.loads(bootstrap_files(bootstrap)['config.json'])
    compressed = re.search(r"Write-DeploymentScript 'config.json' '([^']+)'", bootstrap)
    if compressed:
        return json.loads(gzip.decompress(base64.b64decode(compressed.group(1))))
    encoded = re.search(r"config.json'\),\[Convert\]::FromBase64String\('([^']+)'", bootstrap)
    return json.loads(base64.b64decode(encoded.group(1)))


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


    def join_post(self, path, data=None, token=None, method='POST'):
        headers = {'X-CSRF-Token': self.csrf}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        return self.client.open(path, base_url='https://localhost', method=method, json=data or {}, headers=headers)

    def join_fixtures(self, commit=True, wim=False, allow_http=False, manual=False):
        inv, reg, source, profile = self.fixtures()
        self.enable()
        join_request = self.post if allow_http else self.join_post
        if allow_http:
            with self.store.connect(write=True) as c:
                self.store.put(c, 'public_url', 'http://deploy.test/pc-deploy')
        if wim:
            with self.store.connect(write=True) as c:
                row, = c.execute('SELECT data FROM sources WHERE id=?', (source,)).fetchall()
                value = json.loads(row['data'])
                value.update(kind='wim', image_file='custom.wim')
                c.execute('UPDATE sources SET data=? WHERE id=?', (canonical(value), source))
            inv['wim_apply_v1'] = True
            self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        payload = dict(name='Join by employee', source_id=source, image_index=6, username='ITSetup',
                       password='Test-only-local-password', system_gib=128, computer_prefix='TEST',
                       domain_join=dict(enabled=True, domain='corp.test', ou_path='OU=Workstations,DC=corp,DC=test',
                                        username='join-service@corp.test'),
                       domain_join_password='Test-only-domain-password')
        if wim:
            payload['password'] = ''
        if allow_http:
            payload['domain_join']['allow_http'] = True
        if manual:
            payload['domain_join']['mode'] = 'manual'
        saved = join_request('/pc-deploy/api/profiles', payload)
        self.assertEqual(saved.status_code, 200, saved.json)
        profile = saved.json['id']
        target = dict(device_id=inv['hardware_uuid'], disk_key=inventory(inv)['disks'][0]['key'], employee_id='wfq101755')
        preview = join_request('/pc-deploy/api/jobs/preview', dict(profile_id=profile, targets=[target]))
        self.assertEqual(preview.status_code, 200, preview.json)
        if not commit:
            return inv, reg, profile, target, payload
        result = join_request('/pc-deploy/api/jobs/commit', dict(preview_id=preview.json['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(result.status_code, 200, result.json)
        job = result.json['ids'][0]
        self.assertEqual(join_request('/pc-deploy/api/agent/poll', inv, reg['token']).status_code, 200)
        started = join_request(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        self.assertEqual(started.status_code, 200, started.json)
        with self.store.connect() as c:
            row = c.execute('SELECT secret FROM jobs WHERE id=?', (job,)).fetchone()
            token = self.store.decrypt(row['secret'])['finish_token']
        return inv, reg, job, token, started.json


    def test_manual_domain_join_waits_for_admin_and_completes_after_release(self):
        inv, _, job, token, authorization = self.join_fixtures(manual=True)
        route = f'/pc-deploy/api/agent/jobs/{job}'
        ready = dict(hardware_uuid=inv['hardware_uuid'], computer_name='OLD-IMAGE',
                     os_build=26100, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        self.assertEqual(self.join_post(route+'/domain-join/config', {'hardware_uuid':inv['hardware_uuid']}, token).status_code, 400)
        for patch in ({'hardware_uuid':str(uuid.uuid4())}, {'os_build':19045}, {'oobe_done':False}):
            self.assertEqual(self.join_post(route+'/domain-join/config', dict(ready, **patch), token).status_code, 400)
        self.assertEqual(self.join_post(route+'/domain-join/config', ready, 'wrong-token').status_code, 400)
        waiting = self.join_post(route+'/domain-join/config', ready, token)
        self.assertEqual(waiting.status_code, 200, waiting.json)
        self.assertIs(waiting.json['waiting_for_release'], True)
        self.assertNotIn('password', waiting.json)
        self.assertNotIn('Test-only-domain-password', json.dumps(waiting.json))
        self.assertEqual(self.join_post(route+'/domain-join/config', ready, token).status_code, 200)
        before = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(before['domain_join']['state'], 'waiting_release')
        self.assertIsInstance(before['installed_at'], (float, int))
        self.assertEqual(self.join_post(route+'/domain-join/status', dict(hardware_uuid=inv['hardware_uuid'], stage='checking'), token).status_code, 400)
        self.assertEqual(self.join_post(route+'/domain-join/name', dict(hardware_uuid=inv['hardware_uuid'], unavailable_name='WFQ101755'), token).status_code, 400)
        action = {'job_ids':[job], 'restart_confirmed':True}
        self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release', dict(action, restart_confirmed=False)).status_code, 400)
        released = self.join_post('/pc-deploy/api/jobs/domain-join/release', action)
        self.assertEqual(released.status_code, 200, released.json)
        self.assertNotIn('password', released.json)
        self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release', action).status_code, 200)
        credentials = self.join_post(route+'/domain-join/config', ready, token)
        self.assertEqual(credentials.json['password'], 'Test-only-domain-password')
        self.assertEqual(credentials.json['mode'], 'manual')
        payload = dict(hardware_uuid=inv['hardware_uuid'])
        for stage in ('checking', 'joining', 'restarting'):
            self.assertEqual(self.join_post(route+'/domain-join/status', dict(payload, stage=stage), token).status_code, 200)
        verified = dict(payload, stage='verified', domain='corp.test', computer_name='WFQ101755', secure_channel=True)
        self.assertEqual(self.join_post(route+'/domain-join/status', verified, token).status_code, 200)
        finished = dict(ready, computer_name='WFQ101755', domain_name='corp.test', domain_join_verified=True)
        self.assertEqual(self.join_post(route+'/finish', finished, token).status_code, 200)
        after = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(after['state'], 'completed')
        self.assertEqual(before['installed_at'], after['installed_at'])
        with self.store.connect() as c:
            events = [row['message'] for row in c.execute('SELECT message FROM events WHERE job_id=?', (job,))]
        self.assertEqual(sum('等待管理员统一加域' in message for message in events), 1)
        self.assertEqual(sum('管理员已确认设置完成' in message for message in events), 1)
        self.assertNotIn('Test-only-domain-password', '\n'.join(events))

    def test_manual_join_release_is_atomic_authorized_and_expiry_bound(self):
        inv, _, job, token, _ = self.join_fixtures(manual=True)
        route = f'/pc-deploy/api/agent/jobs/{job}/domain-join/config'
        action = {'job_ids':[job], 'restart_confirmed':True}
        self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release', action).status_code, 400)
        ready = dict(hardware_uuid=inv['hardware_uuid'], computer_name='OLD-IMAGE',
                     os_build=26100, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        self.assertEqual(self.join_post(route, ready, token).status_code, 200)
        for patch in ({'job_ids':[job, str(uuid.uuid4())]}, {'job_ids':[job, job]},
                      {'job_ids':job}, {'restart_confirmed':'true'}):
            self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release', dict(action, **patch)).status_code, 400)
        with self.store.connect() as c:
            data = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
            self.assertNotIn('released_at', data['domain_join'])
        forbidden = self.client.post('/pc-deploy/api/jobs/domain-join/release', base_url='https://localhost', json=action)
        self.assertEqual(forbidden.status_code, 403)
        with self.client.session_transaction() as session_data:
            session_data['admin_role'] = 'viewer'
        self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release', action).status_code, 403)
        with self.client.session_transaction() as session_data:
            session_data['admin_role'] = 'super_admin'
        with self.store.connect(write=True) as c:
            c.execute('UPDATE jobs SET expires=? WHERE id=?', (time.time()-1, job))
        self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release', action).status_code, 400)
        self.assertEqual(self.join_post(route, ready, token).status_code, 400)

    def test_waiting_manual_join_does_not_block_next_installation(self):
        inv, _, job, token, _ = self.join_fixtures(manual=True)
        other, other_reg = self.register(machine(serial='NEXT-INSTALL'))
        profile = next(profile for profile in self.client.get('/pc-deploy/api/dashboard').json['profiles']
                       if not profile.get('domain_join'))['id']
        preview = self.preview(other, profile).json
        committed = self.post('/pc-deploy/api/jobs/commit',
                              dict(preview_id=preview['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(committed.status_code, 200, committed.json)
        with self.store.connect(write=True) as c:
            self.store.put(c, 'concurrency', 1)
        self.assertIsNone(self.post('/pc-deploy/api/agent/poll', other, other_reg['token']).json['job'])
        ready = dict(hardware_uuid=inv['hardware_uuid'], computer_name='OLD-IMAGE',
                     os_build=26100, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        self.assertEqual(self.join_post(f'/pc-deploy/api/agent/jobs/{job}/domain-join/config', ready, token).status_code, 200)
        next_job = self.post('/pc-deploy/api/agent/poll', other, other_reg['token'])
        self.assertEqual(next_job.json['job']['id'], committed.json['ids'][0])

    def test_manual_join_wim_http_gate_keeps_credentials_private_until_release(self):
        inv, _, job, token, authorization = self.join_fixtures(wim=True, allow_http=True, manual=True)
        route = f'/pc-deploy/api/agent/jobs/{job}/domain-join/config'
        bootstrap = decoded_bootstrap(authorization['finalizer_command'])
        self.assertNotIn('Test-only-domain-password', bootstrap)
        self.assertLess(len(authorization['finalizer_command']), 30000)
        config = bootstrap_config(bootstrap)
        self.assertEqual(config['domain_join']['mode'], 'manual')
        self.assertGreater(config['expires_at'], time.time())
        ready = dict(hardware_uuid=inv['hardware_uuid'], computer_name='OLD-IMAGE',
                     os_build=26100, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        pending = self.post(route, ready, token)
        self.assertEqual(pending.status_code, 200, pending.json)
        self.assertNotIn('password', pending.json)
        self.app.config['PC_DEPLOY_ALLOW_HTTP'] = False
        self.assertEqual(self.post('/pc-deploy/api/jobs/domain-join/release',
                                   {'job_ids':[job], 'restart_confirmed':True}).status_code, 400)
        self.app.config['PC_DEPLOY_ALLOW_HTTP'] = True
        self.assertEqual(self.post('/pc-deploy/api/jobs/domain-join/release',
                                   {'job_ids':[job], 'restart_confirmed':True}).status_code, 200)
        self.assertEqual(self.post(route, ready, token).json['password'], 'Test-only-domain-password')


    def test_device_details_are_optional_and_do_not_change_disk_authorization(self):
        raw = machine()
        raw['system_info'] = dict(computer_name='MININT-TEST', cpus=[dict(name='Original CPU', cores=8, threads=16)],
                                  password='must-not-be-persisted')
        inv, reg, _, profile = self.fixtures(raw)
        preview = self.preview(inv, profile)
        self.assertEqual(preview.status_code, 200, preview.json)
        refreshed = copy.deepcopy(raw)
        refreshed['system_info']['cpus'][0]['name'] = 'Commit CPU'
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', refreshed, reg['token']).status_code, 200)
        self.enable()
        commit = self.post('/pc-deploy/api/jobs/commit', dict(preview_id=preview.json['id'],
                           confirmation='YES', physical_confirmed=True))
        self.assertEqual(commit.status_code, 200, commit.json)
        job = commit.json['ids'][0]
        updated = copy.deepcopy(raw)
        updated['system_info'] = dict(computer_name='MININT-TEST', cpus=[dict(name='Refreshed CPU')])
        polled = self.post('/pc-deploy/api/agent/poll', updated, reg['token'])
        self.assertEqual(polled.status_code, 200, polled.json)
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        self.assertEqual(dashboard['devices'][0]['system_info']['cpus'][0]['name'], 'Refreshed CPU')
        snapshot = dashboard['jobs'][0]['device_info']
        self.assertEqual(snapshot['system_info']['cpus'][0]['name'], 'Commit CPU')
        self.assertEqual(snapshot['ram_bytes'], raw['ram_bytes'])
        self.assertEqual(snapshot['hardware_uuid'], raw['hardware_uuid'])
        self.assertNotIn('partitions', snapshot['disks'][0])
        self.assertNotIn('must-not-be-persisted', json.dumps(dashboard))
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', updated, reg['token']).status_code, 200)
        with self.store.connect() as c:
            row = c.execute('SELECT inventory_hash FROM devices WHERE id=?', (raw['hardware_uuid'],)).fetchone()
            self.assertEqual(row['inventory_hash'], digest(inventory(raw)))

    def test_device_report_rejects_unknown_fields_and_bounds_lists(self):
        from pc_deploy.deployment import device_report
        value = dict(computer_name='PC\x00name', ram_bytes=True, secret='hidden',
                     cpus=[dict(name='CPU', cores=True, threads=-1)]*100,
                     networks=[dict(name='NIC', addresses=['172.168.30.60','invalid',True],
                                    token='secret', link_mbps=1000)],
                     volumes='invalid')
        report = device_report(value, 'windows')
        self.assertEqual(report['computer_name'], 'PC name')
        self.assertEqual(len(report['cpus']), 8)
        self.assertNotIn('cores', report['cpus'][0])
        self.assertNotIn('threads', report['cpus'][0])
        self.assertNotIn('ram_bytes', report)
        self.assertNotIn('secret', report)
        self.assertEqual(report['networks'][0]['addresses'], ['172.168.30.60'])
        self.assertNotIn('token', report['networks'][0])
        self.assertNotIn('volumes', report)
        self.assertEqual(device_report(None, 'pe'), {})

    def test_postinstall_display_metadata_is_separate_from_approved_inventory(self):
        inv, _, job, token, _ = self.join_fixtures()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        with self.store.connect() as c:
            original = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
        info = dict(model='HKD-WXX', manufacturer='HUAWEI', system_family='MateBook',
                    product_name='HKD-WXX', product_version='M1010', oem_model='HUAWEI MateBook 14s',
                    ignored_secret='not-a-display-field', system_info=dict(computer_name='ACTUAL-PC',
                    os_name='Windows 11 Pro', os_build='26100', cpus=[dict(name='Test CPU', cores=8, threads=16)]))
        identity = dict(hardware_uuid=inv['hardware_uuid'], device_info=info)
        self.assertEqual(self.join_post(route+'/domain-join/config',
                                       dict(identity, hardware_uuid=str(uuid.uuid4())), token).status_code, 400)
        reply = self.join_post(route+'/domain-join/config', identity, token)
        self.assertEqual(reply.status_code, 200, reply.json)
        self.assertEqual(reply.json['join_state'], 'pending')
        for stage in ('checking', 'joining', 'restarting'):
            self.assertEqual(self.join_post(route+'/domain-join/status', dict(identity, stage=stage), token).status_code, 200)
        dashboard = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        logs = self.client.get(route.replace('/api/agent/', '/api/')+'/events').json['job']
        self.assertEqual(dashboard['model'], 'HKD-WXX')
        self.assertEqual(dashboard['manufacturer'], 'HUAWEI')
        self.assertEqual(dashboard['device_info']['system_info']['computer_name'], 'ACTUAL-PC')
        self.assertEqual(dashboard['device_info']['system_info']['source'], 'windows')
        self.assertGreater(dashboard['device_info']['system_info']['reported_at'], 0)
        self.assertEqual(logs['oem_model'], 'HUAWEI MateBook 14s')
        self.assertNotIn('not-a-display-field', json.dumps(dashboard))
        with self.store.connect() as c:
            current = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
            device = json.loads(c.execute('SELECT data FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()['data'])
        self.assertEqual(current['target'], original['target'])
        self.assertEqual(device['model'], inv['model'])
        verified = dict(identity, stage='verified', domain='corp.test', computer_name='WFQ101755', secure_channel=True)
        self.assertEqual(self.join_post(route+'/domain-join/status', verified, token).status_code, 200)
        finish = dict(identity, computer_name='WFQ101755', os_build=26100, image_state='IMAGE_STATE_COMPLETE',
                      oobe_done=True, domain_name='corp.test', domain_join_verified=True)
        self.assertEqual(self.join_post(route+'/finish', finish, token).status_code, 200)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['oem_model'], info['oem_model'])

    def test_join_diagnostics_keep_platform_host_distinct_from_target_domain(self):
        inv, _, job, token, _ = self.join_fixtures()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        detail = "Stage: platform_status_checking\nPlatform: https://ad.example.test/pc-deploy\nTarget AD domain: corp.test\nError: 无法解析此远程名称: 'ad.example.test'"
        response = self.join_post(route+'/domain-join/status',
                                  dict(hardware_uuid=inv['hardware_uuid'], stage='checking', detail=detail), token)
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['domain_join']['domain'], 'corp.test')
        messages = self.client.get(route.replace('/api/agent/', '/api/')+'/events').json['events']
        self.assertTrue(any(detail in event['message'] for event in messages))
        self.assertTrue(all(event['kind'] != 'failed' for event in messages))

    def test_domain_join_http_opt_in_completes_with_scoped_credentials_and_unchanged_pe(self):
        inv, reg, job, token, authorization = self.join_fixtures(wim=True, allow_http=True)
        bootstrap = decoded_bootstrap(authorization['finalizer_command'])
        config = bootstrap_config(bootstrap)
        self.assertIs(config['allow_http'], True)
        self.assertIs(config['domain_join']['allow_http'], True)
        self.assertTrue(config['server_url'].startswith('http://'))
        self.assertNotIn('Test-only-domain-password', bootstrap)
        route = f'/pc-deploy/api/agent/jobs/{job}'
        identity = dict(hardware_uuid=inv['hardware_uuid'])
        self.assertEqual(self.post(route+'/domain-join/config', identity, reg['token']).status_code, 400)
        self.assertEqual(self.post(route+'/domain-join/config', dict(hardware_uuid=str(uuid.uuid4())), token).status_code, 400)
        credentials = self.post(route+'/domain-join/config', identity, token)
        self.assertEqual(credentials.status_code, 200, credentials.json)
        self.assertEqual(credentials.json['username'], 'join-service@corp.test')
        self.assertEqual(credentials.json['password'], 'Test-only-domain-password')
        assigned = self.post(route+'/domain-join/name', dict(identity, unavailable_name='WFQ101755'), token)
        self.assertEqual(assigned.json['computer_name'], 'WFQ101755A')
        finish = dict(identity, computer_name='WFQ101755A', os_build=26100, image_state='IMAGE_STATE_COMPLETE',
                      oobe_done=True, domain_name='corp.test', domain_join_verified=True)
        self.assertEqual(self.post(route+'/finish', finish, token).status_code, 400)
        for stage in ('checking', 'joining', 'restarting'):
            reply = self.post(route+'/domain-join/status', dict(identity, stage=stage), token)
            self.assertEqual(reply.status_code, 200, reply.json)
        verified = dict(identity, stage='verified', computer_name='WFQ101755A', domain='corp.test', secure_channel=True)
        self.assertEqual(self.post(route+'/domain-join/status', verified, token).status_code, 200)
        self.assertEqual(self.post(route+'/finish', finish, token).status_code, 200)
        events = self.client.get(route.replace('/agent', '')+'/events').json
        self.assertTrue(any('允许内网 HTTP 加域' in e['message'] for e in events['events']))
        self.assertNotIn('Test-only-domain-password', json.dumps(events))

    def test_domain_join_http_cannot_override_server_transport_policy(self):
        inv, _, job, token, _ = self.join_fixtures(allow_http=True)
        self.app.config['PC_DEPLOY_ALLOW_HTTP'] = False
        route = f'/pc-deploy/api/agent/jobs/{job}'
        identity = dict(hardware_uuid=inv['hardware_uuid'], allow_http=True)
        for suffix, payload in (
                ('/domain-join/config', identity),
                ('/domain-join/name', dict(identity, unavailable_name='WFQ101755')),
                ('/domain-join/status', dict(identity, stage='checking')),
                ('/finish', dict(identity, computer_name='WFQ101755', os_build=26100))):
            reply = self.post(route+suffix, payload, token)
            self.assertEqual(reply.status_code, 400, suffix)
        self.assertIs(self.client.get('/pc-deploy/api/dashboard').json['settings']['http_allowed'], False)

    def test_domain_join_transport_permission_is_immutable_for_running_job(self):
        inv, _, job, token, _ = self.join_fixtures()
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        profile = next(p for p in dashboard['profiles'] if p.get('domain_join'))
        updated = dict(profile, domain_join=dict(profile['domain_join'], enabled=True, allow_http=True))
        self.assertEqual(self.join_post('/pc-deploy/api/profiles/'+profile['id'], updated, method='PUT').status_code, 200)
        with self.store.connect(write=True) as c:
            self.store.put(c, 'public_url', 'http://deploy.test/pc-deploy')
        route = f'/pc-deploy/api/agent/jobs/{job}'
        identity = dict(hardware_uuid=inv['hardware_uuid'], allow_http=True)
        for suffix, payload in (
                ('/domain-join/config', identity),
                ('/domain-join/name', dict(identity, unavailable_name='WFQ101755')),
                ('/domain-join/status', dict(identity, stage='checking')),
                ('/finish', dict(identity, computer_name='WFQ101755', os_build=26100))):
            self.assertEqual(self.post(route+suffix, payload, token).status_code, 400, suffix)

    def test_domain_join_blocks_http_pe_before_authorization(self):
        inv, reg, profile, target, _ = self.join_fixtures(commit=False)
        payload = dict(profile_id=profile, targets=[target])
        self.assertEqual(self.post('/pc-deploy/api/jobs/preview', payload).status_code, 400)
        pv = self.join_post('/pc-deploy/api/jobs/preview', payload)
        result = self.join_post('/pc-deploy/api/jobs/commit', dict(preview_id=pv.json['id'], confirmation='YES', physical_confirmed=True))
        job = result.json['ids'][0]
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', inv, reg['token']).status_code, 400)
        with self.store.connect() as c:
            row = c.execute('SELECT state FROM jobs WHERE id=?', (job,)).fetchone()
        self.assertEqual(row['state'], 'queued')
        self.assertEqual(self.join_post('/pc-deploy/api/agent/poll', inv, reg['token']).status_code, 200)
        started = self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        self.assertEqual(started.status_code, 400)
        self.assertNotIn('finalizer_command', started.json)
        with self.store.connect() as c:
            row = c.execute('SELECT consumed FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()
        self.assertFalse(row['consumed'])
        self.assertEqual(self.join_post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code, 200)

    def test_domain_join_requires_https_and_explicit_profile_option(self):
        _, _, _, _, payload = self.join_fixtures(commit=False)
        self.assertEqual(self.post('/pc-deploy/api/profiles', payload).status_code, 400)
        payload['domain_join']['enabled'] = False
        saved = self.post('/pc-deploy/api/profiles', payload)
        self.assertEqual(saved.status_code, 200, saved.json)
        profiles = self.client.get('/pc-deploy/api/dashboard').json['profiles']
        self.assertNotIn('domain_join', next(p for p in profiles if p['id'] == saved.json['id']))

    def test_domain_join_validates_domain_account_ou_and_boolean(self):
        _, _, _, _, payload = self.join_fixtures(commit=False)
        for patch in ({'domain':'127.0.0.1'}, {'domain':'http://corp.test'}, {'username':'administrator'},
                      {'ou_path':'OU=PCs,DC=other,DC=test'}, {'enabled':'true'}, {'allow_http':'true'}, {'allow_http':1}):
            bad = copy.deepcopy(payload)
            bad['domain_join'].update(patch)
            self.assertEqual(self.join_post('/pc-deploy/api/profiles', bad).status_code, 400, patch)

    def test_domain_join_validates_employee_and_allocates_distinct_batch_names(self):
        _, _, profile, target, _ = self.join_fixtures(commit=False)
        route = '/pc-deploy/api/jobs/preview'
        for employee in ('', 'x'*15, 'wfq/test', 'WFQ<script>', '-WFQ', 'WFQ-'):
            bad = dict(target, employee_id=employee)
            self.assertEqual(self.join_post(route, dict(profile_id=profile, targets=[bad])).status_code, 400, employee)
        numeric = self.join_post(route, dict(profile_id=profile, targets=[dict(target, employee_id='12345')]))
        self.assertEqual(numeric.status_code, 200, numeric.json)
        self.assertEqual(numeric.json['targets'][0]['employee_id'], '12345')
        self.assertEqual(numeric.json['targets'][0]['computer_name'], '12345A')
        inv2, _ = self.register(machine(serial='SECOND-LAPTOP'))
        second = dict(device_id=inv2['hardware_uuid'], disk_key=inventory(inv2)['disks'][0]['key'], employee_id='WFQ101755')
        result = self.join_post(route, dict(profile_id=profile, targets=[target, second]))
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual([t['computer_name'] for t in result.json['targets']], ['WFQ101755', 'WFQ101755A'])
        committed = self.join_post('/pc-deploy/api/jobs/commit',
            dict(preview_id=result.json['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(committed.status_code, 200, committed.json)
        with self.store.connect() as c:
            jobs = [json.loads(r['data']) for r in c.execute('SELECT data FROM jobs')]
        self.assertEqual({j['target']['computer_name'] for j in jobs}, {'WFQ101755', 'WFQ101755A'})

    def test_domain_join_collision_is_scoped_idempotent_and_updates_final_name(self):
        inv, reg, job, token, _ = self.join_fixtures()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        conflict = dict(hardware_uuid=inv['hardware_uuid'], unavailable_name='WFQ101755')
        self.assertEqual(self.join_post(route+'/domain-join/name', conflict, reg['token']).status_code, 400)
        assigned = self.join_post(route+'/domain-join/name', conflict, token)
        self.assertEqual(assigned.status_code, 200, assigned.json)
        self.assertEqual(assigned.json['computer_name'], 'WFQ101755A')
        repeated = self.join_post(route+'/domain-join/name', conflict, token)
        self.assertEqual(repeated.json, assigned.json)
        assigned = self.join_post(route+'/domain-join/name', dict(conflict, unavailable_name='WFQ101755A'), token)
        self.assertEqual(assigned.json['computer_name'], 'WFQ101755B')
        config = self.join_post(route+'/domain-join/config', dict(hardware_uuid=inv['hardware_uuid']), token)
        self.assertEqual(config.json['employee_id'], 'WFQ101755')
        self.assertEqual(config.json['computer_name'], 'WFQ101755B')
        for stage in ('checking', 'joining'):
            self.assertEqual(self.join_post(route+'/domain-join/status',
                dict(hardware_uuid=inv['hardware_uuid'], stage=stage), token).status_code, 200)
        self.assertEqual(self.join_post(route+'/domain-join/name',
            dict(conflict, unavailable_name='WFQ101755B'), token).status_code, 400)
        verified = dict(hardware_uuid=inv['hardware_uuid'], stage='verified', domain='corp.test',
                        computer_name='WFQ101755B', secure_channel=True)
        self.assertEqual(self.join_post(route+'/domain-join/status', verified, token).status_code, 200)
        finished = dict(hardware_uuid=inv['hardware_uuid'], computer_name='WFQ101755B', os_build=26100,
                        image_state='IMAGE_STATE_COMPLETE', oobe_done=True, domain_name='corp.test', domain_join_verified=True)
        self.assertEqual(self.join_post(route+'/finish', finished, token).status_code, 200)
        public = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(public['computer_name'], 'WFQ101755B')
        events = self.client.get(route.replace('/agent', '')+'/events').json['events']
        renamed = [e for e in events if '自动改用' in e['message']]
        self.assertEqual(len(renamed), 2)

    def test_domain_join_suffix_is_reserved_across_running_jobs_and_exhausts_safely(self):
        inv, _, job, token, _ = self.join_fixtures()
        route = f'/pc-deploy/api/agent/jobs/{job}/domain-join/name'
        with self.store.connect() as c:
            original = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
        inv2, _ = self.register(machine(serial='SECOND-LAPTOP'))
        target = dict(device_id=inv2['hardware_uuid'], disk_key=inventory(inv2)['disks'][0]['key'], employee_id='WFQ101755')
        pv = self.join_post('/pc-deploy/api/jobs/preview', dict(profile_id=original['profile']['id'], targets=[target]))
        self.assertEqual(pv.json['targets'][0]['computer_name'], 'WFQ101755A')
        committed = self.join_post('/pc-deploy/api/jobs/commit',
            dict(preview_id=pv.json['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(committed.status_code, 200, committed.json)
        assigned = self.join_post(route, dict(hardware_uuid=inv['hardware_uuid'], unavailable_name='WFQ101755'), token)
        self.assertEqual(assigned.json['computer_name'], 'WFQ101755B')
        for letter in 'BCDEFGHIJKLMNOPQRSTUVWXY':
            assigned = self.join_post(route,
                dict(hardware_uuid=inv['hardware_uuid'], unavailable_name='WFQ101755'+letter), token)
            self.assertEqual(assigned.status_code, 200, assigned.json)
        self.assertEqual(assigned.json['computer_name'], 'WFQ101755Z')
        exhausted = self.join_post(route,
            dict(hardware_uuid=inv['hardware_uuid'], unavailable_name='WFQ101755Z'), token)
        self.assertEqual(exhausted.status_code, 400)
        self.assertIn('均已占用', exhausted.json['error'])
        with self.store.connect() as c:
            after = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
        self.assertEqual(after['target']['employee_id'], 'WFQ101755')
        self.assertEqual(after['target']['computer_name'], 'WFQ101755Z')

    def test_domain_join_credentials_are_private_and_authorization_is_task_scoped(self):
        inv, reg, job, token, authorization = self.join_fixtures()
        password = 'Test-only-domain-password'
        public = self.client.get('/pc-deploy/api/dashboard').get_data(as_text=True)
        self.assertNotIn(password, public)
        self.assertNotIn(password, json.dumps(authorization))
        route = f'/pc-deploy/api/agent/jobs/{job}/domain-join/config'
        payload = dict(hardware_uuid=inv['hardware_uuid'])
        self.assertEqual(self.post(route, payload, token).status_code, 400)
        self.assertEqual(self.join_post(route, payload, reg['token']).status_code, 400)
        self.assertEqual(self.join_post(route, dict(hardware_uuid=str(uuid.uuid4())), token).status_code, 400)
        result = self.join_post(route, payload, token)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['computer_name'], 'WFQ101755')
        self.assertEqual(result.json['password'], password)
        self.assertEqual(result.headers['Cache-Control'], 'no-store')
        with self.store.connect() as c:
            encrypted = c.execute('SELECT secret FROM jobs WHERE id=?', (job,)).fetchone()['secret']
        self.assertNotIn(password, encrypted)

    def test_domain_join_does_not_complete_until_trust_is_verified(self):
        inv, _, job, token, _ = self.join_fixtures()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        payload = dict(hardware_uuid=inv['hardware_uuid'], computer_name='WFQ101755', os_build=26100,
                       image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        self.assertEqual(self.join_post(route+'/finish', payload, token).status_code, 400)
        verified = dict(hardware_uuid=inv['hardware_uuid'], stage='verified', domain='corp.test',
                        computer_name='WFQ101755', secure_channel=True)
        for bad_stage in ({}, []):
            self.assertEqual(self.join_post(route+'/domain-join/status',
                dict(hardware_uuid=inv['hardware_uuid'], stage=bad_stage), token).status_code, 400)
        for patch in ({'domain':'other.test'}, {'computer_name':'OTHER'}, {'secure_channel':False}, {'domain':{}}):
            self.assertEqual(self.join_post(route+'/domain-join/status', dict(verified, **patch), token).status_code, 400)
        for stage in ('checking', 'joining', 'restarting'):
            result = self.join_post(route+'/domain-join/status', dict(hardware_uuid=inv['hardware_uuid'], stage=stage), token)
            self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(self.join_post(route+'/domain-join/config', dict(hardware_uuid=inv['hardware_uuid']), token).status_code, 400)
        self.assertEqual(self.join_post(route+'/domain-join/status', dict(hardware_uuid=inv['hardware_uuid'], stage='checking'), token).status_code, 400)
        self.assertEqual(self.join_post(route+'/domain-join/status', verified, token).status_code, 200)
        payload.update(domain_name='corp.test', domain_join_verified=True)
        self.assertEqual(self.join_post(route+'/finish', payload, token).status_code, 200)
        item = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(item['state'], 'completed')
        self.assertEqual(item['domain_join']['state'], 'verified')

    def test_domain_join_bootstrap_fits_with_root_certificate_and_preserves_scripts(self):
        ca = '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(bytes(range(256))*6).decode() + '\n-----END CERTIFICATE-----'
        cfg = dict(job_id=str(uuid.uuid4()), server_url='https://deployment.example.test/pc-deploy',
                   hardware_uuid=str(uuid.uuid4()), token='T'*54, ca_pem=ca,
                   domain_join=dict(domain='corp.example.test', computer_name='WFQ101755', employee_id='WFQ101755'))
        command = finalizer_command(cfg)
        self.assertLess(len(command), 30000)
        bootstrap = decoded_bootstrap(command)
        files = bootstrap_files(bootstrap)
        scripts = {name: content for name, content in files.items() if name.endswith('.ps1')}
        self.assertEqual(set(scripts), {'Finalize.ps1', 'DomainJoin.ps1', 'DeviceInfo.ps1'})
        for name, actual in scripts.items():
            expected = (Path(__file__).parent/'pc_deploy'/'agent'/name).read_text(encoding='utf-8-sig')
            self.assertEqual(actual.replace('\r\n', '\n'), expected)
        self.assertEqual(bootstrap_config(bootstrap), cfg)
        if os.name == 'nt':
            # Run the actual PS5.1 extraction while intercepting every scheduling/ACL command.
            mock = """$ErrorActionPreference='Stop'
function icacls.exe { $global:LASTEXITCODE=0 }
function New-ScheduledTaskAction {}
function New-ScheduledTaskTrigger {}
function Register-ScheduledTask {}
function Start-ScheduledTask {}
"""
            with tempfile.TemporaryDirectory(prefix='pcdeploy-bootstrap-test-') as directory:
                environment = dict(os.environ, ProgramData=directory)
                launcher = base64.b64decode(command.rsplit(' ', 1)[1]).decode('utf-16le')
                encoded = base64.b64encode((mock+launcher).encode('utf-16le')).decode()
                powershell = Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
                result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                folder = Path(directory)/'PCDeploy'/cfg['job_id']
                self.assertEqual(json.loads((folder/'config.json').read_text(encoding='utf-8')), cfg)
                for name in scripts:
                    expected = (Path(__file__).parent/'pc_deploy'/'agent'/name).read_text(encoding='utf-8-sig')
                    self.assertEqual((folder/name).read_text(encoding='utf-8-sig'), expected)

    def test_domain_join_wim_bootstrap_contains_no_join_password_and_stays_within_command_limit(self):
        inv, _, job, token, authorization = self.join_fixtures(wim=True)
        command = authorization['finalizer_command']
        self.assertLess(len(command), 30000)
        bootstrap = decoded_bootstrap(command)
        self.assertIn('DomainJoin.ps1', bootstrap_files(bootstrap))
        self.assertIn('GZipStream', bootstrap)
        self.assertNotIn('Test-only-domain-password', bootstrap)
        payload = dict(hardware_uuid=inv['hardware_uuid'], computer_name='WFQ101755',
                       os_build=22631, image_state='IMAGE_STATE_COMPLETE', oobe_done=True,
                       domain_name='corp.test', domain_join_verified=True)
        verified = dict(hardware_uuid=inv['hardware_uuid'], stage='verified', domain='corp.test',
                        computer_name='WFQ101755', secure_channel=True)
        self.assertEqual(self.join_post(f'/pc-deploy/api/agent/jobs/{job}/domain-join/status', verified, token).status_code, 200)
        self.assertEqual(self.join_post(f'/pc-deploy/api/agent/jobs/{job}/finish', payload, token).status_code, 400)
        payload['os_build'] = 26100
        self.assertEqual(self.join_post(f'/pc-deploy/api/agent/jobs/{job}/finish', payload, token).status_code, 200)

    def test_domain_join_failure_reports_installed_windows_and_redacts_password(self):
        inv, _, job, token, _ = self.join_fixtures()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        failed = dict(hardware_uuid=inv['hardware_uuid'], stage='failed',
                      detail='Access denied Test-only-domain-password')
        result = self.join_post(route+'/domain-join/status', failed, token)
        self.assertEqual(result.status_code, 200, result.json)
        events = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(events['job']['state'], 'failed')
        self.assertTrue(events['job']['domain_join']['os_installed'])
        self.assertNotIn('Test-only-domain-password', json.dumps(events))
        self.assertIn('[redacted]', events['job']['domain_join']['detail'])
        self.assertEqual(self.join_post(route+'/domain-join/status', failed, token).status_code, 200)
        repeated = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(repeated['events'], events['events'])
        self.assertNotIn('Test-only-domain-password', json.dumps(repeated))
        self.assertEqual(self.join_post(route+'/domain-join/config', dict(hardware_uuid=inv['hardware_uuid']), token).status_code, 400)

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

    def test_registration_only_heartbeat_does_not_claim_queued_job(self):
        inv, reg, job = self.queued()
        with self.store.connect(write=True) as c:
            c.execute('UPDATE devices SET last_seen=0 WHERE id=?', (inv['hardware_uuid'],))
        r = self.post('/pc-deploy/api/agent/poll', dict(inv, registration_only=True), reg['token'])
        self.assertEqual(r.status_code, 200, r.json)
        self.assertEqual(r.json, dict(job=None, registration_only=True))
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT state FROM jobs WHERE id=?', (job,)).fetchone()['state'], 'queued')
            self.assertGreater(c.execute('SELECT last_seen FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()['last_seen'], time.time()-10)

    def test_registration_only_still_requires_valid_device_identity(self):
        inv, reg = self.register()
        r = self.post('/pc-deploy/api/agent/poll', dict(inv, registration_only=True), 'invalid-token')
        self.assertIn(r.status_code, (400, 401))
        bad = dict(inv, hardware_uuid=str(uuid.uuid4()), registration_only=True)
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', bad, reg['token']).status_code, 400)

    def test_registration_only_flag_requires_boolean_true(self):
        inv, reg, job = self.queued()
        r = self.post('/pc-deploy/api/agent/poll', dict(inv, registration_only='true'), reg['token'])
        self.assertEqual(r.status_code, 200, r.json)
        self.assertEqual(r.json['job']['id'], job)

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
            self.assertGreater(cfg['expires_at']-time.time(),604790)
            self.assertLessEqual(cfg['expires_at']-time.time(),604800)
            with self.store.connect() as c:
                row=c.execute('SELECT * FROM enrollments WHERE token_hash=?',
                              (token_hash(cfg['enrollment_token']),)).fetchone()
            self.assertEqual(row['expires'],cfg['expires_at'])
            self.assertIn('Build-WinPE.ps1',z.namelist())
            self.assertNotIn('admin_password',cfg)

    def test_enrollment_extension_preserves_existing_iso_token_and_jobs(self):
        inv,reg,job=self.queued()
        identity=token_hash(self.enrollment)
        with self.store.connect() as c:
            before=dict(c.execute('SELECT * FROM enrollments WHERE token_hash=?',(identity,)).fetchone())
            device=dict(c.execute('SELECT * FROM devices').fetchone())
            task=dict(c.execute('SELECT * FROM jobs WHERE id=?',(job,)).fetchone())
        response=self.post(f'/pc-deploy/api/enrollments/{identity}/extend')
        self.assertEqual(response.status_code,200,response.json)
        self.assertGreater(response.json['expires_at']-time.time(),604790)
        with self.store.connect() as c:
            after=dict(c.execute('SELECT * FROM enrollments WHERE token_hash=?',(identity,)).fetchone())
            self.assertEqual(dict(c.execute('SELECT * FROM devices').fetchone()),device)
            self.assertEqual(dict(c.execute('SELECT * FROM jobs WHERE id=?',(job,)).fetchone()),task)
        self.assertEqual(after['uses'],before['uses'])
        self.assertEqual(after['token_hash'],before['token_hash'])
        self.assertEqual(self.post('/pc-deploy/api/agent/register',inv,self.enrollment).status_code,200)

    def test_enrollment_extension_rejects_expired_exhausted_missing_and_untrusted_calls(self):
        identity=token_hash(self.enrollment)
        path=f'/pc-deploy/api/enrollments/{identity}/extend'
        self.assertEqual(self.app.test_client().post(path,json={}).status_code,401)
        self.assertEqual(self.client.post(path,json={}).status_code,403)
        with self.client.session_transaction() as session_data:
            session_data['admin_role']='admin'
        self.assertEqual(self.post(path).status_code,403)
        with self.client.session_transaction() as session_data:
            session_data['admin_role']='super_admin'
        for expires,uses in [(time.time()-1,0),(time.time()+3600,500)]:
            with self.store.connect(write=True) as c:
                c.execute('UPDATE enrollments SET expires=?,uses=? WHERE token_hash=?',(expires,uses,identity))
            self.assertEqual(self.post(path).status_code,400)
        self.assertEqual(self.post('/pc-deploy/api/enrollments/'+'a'*64+'/extend').status_code,400)
        self.assertEqual(self.post('/pc-deploy/api/enrollments/invalid/extend').status_code,400)

    def test_enrollment_extension_never_shortens_validity(self):
        identity=token_hash(self.enrollment)
        expires=time.time()+14*86400
        with self.store.connect(write=True) as c:
            c.execute('UPDATE enrollments SET expires=? WHERE token_hash=?',(expires,identity))
        response=self.post(f'/pc-deploy/api/enrollments/{identity}/extend')
        self.assertEqual(response.json['expires_at'],expires)
        items=self.client.get('/pc-deploy/api/dashboard').json['enrollments']
        self.assertEqual(items,[dict(id=identity,expires_at=expires,uses=0)])

    def test_enrollment_expiry_does_not_end_established_polling(self):
        inv,reg=self.register()
        with self.store.connect(write=True) as c:
            c.execute('UPDATE enrollments SET expires=?',(time.time()-1,))
        self.assertEqual(self.post('/pc-deploy/api/agent/poll',inv,reg['token']).status_code,200)
        self.assertEqual(self.post('/pc-deploy/api/agent/register',inv,self.enrollment).status_code,400)
        self.assertLess(self.client.get('/pc-deploy/api/dashboard').json['enrollments'][0]['expires_at'],time.time())

    def test_quick_source_accepts_metadata_without_hashes_and_ignores_old_hashes(self):
        for kind in ('setup','wim'):
            value=install_source()
            value.update(kind=kind)
            if kind=='wim':
                value['image_file']='win11.wim'
            value.pop('image_sha256',None)
            value.pop('setup_sha256',None)
            response=self.post('/pc-deploy/api/sources',value)
            self.assertEqual(response.status_code,200,response.json)
            value.update(image_sha256='legacy-invalid-unused',setup_sha256='legacy-unused')
            cleaned=source_record(value)
            self.assertEqual(cleaned['image_sha256'],'')
            self.assertEqual(cleaned['setup_sha256'],'')
            self.assertEqual(cleaned['images'][0]['build'],26100)

    def test_boot_file_allowlist(self):
        self.assertEqual(self.client.get('/pc-deploy/boot/secret.key').status_code,404)
        self.assertEqual(self.client.get('/pc-deploy/boot/wimboot').status_code,404)
        self.assertIn('#!ipxe',self.client.get('/pc-deploy/boot.ipxe').text)

    def test_gate_can_enable_http_with_existing_confirmations(self):
        r=self.post('/pc-deploy/api/settings',dict(public_url='http://deploy.test',concurrency=2,
                   ca_pem='',enabled=True,confirmation='ENABLE',isolated_network_confirmed=True))
        self.assertEqual(r.status_code,200)


    def test_inventory_model_metadata_round_trips_without_changing_legacy_hash(self):
        legacy = machine()
        expected = inventory(legacy)
        empty = dict(legacy, manufacturer='', system_family=None, product_name='', product_version='')
        self.assertEqual(digest(inventory(empty)), digest(expected))
        enriched = dict(legacy, model='HKD-WXX', manufacturer='HUAWEI', system_family='MateBook',
                        product_name='HKD-WXX', product_version='M1010')
        inv, reg, _, profile = self.fixtures(enriched)
        device = self.client.get('/pc-deploy/api/dashboard').json['devices'][0]
        self.assertEqual(device['manufacturer'], 'HUAWEI')
        self.assertEqual(device['model'], 'HKD-WXX')
        pv = self.preview(inv, profile)
        self.enable()
        result = self.post('/pc-deploy/api/jobs/commit',
                           dict(preview_id=pv.json['id'], confirmation='YES', physical_confirmed=True))
        job = result.json['ids'][0]
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code, 200)
        snapshot = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(snapshot['model'], 'HKD-WXX')
        self.assertEqual(snapshot['manufacturer'], 'HUAWEI')
        self.assertEqual(snapshot['system_family'], 'MateBook')
        self.assertEqual(snapshot['product_version'], 'M1010')
        with self.assertRaises(Invalid):
            inventory(dict(legacy, manufacturer=['invalid']))

    def test_failed_job_manual_review_keeps_failure_finish_time_and_no_retry(self):
        inv, reg, job = self.queued()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(route+'/start', inv, reg['token'])
        self.post(route+'/event', dict(code='WIM', detail='original diagnostic'), reg['token'])
        with self.store.connect() as c:
            before = dict(c.execute('SELECT * FROM jobs WHERE id=?', (job,)).fetchone())
            consumed = c.execute('SELECT consumed FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()[0]
            finish_token = self.store.decrypt(before['secret'])['finish_token']
        payload = dict(physical_confirmed=True, outcome='installed', note='现场已能进入 Windows')
        review_route = f'/pc-deploy/api/jobs/{job}/review'
        self.assertEqual(self.post(review_route, payload).status_code, 200)
        self.assertEqual(self.post(review_route, payload).status_code, 200)
        result = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(result['job']['state'], 'failed')
        self.assertEqual(result['job']['review']['outcome'], 'installed')
        self.assertEqual(result['job']['review']['operator'], 'test-super-admin')
        self.assertEqual(sum(e['kind'] == 'review' for e in result['events']), 1)
        self.assertTrue(any('original diagnostic' in e['message'] for e in result['events']))
        self.assertEqual(self.post(route+'/finish', {}, finish_token).status_code, 400)
        with self.store.connect() as c:
            after = dict(c.execute('SELECT * FROM jobs WHERE id=?', (job,)).fetchone())
            self.assertEqual(after['updated'], before['updated'])
            self.assertEqual(after['secret'], before['secret'])
            self.assertEqual(c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)
            self.assertEqual(c.execute('SELECT consumed FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()[0], consumed)
        payload['outcome'] = 'not_installed'
        self.assertEqual(self.post(review_route, payload).status_code, 200)
        updated = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(updated['job']['review']['outcome'], 'not_installed')
        self.assertEqual(sum(e['kind'] == 'review' for e in updated['events']), 2)

    def test_manual_review_requires_failed_job_permission_and_explicit_result(self):
        inv, reg, job = self.queued()
        route = f'/pc-deploy/api/jobs/{job}/review'
        valid = dict(physical_confirmed=True, outcome='installed')
        self.assertEqual(self.post(route, valid).status_code, 400)
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/event', dict(code='WIM'), reg['token'])
        for bad in (dict(outcome='installed'), dict(valid, physical_confirmed='true'),
                    dict(valid, outcome='completed'), dict(valid, note=['invalid']), dict(valid, note='x'*501)):
            self.assertEqual(self.post(route, bad).status_code, 400)
        self.assertEqual(self.app.test_client().post(route, json=valid).status_code, 401)
        self.assertEqual(self.client.post(route, json=valid).status_code, 403)
        with self.client.session_transaction() as s:
            s['admin_role'] = 'readonly'
        self.assertEqual(self.post(route, valid).status_code, 403)
        with self.client.session_transaction() as s:
            s['admin_role'] = 'super_admin'
        self.assertIsNone(self.client.get(f'/pc-deploy/api/jobs/{job}/events').json['job']['review'])

    def test_reconcile_does_not_send_retry(self):
        inv,reg,job=self.queued()
        self.post('/pc-deploy/api/agent/poll',inv,reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start',inv,reg['token'])
        self.assertEqual(self.post(f'/pc-deploy/api/jobs/{job}/reconcile',dict(confirmation='CHECKED')).status_code,200)
        profile=self.client.get('/pc-deploy/api/dashboard').json['profiles'][0]['id']
        self.assertEqual(self.preview(inv,profile).status_code,400)

    def test_https_required_outside_unit_mode(self):
        self.app.config['PC_DEPLOY_ALLOW_HTTP'] = False
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

    def test_remote_admin_http_is_supported(self):
        self.app.testing=False
        try:
            r=self.client.get('/pc-deploy/api/session',environ_overrides={'REMOTE_ADDR':'192.0.2.15'})
            self.assertEqual(r.status_code,200)
        finally:
            self.app.testing=True


    def test_http_full_flow_and_completion_config(self):
        from unittest.mock import patch
        import pc_deploy
        self.app.testing = False
        self.addCleanup(setattr, self.app, 'testing', True)
        self.client.environ_base['REMOTE_ADDR'] = '192.0.2.15'
        settings = dict(public_url='http://deploy.test/pc-deploy', concurrency=2, enabled=True,
                        isolated_network_confirmed=True, confirmation='ENABLE', ca_pem='')
        self.assertEqual(self.post('/pc-deploy/api/settings', settings).status_code, 200)
        package = self.post('/pc-deploy/api/bootstrap')
        self.assertEqual(package.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(package.data)) as archive:
            config = json.loads(archive.read('config.json'))
            self.assertEqual(config['server_url'], 'http://deploy.test/pc-deploy')
            self.assertIs(config['allow_http'], True)
        inv, reg, _, profile = self.fixtures()
        pv = self.preview(inv, profile).json
        commit = self.post('/pc-deploy/api/jobs/commit', dict(preview_id=pv['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(commit.status_code, 200)
        job = commit.json['ids'][0]
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', inv, reg['token']).status_code, 200)
        with patch('pc_deploy.answer_file', wraps=pc_deploy.answer_file) as generate:
            result = self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
            self.assertEqual(result.status_code, 200, result.json)
            self.assertIs(generate.call_args.args[5]['allow_http'], True)
            self.assertEqual(generate.call_args.args[5]['server_url'], 'http://deploy.test/pc-deploy')
        with self.store.connect() as c:
            token = self.store.decrypt(c.execute('SELECT secret FROM jobs WHERE id=?', (job,)).fetchone()['secret'])['finish_token']
        report = dict(hardware_uuid=inv['hardware_uuid'], computer_name='TEST-'+digest(inv['hardware_uuid'])[:8].upper(),
                      os_build=26100, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/finish', report, token).status_code, 200)

    def test_https_only_mode_is_optional_and_enforces_transport(self):
        self.app.config['PC_DEPLOY_ALLOW_HTTP'] = False
        self.app.testing = False
        self.addCleanup(setattr, self.app, 'testing', True)
        response = self.client.get('/pc-deploy/api/session', environ_overrides={'REMOTE_ADDR':'192.0.2.15'})
        self.assertEqual(response.status_code, 403)
        response = self.client.get('/pc-deploy/api/session', base_url='https://localhost', environ_overrides={'REMOTE_ADDR':'192.0.2.15'})
        self.assertEqual(response.status_code, 200)
        result = self.post('/pc-deploy/api/settings', dict(public_url='http://deploy.test', concurrency=2, enabled=False))
        self.assertEqual(result.status_code, 400)

    def test_https_bootstrap_does_not_allow_http_downgrade(self):
        self.enable(False)
        package = self.post('/pc-deploy/api/bootstrap')
        with zipfile.ZipFile(io.BytesIO(package.data)) as archive:
            config = json.loads(archive.read('config.json'))
        self.assertIs(config['allow_http'], False)

    def test_embedded_page_allows_only_same_origin_frames(self):
        with self.client.get('/pc-deploy/?embedded=1&view=sources') as response:
            self.assertEqual(response.status_code, 200)
            self.assertIn("frame-ancestors 'self'", response.headers['Content-Security-Policy'])
            self.assertNotIn('frame-ancestors *', response.headers['Content-Security-Policy'])

    def test_expired_embedded_session_keeps_top_level_login_link(self):
        anonymous = self.app.test_client()
        with anonymous.get('/pc-deploy/?embedded=1') as response:
            self.assertEqual(response.status_code, 401)
            self.assertIn('target="_top"', response.text)
            self.assertEqual(response.mimetype, 'text/html')
        self.assertEqual(anonymous.get('/pc-deploy/').headers['Location'], '/admin')

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


    def wim_fixtures(self, mode='wipe_disk', capable=True):
        inv = machine()
        if capable:
            inv['wim_apply_v1'] = True
        inv['disks'][0]['partitions'] = [
            dict(number=1, guid=str(uuid.uuid4()), gpt_type='c12a7328-f81f-11d2-ba4b-00a0c93ec93b',
                 offset=1024**2, size_bytes=260*1024**2, filesystem='FAT32', windows=False),
            dict(number=3, guid=str(uuid.uuid4()), gpt_type='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',
                 offset=1024**3, size_bytes=128*1024**3, filesystem='NTFS', windows=True),
            dict(number=5, guid=str(uuid.uuid4()), gpt_type='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',
                 offset=130*1024**3, size_bytes=256*1024**3, filesystem='NTFS', windows=False)]
        inv, reg = self.register(inv)
        source = install_source()
        source.update(kind='wim', image_file='win11.wim', path=r'\\test-fileserver\reminst')
        source.pop('setup_sha256')
        sr = self.post('/pc-deploy/api/sources', source)
        self.assertEqual(sr.status_code, 200, sr.json)
        pr = self.post('/pc-deploy/api/profiles', dict(name='Custom WIM', source_id=sr.json['id'],
                       image_index=6, system_gib=0, disk_mode=mode))
        self.assertEqual(pr.status_code, 200, pr.json)
        return inv, reg, sr.json['id'], pr.json['id']

    def wim_preview(self, inv, profile, partition=3):
        disk = inventory(inv)['disks'][0]
        target = dict(device_id=inv['hardware_uuid'], disk_key=disk['key'])
        if partition is not None:
            target['partition_key'] = next(p['key'] for p in disk['partitions'] if p['number'] == partition)
        return self.post('/pc-deploy/api/jobs/preview', dict(profile_id=profile, targets=[target]))

    def wim_queued(self, mode='wipe_disk'):
        inv, reg, _, profile = self.wim_fixtures(mode)
        pv = self.wim_preview(inv, profile)
        self.assertEqual(pv.status_code, 200, pv.json)
        self.enable()
        result = self.post('/pc-deploy/api/jobs/commit', dict(
            preview_id=pv.json['id'], confirmation='YES', physical_confirmed=True))
        self.assertEqual(result.status_code, 200, result.json)
        return inv, reg, result.json['ids'][0]


    def test_four_phase_timing_starts_at_dispatch_and_freezes_each_stage(self):
        from unittest.mock import patch
        inv, reg, job, token, _ = self.join_fixtures(wim=True)
        route = f'/pc-deploy/api/agent/jobs/{job}'
        initial = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(initial['timings']['requested_at'], initial['created'])
        self.assertIsNone(initial['timings']['restore_finished_at'])
        self.assertIsNone(initial['timings']['join_started_at'])
        now = time.time()
        with patch('pc_deploy.time.time', return_value=now+100):
            self.assertEqual(self.join_post(route+'/event', dict(stage='boot_files'), reg['token']).status_code, 200)
        with patch('pc_deploy.time.time', return_value=now+120):
            self.assertEqual(self.join_post(route+'/event', dict(stage='awaiting_report'), reg['token']).status_code, 200)
        restored = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['timings']
        self.assertEqual(restored['restore_finished_at'], now+120)
        self.assertIsNone(restored['windows_ready_at'])
        with patch('pc_deploy.time.time', return_value=now+180):
            self.assertEqual(self.join_post(route+'/domain-join/status',
                dict(hardware_uuid=inv['hardware_uuid'], stage='checking'), token).status_code, 200)
        ready = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['timings']
        self.assertEqual(ready['windows_ready_at'], now+180)
        self.assertEqual(ready['join_started_at'], now+180)
        self.assertIsNone(ready['join_finished_at'])
        verified = dict(hardware_uuid=inv['hardware_uuid'], stage='verified',
                        domain='corp.test', computer_name='WFQ101755', secure_channel=True)
        with patch('pc_deploy.time.time', return_value=now+220):
            self.assertEqual(self.join_post(route+'/domain-join/status', verified, token).status_code, 200)
        with self.store.connect() as c:
            data = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
        build = next(image['build'] for image in data['source']['images'] if image['index'] == data['profile']['image_index'])
        finished = dict(hardware_uuid=inv['hardware_uuid'], computer_name='WFQ101755', os_build=build,
                        image_state='IMAGE_STATE_COMPLETE', oobe_done=True,
                        domain_name='corp.test', domain_join_verified=True)
        with patch('pc_deploy.time.time', return_value=now+221):
            self.assertEqual(self.join_post(route+'/finish', finished, token).status_code, 200)
        final = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['timings']
        self.assertEqual(final['restore_finished_at'], now+120)
        self.assertEqual(final['windows_ready_at'], now+180)
        self.assertEqual(final['join_started_at'], now+180)
        self.assertEqual(final['join_finished_at'], now+221)
        self.assertEqual(final['finished_at'], now+221)
        self.assertEqual(self.client.get(f'/pc-deploy/api/jobs/{job}/events').json['job']['timings'], final)

    def test_manual_join_timer_starts_only_at_release(self):
        from unittest.mock import patch
        inv, _, job, token, _ = self.join_fixtures(wim=True, manual=True)
        with self.store.connect() as c:
            data = json.loads(c.execute('SELECT data FROM jobs WHERE id=?', (job,)).fetchone()['data'])
        build = next(image['build'] for image in data['source']['images'] if image['index'] == data['profile']['image_index'])
        ready = dict(hardware_uuid=inv['hardware_uuid'], computer_name='OLD-IMAGE',
                     os_build=build, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        now = time.time()
        with patch('pc_deploy.time.time', return_value=now+10):
            self.assertEqual(self.join_post(f'/pc-deploy/api/agent/jobs/{job}/domain-join/config', ready, token).status_code, 200)
        waiting = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['timings']
        self.assertTrue(waiting['waiting_for_release'])
        self.assertIsNone(waiting['join_started_at'])
        self.assertIsNone(waiting['finished_at'])
        with patch('pc_deploy.time.time', return_value=now+310):
            self.assertEqual(self.join_post('/pc-deploy/api/jobs/domain-join/release',
                dict(job_ids=[job], restart_confirmed=True)).status_code, 200)
        released = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['timings']
        self.assertEqual(released['windows_ready_at'], now+10)
        self.assertEqual(released['join_started_at'], now+310)
        self.assertFalse(released['waiting_for_release'])

    def test_wim_phase_timing_stops_restore_without_claiming_windows_ready(self):
        inv, reg, job = self.wim_queued()
        route = f'/pc-deploy/api/agent/jobs/{job}'
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.assertEqual(self.post(route+'/start', inv, reg['token']).status_code, 200)
        self.assertEqual(self.post(route+'/event', dict(stage='applying', percent=100), reg['token']).status_code, 200)
        progress = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertIsNone(progress['image_applied_at'])
        self.assertIsNone(progress['installed_at'])
        self.assertEqual(self.post(route+'/event', dict(stage='boot_files'), reg['token']).status_code, 200)
        boot = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertGreaterEqual(boot['image_applied_at'], boot['started_at'])
        self.assertIsNone(boot['deployment_finished_at'])
        self.assertEqual(self.post(route+'/event', dict(stage='awaiting_report'), reg['token']).status_code, 200)
        waiting = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(waiting['state'], 'awaiting_report')
        self.assertGreaterEqual(waiting['deployment_finished_at'], boot['image_applied_at'])
        self.assertEqual(waiting['image_applied_at'], boot['image_applied_at'])
        self.assertIsNone(waiting['installed_at'])
        history = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json['job']
        self.assertEqual(history['image_applied_at'], waiting['image_applied_at'])
        self.assertEqual(history['deployment_finished_at'], waiting['deployment_finished_at'])

    def test_automatic_join_reports_windows_ready_before_join_finishes(self):
        inv, _, job, token, _ = self.join_fixtures(wim=True)
        route = f'/pc-deploy/api/agent/jobs/{job}/domain-join/status'
        bad = dict(hardware_uuid=str(uuid.uuid4()), stage='checking')
        self.assertEqual(self.join_post(route, bad, token).status_code, 400)
        self.assertIsNone(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['installed_at'])
        self.assertEqual(self.join_post(route, dict(hardware_uuid=inv['hardware_uuid'], stage='checking'), token).status_code, 200)
        first = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertIsInstance(first['installed_at'], (int, float))
        self.assertEqual(first['state'], 'awaiting_report')
        self.assertEqual(first['domain_join']['state'], 'checking')
        self.assertEqual(self.join_post(route, dict(hardware_uuid=inv['hardware_uuid'], stage='joining'), token).status_code, 200)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['installed_at'], first['installed_at'])

    def test_installation_timing_uses_first_start_and_freezes_at_failure(self):
        inv, reg, job = self.wim_queued('system_partition')
        route = f'/pc-deploy/api/agent/jobs/{job}'
        queued = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertIsNone(queued['started_at'])
        self.assertIsNone(queued['finished_at'])
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.assertEqual(self.post(route+'/start', inv, reg['token']).status_code, 200)
        started = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        with self.store.connect() as c:
            first_start = c.execute("SELECT MIN(created) FROM events WHERE job_id=? AND kind='installing'", (job,)).fetchone()[0]
        self.assertEqual(started['started_at'], first_start)
        self.assertEqual(started['kind'], 'wim')
        self.assertIsNone(started['finished_at'])
        for percent in (12, 43):
            self.assertEqual(self.post(route+'/event', dict(stage='applying', percent=percent), reg['token']).status_code, 200)
        running = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(running['started_at'], first_start)
        self.assertIsNone(running['finished_at'])
        self.post(route+'/event', dict(code='WIM', detail='fixture stop'), reg['token'])
        stopped = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(stopped['state'], 'failed')
        self.assertGreaterEqual(stopped['finished_at'], first_start)
        history = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(history['job']['started_at'], first_start)
        self.assertEqual(history['job']['finished_at'], stopped['finished_at'])
        self.assertGreaterEqual(history['server_time'], stopped['finished_at'])
        again = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(again['finished_at'], stopped['finished_at'])

    def test_cancelled_before_installation_has_no_installation_start(self):
        _, _, job = self.queued()
        self.assertEqual(self.post(f'/pc-deploy/api/jobs/{job}/cancel').status_code, 200)
        result = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(result['state'], 'cancelled')
        self.assertIsNone(result['started_at'])
        self.assertIsNotNone(result['finished_at'])

    def test_wim_cache_metrics_are_retained_and_do_not_flood_logs(self):
        inv, reg, job = self.wim_queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        route = f'/pc-deploy/api/agent/jobs/{job}/event'
        for copied in (0, 50_000_000, 100_000_000):
            response = self.post(route, dict(stage='caching', percent=copied//1_000_000,
                metrics=dict(bytes_copied=copied, total_bytes=100_000_000, bytes_per_second=25_000_000,
                             elapsed_seconds=copied//25_000_000)), reg['token'])
            self.assertEqual(response.status_code, 200, response.json)
        for metrics in (dict(mode='local_cache'), dict(elapsed_seconds=120)):
            self.assertEqual(self.post(route, dict(stage='applying', percent=0, metrics=metrics), reg['token']).status_code, 200)
        self.assertEqual(self.post(route, dict(stage='boot_files'), reg['token']).status_code, 200)
        current = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertEqual(current['performance']['caching']['bytes_copied'], 100_000_000)
        self.assertTrue(current['performance']['caching']['finished'])
        self.assertEqual(current['performance']['applying'], dict(mode='local_cache', elapsed_seconds=120))
        self.assertEqual(self.post(route, dict(stage='caching', percent=0), reg['token']).status_code, 400)
        with self.store.connect() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events WHERE job_id=? AND message=?",
                (job, '正在缓存镜像到所选 Windows 分区')).fetchone()[0], 1)
        log = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(log['job']['performance'], current['performance'])

    def test_wim_cache_metrics_validate_before_mutation(self):
        inv, reg, job = self.wim_queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        route = f'/pc-deploy/api/agent/jobs/{job}/event'
        for metrics in ([], 'bad', dict(elapsed_seconds=True), dict(elapsed_seconds=-1),
                        dict(mode='unknown'), dict(total_bytes=1, bytes_copied=2, bytes_per_second=1),
                        dict(total_bytes=1, bytes_copied=True, bytes_per_second=1), dict(unknown=1)):
            self.assertEqual(self.post(route, dict(stage='caching', percent=50, metrics=metrics), reg['token']).status_code, 400)
        current = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertIsNone(current['progress'])
        self.assertIsNone(current['performance'])
        self.assertEqual(self.post(route, dict(stage='applying', metrics=dict(bytes_per_second=10)), reg['token']).status_code, 400)

    def test_wim_progress_heartbeats_update_status_without_flooding_events(self):
        inv, reg, job = self.wim_queued('system_partition')
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        route = f'/pc-deploy/api/agent/jobs/{job}/event'
        with self.store.connect() as c:
            before = c.execute('SELECT COUNT(*) FROM events WHERE job_id=?', (job,)).fetchone()[0]
        for percent in (None, 0, 15, 15, 37, 25, None, 100):
            response = self.post(route, dict(stage='applying', percent=percent), reg['token'])
            self.assertEqual(response.status_code, 200, response.json)
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        current = next(j for j in dashboard['jobs'] if j['id'] == job)
        self.assertEqual(current['progress']['percent'], 100)
        self.assertEqual(current['state'], 'installing')
        self.assertEqual(current['updated'], current['progress']['updated'])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM events WHERE job_id=?', (job,)).fetchone()[0], before + 1)
            self.assertEqual(c.execute('SELECT last_seen FROM devices WHERE id=?', (inv['hardware_uuid'],)).fetchone()[0], current['updated'])
        for _ in range(3):
            self.assertEqual(self.post(route, dict(stage='boot_files'), reg['token']).status_code, 200)
        self.assertEqual(self.post(route, dict(stage='applying', percent=99), reg['token']).status_code, 400)
        for _ in range(2):
            self.assertEqual(self.post(route, dict(stage='awaiting_report'), reg['token']).status_code, 200)
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        current = next(j for j in dashboard['jobs'] if j['id'] == job)
        self.assertEqual(current['state'], 'awaiting_report')
        self.assertIsNone(current['progress']['percent'])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM events WHERE job_id=?', (job,)).fetchone()[0], before + 3)

    def test_wim_progress_rejects_invalid_percent_before_mutating_status(self):
        inv, reg, job = self.wim_queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        route = f'/pc-deploy/api/agent/jobs/{job}/event'
        for percent in (-1, 101, True, False, 12.5, '30', [], {}):
            with self.subTest(percent=percent):
                self.assertEqual(self.post(route, dict(stage='applying', percent=percent), reg['token']).status_code, 400)
        self.assertEqual(self.post(route, dict(stage='boot_files', percent=100), reg['token']).status_code, 400)
        current = self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]
        self.assertIsNone(current['progress'])
        self.assertEqual(current['state'], 'installing')

    def test_job_logs_collapse_legacy_heartbeats_without_deleting_or_mixing_tasks(self):
        _, _, job = self.queued()
        with self.store.connect(write=True) as c:
            c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                      (job, 'failed', 'older important diagnostic', time.time()))
            for index in range(250):
                for identity in (job, 'another-job'):
                    c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                              (identity, 'installing', '正在还原封装 WIM', time.time()))
            c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                      (job, 'note', 'keep this intervening event', time.time()))
            c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                      (job, 'installing', '正在还原封装 WIM', time.time()))
            count = c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        events = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json['events']
        self.assertIn('older important diagnostic', [e['message'] for e in events])
        self.assertIn('keep this intervening event', [e['message'] for e in events])
        self.assertEqual(sum(e['kind'] == 'installing' for e in events), 2)
        self.assertTrue(all(e['job_id'] == job for e in events))
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM events').fetchone()[0], count)


    def test_task_history_is_paged_by_job_even_for_the_same_device(self):
        _, _, job = self.queued()
        other = str(uuid.uuid4())
        with self.store.connect(write=True) as c:
            c.execute("""INSERT INTO jobs SELECT ?,device_id,boot_id,'failed',data,secret,created-60,
                         updated,expires FROM jobs WHERE id=?""", (other, job))
            for index in range(205):
                c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                          (job, 'note', 'task entry ' + str(index), time.time()))
            for index in range(250):
                c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                          (other, 'failed', 'other task entry ' + str(index), time.time()))
        first = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(first['job']['id'], job)
        self.assertEqual(len(first['events']), 100)
        self.assertIsNotNone(first['next_before'])
        self.assertNotIn('secret', first['job'])
        with self.store.connect(write=True) as c:
            c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                      (job, 'note', 'new head while paging', time.time()))
        events = list(first['events'])
        cursor = first['next_before']
        while cursor is not None:
            page = self.client.get(f'/pc-deploy/api/jobs/{job}/events?before={cursor}').json
            self.assertTrue(all(e['id'] < cursor for e in page['events']))
            events.extend(page['events'])
            cursor = page['next_before']
        self.assertEqual(len(events), 206)  # 205 diagnostic rows plus original confirmation.
        self.assertEqual(len({e['id'] for e in events}), len(events))
        self.assertTrue(all(e['job_id'] == job for e in events))
        self.assertIn('task entry 0', [e['message'] for e in events])
        self.assertNotIn('new head while paging', [e['message'] for e in events])
        latest = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        self.assertEqual(latest['events'][0]['message'], 'new head while paging')
        other_result = self.client.get(f'/pc-deploy/api/jobs/{other}/events').json
        self.assertEqual(other_result['job']['device_id'], first['job']['device_id'])
        self.assertTrue(all(e['job_id'] == other for e in other_result['events']))
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        self.assertTrue(all(e['job_id'] is None for e in dashboard['events']))
        self.assertTrue(any(e['kind'] == 'source' for e in dashboard['events']))

    def test_job_event_history_requires_admin_and_rejects_invalid_cursors(self):
        _, reg, job = self.queued()
        route = f'/pc-deploy/api/jobs/{job}/events'
        self.assertEqual(self.app.test_client().get(route, headers={'Authorization':'Bearer '+reg['token']}).status_code, 401)
        with self.client.session_transaction() as s:
            s['admin_role'] = 'readonly'
        self.assertEqual(self.client.get(route).status_code, 403)
        with self.client.session_transaction() as s:
            s['admin_role'] = 'super_admin'
        for before in ('', '0', '-1', '1.5', 'abc', '9223372036854775808', '9'*100):
            self.assertEqual(self.client.get(route, query_string={'before':before}).status_code, 400)
        self.assertEqual(self.client.get('/pc-deploy/api/jobs/missing/events').status_code, 400)

    def test_job_history_pagination_collapses_heartbeats_before_the_cursor(self):
        _, _, job = self.queued()
        with self.store.connect(write=True) as c:
            for _ in range(250):
                c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                          (job, 'installing', '正在还原封装 WIM', time.time()))
            for index in range(100):
                c.execute('INSERT INTO events(job_id,kind,message,created) VALUES(?,?,?,?)',
                          (job, 'note', 'after heartbeat ' + str(index), time.time()))
        route = f'/pc-deploy/api/jobs/{job}/events'
        first = self.client.get(route).json
        second = self.client.get(route, query_string={'before':first['next_before']}).json
        self.assertEqual(len(first['events']), 100)
        self.assertEqual(sum(e['kind'] == 'installing' for e in second['events']), 1)
        self.assertIsNone(second['next_before'])

    def test_failure_details_reach_job_logs_without_exposing_job_secrets(self):
        inv, reg, job = self.queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token']).status_code, 200)
        with self.store.connect() as c:
            secret = self.store.decrypt(c.execute('SELECT secret FROM jobs WHERE id=?', (job,)).fetchone()['secret'])
        sensitive = [reg['token']] + [v for v in secret.values() if isinstance(v, str) and v]
        detail = 'Error: access path denied\nCommand: Add-PartitionAccessPath\nScript line: 372\n' + '\n'.join(sensitive)
        response = self.post(f'/pc-deploy/api/agent/jobs/{job}/event',
                             dict(code='DISK_CHANGED', detail=detail), reg['token'])
        self.assertEqual(response.status_code, 200, response.json)
        dashboard = self.client.get('/pc-deploy/api/dashboard').json
        self.assertEqual(dashboard['jobs'][0]['state'], 'failed')
        history = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json
        message = next(e['message'] for e in history['events'] if e['kind'] == 'failed')
        self.assertIn('客户端错误详情：\nError: access path denied', message)
        self.assertIn('Command: Add-PartitionAccessPath\nScript line: 372', message)
        self.assertIn('[REDACTED]', message)
        for value in sensitive:
            self.assertNotIn(value, json.dumps(dashboard))
            self.assertNotIn(value, json.dumps(history))

    def test_failure_details_are_bounded_and_control_characters_removed(self):
        inv, reg, job = self.wim_queued('system_partition')
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
        response = self.post(f'/pc-deploy/api/agent/jobs/{job}/event',
                             dict(code='DISK_CHANGED', detail='Error:\r\n\x00access denied\t' + 'x' * 12000), reg['token'])
        self.assertEqual(response.status_code, 200, response.json)
        events = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json['events']
        message = next(e['message'] for e in events if e['kind'] == 'failed')
        detail = message.split('\n客户端错误详情：\n', 1)[1]
        self.assertLessEqual(len(detail), 8192)
        self.assertTrue(detail.startswith('Error:\naccess denied\t'))
        self.assertNotIn('\x00', detail)
        self.assertNotIn('\r', detail)

    def test_legacy_or_malformed_failure_detail_does_not_lose_failure_event(self):
        for detail in (None, '', {'unexpected': 'object'}):
            with self.subTest(detail=detail):
                inv, reg, job = self.wim_queued('system_partition')
                self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
                self.post(f'/pc-deploy/api/agent/jobs/{job}/start', inv, reg['token'])
                response = self.post(f'/pc-deploy/api/agent/jobs/{job}/event',
                                     dict(code='DISK_CHANGED', detail=detail), reg['token'])
                self.assertEqual(response.status_code, 200, response.json)
                events = self.client.get(f'/pc-deploy/api/jobs/{job}/events').json['events']
                self.assertIn('客户端未上报有效错误详情', events[0]['message'])
                self.assertEqual(events[0]['kind'], 'failed')

    def test_wim_preserve_settings_does_not_require_new_local_password(self):
        self.wim_fixtures()
        d = self.client.get('/pc-deploy/api/dashboard').json
        self.assertEqual(d['sources'][0]['kind'], 'wim')
        self.assertEqual(d['sources'][0]['setup_sha256'], '')
        p = d['profiles'][0]
        self.assertTrue(p['preserve_image_settings'])
        self.assertEqual(p['username'], '')
        self.assertFalse(d['settings']['enabled'])

    def test_wim_blocks_legacy_pe_before_task_creation(self):
        inv, _, _, profile = self.wim_fixtures(capable=False)
        result = self.wim_preview(inv, profile)
        self.assertEqual(result.status_code, 400)
        self.assertIn('PE', result.json['error'])
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'], [])

    def test_wim_preserve_requires_explicit_system_partition(self):
        inv, _, _, profile = self.wim_fixtures('system_partition')
        self.assertEqual(self.wim_preview(inv, profile, partition=None).status_code, 400)
        self.assertEqual(self.wim_preview(inv, profile, partition=5).status_code, 400)
        result = self.wim_preview(inv, profile)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['targets'][0]['partitions']['windows']['number'], 3)
        self.assertEqual(result.json['targets'][0]['partitions']['efi']['number'], 1)
        self.assertIn('保留其他分区', result.json['warning'])

    def test_wim_preserve_rejects_ambiguous_efi(self):
        inv, reg, _, profile = self.wim_fixtures('system_partition')
        extra = copy.deepcopy(inv['disks'][0]['partitions'][0])
        extra.update(number=2, guid=str(uuid.uuid4()), offset=300*1024**2)
        inv['disks'][0]['partitions'].append(extra)
        self.assertEqual(self.post('/pc-deploy/api/agent/poll', inv, reg['token']).status_code, 200)
        self.assertEqual(self.wim_preview(inv, profile).status_code, 400)

    def test_wim_partition_change_invalidates_preview(self):
        inv, reg, _, profile = self.wim_fixtures('system_partition')
        pv = self.wim_preview(inv, profile)
        inv['disks'][0]['partitions'][1]['guid'] = str(uuid.uuid4())
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.enable()
        result = self.post('/pc-deploy/api/jobs/commit', dict(preview_id=pv.json['id'],
            confirmation='YES', physical_confirmed=True))
        self.assertEqual(result.status_code, 400)

    def test_wim_full_flow_has_no_setup_answer_or_new_account(self):
        inv, reg, identity = self.wim_queued()
        job = self.post('/pc-deploy/api/agent/poll', inv, reg['token']).json['job']
        self.assertEqual(job['source']['kind'], 'wim')
        result = self.post(f'/pc-deploy/api/agent/jobs/{identity}/start', inv, reg['token'])
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['kind'], 'wim')
        self.assertNotIn('answer_xml', result.json)
        self.assertNotIn('Test-only-share-secret', json.dumps(result.json))
        for stage in ('applying', 'boot_files', 'awaiting_report'):
            r = self.post(f'/pc-deploy/api/agent/jobs/{identity}/event', dict(stage=stage), reg['token'])
            self.assertEqual(r.status_code, 200, r.json)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['state'], 'awaiting_report')
        with self.store.connect() as c:
            row = c.execute('SELECT secret FROM jobs WHERE id=?', (identity,)).fetchone()
            token = self.store.decrypt(row['secret'])['finish_token']
        body = dict(hardware_uuid=inv['hardware_uuid'], computer_name='PRESERVED-NAME',
                    os_build=26100, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        r = self.post(f'/pc-deploy/api/agent/jobs/{identity}/finish', body, token)
        self.assertEqual(r.status_code, 200, r.json)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['jobs'][0]['state'], 'completed')

    def test_wim_preserve_start_is_scoped_and_one_time(self):
        inv, reg, identity = self.wim_queued('system_partition')
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        route = f'/pc-deploy/api/agent/jobs/{identity}/start'
        self.assertEqual(self.post(route, inv, reg['token']).status_code, 200)
        self.assertEqual(self.post(route, inv, reg['token']).status_code, 400)

    def test_wim_finish_checks_actual_image_build_and_uuid(self):
        inv, reg, identity = self.wim_queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.post(f'/pc-deploy/api/agent/jobs/{identity}/start', inv, reg['token'])
        with self.store.connect() as c:
            row = c.execute('SELECT secret FROM jobs WHERE id=?', (identity,)).fetchone()
            token = self.store.decrypt(row['secret'])['finish_token']
        body = dict(hardware_uuid=inv['hardware_uuid'], computer_name='EXISTING',
                    os_build=22631, image_state='IMAGE_STATE_COMPLETE', oobe_done=True)
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{identity}/finish', body, token).status_code, 400)
        body.update(os_build=26100, hardware_uuid=str(uuid.uuid4()))
        self.assertEqual(self.post(f'/pc-deploy/api/agent/jobs/{identity}/finish', body, token).status_code, 400)

    def test_wim_cannot_start_when_real_dispatch_disabled(self):
        inv, reg, identity = self.wim_queued()
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.enable(False)
        result = self.post(f'/pc-deploy/api/agent/jobs/{identity}/start', inv, reg['token'])
        self.assertEqual(result.status_code, 400)

    def test_existing_setup_source_cannot_be_silently_converted(self):
        _, _, source, _ = self.fixtures()
        value = install_source()
        value.update(kind='wim', image_file='win11.wim')
        result = self.post('/pc-deploy/api/sources/'+source, value, method='PUT')
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.client.get('/pc-deploy/api/dashboard').json['sources'][0]['kind'], 'setup')

    def test_wim_profile_rejects_unknown_mode_password_and_resize_preserve(self):
        _, _, source, _ = self.wim_fixtures()
        base = dict(name='Bad', source_id=source, image_index=6)
        for change in (dict(disk_mode='auto'), dict(password='Test-password-123'),
                       dict(disk_mode='system_partition', system_gib=128)):
            with self.subTest(change=change):
                self.assertEqual(self.post('/pc-deploy/api/profiles', dict(base, **change)).status_code, 400)

    def test_switching_wim_profile_to_setup_requires_valid_password(self):
        _, _, _, profile = self.wim_fixtures()
        source = self.post('/pc-deploy/api/sources', install_source()).json['id']
        value = dict(name='Original again', source_id=source, image_index=6, system_gib=128,
                     username='ITSetup', computer_prefix='TEST')
        result = self.post('/pc-deploy/api/profiles/'+profile, value, method='PUT')
        self.assertEqual(result.status_code, 400)
        value['password'] = 'Test-only-password-123'
        self.assertEqual(self.post('/pc-deploy/api/profiles/'+profile, value, method='PUT').status_code, 200)

    def test_wim_filename_rejects_path_and_shell_syntax(self):
        for filename in (r'..\win11.wim', r'C:\win11.wim', r'folder\win11.wim', 'win11.wim:stream',
                         'a".wim', 'a;test.wim', 'a.wim\n'):
            with self.subTest(filename=filename):
                source = install_source()
                source.update(kind='wim', image_file=filename)
                with self.assertRaises(Invalid):
                    source_record(source)

    def test_wim_partition_inventory_rejects_overlap_and_duplicate_guid(self):
        inv, _, _, _ = self.wim_fixtures()
        overlap = copy.deepcopy(inv)
        overlap['disks'][0]['partitions'][1]['offset'] = 100*1024**2
        with self.assertRaises(Invalid):
            inventory(overlap)
        inv['disks'][0]['partitions'][1]['guid'] = inv['disks'][0]['partitions'][0]['guid']
        with self.assertRaises(Invalid):
            inventory(inv)


class ValidationTests(unittest.TestCase):
    def test_dangerous_urls_rejected(self):
        for url in ('ftp://deploy.test','https://user:pass@deploy.test','https://deploy.test/path',
                    'https://deploy.test?x=1','file:///c:/windows','https://deploy.test\nreboot'):
            with self.subTest(url=url),self.assertRaises(Invalid): public_url(url)

    def test_local_preview_and_https(self):
        self.assertEqual(public_url('http://127.0.0.1:8090'),'http://127.0.0.1:8090/pc-deploy')
        self.assertEqual(public_url('https://deploy.test/'),'https://deploy.test/pc-deploy')
        self.assertEqual(public_url('http://192.0.2.10:8080'), 'http://192.0.2.10:8080/pc-deploy')

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
        self.platform.app.config['PC_DEPLOY_ALLOW_HTTP'] = False
        self.addCleanup(self.platform.app.config.pop, 'PC_DEPLOY_ALLOW_HTTP', None)
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
