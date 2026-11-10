import json
import secrets
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_pc_deploy as platform
from pc_deploy.asset_sync import PATH, INTAKE_PATH, endpoint_url, post_registration, asset_display_name


class AssetSyncTests(unittest.TestCase):
    def setUp(self):
        platform.PlatformTests.setUp(self)
        self.context = self.app.app_context()
        self.context.push()

    def tearDown(self):
        self.context.pop()
        platform.PlatformTests.tearDown(self)
    post = platform.PlatformTests.post
    register = platform.PlatformTests.register

    def configure(self, **changes):
        with self.store.connect() as c:
            revision = self.sender.config(c)['revision']
        value = dict(enabled=True, revision=revision, endpoint='http://asset.test', category_id=7,
                     token=self.token)
        value.update(changes)
        return self.post('/pc-deploy/api/asset-sync/settings', value)

    @property
    def sender(self):
        return self.app.extensions['pc_deploy_asset_sender']

    @property
    def token(self):
        if not hasattr(self, '_token'):
            self._token = 'adp_' + str(uuid.uuid4()) + '.' + secrets.token_urlsafe(32)
        return self._token

    def save(self, version=0):
        if version == 0:
            with self.store.connect(write=True) as c:
                config = self.sender.config(c)
                self.store.put(c, 'asset_sync', dict(config, enabled=False))
            value = platform.machine()
            value['system_info'] = dict(cpus=[dict(name='Fixture CPU')], gpus=[dict(name='Fixture GPU')])
            self.register(value)
            with self.store.connect(write=True) as c:
                self.store.put(c, 'asset_sync', config)
                version = c.execute('SELECT version FROM asset_registrations').fetchone()[0]
        device = self.client.get('/pc-deploy/api/dashboard').json['devices'][0]
        result = self.post('/pc-deploy/api/asset-registrations/' + device['id'],
                           dict(asset_tag='001234567890', version=version,
                                inventory_revision=device['asset_inventory_revision']))
        self.assertEqual(result.status_code, 200, result.json)
        return result.json['registration']

    def row(self):
        with self.store.connect() as c:
            return dict(c.execute('SELECT * FROM asset_sync_outbox ORDER BY created DESC LIMIT 1').fetchone())

    def success(self, endpoint, token, ca, encoded, result='created'):
        request = json.loads(encoded)
        return dict(created=201, already_exists=200, configuration_conflict=409)[result], dict(
            result=result, externalRegistrationId=request['externalRegistrationId'],
            asset=dict(id=81, assetTag=request['assetTag'], version=0), differences=[], warnings=[], replayed=False)

    def test_auto_intake_needs_no_manual_tag_or_category_and_receives_number_after_approval(self):
        self.assertEqual(self.configure(category_id=None).status_code, 200)
        inv, reg = self.register()
        row = self.row()
        payload = json.loads(row['payload'])
        self.assertNotIn('assetTag', payload)
        self.assertIsNone(payload['categoryId'])
        self.assertEqual(row['endpoint'], 'http://asset.test' + INTAKE_PATH)
        self.sender.transport = lambda *args: (202, dict(externalRegistrationId=row['id'], result='pending_review', asset=None))
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'pending_review')
        polled = []
        def approved(*args):
            polled.append(args)
            return 200, dict(externalRegistrationId=row['id'], result='approved', asset=dict(id=81, assetTag='202611100001', version=0))
        self.sender.status_transport = approved
        self.sender.process_one(now=self.row()['next_attempt'] + 1)
        self.assertEqual(self.row()['state'], 'approved')
        self.assertIn('/intakes/ad%3A', polled[0][0])
        saved = self.client.get('/pc-deploy/api/dashboard').json['asset_registrations'][0]
        self.assertEqual(saved['asset_tag'], '202611100001')
        inv['boot_id'] = str(uuid.uuid4())
        self.register(inv)
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM asset_sync_outbox').fetchone()[0], 1)

    def test_auto_intake_freezes_first_request_across_poll_and_reject(self):
        self.configure(category_id=None)
        inv, reg = self.register()
        row = self.row()
        inv['system_info'] = dict(cpus=[dict(name='Changed CPU')], gpus=[])
        result = self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(self.row()['payload'], row['payload'])
        self.sender.transport = lambda *args: (200, dict(externalRegistrationId=row['id'], result='rejected', asset=None, message='not new'))
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'rejected')
        self.post('/pc-deploy/api/agent/poll', inv, reg['token'])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM asset_sync_outbox').fetchone()[0], 1)

    def test_enabling_intake_backfills_existing_devices_and_missing_model_can_be_reviewed(self):
        inv, reg = self.register()
        with self.store.connect(write=True) as c:
            saved = json.loads(c.execute('SELECT data FROM asset_registrations').fetchone()[0])
            saved['inventory']['model'] = ''
            saved['inventory']['oem_model'] = ''
            from pc_deploy.asset_sync import registration_payload
            payload = json.loads(registration_payload(saved, None, 'ad:missing:1', intake=True))
            self.assertIsNone(payload['snapshot']['model'])
        self.configure(category_id=None)
        self.assertEqual(self.row()['state'], 'pending')
        self.assertEqual(json.loads(self.row()['data'])['kind'], 'intake')
        self.configure(category_id=None, token='')
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM asset_sync_outbox').fetchone()[0], 1)

    def test_intake_lost_response_reuses_identical_request_and_rejects_bad_approved_number(self):
        self.configure(category_id=None)
        self.register()
        before = self.row()
        self.sender.transport = lambda *args: (_ for _ in ()).throw(OSError('lost response'))
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'retry')
        received = []
        def pending(*args):
            received.append(args[-1])
            return 202, dict(externalRegistrationId=before['id'], result='pending_review', asset=None)
        self.sender.transport = pending
        self.sender.process_one(now=self.row()['next_attempt'] + 1)
        self.assertEqual(received, [before['payload']])
        self.sender.status_transport = lambda *args: (200, dict(externalRegistrationId=before['id'], result='approved',
                                                               asset=dict(id=81, assetTag='not-a-valid-number', version=0)))
        self.sender.process_one(now=self.row()['next_attempt'] + 1)
        self.assertEqual(self.row()['state'], 'blocked')
        self.assertEqual(json.loads(self.row()['data'])['code'], 'RESPONSE_MISMATCH')

    def test_multiple_devices_with_same_sn_have_separate_intake_keys(self):
        self.configure(category_id=None)
        self.register(platform.machine(serial='SAME-SN'))
        self.register(platform.machine(serial='SAME-SN'))
        with self.store.connect() as c:
            rows = list(c.execute('SELECT id,asset_tag FROM asset_sync_outbox'))
            self.assertEqual(len(rows), 2)
            self.assertNotEqual(rows[0]['id'], rows[1]['id'])

    def test_intake_waits_for_receiver_upgrade_without_losing_request(self):
        self.configure(category_id=None)
        self.register()
        original = self.row()
        self.sender.transport = lambda *args: (404, None)
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'retry')
        self.assertEqual(self.row()['payload'], original['payload'])
        self.sender.transport = lambda *args: (202, dict(externalRegistrationId=original['id'], result='pending_review', asset=None))
        self.sender.process_one(now=self.row()['next_attempt'] + 1)
        self.assertEqual(self.row()['state'], 'pending_review')

    def test_old_never_submitted_manual_draft_becomes_review_not_direct_creation(self):
        self.save()
        self.assertEqual(self.configure(category_id=None).status_code, 200)
        row = self.row()
        self.assertEqual(json.loads(row['data'])['kind'], 'intake')
        self.assertNotIn('assetTag', json.loads(row['payload']))
        with self.store.connect() as c:
            saved = json.loads(c.execute('SELECT data FROM asset_registrations').fetchone()[0])
            self.assertEqual(saved['kind'], 'intake')
            self.assertEqual(saved['asset_tag'], '')

    def test_readable_asset_name_is_separate_from_firmware_model(self):
        self.configure(category_id=None)
        value = platform.machine()
        value.update(model='20R4S4E200', manufacturer='LENOVO', system_family='ThinkPad L13', product_version='ThinkPad L13')
        self.register(value)
        payload = json.loads(self.row()['payload'])
        self.assertEqual(payload['name'], 'LENOVO ThinkPad L13')
        self.assertEqual(payload['snapshot']['model'], '20R4S4E200')
        self.assertEqual(asset_display_name(dict(model='HKD-WXX', manufacturer='HUAWEI')), 'HUAWEI MateBook 14s')
        self.assertEqual(asset_display_name(dict(model='HP 288 Pro G4 MT Business PC', manufacturer='HP')), 'HP 288 Pro G4 MT Business PC')
        self.assertIsNone(asset_display_name(dict(model='System Product Name', manufacturer='System Manufacturer')))

    def test_http_settings_are_encrypted_and_not_exposed_to_dashboard(self):
        self.assertEqual(self.configure().status_code, 200)
        public = self.client.get('/pc-deploy/api/dashboard').json['asset_sync']
        self.assertTrue(public['enabled'])
        self.assertTrue(public['has_token'])
        self.assertNotIn(self.token, json.dumps(public))
        with self.store.connect() as c:
            values = [row[0] for row in c.execute('SELECT value FROM settings')]
            self.assertNotIn(self.token, ''.join(values))

    def test_http_registration_uses_exact_asset_number_before_installation(self):
        self.configure()
        self.save()
        self.sender.transport = self.success
        self.assertTrue(self.sender.process_one())
        row = self.row()
        self.assertEqual(row['state'], 'synced')
        payload = json.loads(row['payload'])
        self.assertEqual(payload['assetTag'], '001234567890')
        self.assertEqual(payload['categoryId'], 7)
        self.assertEqual(payload['snapshot']['cpu'], 'Fixture CPU')
        self.assertEqual(payload['operator']['id'], 'test-super-admin')
        self.assertEqual(len(payload['snapshot']['internalDisks']), 1)
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM jobs').fetchone()[0], 0)

    def test_lost_response_retries_identical_payload_and_id(self):
        self.configure(); self.save()
        calls = []
        def transport(*args):
            calls.append(args[3])
            if len(calls) == 1:
                raise TimeoutError('test lost response')
            return self.success(*args)
        self.sender.transport = transport
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'retry')
        self.sender.process_one(now=time.time() + 10)
        self.assertEqual(self.row()['state'], 'synced')
        self.assertEqual(calls[0], calls[1])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM asset_sync_outbox').fetchone()[0], 1)

    def test_configuration_difference_is_not_success_and_not_automatically_retried(self):
        self.configure(); self.save()
        def conflict(*args):
            status, body = self.success(*args, result='configuration_conflict')
            body['differences'] = [dict(field='cpu', existing='Existing CPU', incoming='Fixture CPU')]
            return status, body
        self.sender.transport = conflict
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'conflict')
        self.assertFalse(self.sender.process_one(now=time.time() + 1000))

    def test_authentication_failure_pauses_sender_until_credential_update(self):
        self.configure(); self.save()
        self.sender.transport = lambda *args: (401, dict(code='AUTHENTICATION_FAILED'))
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'blocked')
        self.assertFalse(self.sender.process_one())
        self.configure()
        self.sender.transport = self.success
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'synced')

    def test_changing_target_never_retargets_an_existing_request(self):
        self.configure(); self.save()
        original = self.row()['endpoint']
        self.configure(endpoint='http://another-asset.test')
        self.assertFalse(self.sender.process_one())
        self.assertEqual(self.row()['state'], 'blocked')
        self.assertEqual(self.row()['endpoint'], original)

    def test_invalid_asset_response_cannot_mark_success(self):
        self.configure(); self.save()
        def invalid(*args):
            status, body = self.success(*args)
            body['asset']['assetTag'] = '999999999999'
            return status, body
        self.sender.transport = invalid
        self.sender.process_one()
        self.assertEqual(self.row()['state'], 'blocked')

    def test_connection_probe_returns_real_choices_without_enabling_or_enqueuing(self):
        received = []
        def probe(*args):
            received.append(args)
            return 200, dict(receiver='asset-management', protocolVersion=1,
                             categories=[dict(id=22, name='实际笔记本电脑')])
        self.sender.probe_transport = probe
        result = self.post('/pc-deploy/api/asset-sync/probe', dict(endpoint='http://asset.test', token=self.token))
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['categories'], [dict(id=22, name='实际笔记本电脑')])
        self.assertEqual(received[0][0], 'http://asset.test' + INTAKE_PATH)
        self.assertFalse(self.client.get('/pc-deploy/api/dashboard').json['asset_sync']['enabled'])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM asset_sync_outbox').fetchone()[0], 0)

    def test_probe_reports_disabled_receiver_and_does_not_reflect_credentials(self):
        self.sender.probe_transport = lambda *args: (503, dict(code='INTEGRATION_DISABLED', message=self.token))
        result = self.post('/pc-deploy/api/asset-sync/probe', dict(endpoint='http://asset.test', token=self.token))
        self.assertEqual(result.status_code, 400)
        self.assertNotIn(self.token, result.get_data(as_text=True))
        self.assertIn('启用', result.json['error'])

    def test_probe_identifies_each_invalid_dictionary_without_reflecting_unknown_text(self):
        for label, name in (('公司', '微丰启'), ('位置', '公司'), ('状态', '当前可用')):
            with self.subTest(label=label):
                message = f'{label}“{name}”须存在唯一且启用的字典记录；未自动新建'
                self.sender.probe_transport = lambda *args: (409, dict(
                    code='DEFAULT_DICTIONARY_INVALID', message=message))
                result = self.post('/pc-deploy/api/asset-sync/probe', dict(endpoint='http://asset.test', token=self.token))
                self.assertEqual(result.status_code, 400)
                self.assertEqual(result.json['error'], 'asset：' + message)
                state, detail, paused = self.sender.outcome(409, dict(
                    code='DEFAULT_DICTIONARY_INVALID', message=message), {})
                self.assertEqual(state, 'blocked')
                self.assertEqual(detail['message'], 'asset：' + message)
                self.assertFalse(paused)
        for response in (dict(code='DEFAULT_DICTIONARY_INVALID', message=self.token),
                         dict(code='OTHER_ERROR', message=message), [], None):
            self.sender.probe_transport = lambda *args: (409, response)
            result = self.post('/pc-deploy/api/asset-sync/probe', dict(endpoint='http://asset.test', token=self.token))
            self.assertEqual(result.status_code, 400)
            self.assertNotIn(self.token, result.get_data(as_text=True))
            self.assertIn('字典不唯一', result.json['error'])

    def test_configuration_and_probe_require_admin_and_csrf(self):
        for route in ('/pc-deploy/api/asset-sync/settings', '/pc-deploy/api/asset-sync/probe'):
            self.assertEqual(self.client.post(route, json={}).status_code, 403)
        with self.client.session_transaction() as session:
            session['admin_role'] = 'viewer'
        self.assertEqual(self.post('/pc-deploy/api/asset-sync/probe', {}).status_code, 403)

    def test_endpoint_rejects_credentials_query_and_unrelated_paths(self):
        for endpoint in ('http://user:pass@asset.test', 'http://asset.test?token=secret', 'file:///etc/passwd', 'http://asset.test/admin'):
            with self.assertRaises(platform.Invalid):
                endpoint_url(endpoint)

    def test_http_transport_never_follows_redirect_with_credential(self):
        calls = []
        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/must-not-receive-token')
                self.end_headers()
            def do_GET(self):
                calls.append(self.path)
                self.send_response(200); self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            status, _ = post_registration('http://127.0.0.1:' + str(server.server_port) + PATH, self.token, '', '{}')
            self.assertEqual(status, 302)
            self.assertEqual(calls, [PATH])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
