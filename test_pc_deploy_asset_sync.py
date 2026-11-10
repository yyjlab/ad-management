import json
import secrets
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_pc_deploy as platform
from pc_deploy.asset_sync import PATH, endpoint_url, post_registration


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
            value = platform.machine()
            value['system_info'] = dict(cpus=[dict(name='Fixture CPU')], gpus=[dict(name='Fixture GPU')])
            self.register(value)
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
        self.assertEqual(received[0][0], 'http://asset.test' + PATH)
        self.assertFalse(self.client.get('/pc-deploy/api/dashboard').json['asset_sync']['enabled'])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM asset_sync_outbox').fetchone()[0], 0)

    def test_probe_reports_disabled_receiver_and_does_not_reflect_credentials(self):
        self.sender.probe_transport = lambda *args: (503, dict(code='INTEGRATION_DISABLED', message=self.token))
        result = self.post('/pc-deploy/api/asset-sync/probe', dict(endpoint='http://asset.test', token=self.token))
        self.assertEqual(result.status_code, 400)
        self.assertNotIn(self.token, result.get_data(as_text=True))
        self.assertIn('启用', result.json['error'])

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
