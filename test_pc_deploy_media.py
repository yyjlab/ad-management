"""Isolated queue/credential tests. No AD, DISM, USB or production endpoint is contacted."""
import hashlib
import io
import json
import time
import unittest
import uuid
import zipfile
from unittest.mock import patch

import test_pc_deploy as base
from test_pc_deploy import machine
from pc_deploy import token_hash
from pc_deploy.media import CHUNK_SIZE


class MediaTests(unittest.TestCase):
    setUp = base.PlatformTests.setUp
    tearDown = base.PlatformTests.tearDown
    post = base.PlatformTests.post
    enable = base.PlatformTests.enable
    register = base.PlatformTests.register

    def builder(self):
        self.enable(False)
        response = self.post('/pc-deploy/api/builders/package', dict(name='Test builder'))
        self.assertEqual(response.status_code, 200, response.json if response.is_json else response.status_code)
        with zipfile.ZipFile(io.BytesIO(response.data)) as z:
            config = json.loads(z.read('builder-registration.json'))
            self.assertIn('Install-Builder.ps1', z.namelist())
            self.assertIn('Start-Builder.ps1', z.namelist())
            self.assertIn('Build-LocalMedia.ps1', z.namelist())
        self.poll(config)
        return config

    def poll(self, config, instance=None):
        config.setdefault('instance', instance or str(uuid.uuid4()))
        return self.post('/pc-deploy/api/media-worker/poll', dict(instance=instance or config['instance'],
                         template_name='Test PE', driver_name='ASIX test'), config['token'])

    def build(self, config=None):
        config = config or self.builder()
        response = self.post('/pc-deploy/api/media', dict(builder_id=config['builder_id'],
                             registration_only=True, include_drivers=True))
        self.assertEqual(response.status_code, 200, response.json)
        identity = response.json['id']
        reply = self.poll(config)
        self.assertEqual(reply.json['job']['id'], identity)
        return config, identity

    def update(self, config, identity, stage, **kw):
        return self.post(f'/pc-deploy/api/media-worker/jobs/{identity}/update',
                         dict(stage=stage, **kw), config['token'])

    def iso(self):
        raw = bytearray(CHUNK_SIZE + 31)
        raw[32769:32774] = b'CD001'
        return bytes(raw)

    def chunk(self, config, identity, offset, raw):
        return self.client.post(f'/pc-deploy/api/media-worker/jobs/{identity}/chunk', data=raw,
            headers={'Authorization':'Bearer '+config['token'], 'X-Upload-Offset':str(offset)},
            content_type='application/octet-stream')

    def prepare_upload(self, config, identity, raw=None):
        raw = self.iso() if raw is None else raw
        r = self.update(config, identity, '上传 ISO', size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(r.status_code, 200, r.json)
        return raw

    def test_policy_custom_and_never_expire_are_enforced_on_server(self):
        self.enable(False)
        for days in (1, 30, None):
            self.assertEqual(self.post('/pc-deploy/api/enrollment-policy',dict(days=days)).status_code,200)
            response=self.post('/pc-deploy/api/bootstrap')
            with zipfile.ZipFile(io.BytesIO(response.data)) as z:
                config=json.loads(z.read('config.json'))
            if days is None:
                self.assertIsNone(config['expires_at'])
                with self.store.connect() as c:
                    self.assertEqual(c.execute('SELECT expires FROM enrollments WHERE token_hash=?',
                                               (token_hash(config['enrollment_token']),)).fetchone()[0],-1)
                with patch('pc_deploy.time.time',return_value=time.time()+4000*86400):
                    self.assertEqual(self.post('/pc-deploy/api/agent/register',machine(),
                                               config['enrollment_token']).status_code,200)
            else:
                self.assertAlmostEqual(config['expires_at']-time.time(),days*86400,delta=3)

    def test_policy_rejects_invalid_and_requires_admin_csrf(self):
        for days in (True, False, 0, -1, 3651, '7', 2.5):
            self.assertEqual(self.post('/pc-deploy/api/enrollment-policy',dict(days=days)).status_code,400)
        self.assertEqual(self.post('/pc-deploy/api/enrollment-policy').status_code,400)
        self.assertEqual(self.client.post('/pc-deploy/api/enrollment-policy',json=dict(days=None)).status_code,403)
        self.assertEqual(self.app.test_client().post('/pc-deploy/api/builders/package',json=dict(name='X')).status_code,401)

    def test_existing_iso_can_be_changed_without_issuing_new_token_and_can_be_revoked(self):
        identity=token_hash(self.enrollment)
        with self.store.connect(write=True) as c:
            c.execute('UPDATE enrollments SET expires=0')
        for days in (None, 21):
            result=self.post(f'/pc-deploy/api/enrollments/{identity}/validity',dict(days=days))
            self.assertEqual(result.status_code,200)
            self.assertEqual(self.post('/pc-deploy/api/agent/register',machine(),self.enrollment).status_code,200)
            with self.store.connect() as c:
                self.assertEqual(c.execute('SELECT COUNT(*) FROM enrollments').fetchone()[0],1)
        self.assertEqual(self.post(f'/pc-deploy/api/enrollments/{identity}/revoke').status_code,200)
        self.assertEqual(self.post('/pc-deploy/api/agent/register',machine(),self.enrollment).status_code,400)
        self.assertEqual(self.post(f'/pc-deploy/api/enrollments/{identity}/validity',dict(days=None)).status_code,400)

    def test_never_expiring_token_stays_never_expiring_when_extended(self):
        identity=token_hash(self.enrollment)
        self.post(f'/pc-deploy/api/enrollments/{identity}/validity',dict(days=None))
        r=self.post(f'/pc-deploy/api/enrollments/{identity}/extend')
        self.assertEqual(r.status_code,200)
        self.assertIsNone(r.json['expires_at'])

    def test_builder_is_visible_without_exposing_credentials(self):
        config=self.builder()
        result=self.client.get('/pc-deploy/api/dashboard')
        self.assertNotIn(config['token'],result.text)
        builder=result.json['media']['builders'][0]
        self.assertTrue(builder['online'])
        self.assertEqual(builder['driver_name'],'ASIX test')
        self.assertNotIn('token_hash',builder)
        with self.store.connect() as c:
            self.assertNotIn(config['token'],str([dict(r) for r in c.execute('SELECT * FROM media_builders')]))

    def test_offline_duplicate_and_missing_choices_are_rejected(self):
        config=self.builder()
        self.assertEqual(self.post('/pc-deploy/api/media',dict(builder_id=config['builder_id'])).status_code,400)
        with self.store.connect(write=True) as c:
            c.execute('UPDATE media_builders SET seen=0')
        value=dict(builder_id=config['builder_id'],registration_only=False,include_drivers=False)
        self.assertEqual(self.post('/pc-deploy/api/media',value).status_code,400)
        self.poll(config)
        self.assertEqual(self.post('/pc-deploy/api/media',value).status_code,200)
        self.assertEqual(self.post('/pc-deploy/api/media',value).status_code,400)

    def test_same_claim_retry_is_idempotent_other_instance_cannot_claim(self):
        config,identity=self.build()
        self.assertEqual(self.poll(config).json['job']['id'],identity)
        self.assertIsNone(self.poll(config,str(uuid.uuid4())).json['job'])

    def test_stale_build_fails_instead_of_being_reassigned(self):
        config,identity=self.build()
        with self.store.connect(write=True) as c:
            c.execute('UPDATE media_builds SET updated=?',(time.time()-181,))
        self.assertIsNone(self.poll(config).json['job'])
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT state FROM media_builds').fetchone()[0],'failed')

    def test_job_package_has_latest_scripts_mode_and_saved_validity(self):
        self.post('/pc-deploy/api/enrollment-policy',dict(days=None))
        config,identity=self.build()
        response=self.client.get(f'/pc-deploy/api/media-worker/jobs/{identity}/package',
                                 headers={'Authorization':'Bearer '+config['token']})
        self.assertEqual(response.status_code,200)
        with zipfile.ZipFile(io.BytesIO(response.data)) as z:
            cfg=json.loads(z.read('config.json'))
            self.assertIsNone(cfg['expires_at'])
            self.assertTrue(cfg['registration_only'])
            self.assertTrue(cfg['include_drivers'])
            self.assertIn('Invoke-WaitingPlatform',z.read('Deploy-Agent.ps1').decode('utf-8-sig'))
            self.assertIn('HardwareInfo.ps1', z.namelist())
        self.assertNotIn(config['token'],response.data.decode('latin1'))

    def test_worker_credentials_cannot_claim_install_or_admin_capabilities(self):
        config,identity=self.build()
        stranger=self.builder()
        self.assertEqual(self.update(stranger,identity,'生成 ISO').status_code,400)
        self.assertEqual(self.client.get(f'/pc-deploy/api/media-worker/jobs/{identity}/package',
                         headers={'Authorization':'Bearer '+stranger['token']}).status_code,400)
        self.assertEqual(self.post('/pc-deploy/api/agent/register',machine(),config['token']).status_code,400)
        self.assertEqual(self.post('/pc-deploy/api/media-worker/poll',dict(instance=str(uuid.uuid4())),
                                  self.enrollment).status_code,400)
        anonymous=self.app.test_client()
        self.assertEqual(anonymous.post('/pc-deploy/api/media',json={},headers={
                         'Authorization':'Bearer '+config['token']}).status_code,401)

    def test_chunk_upload_is_bounded_ordered_idempotent_and_hash_checked(self):
        config,identity=self.build()
        raw=self.prepare_upload(config,identity)
        self.assertEqual(self.chunk(config,identity,3,raw[:3]).status_code,400)
        first=raw[:CHUNK_SIZE]
        self.assertEqual(self.chunk(config,identity,0,first).status_code,200)
        self.assertEqual(self.chunk(config,identity,0,first).status_code,200)
        self.assertEqual(self.chunk(config,identity,0,b'bad').status_code,400)
        finish=f'/pc-deploy/api/media-worker/jobs/{identity}/finish'
        self.assertEqual(self.post(finish,token=config['token']).status_code,400)
        self.assertEqual(self.chunk(config,identity,CHUNK_SIZE,raw[CHUNK_SIZE:]).status_code,200)
        self.assertEqual(self.chunk(config,identity,len(raw),b'bad').status_code,400)
        self.assertEqual(self.post(finish,token=config['token']).status_code,200)
        self.assertEqual(self.post(finish,token=config['token']).status_code,200)
        response=self.client.get(f'/pc-deploy/api/media/{identity}/download')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.data,raw)
        response.close()
        with self.store.connect() as c:
            self.assertFalse(self.store.setting(c,'enabled',False))
            self.assertEqual(c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)

    def test_oversized_chunks_iso_and_stage_changes_rejected(self):
        config,identity=self.build()
        self.assertEqual(self.update(config,identity,'bad').status_code,400)
        self.assertEqual(self.update(config,identity,'上传 ISO',size=3*1024**3,sha256='a'*64).status_code,400)
        self.prepare_upload(config,identity)
        self.assertEqual(self.chunk(config,identity,0,bytes(CHUNK_SIZE+1)).status_code,413)
        self.assertEqual(self.update(config,identity,'生成 ISO').status_code,400)
        self.assertEqual(self.update(config,identity,'上传 ISO',size=40000,sha256='b'*64).status_code,400)

    def test_cancel_and_revocation_stop_publishing(self):
        config,identity=self.build()
        self.post(f'/pc-deploy/api/media/{identity}/cancel')
        self.assertEqual(self.update(config,identity,'生成 ISO').status_code,400)
        self.assertEqual(self.client.get(f'/pc-deploy/api/media/{identity}/download').status_code,400)
        self.post(f'/pc-deploy/api/builders/{config["builder_id"]}/revoke')
        self.assertEqual(self.poll(config).status_code,400)

    def test_wrong_hash_or_non_iso_never_becomes_downloadable(self):
        config,identity=self.build()
        raw=self.prepare_upload(config,identity,bytes(40000))
        self.chunk(config,identity,0,raw)
        finish=f'/pc-deploy/api/media-worker/jobs/{identity}/finish'
        self.assertEqual(self.post(finish,token=config['token']).status_code,400)
        self.assertEqual(self.client.get(f'/pc-deploy/api/media/{identity}/download').status_code,400)
        self.post(f'/pc-deploy/api/media/{identity}/cancel')
        config,identity=self.build(config)
        raw=self.iso()
        self.update(config,identity,'上传 ISO',size=len(raw),sha256='b'*64)
        self.chunk(config,identity,0,raw[:CHUNK_SIZE])
        self.chunk(config,identity,CHUNK_SIZE,raw[CHUNK_SIZE:])
        self.assertEqual(self.post(f'/pc-deploy/api/media-worker/jobs/{identity}/finish',token=config['token']).status_code,400)


    def test_real_powershell_worker_against_isolated_http_queue_with_lost_chunk_response(self):
        import os
        import shutil
        import subprocess
        import threading
        from pathlib import Path
        from werkzeug.serving import make_server, WSGIRequestHandler
        pwsh=shutil.which('pwsh')
        if not pwsh:
            self.skipTest('PowerShell 7 unavailable')
        config=self.builder()
        response=self.post('/pc-deploy/api/media',dict(builder_id=config['builder_id'],
                           registration_only=False,include_drivers=False))
        identity=response.json['id']
        root=Path(self.directory.name)/'worker'
        root.mkdir()
        shutil.copyfile(Path(__file__).parent/'pc_deploy/scripts/Start-Builder.ps1',root/'Start-Builder.ps1')
        fake_build = (
            "param([string]$JobDirectory)\n"
            "$ErrorActionPreference='Stop'\n"
            "[IO.File]::WriteAllText((Join-Path $JobDirectory 'stage.txt'),'生成 ISO',[Text.Encoding]::UTF8)\n"
            "$bytes=[byte[]]::new(262175)\n"
            "[Text.Encoding]::ASCII.GetBytes('CD001').CopyTo($bytes,32769)\n"
            "[IO.File]::WriteAllBytes((Join-Path $JobDirectory 'pc-deploy.iso'),$bytes)\n"
        )
        (root/'Build-LocalMedia.ps1').write_text(fake_build,encoding='utf-8-sig')
        env=dict(os.environ,PCDEPLOY_TEST_TOKEN=config['token'])
        protected=subprocess.run([pwsh,'-NoProfile','-NonInteractive','-Command',
            'Add-Type -AssemblyName System.Security; [Convert]::ToBase64String('
            '[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($env:PCDEPLOY_TEST_TOKEN),'
            '$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))'],
            env=env,check=True,capture_output=True,text=True,timeout=20).stdout.strip()
        original=self.app.wsgi_app
        dropped=[]
        def simulate_lost_response(environ,start_response):
            def respond(status,headers,exc_info=None):
                if environ['PATH_INFO'].endswith('/chunk') and not dropped:
                    dropped.append(True)
                    status='503 Service Unavailable'
                return start_response(status,headers,exc_info)
            return original(environ,respond)
        self.app.wsgi_app=simulate_lost_response
        class Quiet(WSGIRequestHandler):
            def log_request(self,*args,**kwargs):
                pass
        server=make_server('127.0.0.1',0,self.app,threaded=True,request_handler=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            local=dict(builder_id=config['builder_id'],server_url=f'http://127.0.0.1:{server.server_port}/pc-deploy',
                       protected_token=protected,template_directory=str(root),wim_relative='sources\\boot.wim',
                       oscdimg_path='unused',bios_boot_path='unused',uefi_boot_path='unused',driver_directory='',
                       work_root=str(root/'Builds'))
            (root/'builder.json').write_text(json.dumps(local),encoding='utf-8')
            completed=subprocess.run([pwsh,'-NoProfile','-NonInteractive','-File',str(root/'Start-Builder.ps1'),
                                      '-ConfigurationPath',str(root/'builder.json'),'-Once'],
                                      capture_output=True,text=True,encoding='utf-8',timeout=70)
            self.assertEqual(completed.returncode,0,completed.stderr)
            self.assertNotIn(config['token'],completed.stdout+completed.stderr)
            row=self.client.get('/pc-deploy/api/dashboard').json['media']['builds'][0]
            self.assertEqual(row['state'],'ready',completed.stdout+completed.stderr)
            self.assertEqual(row['sha256'],hashlib.sha256(self.iso()).hexdigest())
            self.assertTrue(dropped)
            self.assertTrue((root/'Builds'/identity/'build.log').is_file())
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()
            self.app.wsgi_app=original


    def test_local_package_download_needs_no_builder_and_creates_no_build_job(self):
        self.enable(False)
        self.post('/pc-deploy/api/enrollment-policy',dict(days=None))
        response=self.post('/pc-deploy/api/local-media/package',dict(registration_only=False,include_drivers=True))
        self.assertEqual(response.status_code,200)
        self.assertIn('pc-deploy-local-build.zip',response.headers['Content-Disposition'])
        with zipfile.ZipFile(io.BytesIO(response.data)) as z:
            config=json.loads(z.read('config.json'))
            self.assertIsNone(config['expires_at'])
            self.assertFalse(config['registration_only'])
            self.assertTrue(config['include_drivers'])
            for name in ('Start-Build.cmd','Build-OnThisPC.ps1','Build-LocalMedia.ps1','Deploy-Agent.ps1','Start.ps1','DeviceInfo.ps1','HardwareInfo.ps1'):
                self.assertIn(name,z.namelist())
            self.assertNotIn('builder-registration.json',z.namelist())
            self.assertNotIn('Start-Builder.ps1',z.namelist())
            self.assertNotIn('Install-Builder.ps1',z.namelist())
            self.assertIn('-File "%~dp0Build-OnThisPC.ps1"',z.read('Start-Build.cmd').decode())
            self.assertNotIn('Get-VerifiedHash',z.read('Deploy-Agent.ps1').decode('utf-8-sig'))
        with self.store.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM media_builders').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM media_builds').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
            self.assertFalse(self.store.setting(c,'enabled',False))
        self.assertEqual(self.post('/pc-deploy/api/agent/register',machine(),config['enrollment_token']).status_code,200)

    def test_local_package_validates_options_and_uses_admin_csrf(self):
        path='/pc-deploy/api/local-media/package'
        self.assertEqual(self.app.test_client().post(path,json={}).status_code,401)
        self.assertEqual(self.client.post(path,json=dict(registration_only=True,include_drivers=False)).status_code,403)
        self.assertEqual(self.post(path,dict(registration_only='false',include_drivers=True)).status_code,400)
        self.assertEqual(self.post(path,dict(registration_only=True)).status_code,400)
        self.enable(False)
        response=self.post(path,dict(registration_only=True,include_drivers=False))
        self.assertEqual(response.status_code,200)
        with zipfile.ZipFile(io.BytesIO(response.data)) as z:
            config=json.loads(z.read('config.json'))
        self.assertTrue(config['registration_only'])
        self.assertFalse(config['include_drivers'])

if __name__ == '__main__':
    unittest.main()
