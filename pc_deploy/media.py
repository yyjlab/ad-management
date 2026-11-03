"""Fixed-purpose Windows ISO builder queue; never executes host commands."""
import hashlib
import io
import json
import re
import secrets
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from flask import jsonify, request, send_file
from .deployment import Invalid, integer, canonical, text

ROOT = Path(__file__).parent
CHUNK_SIZE = 256 * 1024
MAX_ISO_SIZE = 2 * 1024 ** 3
ACTIVE = ('queued', 'building', 'uploading')


def media_dashboard(c):
    now = time.time()
    builders = [dict(id=r['id'], name=r['name'], online=now-r['seen'] < 45,
                     **json.loads(r['data'])) for r in
                c.execute('SELECT * FROM media_builders WHERE revoked=0 ORDER BY name')]
    builds = []
    for row in c.execute('SELECT * FROM media_builds ORDER BY created DESC LIMIT 30'):
        d = json.loads(row['data'])
        builds.append(dict(id=row['id'], builder_id=row['builder_id'], state=row['state'],
                           created=row['created'], updated=row['updated'],
                           stale=row['state'] in ACTIVE and now-row['updated'] > 180,
                           registration_only=d['registration_only'], include_drivers=d['include_drivers'],
                           enrollment_id=d['enrollment_id'], stage=d.get('stage', ''),
                           size=d.get('size', 0), sha256=d.get('sha256', '')))
    return dict(builders=builders, builds=builds)


def register_media_routes(app, store, admin, body, tls_required, bearer, event, create_config, bootstrap_zip):
    def hashed(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def worker(c):
        tls_required()
        row = c.execute('SELECT * FROM media_builders WHERE token_hash=? AND revoked=0',
                        (hashed(bearer()),)).fetchone()
        if not row:
            raise Invalid('制作端凭据已撤销或无效')
        return row

    def artifact(identity):
        if not re.fullmatch(r'[0-9a-f-]{36}', identity):
            raise Invalid('制作任务编号无效')
        directory = store.root / 'media'
        directory.mkdir(exist_ok=True)
        return directory / (identity + '.iso')

    def owned(c, identity, states):
        builder = worker(c)
        row = c.execute('SELECT * FROM media_builds WHERE id=? AND builder_id=?',
                        (identity, builder['id'])).fetchone()
        if not row or row['state'] not in states:
            raise Invalid('制作任务已结束或不属于此制作端')
        if time.time()-row['created'] > 6*3600:
            raise Invalid('制作任务超过 6 小时，请在页面结束记录后重新制作')
        return row, json.loads(row['data'])

    @app.post('/api/builders/package')
    @admin
    def builder_package():
        name = text(body().get('name'), '制作电脑名称', 1, 80)
        identity, token = str(uuid.uuid4()), secrets.token_urlsafe(40)
        with store.connect(write=True) as c:
            if c.execute('SELECT COUNT(*) FROM media_builders WHERE revoked=0').fetchone()[0] >= 10:
                raise Invalid('最多配置 10 个制作端，请先停用不再使用的制作端')
            config = dict(server_url=store.setting(c, 'public_url'), builder_id=identity, token=token)
            # Apply exactly the same URL validation as PE package creation, without issuing a PE token.
            create_config(c, issue=False)
            c.execute('INSERT INTO media_builders VALUES(?,?,?,?,?,0)',
                      (identity, name, hashed(token), 0, '{}'))
            event(c, 'media', '已生成 Windows 制作端安装包：' + name)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('builder-registration.json', canonical(config))
            for filename in ('Install-Builder.ps1', 'Start-Builder.ps1', 'Build-LocalMedia.ps1'):
                z.write(ROOT / 'scripts' / filename, filename)
            z.writestr('安装说明.txt', '需要 Windows、PowerShell 7 和管理员权限。\r\n'
                       '右键终端以管理员身份运行 pwsh，再执行 .\\Install-Builder.ps1。\r\n'
                       '选择现有的可用 PE Media 文件夹、oscdimg 及 BIOS/UEFI 引导文件；不会写入 U 盘。\r\n'
                       '仅首次安装需要配置，之后在后台点击一键制作。制作时电脑需开机且当前用户已登录。\r\n')
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name='pc-deploy-builder.zip',
                         mimetype='application/zip')

    @app.post('/api/builders/<identity>/revoke')
    @admin
    def revoke_builder(identity):
        with store.connect(write=True) as c:
            c.execute('UPDATE media_builders SET revoked=1 WHERE id=?', (identity,))
            c.execute("UPDATE media_builds SET state='failed',updated=? WHERE builder_id=? "
                      "AND state IN ('queued','building','uploading')", (time.time(), identity))
            event(c, 'media', '已停用制作端；不会关机或中断其他程序')
        return jsonify(ok=True)

    @app.post('/api/media')
    @admin
    def create_media():
        value = body()
        if type(value.get('registration_only')) is not bool or type(value.get('include_drivers')) is not bool:
            raise Invalid('请明确选择启动模式和是否注入驱动')
        identity, now = str(uuid.uuid4()), time.time()
        with store.connect(write=True) as c:
            builder = c.execute('SELECT * FROM media_builders WHERE id=? AND revoked=0',
                                (value.get('builder_id'),)).fetchone()
            if not builder or now-builder['seen'] >= 45:
                raise Invalid('Windows 制作端未在线，请先完成一次性安装并开机登录')
            if c.execute("SELECT id FROM media_builds WHERE builder_id=? AND state IN "
                         "('queued','building','uploading')", (builder['id'],)).fetchone():
                raise Invalid('该制作端已有任务，请等待完成')
            if c.execute('SELECT COUNT(*) FROM media_builds').fetchone()[0] >= 50:
                raise Invalid('制作记录已达保留上限，请联系管理员归档，平台不自动删除 ISO')
            if shutil.disk_usage(store.root).free < MAX_ISO_SIZE:
                raise Invalid('服务器可用空间不足 2 GiB')
            config = create_config(c)
            config['registration_only'] = value['registration_only']
            config['include_drivers'] = value['include_drivers']
            data = dict(registration_only=value['registration_only'], include_drivers=value['include_drivers'],
                        enrollment_id=hashed(config['enrollment_token']), stage='等待制作端领取')
            c.execute('INSERT INTO media_builds VALUES(?,?,?,?,?,?,?)',
                      (identity, builder['id'], 'queued', canonical(data), store.encrypt(config), now, now))
            event(c, 'media', '已创建 ISO 制作任务；不下发安装、不写入 U 盘', identity)
        return jsonify(ok=True, id=identity)

    @app.post('/api/media/<identity>/cancel')
    @admin
    def cancel_media(identity):
        with store.connect(write=True) as c:
            c.execute("UPDATE media_builds SET state='failed',updated=? WHERE id=? AND state IN "
                      "('queued','building','uploading')", (time.time(), identity))
            event(c, 'media', '已结束 ISO 制作记录；制作端不会再发布该产物，不删除本地文件', identity)
        return jsonify(ok=True)

    @app.get('/api/media/<identity>/download')
    @admin
    def download_media(identity):
        with store.connect() as c:
            row = c.execute("SELECT * FROM media_builds WHERE id=? AND state='ready'", (identity,)).fetchone()
            if not row:
                raise Invalid('ISO 尚未制作完成')
            data = json.loads(row['data'])
            join = c.execute('SELECT * FROM enrollments WHERE token_hash=?', (data['enrollment_id'],)).fetchone()
            if not join or (join['expires'] != -1 and join['expires'] < time.time()) or join['uses'] >= 500:
                raise Invalid('此 ISO 的登记凭据已失效，请先修改有效期或重新制作')
        return send_file(artifact(identity), as_attachment=True, download_name='pc-deploy-'+identity[:8]+'.iso',
                         mimetype='application/x-iso9660-image', conditional=True)

    @app.post('/api/media-worker/poll')
    def worker_poll():
        value, now = body(), time.time()
        instance = text(value.get('instance'), '制作端会话', 36, 36)
        if not re.fullmatch(r'[0-9a-f-]{36}', instance):
            raise Invalid('制作端会话无效')
        info = dict(driver_name=text(value.get('driver_name', '无额外驱动'), '驱动名称', 1, 100),
                    template_name=text(value.get('template_name', 'WinPE'), 'PE 模板名称', 1, 100))
        with store.connect(write=True) as c:
            builder = worker(c)
            c.execute('UPDATE media_builders SET seen=?,data=? WHERE id=?', (now, canonical(info), builder['id']))
            # Never automatically reassign an interrupted build or run its commands twice.
            c.execute("UPDATE media_builds SET state='failed' WHERE builder_id=? AND state IN "
                      "('building','uploading') AND (updated<? OR created<?)",
                      (builder['id'], now-180, now-6*3600))
            row = c.execute("SELECT * FROM media_builds WHERE builder_id=? AND state IN "
                            "('building','uploading')", (builder['id'],)).fetchone()
            if row:
                data = json.loads(row['data'])
                return jsonify(job=dict(id=row['id']) if data.get('instance') == instance else None)
            row = c.execute("SELECT * FROM media_builds WHERE builder_id=? AND state='queued' ORDER BY created LIMIT 1",
                            (builder['id'],)).fetchone()
            if not row:
                return jsonify(job=None)
            data = json.loads(row['data'])
            data.update(instance=instance, stage='准备 PE 文件')
            c.execute("UPDATE media_builds SET state='building',data=?,updated=? WHERE id=?",
                      (canonical(data), now, row['id']))
        return jsonify(job=dict(id=row['id']))

    @app.get('/api/media-worker/jobs/<identity>/package')
    def worker_job_package(identity):
        with store.connect() as c:
            row, data = owned(c, identity, ('building',))
            config = store.decrypt(row['secret'])
        buf = bootstrap_zip(config)
        return send_file(buf, mimetype='application/zip', as_attachment=True, download_name='client.zip')

    @app.post('/api/media-worker/jobs/<identity>/update')
    def worker_update(identity):
        value = body()
        stage = value.get('stage')
        stages = ('准备 PE 文件', '注入客户端和驱动', '生成 ISO', '上传 ISO', '制作失败')
        if stage not in stages:
            raise Invalid('制作阶段无效')
        with store.connect(write=True) as c:
            row, data = owned(c, identity, ('building', 'uploading'))
            data['stage'] = stage
            if stage == '制作失败':
                state = 'failed'
            elif stage == '上传 ISO':
                size = integer(value.get('size'), 'ISO 大小', 32774, MAX_ISO_SIZE)
                sha = value.get('sha256', '')
                if not isinstance(sha, str) or not re.fullmatch('[a-f0-9]{64}', sha):
                    raise Invalid('ISO 校验值无效')
                if row['state'] == 'uploading' and (size != data['size'] or sha != data['sha256']):
                    raise Invalid('不得更换正在上传的 ISO')
                data.update(size=size, sha256=sha)
                state = 'uploading'
            else:
                if row['state'] != 'building':
                    raise Invalid('制作阶段不能回退')
                state = 'building'
            c.execute('UPDATE media_builds SET data=?,state=?,updated=? WHERE id=?',
                      (canonical(data), state, time.time(), identity))
            c.execute('UPDATE media_builders SET seen=? WHERE id=?', (time.time(), row['builder_id']))
        return jsonify(ok=True)

    @app.post('/api/media-worker/jobs/<identity>/chunk')
    def upload_chunk(identity):
        raw = request.stream.read(CHUNK_SIZE+1)
        if not raw or len(raw) > CHUNK_SIZE:
            raise Invalid('ISO 分块大小无效')
        offset = request.headers.get('X-Upload-Offset', '')
        if not re.fullmatch(r'[0-9]{1,10}', offset):
            raise Invalid('上传偏移无效')
        offset = int(offset)
        with store.connect(write=True) as c:
            row, data = owned(c, identity, ('uploading',))
            if offset+len(raw) > data['size']:
                raise Invalid('上传超出声明的 ISO 大小')
            path = artifact(identity).with_suffix('.part')
            if not path.exists():
                path.touch(exist_ok=False)
            with path.open('r+b') as f:
                f.seek(0, 2)
                length = f.tell()
                if length == offset:
                    f.write(raw)
                elif offset+len(raw) <= length:
                    f.seek(offset)
                    if f.read(len(raw)) != raw:
                        raise Invalid('重复上传的数据不一致')
                else:
                    raise Invalid('上传分块顺序不正确')
            c.execute('UPDATE media_builds SET updated=? WHERE id=?', (time.time(), identity))
            c.execute('UPDATE media_builders SET seen=? WHERE id=?', (time.time(), row['builder_id']))
        return jsonify(ok=True, offset=offset+len(raw))

    @app.post('/api/media-worker/jobs/<identity>/finish')
    def finish_upload(identity):
        with store.connect(write=True) as c:
            row, data = owned(c, identity, ('uploading', 'ready'))
            if row['state'] == 'ready':
                return jsonify(ok=True)
            path = artifact(identity)
            part = path.with_suffix('.part')
            # After a process crash between rename and DB commit, validate the same complete file.
            source = part if part.exists() else path
            if not source.is_file() or source.stat().st_size != data['size']:
                raise Invalid('ISO 上传不完整')
            digest = hashlib.sha256()
            with source.open('rb') as f:
                f.seek(32769)
                if f.read(5) != b'CD001':
                    raise Invalid('产物不是有效的 ISO 文件')
                f.seek(0)
                for block in iter(lambda: f.read(1024*1024), b''):
                    digest.update(block)
            if digest.hexdigest() != data['sha256']:
                raise Invalid('ISO 完整文件校验失败')
            if source == part:
                part.replace(path)
            data['stage'] = '制作完成'
            c.execute("UPDATE media_builds SET state='ready',data=?,updated=? WHERE id=?",
                      (canonical(data), time.time(), identity))
            event(c, 'media', 'ISO 已制作完成并通过 SHA256 校验', identity)
        return jsonify(ok=True)
