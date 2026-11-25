import io
import smtplib
import unittest
import uuid
from datetime import datetime, timedelta
from html import escape
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ldap3

from account_notifications import (DOMAIN_PASSWORD_NOTICE, DOMAIN_TEMPLATE_NAME, MAX_ATTACHMENT, OLD_DOMAIN_PASSWORD_NOTICE,
                                   PASSWORD_NOTICE, VPN_TEMPLATE_ID, seed_templates, suggested_account)
from itsdangerous import URLSafeTimedSerializer
import test_domain_password_policy as policy_tests


class AccountNoticeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy_tests.DomainPasswordPolicyTests.setUpClass.__func__(cls)

    def setUp(self):
        self.p = self.platform
        context = self.p.app.app_context()
        context.push()
        self.addCleanup(context.pop)
        self.addCleanup(self.p.db.session.remove)
        self.p.db.drop_all()
        self.p.db.create_all()
        self.Template, self.Attachment, self.Delivery = self.p.account_notice_models
        seed_templates(self.p.db, self.p.account_notice_models)
        self.user = self.p.AdminUser(username='notice-test', role='super_admin', password_hash='unused')
        self.p.db.session.add(self.user)
        self.p.db.session.commit()
        self.config = patch.dict(self.p.app.config, MAIL_SERVER='smtp.example.test', MAIL_PORT=465,
            MAIL_USERNAME='it@example.test', MAIL_PASSWORD='smtp-secret-not-for-response', AD_BASE_DN='DC=test')
        self.config.start()
        self.addCleanup(self.config.stop)
        self.client = self.p.app.test_client()
        with self.client.session_transaction() as s:
            s.update(admin_logged_in=True, admin_username=self.user.username, admin_role=self.user.role)
        config = self.client.get(self.url('/config')).json
        self.headers = {'X-CSRF-Token': config['csrf_token']}
        self.template = self.client.get(self.url('/templates')).json['templates'][0]
        smtp = patch('account_notifications.smtplib.SMTP_SSL')
        self.smtp = smtp.start()
        self.addCleanup(smtp.stop)
        self.connection = self.smtp.return_value.__enter__.return_value
        self.connection.send_message.return_value = {}

    @staticmethod
    def url(path):
        return '/api/admin/account-notifications' + path

    def post(self, path, value):
        return self.client.post(self.url(path), json=value, headers=self.headers)

    def preview(self, **changes):
        value = dict(template_id=self.template['id'], version=self.template['version'],
            recipient_name='张三', to_email='staff@example.test', account='wfq101755', employee_id='wfq101755',
            password_instruction='请使用现有密码', notes='', login_url='https://vpn.example.test',
            tutorial_url='', download_url='')
        value.update(changes)
        return self.post('/preview', value)

    def send(self, preview=None, key=None, **changes):
        preview = preview or self.preview().json
        body = dict(preview_token=preview['preview_token'], request_key=key or str(uuid.uuid4()),
                    mode='employee', confirm_text='SEND')
        body.update(changes)
        return self.post('/send', body)

    def test_permissions_and_csrf(self):
        anonymous = self.p.app.test_client()
        self.assertEqual(anonymous.get(self.url('/config')).status_code, 401)
        self.assertEqual(self.client.post(self.url('/preview'), json={}).status_code, 403)
        self.user.role = 'readonly'
        self.p.db.session.commit()
        self.assertEqual(self.client.get(self.url('/templates')).status_code, 403)
        self.smtp.assert_not_called()

    def test_old_vpn_provision_request_is_rejected_without_email(self):
        self.assertEqual(self.template['id'], VPN_TEMPLATE_ID)
        password, key = 'MockPassword12', str(uuid.uuid4())
        preview = self.preview(password=password).json
        response = self.send(preview, key, password=password, provision_vpn=True)
        self.assertEqual(response.status_code, 400)
        self.assertIn('VPN 自动开通已停用', response.json['message'])
        self.smtp.assert_not_called()
        self.assertEqual(self.Delivery.query.count(), 0)
        sent = self.send(preview, key, password=password).json
        self.assertTrue(sent['success'])
        self.assertNotIn('vpn_status', sent['delivery']['snapshot'])
        self.connection.send_message.assert_called_once()

    def test_template_edit_and_stale_version(self):
        value = {k: v for k, v in self.template.items() if k not in ('id', 'attachments')}
        value.update(name='企业邮箱', system_name='邮箱')
        response = self.post('/templates/' + self.template['id'], value)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['template']['version'], self.template['version'] + 1)
        self.assertEqual(self.post('/templates/' + self.template['id'], value).status_code, 409)
        value['password'] = 'not-accepted'
        self.assertEqual(self.post('/templates', value).status_code, 400)

    def test_notes_preview_and_mail_share_text_and_uniform_password_notice(self):
        notes = '请先阅读教程。\n补充说明：<script>alert(1)</script>'
        preview = self.preview(notes=notes, password_instruction='旧的密码说明').json
        self.assertIn(notes, preview['text'])
        self.assertIn('&lt;script&gt;', preview['html'])
        self.assertNotIn('<script>', preview['html'])
        self.assertIn(PASSWORD_NOTICE, preview['text'])
        self.assertNotIn('旧的密码说明', preview['text'])
        response = self.send(preview)
        self.assertTrue(response.json['success'])
        message = self.connection.send_message.call_args.args[0]
        self.assertIn(notes, message.get_body(preferencelist=('plain',)).get_content())
        self.assertEqual(response.json['delivery']['snapshot']['password_instruction'], PASSWORD_NOTICE)

    def test_generic_templates_still_show_uniform_notice(self):
        row = self.Template.query.filter(self.Template.id != VPN_TEMPLATE_ID).one()
        row.password_instruction = '旧的密码说明'
        self.p.db.session.commit()
        templates = self.client.get(self.url('/templates')).json['templates']
        self.assertTrue(all(t['password_instruction'] == PASSWORD_NOTICE for t in templates))
        self.assertEqual(self.client.get(self.url('/config')).json['password_notice'], PASSWORD_NOTICE)

    def test_vpn_password_notice_is_editable_and_shared_with_email(self):
        value = {k: v for k, v in self.template.items() if k not in ('id', 'attachments')}
        hint = '仅限 <本人使用>，请勿转发。'
        endpoint = '/templates/' + VPN_TEMPLATE_ID
        self.assertEqual(self.post(endpoint, dict(value, password_instruction='x' * 501)).status_code, 400)
        self.assertEqual(self.post(endpoint, dict(value, password_instruction='第一行\n第二行')).status_code, 400)
        saved = self.post(endpoint, dict(value, password_instruction=hint))
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json['template']['password_instruction'], hint)
        version = saved.json['template']['version']
        preview = self.preview(version=version, password_instruction='不采用此提示').json
        self.assertIn(hint, preview['text'])
        self.assertIn(escape(hint), preview['html'])
        self.assertNotIn('不采用此提示', preview['text'])
        sent = self.send(preview).json
        self.assertTrue(sent['success'])
        self.assertEqual(sent['delivery']['snapshot']['password_instruction'], hint)
        mail = self.connection.send_message.call_args.args[0]
        self.assertIn(hint, mail.get_body(preferencelist=('plain',)).get_content())

        reset = self.post(endpoint, dict(value, version=version, password_instruction=''))
        self.assertEqual(reset.json['template']['password_instruction'], PASSWORD_NOTICE)

    def test_domain_template_reuses_ad_account_and_sends_without_vpn_fields(self):
        row = next(t for t in self.Template.query.all() if t.id != VPN_TEMPLATE_ID)
        row.name = DOMAIN_TEMPLATE_NAME
        row.password_instruction = OLD_DOMAIN_PASSWORD_NOTICE
        row.tutorial_url = 'https://example.test/legacy'
        self.p.db.session.add(self.Attachment(id=str(uuid.uuid4()), template_id=row.id,
            filename='legacy.ovpn', content=b'client'))
        self.p.db.session.commit()
        template = next(t for t in self.client.get(self.url('/templates')).json['templates'] if t['id'] == row.id)
        self.assertTrue(template['domain_account'])
        self.assertEqual(template['password_instruction'], DOMAIN_PASSWORD_NOTICE)
        default_preview = self.preview(template_id=row.id, version=template['version']).json
        self.assertIn('PIN', default_preview['text'])
        self.assertIn('人脸或指纹登录', default_preview['text'])
        self.assertEqual(template['attachments'], [])
        update = {k: v for k, v in template.items() if k not in ('id', 'attachments', 'domain_account', 'wifi_configured')}
        hint, default = 'Windows 登录后请及时修改密码。\n\n至少 8 个字符，<特殊符号可选>。', 'TestDefault12'
        update.update(password_instruction=hint.replace('\n', '\r\n'), initial_password=default, tutorial_url='')
        saved = self.post('/templates/' + row.id, update)
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json['template']['password_instruction'], hint)
        self.assertNotIn(default, saved.get_data(as_text=True))
        self.assertEqual(self.p.db.session.get(self.Template, row.id).tutorial_url, 'https://example.test/legacy')
        setting = self.p.SystemSetting.query.filter_by(key=f'account_notice_initial_password:{row.id}').one()
        self.assertNotIn(default, setting.value)
        endpoint = '/templates/' + row.id + '/initial-password'
        self.assertEqual(self.client.post(self.url(endpoint), json={}).status_code, 403)
        secret = self.post(endpoint, {})
        self.assertEqual(secret.json['password'], default)
        self.assertEqual(secret.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.post('/templates/' + VPN_TEMPLATE_ID + '/initial-password', {}).status_code, 404)
        update.update(version=saved.json['template']['version'], initial_password='')
        saved = self.post('/templates/' + row.id, update)
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(self.post(endpoint, {}).json['password'], default)

        override = 'TestOverride12'
        preview = self.preview(template_id=row.id, version=saved.json['template']['version'],
            account='zhangsan', employee_id='wfq123456', password=override,
            tutorial_url='https://example.test/ignored', password_instruction='不采用此提示').json
        self.assertIn('登录账号：wfq123456', preview['text'])
        self.assertLess(preview['text'].index(row.intro), preview['text'].index('登录账号'))
        self.assertLess(preview['text'].index('登录账号'), preview['text'].index('初始密码'))
        self.assertIn(hint, preview['text'])
        self.assertEqual(preview['rows'][-1]['value'], hint)
        html_hint = escape(hint).replace('\n', '<br>')
        self.assertIn(html_hint, preview['html'])
        self.assertIn(override, preview['text'])
        self.assertNotIn('example.test', preview['text'])
        self.assertNotIn(default, preview['text'])
        sent = self.send(preview, password=override)
        self.assertTrue(sent.json['success'])
        message = self.connection.send_message.call_args.args[0]
        plain = message.get_body(preferencelist=('plain',)).get_content()
        rich = message.get_body(preferencelist=('html',)).get_content()
        self.assertIn(hint, plain)
        self.assertIn(html_hint, rich)
        for body in (plain, rich):
            self.assertLess(body.index(row.intro), body.index('登录账号'))
            self.assertLess(body.index('登录账号'), body.index('初始密码'))
            self.assertIn(override, body)
        self.assertEqual(rich.count('background-color:#eaf2ff'), 2)
        self.assertFalse(list(message.iter_attachments()))
        self.assertNotIn(override, self.Delivery.query.one().snapshot)

    def test_domain_wifi_settings_appear_in_mail_but_not_history_or_preview_token(self):
        row = self.Template.query.filter(self.Template.id != VPN_TEMPLATE_ID).one()
        row.name = DOMAIN_TEMPLATE_NAME
        self.p.db.session.commit()
        endpoint = '/templates/' + row.id
        options = dict(name=row.name, version=row.version, system_name=row.system_name,
                       subject=row.subject, intro=row.intro)
        secrets = {'WIFI-OA': 'MockOffice<Wifi14', 'WIFI-Mobile': 'MockMobileWifi23!'}
        self.assertEqual(self.post(endpoint, dict(options, wifi_passwords={'other': 'test'})).status_code, 400)
        vpn = {k: v for k, v in self.template.items() if k not in ('id', 'attachments')}
        self.assertEqual(self.post('/templates/' + VPN_TEMPLATE_ID, dict(vpn, wifi_passwords=secrets)).status_code, 400)
        saved = self.post(endpoint, dict(options, wifi_passwords=secrets))
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json['template']['wifi_configured'], list(secrets))
        ciphertexts = self.p.SystemSetting.query.filter(self.p.SystemSetting.key.like('account_notice_wifi:%')).all()
        self.assertEqual(len(ciphertexts), 2)
        self.assertTrue(all(secret not in str([item.value for item in ciphertexts]) for secret in secrets.values()))
        for secret in secrets.values():
            self.assertNotIn(secret, str(saved.json))
            self.assertNotIn(secret, str(self.client.get(self.url('/templates')).json))

        previous_version = saved.json['template']['version']
        password = 'MockAccountPassword12!'
        previous = self.preview(template_id=row.id, version=previous_version, password=password)
        self.assertEqual(previous.headers['Cache-Control'], 'no-store')
        self.assertEqual([item['label'] for item in previous.json['rows'] if item.get('kind') == 'credential'],
                         ['登录账号', '初始密码'])
        signer = URLSafeTimedSerializer(self.p.app.secret_key, salt='account-notification-preview-v1')
        token_data = signer.loads(previous.json['preview_token'])
        for secret in secrets.values():
            self.assertIn(secret, previous.json['text'])
            self.assertIn(escape(secret), previous.json['html'])
            self.assertNotIn(secret, str(token_data))

        changed_wifi = 'MockRotatedWifi46!'
        changed = self.post(endpoint, dict(options, version=previous_version,
            wifi_passwords={'WIFI-OA': '', 'WIFI-Mobile': changed_wifi}))
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(self.send(previous.json, password=password).status_code, 409)
        self.smtp.assert_not_called()
        notes = '请核对办公网络。'
        preview = self.preview(template_id=row.id, version=changed.json['template']['version'],
                               password=password, notes=notes).json
        self.assertIn(secrets['WIFI-OA'], preview['text'])
        self.assertIn(changed_wifi, preview['text'])
        self.assertNotIn(secrets['WIFI-Mobile'], preview['text'])
        self.assertEqual(preview['rows'][-2]['text'], notes)
        self.assertEqual(preview['rows'][-1]['kind'], 'guidance')
        self.assertTrue(self.send(preview, password=password).json['success'])
        mail = self.connection.send_message.call_args.args[0]
        for representation in ('plain', 'html'):
            body = mail.get_body(preferencelist=(representation,)).get_content()
            self.assertLess(body.index('WIFI-Mobile'), body.index(notes))
            self.assertLess(body.index(notes), body.index('密码说明'))
        for secret in (secrets['WIFI-OA'], changed_wifi):
            self.assertIn(secret, mail.get_body(preferencelist=('plain',)).get_content())
            self.assertIn(escape(secret), mail.get_body(preferencelist=('html',)).get_content())
            self.assertNotIn(secret, self.Delivery.query.one().snapshot)
            self.assertNotIn(secret, str(self.client.get(self.url('/deliveries')).json))
        self.assertNotIn('公司 Wi-Fi', self.preview().json['text'])

    def test_preview_and_html_mail_display_links_with_original_addresses(self):
        url = 'https://docs.example.test/vpn?space=123&file=456'
        preview = self.preview(login_url='', tutorial_url=url).json
        self.assertEqual([row for row in preview['rows'] if 'href' in row],
                         [dict(text='使用教程：', href=url, link_text='查看配置教程')])
        self.assertIn('使用教程：' + url, preview['text'])
        self.assertTrue(self.send(preview).json['success'])
        mail = self.connection.send_message.call_args.args[0]
        for body in (preview['html'], mail.get_body(preferencelist=('html',)).get_content()):
            self.assertIn(f'href="{escape(url)}" title="{escape(url)}"', body)
            self.assertIn('>查看配置教程</a>', body)
        self.assertIn(url, mail.get_body(preferencelist=('plain',)).get_content())

    def test_preview_escapes_text_and_validates_fields(self):
        result = self.preview(recipient_name='<script>alert(1)</script>')
        self.assertEqual(result.status_code, 200)
        self.assertNotIn('<script>', result.json['html'])
        self.assertIn('&lt;script&gt;', result.json['html'])
        for changes in ({'to_email': 'a@example.test\r\nBcc:b@example.test'},
                        {'login_url': 'javascript:alert(1)'}, {'account': ''}, {'version': True}):
            self.assertIn(self.preview(**changes).status_code, (400, 409))
        self.assertEqual(self.preview(password='bad\nsecret').status_code, 400)

    def test_send_and_duplicate_use_same_mail(self):
        preview, key = self.preview().json, str(uuid.uuid4())
        response = self.send(preview, key)
        self.assertTrue(response.json['success'])
        self.assertEqual(response.json['delivery']['status'], 'submitted')
        self.assertTrue(self.send(preview, key).json['replayed'])
        self.assertEqual(self.connection.send_message.call_count, 1)
        message = self.connection.send_message.call_args.args[0]
        self.assertEqual(message['To'], 'staff@example.test')
        self.assertIn('张三', message.get_body(preferencelist=('plain',)).get_content())
        self.assertNotIn('smtp-secret', str(message))
        self.assertEqual(self.Delivery.query.count(), 1)
        changed = self.preview(account='another').json
        self.assertEqual(self.send(changed, key).status_code, 409)
        self.assertEqual(self.connection.send_message.call_count, 1)

    def test_test_mail_does_not_send_to_employee(self):
        response = self.send(mode='test', test_email='admin@example.test')
        self.assertTrue(response.json['success'])
        message = self.connection.send_message.call_args.args[0]
        self.assertEqual(message['To'], 'admin@example.test')
        self.assertTrue(message['Subject'].startswith('【测试】'))
        self.assertIn('测试邮件', message.get_body(preferencelist=('plain',)).get_content())

    def test_pinyin_account_suggestions(self):
        for name, account in [('袁玉杰', 'yuanyujie'), ('张三', 'zhangsan'), ('吕伟', 'lvwei'), ('Alice Smith', 'alicesmith')]:
            self.assertEqual(suggested_account(name), account)
        config = self.client.get(self.url('/config')).json
        self.assertEqual(config['default_cc_email'], 'yuanyujie@shunhs.cn')
        self.assertEqual(config['domain_default_cc_email'], 'yuanyujie@shunhs.cn, liuchongxiang@shunhs.cn')

    def test_cc_and_password_delivery_without_plaintext_storage(self):
        password, cc, key = 'MockPassword12!', 'yuanyujie@shunhs.cn', str(uuid.uuid4())
        preview = self.preview(password=password, cc_email=cc).json
        self.assertIn(password, preview['text'])
        signer = URLSafeTimedSerializer(self.p.app.secret_key, salt='account-notification-preview-v1')
        self.assertNotIn(password, str(signer.loads(preview['preview_token'])))
        response = self.send(preview, key, password=password)
        self.assertTrue(response.json['success'])
        message = self.connection.send_message.call_args.args[0]
        self.assertEqual(message['Cc'], cc)
        self.assertEqual(self.connection.send_message.call_args.kwargs['to_addrs'], ['staff@example.test', cc])
        self.assertIn(password, message.get_body(preferencelist=('plain',)).get_content())
        row = self.Delivery.query.one()
        self.assertNotIn(password, row.snapshot)
        self.assertNotIn(password, str(self.client.get(self.url('/deliveries')).json))
        self.assertEqual(response.json['delivery']['cc_email'], cc)
        self.assertTrue(response.json['delivery']['snapshot']['password_included'])
        self.assertTrue(self.send(preview, key, password=password).json['replayed'])
        self.assertEqual(self.connection.send_message.call_count, 1)
        changed = self.preview(password='Different12!', cc_email=cc).json
        self.assertEqual(self.send(changed, key, password='Different12!').status_code, 409)

    def test_password_changes_require_new_preview_and_escape_html(self):
        password = ' Example<&12! '
        preview = self.preview(password=password).json
        self.assertIn('Example&lt;&amp;12!', preview['html'])
        self.assertEqual(self.send(preview, password='changed').status_code, 409)
        self.smtp.assert_not_called()
        self.assertTrue(self.send(preview, password=password).json['success'])
        self.assertIn(password, self.connection.send_message.call_args.args[0].get_body(preferencelist=('plain',)).get_content())
        self.assertEqual(self.preview(cc_email='bad\r\nBcc:someone@example.test').status_code, 400)
        self.assertEqual(self.preview(password='x' * 129).status_code, 400)

    def test_test_email_never_uses_form_cc(self):
        password = 'MockPassword12!'
        preview = self.preview(password=password, cc_email='yuanyujie@shunhs.cn').json
        response = self.send(preview, password=password, mode='test', test_email='admin@example.test')
        self.assertTrue(response.json['success'])
        message = self.connection.send_message.call_args.args[0]
        self.assertIsNone(message['Cc'])
        self.assertEqual(self.connection.send_message.call_args.kwargs['to_addrs'], ['admin@example.test'])
        self.assertEqual(response.json['delivery']['cc_email'], '')

    def test_partial_cc_refusal_does_not_retry_accepted_recipients(self):
        cc, key = 'yuanyujie@shunhs.cn', str(uuid.uuid4())
        additional = 'it@example.test'
        preview = self.preview(cc_email=f'{cc}, {additional}, {cc.upper()}').json
        self.assertEqual(preview['cc_email'], f'{cc}, {additional}')
        self.connection.send_message.return_value = {additional: (550, b'unknown recipient')}
        response = self.send(preview, key)
        self.assertEqual(response.json['delivery']['status'], 'partial')
        self.assertIn('抄送邮箱', response.json['delivery']['message'])
        mail = self.connection.send_message.call_args.args[0]
        self.assertEqual(self.connection.send_message.call_args.kwargs['to_addrs'], ['staff@example.test', cc, additional])
        self.assertEqual([address.addr_spec for address in mail['Cc'].addresses], [cc, additional])
        self.assertTrue(self.send(preview, key).json['replayed'])
        self.assertEqual(self.connection.send_message.call_count, 1)
        self.assertEqual(self.preview(cc_email=f'{cc},invalid').status_code, 400)
        self.assertEqual(self.preview(cc_email=','.join(f'c{i}@example.test' for i in range(6))).status_code, 400)

    def test_smtp_failure_and_uncertain_result_are_recorded(self):
        self.connection.login.side_effect = smtplib.SMTPAuthenticationError(535, b'rejected')
        self.assertEqual(self.send().json['delivery']['status'], 'failed')
        self.connection.login.side_effect = None
        self.connection.send_message.side_effect = TimeoutError('uncertain')
        preview, key = self.preview().json, str(uuid.uuid4())
        response = self.send(preview, key)
        self.assertEqual(response.json['delivery']['status'], 'unknown')
        self.send(preview, key)
        self.assertEqual(self.connection.send_message.call_count, 1)
        history = self.client.get(self.url('/deliveries')).json
        self.assertEqual(history['total'], 2)
        self.assertNotIn('smtp-secret', str(history))

    def test_preview_cannot_send_after_template_change(self):
        preview = self.preview().json
        row = self.p.db.session.get(self.Template, self.template['id'])
        row.version += 1
        self.p.db.session.commit()
        self.assertEqual(self.send(preview).status_code, 409)
        self.smtp.assert_not_called()

    def upload(self, name, content):
        return self.client.post(self.url('/templates/' + self.template['id'] + '/attachments'),
            data={'file': (io.BytesIO(content), name)}, headers=self.headers)

    def test_attachments_sent_and_download_requires_login(self):
        result = self.upload('company.ovpn', b'client\n<key>shared-key</key>')
        self.assertEqual(result.status_code, 200)
        self.template = result.json['template']
        file = self.template['attachments'][0]
        self.assertTrue(file['private_key'])
        self.assertEqual(self.p.app.test_client().get(self.url('/attachments/' + file['id'])).status_code, 401)
        download = self.client.get(self.url('/attachments/' + file['id']))
        self.assertIn(b'shared-key', download.data)
        self.assertEqual(download.headers['Cache-Control'], 'no-store')
        self.send()
        mail = self.connection.send_message.call_args.args[0]
        self.assertEqual(list(mail.iter_attachments())[0].get_filename(), 'company.ovpn')
        preview = self.preview().json
        self.client.delete(self.url('/attachments/' + file['id']), headers=self.headers)
        self.assertEqual(self.send(preview).status_code, 409)

    def test_attachment_limits(self):
        for name, content in [('bad.exe', b'x'), ('../a.ovpn', b'x'), ('a.pdf', b'not-pdf'),
                              ('huge.ovpn', b'x' * (MAX_ATTACHMENT + 1))]:
            self.assertEqual(self.upload(name, content).status_code, 400)
        for index in range(3):
            self.assertEqual(self.upload(f'c{index}.ovpn', b'client').status_code, 200)
        self.assertEqual(self.upload('c4.ovpn', b'client').status_code, 400)

    def test_ad_search_read_only_and_filter_escaped(self):
        conn = MagicMock()
        conn.result = {'result': 0}
        conn.entries = [SimpleNamespace(entry_attributes_as_dict={
            'sAMAccountName': ['wfq101755'], 'description': ['张三'], 'mail': ['staff@example.test'],
            'department': ['研发部']})]
        with patch.object(self.p, 'get_ad_connection', return_value=conn):
            response = self.client.get(self.url('/recipients?q=ab%2A'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['recipients'][0]['name'], '张三')
        self.assertEqual(response.json['recipients'][0]['suggested_account'], 'zhangsan')
        self.assertIn(r'ab\2a', conn.search.call_args.args[1])
        conn.add.assert_not_called()
        conn.modify.assert_not_called()
        conn.unbind.assert_called_once()

    def test_missing_smtp_and_stale_process(self):
        with patch.dict(self.p.app.config, MAIL_PASSWORD=''):
            self.assertEqual(self.send().status_code, 503)
        self.smtp.assert_not_called()
        self.assertEqual(self.Delivery.query.count(), 0)
        self.send()
        row = self.Delivery.query.one()
        row.status = 'sending'
        row.created_at = datetime.utcnow() - timedelta(minutes=6)
        self.p.db.session.commit()
        response = self.client.get(self.url('/deliveries'))
        self.assertEqual(response.json['deliveries'][0]['status'], 'unknown')

    def test_exact_recipient_lookup_and_email_status(self):
        conn = MagicMock()
        conn.result = {'result': 0}
        conn.entries = [SimpleNamespace(entry_attributes_as_dict={
            'sAMAccountName': [f'wfq00000{index}'], 'description': ['其他说明'],
            'displayName': ['张三'], 'mail': [mail]}) for index, mail in enumerate(
                [' staff@example.test ', '', 'not-an-email'])]
        with patch.object(self.p, 'get_ad_connection', return_value=conn):
            response = self.client.get(self.url('/recipients?q=张三&exact=1'))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['exact'])
        self.assertFalse(response.json['truncated'])
        self.assertEqual([p['email_status'] for p in response.json['recipients']], ['valid', 'missing', 'invalid'])
        self.assertEqual(response.json['recipients'][0]['email'], 'staff@example.test')
        self.assertEqual(response.json['recipients'][0]['name'], '张三')
        self.assertIn('(displayName=张三)', conn.search.call_args.args[1])
        self.assertNotIn('*', conn.search.call_args.args[1])
        conn.modify.assert_not_called()

    def test_exact_lookup_escapes_wildcards_and_keeps_duplicate_names(self):
        conn = MagicMock()
        conn.result = {'result': 4}
        conn.entries = [SimpleNamespace(entry_attributes_as_dict={
            'sAMAccountName': [ident], 'cn': ['ab*'], 'mail': []}) for ident in ['person1', 'person2']]
        with patch.object(self.p, 'get_ad_connection', return_value=conn):
            response = self.client.get(self.url('/recipients?q=ab%2A&exact=1'))
        self.assertTrue(response.json['truncated'])
        self.assertEqual(len(response.json['recipients']), 2)
        self.assertIn(r'(cn=ab\2a)', conn.search.call_args.args[1])
        self.assertEqual(response.json['recipients'][0]['name'], 'ab*')

    def test_no_recipient_is_distinct_from_directory_failure(self):
        conn = MagicMock()
        conn.result, conn.entries = {'result': 0}, []
        with patch.object(self.p, 'get_ad_connection', return_value=conn):
            response = self.client.get(self.url('/recipients?q=不存在&exact=1'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['recipients'], [])
        with patch.object(self.p, 'get_ad_connection', side_effect=OSError('directory offline')):
            response = self.client.get(self.url('/recipients?q=不存在&exact=1'))
        self.assertEqual(response.status_code, 503)
        self.assertIn('无法查询 AD', response.json['message'])

    def test_save_recipient_email_only_changes_mail_without_sending(self):
        row = self.Template.query.filter(self.Template.id != VPN_TEMPLATE_ID).one()
        row.name = DOMAIN_TEMPLATE_NAME
        self.p.db.session.commit()
        address = 'staff@example.test'
        body = dict(template_id=row.id, employee_id='wfq123456', email=address)
        dn = 'CN=Test Staff,OU=People,DC=test'
        self.assertEqual(self.client.post(self.url('/recipients/email'), json=body).status_code, 403)
        for current in ([], ['bad-address']):
            with self.subTest(current=current):
                conn = MagicMock(result={'result': 0}, entries=[SimpleNamespace(
                    entry_dn=dn, entry_attributes_as_dict={'mail': current})])
                with patch.object(self.p, 'get_ad_connection', return_value=conn):
                    response = self.post('/recipients/email', body)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json['email'], address)
                self.assertIn('(sAMAccountName=wfq123456)', conn.search.call_args.args[1])
                changes = [(ldap3.MODIFY_DELETE, current)] if current else []
                conn.modify.assert_called_once_with(dn, {'mail': [*changes, (ldap3.MODIFY_ADD, [address])]})
                conn.unbind.assert_called_once()
        self.assertEqual(self.p.AdminActionLog.query.filter_by(action='补全 AD 邮箱').count(), 2)
        self.smtp.assert_not_called()
        self.assertEqual(self.Delivery.query.count(), 0)

    def test_save_recipient_email_refuses_existing_valid_mail_ambiguity_and_race(self):
        row = self.Template.query.filter(self.Template.id != VPN_TEMPLATE_ID).one()
        row.name = DOMAIN_TEMPLATE_NAME
        self.p.db.session.commit()
        body = dict(template_id=row.id, employee_id='wfq000001', email='corrected@example.test')
        endpoint = '/recipients/email'
        known = SimpleNamespace(entry_dn='CN=Test,DC=test', entry_attributes_as_dict={'mail': ['existing@example.test']})
        conn = MagicMock(result={'result': 0}, entries=[known])
        with patch.object(self.p, 'get_ad_connection', return_value=conn):
            self.assertEqual(self.post(endpoint, dict(body, template_id=VPN_TEMPLATE_ID)).status_code, 400)
            self.assertEqual(self.post(endpoint, dict(body, email='invalid')).status_code, 400)
            self.assertEqual(self.post(endpoint, body).status_code, 409)
            conn.entries = [known, known]
            self.assertEqual(self.post(endpoint, body).status_code, 409)
            conn.entries = []
            self.assertEqual(self.post(endpoint, body).status_code, 404)
            conn.modify.assert_not_called()
            conn.entries = [SimpleNamespace(entry_dn=known.entry_dn, entry_attributes_as_dict={'mail': []})]
            conn.modify.side_effect = lambda *_: setattr(conn, 'result', {'result': 19})
            response = self.post(endpoint, body)
            self.assertEqual(response.status_code, 409)
            self.assertIn('没有覆盖', response.json['message'])
            conn.modify.assert_called_once()
        self.smtp.assert_not_called()


if __name__ == '__main__':
    unittest.main()
