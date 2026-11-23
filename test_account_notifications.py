import io
import smtplib
import unittest
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from account_notifications import MAX_ATTACHMENT, seed_templates
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

    def test_template_edit_and_stale_version(self):
        value = {k: v for k, v in self.template.items() if k not in ('id', 'attachments')}
        value.update(name='企业邮箱', system_name='邮箱')
        response = self.post('/templates/' + self.template['id'], value)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['template']['version'], self.template['version'] + 1)
        self.assertEqual(self.post('/templates/' + self.template['id'], value).status_code, 409)
        value['password'] = 'not-accepted'
        self.assertEqual(self.post('/templates', value).status_code, 400)

    def test_preview_escapes_text_and_validates_fields(self):
        result = self.preview(recipient_name='<script>alert(1)</script>')
        self.assertEqual(result.status_code, 200)
        self.assertNotIn('<script>', result.json['html'])
        self.assertIn('&lt;script&gt;', result.json['html'])
        for changes in ({'to_email': 'a@example.test\r\nBcc:b@example.test'},
                        {'login_url': 'javascript:alert(1)'}, {'account': ''}, {'version': True}):
            self.assertIn(self.preview(**changes).status_code, (400, 409))
        self.assertEqual(self.preview(password='secret').status_code, 400)

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


if __name__ == '__main__':
    unittest.main()
