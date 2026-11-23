// All AD and mail requests are mocked. Requires Playwright and Microsoft Edge.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
    const browser = await chromium.launch({channel:'msedge',headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1440,height:1000}});
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        let role = 'super_admin', records = [], seen = [], template;
        const initial = () => ({id:'template-1',version:1,name:'VPN 开通',system_name:'公司 VPN',
            subject:'VPN 开通通知',intro:'您的账号已开通',active:true,login_url:'http://vpn.example.test',
            tutorial_url:'',download_url:'',password_instruction:'使用现有密码',attachments:[]});
        template = initial();
        await page.route('**/*', async route => {
            const req=route.request(), url=new URL(req.url()), endpoint=url.pathname.replace('/api/admin/account-notifications','');
            if(url.pathname==='/admin/manage'||url.pathname==='/admin.html') return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(__dirname,url.pathname==='/admin.html'?'admin.html':'admin_manage.html'),'utf8')});
            if(url.pathname==='/account_notifications.html')return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(__dirname,'account_notifications.html'),'utf8')});
            let result={success:true};
            if(url.pathname==='/api/admin/check')result={logged_in:true,username:'admin',role,permissions:['view_user','system_settings']};
            if(url.pathname.startsWith('/api/admin/account-notifications')){
                assert.equal(role,'super_admin');
                if(req.method()!=='GET')assert.equal(req.headers()['x-csrf-token'],'test-csrf');
                if(endpoint==='/config')result={success:true,csrf_token:'test-csrf',mail_ready:true,sender:'it@example.test'};
                if(endpoint==='/templates'&&req.method()==='GET')result={success:true,templates:[template]};
                if(endpoint.startsWith('/templates/')&&req.method()==='POST'){
                    if(endpoint.endsWith('/attachments'))template={...template,version:template.version+1,attachments:[{id:'file-1',filename:'company.ovpn',size:35,private_key:false}]};
                    else template={...template,...req.postDataJSON(),version:template.version+1};
                    result={success:true,template};
                }
                if(endpoint==='/recipients'){
                    const people={
                        '张三':[{name:'张三',employee_id:'wfq101755',email:'staff@example.test',email_status:'valid',department:'研发部'}],
                        '李四':[{name:'李四',employee_id:'wfq000001',email:'',email_status:'missing',department:'行政部'}],
                        '王五':[{name:'王五',employee_id:'wfq000002',email:'bad@@example.test',email_status:'invalid',department:''}],
                        '赵六':[{name:'赵六',employee_id:'wfq000003',email:'a@example.test',email_status:'valid',department:'研发部'},
                               {name:'赵六',employee_id:'wfq000004',email:'b@example.test',email_status:'valid',department:'行政部'}]
                    };
                    result={success:true,exact:url.searchParams.get('exact')==='1',truncated:false,recipients:people[url.searchParams.get('q')]||[]};
                }
                if(endpoint==='/preview'){
                    const body=req.postDataJSON();seen.push(body);
                    result={success:true,preview_token:'preview-token',subject:template.subject,recipient:body.to_email,html:'<html><body><h2>公司 VPN</h2><p>账号开通通知</p></body></html>'};
                }
                if(endpoint==='/send'){
                    const body=req.postDataJSON();assert.equal(body.confirm_text,'SEND');assert.match(body.request_key,/^[a-f0-9-]{36}$/);
                    const record={id:String(records.length+1),mode:body.mode,to_email:body.mode==='test'?body.test_email:seen.at(-1).to_email,
                        operator:'admin',subject:template.subject,status:'submitted',message:'邮件服务器已接受；不代表收件人已收到或阅读',created_at:'2026-11-23T02:00:00Z',snapshot:{...template,...seen.at(-1),template_id:template.id}};
                    records.unshift(record);result={success:true,delivery:record};
                }
                if(endpoint==='/deliveries')result={success:true,page:1,total:records.length,deliveries:records};
            }
            return route.fulfill({contentType:'application/json',body:JSON.stringify(result)});
        });
        await page.goto('http://account-notice.test/admin/manage');
        await page.locator('#accountNoticeMenu').waitFor({state:'visible'});
        assert.equal(await page.locator('aside > :last-child').getAttribute('id'),'accountNoticeMenu');
        await page.locator('#accountNoticeMenu').click();
        const frame=page.frameLocator('#accountNoticeFrame');
        await frame.locator('#composeTemplate option[value="template-1"]').waitFor({state:'attached'});
        await frame.locator('#employeeSearch').fill('张三');
        await frame.locator('#recipientHint').filter({hasText:'邮箱已自动填写'}).waitFor();
        assert.equal(await frame.locator('#to_email').inputValue(),'staff@example.test');
        await frame.locator('#searchEmployee').click();
        await frame.locator('.result').click();
        assert.equal(await frame.locator('#to_email').inputValue(),'staff@example.test');
        assert.equal(await frame.locator('#account').inputValue(),'wfq101755');
        await frame.locator('#recipient_name').fill('李四');
        assert.equal(await frame.locator('#to_email').inputValue(),'');
        await frame.locator('#recipientHint').filter({hasText:'尚未填写邮箱'}).waitFor();
        assert.equal(await frame.locator('#employee_id').inputValue(),'wfq000001');
        await frame.locator('#recipient_name').fill('王五');
        await frame.locator('#recipientHint').filter({hasText:'邮箱格式不正确'}).waitFor();
        assert.equal(await frame.locator('#to_email').inputValue(),'');
        await frame.locator('#to_email').fill('corrected@example.test');
        assert.equal(await frame.locator('#to_email').inputValue(),'corrected@example.test');
        await frame.locator('#recipient_name').fill('不存在');
        await frame.locator('#recipientHint').filter({hasText:'未找到匹配的域账号'}).waitFor();
        assert.equal(await frame.locator('#employee_id').inputValue(),'');
        assert.equal(await frame.locator('#account').inputValue(),'');
        await frame.locator('#recipient_name').fill('赵六');
        await frame.locator('#recipientHint').filter({hasText:'多个同名域账号'}).waitFor();
        assert.equal(await frame.locator('#to_email').inputValue(),'');
        assert.equal(await frame.locator('.result').count(),2);
        await frame.locator('.result').nth(1).click();
        assert.equal(await frame.locator('#employee_id').inputValue(),'wfq000004');
        assert.equal(await frame.locator('#to_email').inputValue(),'b@example.test');
        await frame.locator('#recipient_name').fill('张三');
        await frame.locator('#recipientHint').filter({hasText:'邮箱已自动填写'}).waitFor();
        await frame.locator('#previewButton').click();
        await frame.locator('#previewDialog').waitFor({state:'visible'});
        assert(await frame.locator('#confirmSend').isDisabled());
        await frame.locator('#testEmail').fill('it@example.test');
        await frame.locator('#sendTest').click();
        await frame.locator('#sendResult').filter({hasText:'测试邮件'}).waitFor();
        assert.equal(records.length,1);assert.equal(records[0].to_email,'it@example.test');
        await frame.locator('#confirmOpened').check();
        await frame.locator('#confirmSend').click();
        await frame.locator('#sendResult').filter({hasText:'邮件服务器已接受'}).waitFor();
        assert.equal(records.length,2);assert.equal(records[0].to_email,'staff@example.test');
        await frame.locator('[data-close="previewDialog"]').first().click();
        await frame.locator('[data-tab="history"]').click();
        await frame.locator('#historyBody tr').nth(1).waitFor();
        assert.equal(await frame.locator('#historyBody tr').count(),2);
        await frame.locator('#historyBody .link-button').first().click();
        assert((await frame.locator('#deliveryDetail').textContent()).includes('wfq101755'));
        await frame.locator('[data-close="detailDialog"]').first().click();
        await frame.locator('[data-tab="templates"]').click();
        await frame.locator('#templateForm [name=name]').fill('公司 VPN 通知');
        await frame.locator('#templateForm [type=submit]').click();
        await frame.locator('#globalMessage').filter({hasText:'模板已保存'}).waitFor();
        assert.equal(template.name,'公司 VPN 通知');
        await frame.locator('#attachmentFile').setInputFiles({name:'company.ovpn',mimeType:'application/octet-stream',buffer:Buffer.from('client')});
        await frame.locator('#uploadFile').click();
        await frame.locator('#attachmentList a').waitFor();
        assert.equal(await frame.locator('#attachmentList a').textContent(),'company.ovpn');
        await frame.locator('[data-tab="send"]').click();
        const png=await page.screenshot();assert(png.length>10000);
        await page.reload();
        await frame.locator('#composeTemplate').waitFor();
        assert.equal(new URL(page.url()).hash,'#accountNotifications');
        await page.setViewportSize({width:390,height:844});
        await frame.locator('#composeTemplate').waitFor();
        assert(await frame.locator('body').evaluate(el=>el.scrollWidth<=innerWidth));
        await frame.locator('[data-tab="templates"]').click();
        assert(await frame.locator('body').evaluate(el=>el.scrollWidth<=innerWidth));
        await page.goto('http://account-notice.test/admin.html');
        await page.locator('#accountNoticeMenu').waitFor({state:'visible'});
        assert.equal(await page.locator('aside > :last-child').getAttribute('id'),'accountNoticeMenu');
        role='readonly';await page.goto('http://account-notice.test/admin/manage');
        await page.waitForFunction(()=>document.getElementById('loginUser').textContent.includes('admin'));
        assert(await page.locator('#accountNoticeMenu').isHidden());
        assert.deepEqual(errors,[]);
        console.log('PASS account notice: automatic AD lookup, missing/invalid email, duplicate names, manual correction, preview, delivery and mobile layout');
    } finally {await browser.close();}
}
run().catch(e=>{console.error(e);process.exitCode=1;});
