// All AD and mail requests are mocked. Requires Playwright and Microsoft Edge.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
    const passwordNotice='请妥善保管此密码，请勿向他人透露或转发。';
    const browser = await chromium.launch({channel:'msedge',headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1440,height:1000}});
        const routerUrl='https://192.168.110.1/cgi-bin/luci/';
        await page.context().route('https://192.168.110.1/**', route=>{
            if(route.request().url()!==routerUrl)return route.abort();
            assert.equal(route.request().method(),'GET');
            assert.equal(route.request().postData(),null);
            return route.fulfill({contentType:'text/html',body:'<title>Mock router login</title>'});
        });
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        let role = 'super_admin', records = [], seen = [], template, apiRequests=0, previewPassword='';
        const emailWrites=[], domainCc='yuanyujie@shunhs.cn, liuchongxiang@shunhs.cn';
        const initial = () => ({id:'template-1',version:1,name:'VPN 开通',system_name:'公司 VPN',
            subject:'VPN 开通通知',intro:'您的账号已开通',active:true,login_url:'http://vpn.example.test',
            tutorial_url:'',download_url:'',password_instruction:passwordNotice,attachments:[]});
        template = initial();
        const wifi = {};
        const officeWifi='MockOfficeWifi14!', mobileWifi='MockMobileWifi23!';
        let domainPassword='TestDefault12', domain={...initial(),id:'domain-1',name:'域账号开通',
            domain_account:true,system_name:'微丰启 AD 域',password_instruction:'此密码为初始密码。',login_url:''};
        await page.route('**/*', async route => {
            const req=route.request(), url=new URL(req.url()), endpoint=url.pathname.replace('/api/admin/account-notifications','');
            if(url.pathname==='/admin/manage'||url.pathname==='/admin.html') return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(__dirname,url.pathname==='/admin.html'?'admin.html':'admin_manage.html'),'utf8')});
            if(url.pathname==='/account_notifications.html')return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(__dirname,'account_notifications.html'),'utf8')});
            let result={success:true};
            if(url.pathname==='/api/admin/check')result={logged_in:true,username:'admin',role,permissions:['view_user','system_settings']};
            if(url.pathname.startsWith('/api/admin/account-notifications')){
                apiRequests++;
                assert.equal(role,'super_admin');
                if(req.method()!=='GET')assert.equal(req.headers()['x-csrf-token'],'test-csrf');
                if(endpoint==='/config')result={success:true,csrf_token:'test-csrf',mail_ready:true,sender:'it@example.test',default_cc_email:'yuanyujie@shunhs.cn',domain_default_cc_email:domainCc,password_notice:passwordNotice,vpn_template_id:'template-1'};
                if(endpoint==='/templates'&&req.method()==='GET')result={success:true,templates:[template,domain]};
                if(endpoint.startsWith('/templates/')&&req.method()==='POST'){
                    if(endpoint==='/templates/domain-1/initial-password')result={success:true,password:domainPassword};
                    else if(endpoint==='/templates/domain-1'){
                        const {initial_password,wifi_passwords,...body}=req.postDataJSON();
                        if(initial_password)domainPassword=initial_password;
                        for(const [ssid,secret] of Object.entries(wifi_passwords||{}))if(secret)wifi[ssid]=secret;
                        domain={...domain,...body,wifi_configured:Object.keys(wifi),version:domain.version+1};result={success:true,template:domain};
                    }else{
                        if(endpoint.endsWith('/attachments'))template={...template,version:template.version+1,attachments:[{id:'file-1',filename:'company.ovpn',size:35,private_key:false}]};
                        else template={...template,...req.postDataJSON(),version:template.version+1};
                        result={success:true,template};
                    }
                }
                if(endpoint==='/recipients'){
                    const people={
                        '张三':[{name:'张三',employee_id:'wfq101755',email:'staff@example.test',email_status:'valid',department:'研发部'}],
                        '李四':[{name:'李四',employee_id:'wfq000001',email:'',email_status:'missing',department:'行政部'}],
                        '王五':[{name:'王五',employee_id:'wfq000002',email:'bad@@example.test',email_status:'invalid',department:''}],
                        '赵六':[{name:'赵六',employee_id:'wfq000003',email:'a@example.test',email_status:'valid',department:'研发部'},
                               {name:'赵六',employee_id:'wfq000004',email:'b@example.test',email_status:'valid',department:'行政部'}],
                        '袁玉杰':[{name:'袁玉杰',employee_id:'wfq100393',email:'yuan@example.test',email_status:'valid',department:'研发部'}]
                    };
                    const query=url.searchParams.get('q'),spellings={'张三':'zhangsan','李四':'lisi','王五':'wangwu','赵六':'zhaoliu','袁玉杰':'yuanyujie','不存在':'bucunzai'};
                    result={success:true,exact:url.searchParams.get('exact')==='1',truncated:false,suggested_account:spellings[query]||'',recipients:(people[query]||[]).map(p=>({...p,suggested_account:spellings[p.name]}))};
                }
                if(endpoint==='/recipients/email'){
                    const body=req.postDataJSON();emailWrites.push(body);
                    result={success:true,email:body.email,message:'邮箱已保存到 AD'};
                }
                if(endpoint==='/preview'){
                    const {password,...body}=req.postDataJSON();previewPassword=password;seen.push(body);
                    assert.equal(typeof password,'string');
                    assert(!('temporaryPassword' in body));
                    const current=body.template_id===domain.id?domain:template;
                    const cc=body.cc_email.split(',').map(address=>address.trim()).join(', ');
                    result={success:true,preview_token:'preview-token',subject:current.subject,recipient:body.to_email,cc_email:cc,text:`您好，${body.recipient_name}：\n\n${current.intro}\n\n登录账号：${body.account}\n\n初始密码：${password}\n\n密码说明：${current.password_instruction}\n\n${body.notes}`,html:''};
                    result.rows=current.domain_account?[
                        {text:`您好，${body.recipient_name}：`},
                        {text:current.intro},
                        {kind:'credential',label:'登录账号',value:body.account},
                        {kind:'credential',label:'初始密码',value:password},
                        {kind:'guidance',label:'密码说明',value:current.password_instruction},
                        {kind:'section',text:'公司 Wi-Fi'},
                        ...Object.entries(wifi).map(([label,value])=>({kind:'wifi',label,value})),
                    ]:[{text:result.text},{text:'使用教程：',href:body.tutorial_url,link_text:'查看配置教程'}];
                }
                if(endpoint==='/send'){
                    const body=req.postDataJSON();assert.equal(body.confirm_text,'SEND');assert.match(body.request_key,/^[a-f0-9-]{36}$/);
                    assert(!('provision_vpn' in body));
                    assert.equal(body.password,previewPassword);
                    const record={id:String(records.length+1),mode:body.mode,to_email:body.mode==='test'?body.test_email:seen.at(-1).to_email,
                        cc_email:body.mode==='test'?'':seen.at(-1).cc_email,operator:'admin',subject:template.subject,status:'submitted',message:'邮件服务器已接受；不代表收件人已收到或阅读',created_at:'2026-11-23T02:00:00Z',snapshot:{...template,...seen.at(-1),template_id:template.id,password_included:!!previewPassword}};
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
        assert.equal((await frame.locator('#temporaryPassword').inputValue()).length,12);
        assert(await frame.locator('#includePassword').isChecked());
        assert.equal(await frame.locator('#cc_email').inputValue(),'yuanyujie@shunhs.cn');
        const beforeGenerator=apiRequests;
        await frame.locator('#generatePassword').click();
        const generated=await frame.locator('#passwordTool').evaluate(()=>Array.from({length:40},()=>{
            generateTemporaryPassword();return document.getElementById('temporaryPassword').value;
        }));
        assert(generated.every(value=>value.length===12&&/^[A-Za-z0-9]+$/.test(value)&&/[A-Z]/.test(value)&&/[a-z]/.test(value)&&/[0-9]/.test(value)));
        assert.equal(new Set(generated).size,generated.length);
        await frame.locator('#passwordLength').fill('24');
        await frame.locator('#generatePassword').click();
        assert.equal((await frame.locator('#temporaryPassword').inputValue()).length,24);
        await frame.locator('#passwordDigits').uncheck();
        assert(/^[A-Za-z]+$/.test(await frame.locator('#temporaryPassword').inputValue()));
        await frame.locator('#passwordSymbols').check();
        assert(/[^A-Za-z0-9]/.test(await frame.locator('#temporaryPassword').inputValue()));
        for(const length of [8,64]){
            await frame.locator('#passwordLength').fill(String(length));
            await frame.locator('#generatePassword').click();
            assert.equal((await frame.locator('#temporaryPassword').inputValue()).length,length);
        }
        await frame.locator('#passwordLength').fill('7');
        await frame.locator('#generatePassword').click();
        assert((await frame.locator('#passwordToolStatus').textContent()).includes('8～64'));
        await frame.locator('#temporaryPassword').fill('CustomTestPassword2!');
        await frame.locator('#toggleTemporaryPassword').click();
        assert.equal(await frame.locator('#temporaryPassword').getAttribute('type'),'text');
        await frame.locator('#toggleTemporaryPassword').click();
        assert.equal(await frame.locator('#temporaryPassword').getAttribute('type'),'password');
        await frame.locator('#passwordTool').evaluate(()=>{
            window.originalCopy=document.execCommand;
            document.execCommand=command=>{if(command==='copy'){window.copiedPassword=document.querySelector('.copy-buffer').value;return true;}return false;};
        });
        await frame.locator('#copyTemporaryPassword').click();
        await frame.locator('#passwordToolStatus').filter({hasText:'已复制'}).waitFor();
        assert(await frame.locator('#passwordTool').evaluate(()=>window.copiedPassword==='CustomTestPassword2!'));
        assert.equal(await frame.locator('.copy-buffer').count(),0);
        await frame.locator('#passwordTool').evaluate(()=>{document.execCommand=window.originalCopy;delete window.copiedPassword;delete window.originalCopy;});
        assert.equal(apiRequests,beforeGenerator);
        await frame.locator('#employeeSearch').fill('袁玉杰');
        await frame.locator('#recipientHint').filter({hasText:'邮箱已自动填写'}).waitFor();
        assert.equal(await frame.locator('#account').inputValue(),'yuanyujie');
        await frame.locator('#account').fill('yuan.custom');
        assert.equal(await frame.locator('#account').inputValue(),'yuan.custom');
        await frame.locator('#employeeSearch').fill('张三');
        await frame.locator('#recipientHint').filter({hasText:'邮箱已自动填写'}).waitFor();
        assert.equal(await frame.locator('#to_email').inputValue(),'staff@example.test');
        await frame.locator('#searchEmployee').click();
        await frame.locator('.result').click();
        assert.equal(await frame.locator('#to_email').inputValue(),'staff@example.test');
        assert.equal(await frame.locator('#account').inputValue(),'zhangsan');
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
        assert.equal(await frame.locator('#account').inputValue(),'bucunzai');
        await frame.locator('#recipient_name').fill('赵六');
        await frame.locator('#recipientHint').filter({hasText:'多个同名域账号'}).waitFor();
        assert.equal(await frame.locator('#to_email').inputValue(),'');
        assert.equal(await frame.locator('.result').count(),2);
        await frame.locator('.result').nth(1).click();
        assert.equal(await frame.locator('#employee_id').inputValue(),'wfq000004');
        assert.equal(await frame.locator('#to_email').inputValue(),'b@example.test');
        await frame.locator('#recipient_name').fill('张三');
        await frame.locator('#recipientHint').filter({hasText:'邮箱已自动填写'}).waitFor();
        const notes='新增员工，请先安装客户端。\n<img src=x onerror="window.previewInjected=true">';
        const tutorialUrl='https://docs.example.test/vpn?space=123&file=456';
        await frame.locator('#tutorial_url').fill(tutorialUrl);
        await frame.locator('#notes').fill(notes);
        assert.equal(await frame.locator('#password_instruction').inputValue(),passwordNotice);
        assert(await frame.locator('#password_instruction').getAttribute('readonly')!==null);
        await frame.locator('#previewButton').click();
        await frame.locator('#previewDialog').waitFor({state:'visible'});
        assert((await frame.locator('#previewMailBody').innerText()).includes(notes));
        assert((await frame.locator('#previewMailBody').innerText()).includes('CustomTestPassword2!'));
        assert((await frame.locator('#previewMailBody').innerText()).includes(passwordNotice));
        const tutorial=frame.locator('#previewMailBody').getByRole('link',{name:'查看配置教程'});
        assert.equal(await tutorial.getAttribute('href'),tutorialUrl);
        assert.equal(await tutorial.getAttribute('title'),tutorialUrl);
        assert(!(await frame.locator('#previewMailBody').innerText()).includes(tutorialUrl));
        assert.equal(await frame.locator('#emailPreview iframe, #emailPreview img').count(),0);
        assert(await frame.locator('#previewMailBody').evaluate(()=>window.previewInjected===undefined));
        const bounds=await frame.locator('#emailPreview').boundingBox();
        assert(bounds.width>300&&bounds.height>200);
        assert.equal(await frame.locator('#previewCc').textContent(),'yuanyujie@shunhs.cn');
        assert.equal(previewPassword,'CustomTestPassword2!');
        assert(await frame.locator('#confirmSend').isDisabled());
        const routerLink=frame.getByRole('link',{name:'去路由器开通 VPN'});
        assert.equal(await routerLink.getAttribute('href'),routerUrl);
        assert.equal(await routerLink.getAttribute('rel'),'noopener noreferrer');
        const requestsBeforeJump=apiRequests;
        const [routerTab]=await Promise.all([page.context().waitForEvent('page'),routerLink.click()]);
        await routerTab.waitForURL(routerUrl);
        assert.equal(await routerTab.title(),'Mock router login');
        await routerTab.close();
        assert.equal(apiRequests,requestsBeforeJump);
        assert.equal(records.length,0);
        assert(await frame.locator('#previewDialog').isVisible());
        assert(await frame.locator('#confirmSend').isDisabled());
        await frame.locator('#testEmail').fill('it@example.test');
        await frame.locator('#sendTest').click();
        await frame.locator('#sendResult').filter({hasText:'测试邮件'}).waitFor();
        assert.equal(records.length,1);assert.equal(records[0].to_email,'it@example.test');
        await frame.locator('#confirmOpened').check();
        await frame.locator('#confirmSend').click();
        await frame.locator('#sendResult').filter({hasText:'邮件服务器已接受'}).waitFor();
        assert.equal(records.length,2);assert.equal(records[0].to_email,'staff@example.test');
        assert.equal(records[0].cc_email,'yuanyujie@shunhs.cn');
        assert.equal(records[1].cc_email,'');
        assert(!JSON.stringify(records).includes('CustomTestPassword2!'));
        await frame.locator('[data-close="previewDialog"]').first().click();
        await frame.locator('[data-tab="history"]').click();
        await frame.locator('#historyBody tr').nth(1).waitFor();
        assert.equal(await frame.locator('#historyBody tr').count(),2);
        await frame.locator('#historyBody .link-button').first().click();
        assert((await frame.locator('#deliveryDetail').textContent()).includes('zhangsan'));
        assert((await frame.locator('#deliveryDetail').textContent()).includes('不保存明文'));
        await frame.locator('[data-close="detailDialog"]').first().click();
        await frame.locator('[data-tab="templates"]').click();
        assert(await frame.locator('#domainWifiSettings').isHidden());
        const vpnHint='请妥善保管 VPN 密码，仅限本人使用。';
        await frame.locator('#templateForm [name=password_instruction]').fill(vpnHint);
        await frame.locator('#templateForm [name=name]').fill('公司 VPN 通知');
        await frame.locator('#templateForm [type=submit]').click();
        await frame.locator('#globalMessage').filter({hasText:'模板已保存'}).waitFor();
        assert.equal(template.name,'公司 VPN 通知');
        assert.equal(template.password_instruction,vpnHint);
        assert.equal(await frame.locator('#password_instruction').inputValue(),vpnHint);
        await frame.locator('#attachmentFile').setInputFiles({name:'company.ovpn',mimeType:'application/octet-stream',buffer:Buffer.from('client')});
        await frame.locator('#uploadFile').click();
        await frame.locator('#attachmentList a').waitFor();
        assert.equal(await frame.locator('#attachmentList a').textContent(),'company.ovpn');
        await frame.locator('#templateList').getByRole('button',{name:/域账号开通/}).click();
        assert(await frame.locator('#templateAttachments').isHidden());
        await frame.locator('#templateForm [name=password_instruction]').fill('登录 Windows 后按 Ctrl + Alt + Delete 更改密码。');
        await frame.locator('#templateForm [name=initial_password]').fill('NewTestDefault12');
        await frame.locator('#templateForm [name="WIFI-OA"]').fill(officeWifi);
        await frame.locator('#templateForm [name="WIFI-Mobile"]').fill(mobileWifi);
        await frame.locator('#templateForm [type=submit]').click();
        await page.waitForFunction(()=>document.querySelector('#accountNoticeFrame').contentDocument
            .querySelector('#globalMessage').textContent.includes('模板已保存'));
        assert.equal(await frame.locator('#templateForm [name="WIFI-OA"]').inputValue(),'');
        assert.equal(await frame.locator('#templateForm [name="WIFI-OA"]').getAttribute('placeholder'),'已保存，留空保留');
        await frame.locator('[data-tab="send"]').click();
        await frame.locator('#account').fill('vpn.manual');
        await frame.locator('#composeTemplate').selectOption('domain-1');
        await frame.locator('#temporaryPassword').filter({visible:true}).waitFor();
        await page.waitForFunction(()=>document.querySelector('#accountNoticeFrame').contentDocument
            .querySelector('#temporaryPassword').value==='NewTestDefault12');
        assert.equal(await frame.locator('#account').inputValue(),'wfq101755');
        assert(await frame.locator('#generatePassword').isHidden());
        assert(await frame.locator('#login_url').isHidden());
        assert.deepEqual((await frame.locator('#cc_email').inputValue()).split(',').map(address=>address.trim()),domainCc.split(', '));
        await frame.locator('#cc_email').fill(domainCc+',manager@example.test');
        await frame.locator('#temporaryPassword').fill('OneTimeTest12');
        await frame.locator('#previewButton').click();
        await frame.locator('#previewMailBody').filter({hasText:'OneTimeTest12'}).waitFor();
        assert.deepEqual(seen.at(-1).cc_email.split(',').map(address=>address.trim()),[...domainCc.split(', '),'manager@example.test']);
        assert.equal(await frame.locator('#previewCc').innerText(),domainCc+', manager@example.test');
        assert.deepEqual(await frame.locator('.mail-credentials strong').allTextContents(),['wfq101755','OneTimeTest12']);
        assert.match(await frame.locator('.mail-credentials').evaluate(el=>el.previousElementSibling.textContent),/您的账号已开通/);
        assert.deepEqual(await frame.locator('.mail-wifi-row strong').allTextContents(),[officeWifi,mobileWifi]);
        assert(await frame.locator('.mail-credentials').evaluate(el=>{
            const [account,password]=el.children;
            return account.getBoundingClientRect().bottom<=password.getBoundingClientRect().top;
        }));
        assert(await frame.locator('.mail-credentials').evaluate(el=>{
            const transparent='rgba(0, 0, 0, 0)';
            return getComputedStyle(el).backgroundColor===transparent &&
                Array.from(el.querySelectorAll('strong')).every(value=>
                    getComputedStyle(value).backgroundColor!==transparent &&
                    value.getBoundingClientRect().width<el.clientWidth);
        }));
        assert(await frame.locator('.mail-wifi-row').evaluateAll(rows=>rows.every(row=>{
            const [label,value]=row.children;
            return label.getBoundingClientRect().bottom<=value.getBoundingClientRect().top;
        })));
        assert((await frame.locator('#previewDialog').screenshot()).length>10000);
        await page.setViewportSize({width:390,height:844});
        assert(await frame.locator('.preview-frame').evaluate(el=>el.scrollWidth<=el.clientWidth));
        assert(await frame.locator('#previewScroll').evaluate(el=>el.scrollWidth<=el.clientWidth));
        assert.equal(await frame.locator('.preview-frame').evaluate(el=>getComputedStyle(el).overflowY),'visible');
        assert(await frame.locator('#confirmSend').isVisible());
        assert.equal(await frame.locator('.mail-credentials').evaluate(el=>getComputedStyle(el).gridTemplateColumns.split(' ').length),1);
        await page.setViewportSize({width:1440,height:1000});
        assert((await frame.locator('#previewMailBody').innerText()).includes('Ctrl + Alt + Delete'));
        assert(await frame.locator('#openVpnRouter').isHidden());
        await frame.locator('[data-close="previewDialog"]').first().click();
        await frame.locator('#composeTemplate').selectOption('template-1');
        assert.equal(await frame.locator('#account').inputValue(),'vpn.manual');
        assert.equal(await frame.locator('#temporaryPassword').inputValue(),'CustomTestPassword2!');
        assert(await frame.locator('#generatePassword').isVisible());
        await frame.locator('#previewButton').click();
        await frame.locator('#previewMailBody').filter({hasText:vpnHint}).waitFor();
        await frame.locator('[data-close="previewDialog"]').first().click();
        await frame.locator('#composeTemplate').selectOption('domain-1');
        await frame.locator('#recipient_name').fill('李四');
        await frame.locator('#recipientHint').filter({hasText:'尚未填写邮箱'}).waitFor();
        assert.equal(await frame.locator('#adRecipientDepartment').textContent(),'行政部');
        assert.equal(await frame.locator('#adRecipientEmail').textContent(),'未填写');
        assert(await frame.locator('#saveAdEmail').isDisabled());
        await frame.locator('#to_email').fill('corrected@example.test');
        await frame.locator('#previewButton').click();
        await frame.locator('#previewRecipient').filter({hasText:'corrected@example.test'}).waitFor();
        assert.equal(emailWrites.length,0);
        await frame.locator('[data-close="previewDialog"]').first().click();
        page.once('dialog', dialog=>dialog.accept());
        await frame.locator('#saveAdEmail').click();
        await frame.locator('#recipientHint').filter({hasText:'邮箱已保存到 AD'}).waitFor();
        assert.deepEqual(emailWrites,[{template_id:'domain-1',employee_id:'wfq000001',email:'corrected@example.test'}]);
        assert.equal(records.length,2);
        assert.equal(await frame.locator('#adRecipientEmail').textContent(),'corrected@example.test');
        assert(await frame.locator('#saveAdEmail').isHidden());
        await frame.locator('#composeTemplate').selectOption('template-1');
        const png=await page.screenshot();assert(png.length>10000);
        await page.reload();
        await frame.locator('#composeTemplate').waitFor();
        assert.equal((await frame.locator('#temporaryPassword').inputValue()).length,12);
        assert.equal(new URL(page.url()).hash,'#accountNotifications');
        await page.setViewportSize({width:390,height:844});
        await frame.locator('#composeTemplate').waitFor();
        assert(await frame.locator('#passwordTool').isVisible());
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
        console.log('PASS account notice: AD email save, manual recipients, CC defaults, preview and mobile layout');
    } finally {await browser.close();}
}
run().catch(e=>{console.error(e);process.exitCode=1;});
