// Browser regression fixtures only; never contacts an AD, SMB share, or device.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
  const browser = await chromium.launch({channel:'msedge',headless:true});
  let checks=0;
  try {
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[], requests=[];
    page.on('pageerror',error=>errors.push(error.message));
    let role='super_admin',expired=false,saves=0,extensions=0,policyPayload=null,validityPayload=null,mediaPayload=null,enrollmentExpires=1793433600,fixture=null,profilePayload=null,previewPayload=null;
    const settings={public_url:'http://ad-menu.test/pc-deploy',enabled:false,concurrency:2,ca_pem:''};
    const media={builders:[{id:'test-builder',name:'测试制作电脑',online:true,template_name:'WinPE',driver_name:'ASIX'}],builds:[]};
    const adHtml=fs.readFileSync(path.join(__dirname,'admin_manage.html'),'utf8');
    await page.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());
      requests.push(url.pathname);
      if(url.pathname==='/admin/manage') return route.fulfill({contentType:'text/html',body:adHtml});
      if(url.pathname==='/pc-deploy/') return route.fulfill({contentType:'text/html',
        headers:{'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'self'"},
        body:fs.readFileSync(path.join(__dirname,'pc_deploy/static/index.html'),'utf8')});
      if(url.pathname.startsWith('/pc-deploy/static/')){
        const name=path.basename(url.pathname);
        if(!['app.js','app.css'].includes(name)) return route.fulfill({status:404,body:''});
        return route.fulfill({contentType:name.endsWith('.js')?'application/javascript':'text/css',body:fs.readFileSync(path.join(__dirname,'pc_deploy/static',name),'utf8')});
      }
      if(url.pathname==='/api/admin/check') return route.fulfill({json:{logged_in:true,username:'test-admin',role,
        permissions:['view_user','view_dashboard','view_computers','view_logs','manage_admins','system_settings','password_policy']}});
      if(url.pathname==='/pc-deploy/api/session') return route.fulfill(expired ? {status:401,json:{error:'请先登录 AD 管理后台'}} : {json:{authenticated:true,username:'test-admin',csrf:'fixture-csrf',test_mode:true}});
      if(url.pathname==='/pc-deploy/api/profiles' && request.method()==='POST') {
        profilePayload=request.postDataJSON();
        return route.fulfill({json:{ok:true,id:'new-profile'}});
      }
      if(url.pathname==='/pc-deploy/api/jobs/preview') {
        previewPayload=request.postDataJSON();
        const disk=fixture.devices[0].disks[0];
        return route.fulfill({json:{id:'preview-1',profile:'WIM preserve',source:'Custom WIM',warning:'只格式化所选 Windows 分区，保留其他分区，更新同盘 EFI。',
          targets:[{serial:'TEST-LAPTOP',boot_code:'ABC123',disk,partitions:{windows:disk.partitions[0]}}]}});
      }
      if(url.pathname==='/pc-deploy/api/enrollments/'+'a'.repeat(64)+'/extend'){
        assert.equal(request.method(),'POST');
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        extensions++;
        return route.fulfill({json:{ok:true,expires_at:1793952000}});
      }
      if(url.pathname==='/pc-deploy/api/enrollment-policy'){
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        policyPayload=request.postDataJSON();settings.enrollment_days=policyPayload.days;
        return route.fulfill({json:{ok:true}});
      }
      if(url.pathname==='/pc-deploy/api/enrollments/'+'a'.repeat(64)+'/validity'){
        validityPayload=request.postDataJSON();
        enrollmentExpires=validityPayload.days===null?null:1793347200+validityPayload.days*86400;
        return route.fulfill({json:{ok:true,expires_at:enrollmentExpires}});
      }
      if(url.pathname==='/pc-deploy/api/local-media/package'){
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        mediaPayload=request.postDataJSON();
        return route.fulfill({contentType:'application/zip',body:Buffer.from('PK-test-local-package')});
      }
      if(url.pathname==='/pc-deploy/api/media'){
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        mediaPayload=request.postDataJSON();
        media.builds=[{id:'test-media',builder_id:'test-builder',state:'ready',registration_only:mediaPayload.registration_only,
          created:1793347200,updated:1793347200,stage:'制作完成',enrollment_id:'a'.repeat(64),sha256:'b'.repeat(64)}];
        return route.fulfill({json:{ok:true,id:'test-media'}});
      }
      if(url.pathname==='/pc-deploy/api/dashboard') return route.fulfill({json:fixture||{devices:[],sources:[],profiles:[],jobs:[],events:[],settings,
        boot_files:{wimboot:false,'boot.wim':false,BCD:false,'boot.sdi':false},enrollments:[{id:'a'.repeat(64),expires_at:enrollmentExpires,uses:1}],media,server_time:1793347200}});
      if(url.pathname==='/pc-deploy/api/settings'){
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        const payload=request.postDataJSON();
        assert.equal(payload.public_url,'http://192.0.2.10/pc-deploy');
        assert.equal(payload.enabled,false);
        Object.assign(settings,payload);saves++;
        return route.fulfill({json:{ok:true}});
      }
      if(url.pathname.startsWith('/pc-deploy/')) return route.fulfill({status:404,json:{error:'Unused deployment fixture endpoint'}});
      return route.fulfill({json:{success:false,message:'Unused AD fixture endpoint'}});
    });
    await page.goto('http://ad-menu.test/admin/manage');
    await page.locator('#pcDeployGroup').waitFor({state:'visible'});
    const names=(await page.locator('.sidebar .menu-item').allTextContents()).map(s=>s.replace(/[▸▾]/g,'').trim());
    assert.deepEqual(names,['数据概览','AD用户管理','计算机管理','域密码策略','组策略管理','密码到期提醒','日志中心','审批中心','用户中心','登录审计','系统设置','备份恢复','电脑装机']);checks++;
    assert.equal(requests.filter(p=>p.startsWith('/pc-deploy/')).length,0);checks++;
    assert.ok(await page.locator('#pcDeploySubmenu').isHidden());checks++;
    await page.locator('#pcDeployMenu').click();
    await page.locator('#pcDeploySubmenu').waitFor({state:'visible'});
    assert.equal(page.url(),'http://ad-menu.test/admin/manage');checks++;
    assert.deepEqual(await page.locator('[data-deploy-view]').allTextContents(),['设备工作台','安装源','装机方案','任务记录','启动与设置']);checks++;
    const frame=page.frameLocator('#pcDeployFrame');
    await frame.locator('#workspace:not([hidden])').waitFor();
    assert.ok(await frame.locator('.sidebar').isHidden());checks++;
    assert.ok(await frame.locator('.back-to-ad').isHidden());checks++;
    assert.equal(await frame.locator('#auth-password').count(),0);checks++;
    const firstParent=await page.locator('#pcDeployMenu').boundingBox();
    const firstChild=await page.locator('[data-deploy-view=devices]').boundingBox();
    assert.ok(firstChild.x>firstParent.x);checks++;
    for(const [view,title] of Object.entries({devices:'设备工作台',sources:'安装源',profiles:'装机方案',jobs:'任务记录',settings:'启动与设置'})){
      await page.locator(`[data-deploy-view=${view}]`).click();
      await page.waitForFunction(t=>document.getElementById('pcDeployFrame').contentDocument?.getElementById('page-title')?.textContent===t,title);
      assert.equal(page.url(),'http://ad-menu.test/admin/manage');checks++;
      assert.ok(await page.locator(`[data-deploy-view=${view}]`).evaluate(e=>e.classList.contains('active')));checks++;
    }
    assert.ok((await frame.locator('#page-content').textContent()).includes('登记凭据有效期 7 天'));checks++;
    await frame.locator('[data-action=extend-enrollment]').click();
    await page.waitForFunction(()=>document.getElementById('pcDeployFrame').contentDocument?.getElementById('toast')?.textContent.startsWith('登记包有效期：'));
    assert.equal(extensions,1);checks++;
    await frame.locator('#public-url').fill('http://192.0.2.10/pc-deploy');
    await frame.locator('#settings-form [type=submit]').click();
    await page.waitForFunction(()=>document.getElementById('pcDeployFrame').contentDocument?.getElementById('toast')?.textContent==='设置已保存');
    assert.equal(saves,1);checks++;
    await frame.locator('#enrollment-policy-form [name=validity_mode]').selectOption('never');
    assert.ok(await frame.locator('#enrollment-policy-form [name=days]').isDisabled());checks++;
    await frame.locator('#enrollment-policy-form [type=submit]').click();
    await page.waitForFunction(()=>document.getElementById('pcDeployFrame').contentDocument?.querySelector('#enrollment-policy-form [name=validity_mode]')?.value==='never');
    assert.deepEqual(policyPayload,{days:null});checks++;
    await frame.locator('[data-action=edit-enrollment]').click();
    await frame.locator('#enrollment-validity-form [name=days]').fill('21');
    await frame.locator('#enrollment-validity-form [type=submit]').click();
    await frame.locator('#modal').waitFor({state:'hidden'});
    assert.deepEqual(validityPayload,{days:21});checks++;
    await frame.locator('[data-action=edit-enrollment]').click();
    await frame.locator('#enrollment-validity-form [name=validity_mode]').selectOption('never');
    await frame.locator('#enrollment-validity-form [type=submit]').click();
    await frame.locator('#modal').waitFor({state:'hidden'});
    assert.deepEqual(validityPayload,{days:null});checks++;
    assert.ok((await frame.locator('#page-content').textContent()).includes('永不过期'));checks++;
    assert.equal(await frame.locator('#media-form [name=builder_id]').count(),0);checks++;
    assert.equal(await frame.locator('[data-action=builder-package]').count(),0);checks++;
    assert.ok(!(await frame.locator('#media-panel').textContent()).includes('离线'));checks++;
    await frame.locator('#media-form [name=mode]').selectOption('registration');
    await frame.locator('#media-form [name=include_drivers]').uncheck();
    const [download]=await Promise.all([page.waitForEvent('download'),frame.locator('#media-form [type=submit]').click()]);
    assert.equal(download.suggestedFilename(),'pc-deploy-local-build.zip');checks++;
    assert.deepEqual(mediaPayload,{registration_only:true,include_drivers:false});checks++;
    assert.ok(!requests.includes('/pc-deploy/api/builders/package'));checks++;
    assert.ok(!requests.includes('/pc-deploy/api/media'));checks++;

    await page.evaluate(()=>window.dispatchEvent(new MessageEvent('message',{origin:location.origin,source:window,data:{type:'pc-deploy:view',view:'jobs'}})));
    assert.ok(await page.locator('[data-deploy-view=settings]').evaluate(e=>e.classList.contains('active')));checks++;
    await page.evaluate(()=>document.getElementById('pcDeployFrame').contentWindow.dispatchEvent(new MessageEvent('message',{origin:'https://untrusted.test',source:window,data:{type:'pc-deploy:navigate',view:'jobs'}})));
    assert.equal(await frame.locator('#page-title').textContent(),'启动与设置');checks++;
    await page.locator('#pcDeployMenu').click();
    assert.ok(await page.locator('#pcDeploySubmenu').isHidden());checks++;
    await page.locator('#pcDeployMenu').click();
    assert.ok(await page.locator('#pcDeploySubmenu').isVisible());checks++;
    await page.locator('[data-page=computers]').click();
    await page.waitForFunction(()=>!document.getElementById('pcDeployFrame').hasAttribute('src'));
    assert.ok(await page.locator('#page-computers').isVisible());checks++;
    assert.ok(await page.locator('#page-pcDeploy').isHidden());checks++;
    await page.locator('[data-deploy-view=sources]').click();
    await frame.locator('#page-title').filter({hasText:'安装源'}).waitFor();
    assert.equal(await frame.getByText('下载检测脚本 ↓',{exact:true}).getAttribute('href'),'/pc-deploy/api/tools/inspect-source');checks++;
    assert.ok(!requests.some(p=>['/api/session','/api/dashboard','/api/settings','/api/login','/api/setup'].includes(p)));checks++;
    for(const deniedRole of ['admin','readonly']){
      role=deniedRole;
      await page.reload();
      await page.waitForFunction(text=>document.getElementById('loginUser').textContent.includes(text),deniedRole==='admin'?'（管理员）':'（只读用户）');
      assert.ok(await page.locator('#pcDeployGroup').isHidden());checks++;
      await page.evaluate(()=>openPcDeploy('devices'));
      assert.equal(await page.locator('#pcDeployFrame').getAttribute('src'),null);checks++;
    }
    role='super_admin';expired=true;
    await page.reload();
    await page.locator('#pcDeployGroup').waitFor({state:'visible'});
    await page.locator('#pcDeployMenu').click();
    await frame.locator('#auth:not([hidden])').waitFor();
    assert.equal(await frame.getByText('前往 AD 后台登录',{exact:true}).getAttribute('target'),'_top');checks++;
    expired=false;
    await page.setViewportSize({width:390,height:844});
    await page.reload();
    await page.locator('#pcDeployGroup').waitFor({state:'visible'});
    await page.locator('#pcDeployMenu').click();
    await frame.locator('#workspace:not([hidden])').waitFor();
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));checks++;
    const box=await page.locator('#pcDeployFrame').boundingBox();
    assert.ok(box.x>=0&&box.x+box.width<=391);checks++;
    await page.goto('http://ad-menu.test/pc-deploy/');
    await page.locator('#workspace:not([hidden])').waitFor();
    assert.ok(await page.locator('.sidebar').isVisible());checks++;

    // WIM form/device fixtures; still intercept every request and keep real dispatch disabled.
    const sourceBase={images:[{index:1,name:'Windows 11 Pro',build:26100}],family:'windows11',
      path:'\\\\fixture-files\\reminst',image_sha256:'a'.repeat(64),smb_user:'FIXTURE\\read'};
    const disk={number:7,key:'disk-7',serial:'SSD-7',unique_id:'HW-7',model:'Fixture SSD',bus:'NVMe',
      size_bytes:512*1024**3,eligible:true,partitions:[{number:3,key:'partition-3',guid:'33333333-3333-3333-3333-333333333333',
        gpt_type:'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',filesystem:'NTFS',windows:true,offset:1024**3,size_bytes:128*1024**3}]};
    fixture={devices:[{id:'laptop-1',serial:'TEST-LAPTOP',model:'Fixture Laptop',firmware:'UEFI',architecture:'amd64',
      online:true,consumed:false,tpm2:true,secure_boot:true,macs:['02:00:00:00:00:01'],disks:[disk],
      boot_code:'ABC123',last_seen:1793347200}],sources:[{...sourceBase,id:'setup-source',kind:'setup',name:'Original Setup'},
      {...sourceBase,id:'wim-source',kind:'wim',name:'Custom WIM',image_file:'win11.wim'}],
      profiles:[{id:'setup-profile',name:'Original Setup profile',source_id:'setup-source',image_index:1,
        system_gib:128,username:'ITSetup',computer_prefix:'PC'},
        {id:'wim-profile',name:'WIM preserve',source_id:'wim-source',image_index:1,system_gib:0,
          disk_mode:'system_partition',preserve_image_settings:true,username:'',computer_prefix:''}],
      jobs:[],events:[],settings,boot_files:{},server_time:1793347200};
    await page.setViewportSize({width:1440,height:1000});
    await page.reload();
    await page.locator('#workspace:not([hidden])').waitFor();
    await page.locator('[data-view=profiles]').click();
    await page.locator('[data-action=new-profile]').click();
    assert.ok(await page.locator('#profile-form [name=username]').isVisible());checks++;
    assert.ok(await page.locator('#profile-form [name=password]').evaluate(e=>e.required));checks++;
    await page.locator('#source-choice').selectOption('wim-source');
    assert.ok(await page.locator('#profile-form [name=username]').isDisabled());checks++;
    assert.ok(await page.locator('#profile-form [name=password]').isHidden());checks++;
    assert.ok(await page.locator('#wim-profile-help').isVisible());checks++;
    await page.locator('#disk-mode').selectOption('system_partition');
    assert.ok(await page.locator('#profile-form [name=system_gib]').isDisabled());checks++;
    await page.locator('#profile-form [name=name]').fill('Custom restore');
    await page.locator('#profile-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    assert.equal(profilePayload.disk_mode,'system_partition');checks++;
    assert.equal(profilePayload.system_gib,0);checks++;
    assert.ok(!('password' in profilePayload)&&!('username' in profilePayload)&&!('product_key' in profilePayload));checks++;
    await page.locator('[data-view=devices]').click();
    await page.locator('#profile-choice').selectOption('wim-profile');
    await page.locator('[data-disk=laptop-1]').selectOption('disk-7');
    await page.locator('[data-partition=laptop-1]').selectOption('partition-3');
    await page.locator('[data-device=laptop-1]').check();
    await page.locator('#preview-button').click();
    await page.locator('#modal[open]').waitFor();
    assert.equal(previewPayload.targets[0].partition_key,'partition-3');checks++;
    assert.equal(previewPayload.targets[0].disk_key,'disk-7');checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('只格式化分区 3'));checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('所选 Windows 分区数据可删除'));checks++;
    assert.ok(await page.locator('#commit-form [type=submit]').isDisabled());checks++;
    await page.locator('#commit-form [data-action=close]').click();
    await page.locator('#profile-choice').selectOption('setup-profile');
    assert.equal(await page.locator('[data-partition]').count(),0);checks++;
    await page.locator('[data-view=profiles]').click();
    await page.locator('[data-action=edit-profile][data-id=setup-profile]').click();
    assert.ok(await page.locator('#profile-form [name=username]').isEnabled());checks++;
    assert.ok(await page.locator('#disk-mode').isHidden());checks++;
    await page.locator('#profile-form [data-action=close]').click();

    // Failure output is displayed as literal multiline text, including untrusted tool output.
    const failureText='目标磁盘或分区复核、准备失败，已停止\n客户端错误详情：\nError: Access denied\nCommand: Add-PartitionAccessPath\nScript line: 372\n<img src=x onerror="window.logInjected=true">\n'+'x'.repeat(1000);
    fixture.events=[{id:1,kind:'failed',created:1793347200,message:failureText}];
    await page.locator('[data-view=jobs]').click();
    const failureLog=page.locator('.log span').first();
    assert.equal(await failureLog.textContent(),failureText);checks++;
    assert.equal(await failureLog.evaluate(el=>getComputedStyle(el).whiteSpace),'pre-wrap');checks++;
    assert.equal(await page.locator('.log img').count(),0);checks++;
    assert.equal(await page.evaluate(()=>window.logInjected),undefined);checks++;
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));checks++;

    fixture.jobs=[{id:'progress-job',device_id:'laptop-1',model:'Fixture Laptop',serial:'TEST-LAPTOP',disk,
      profile:'WIM preserve',state:'installing',created:1793347200,updated:1793347300,stale:false,
      progress:{stage:'applying',percent:37,updated:1793347300}}];
    await page.setViewportSize({width:1440,height:1000});
    await page.locator('#refresh').click();
    const liveProgress=page.locator('.job-progress');
    await liveProgress.waitFor();
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),'37');checks++;
    assert.ok((await liveProgress.textContent()).includes('37%'));checks++;
    fixture.jobs[0].progress.percent=100;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress progress')?.getAttribute('value')==='100');
    assert.ok(!(await liveProgress.textContent()).includes('安装后系统已回报'));checks++;
    fixture.jobs[0].progress={stage:'boot_files',percent:null,updated:1793347400};
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress')?.textContent.includes('配置 UEFI'));
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),null);checks++;
    fixture.jobs[0].state='awaiting_report';
    fixture.jobs[0].progress.stage='awaiting_report';
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress')?.textContent.includes('等待新系统回报'));
    assert.ok((await liveProgress.textContent()).includes('最后回报'));checks++;
    fixture.jobs[0].state='completed';
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress')?.textContent.includes('安装后系统已回报'));
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),'100');checks++;
    fixture.jobs[0].state='failed';
    fixture.jobs[0].progress={stage:'applying',percent:43,updated:1793347400};
    await page.locator('#refresh').click();
    await page.locator('.job-progress.stopped').waitFor();
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),'43');checks++;
    assert.ok((await liveProgress.textContent()).includes('已停止'));checks++;
    fixture.jobs[0].progress=null;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>!document.querySelector('.job-progress'));
    assert.equal(await page.locator('.job-progress').count(),0);checks++;
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));checks++;

    assert.deepEqual(errors,[]);checks++;
    console.log(`${checks} nested menu, embedded page, HTTP form, role, message origin, lifecycle, mobile and WIM restore UI checks passed. No live system contacted.`);
  }finally{await browser.close();}
}
run().catch(error=>{console.error(error);process.exitCode=1;});
