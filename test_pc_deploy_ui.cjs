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
    const jobLogEvents={};let releasePayload=null,jobLogError=false,jobLogGate=null,dashboardGate=null,jobReviewPayload=null;
    const settings={public_url:'http://ad-menu.test/pc-deploy',enabled:false,concurrency:2,ca_pem:'',http_allowed:true};
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
      if(/^\/pc-deploy\/api\/profiles(?:\/[^/]+)?$/.test(url.pathname) && ['POST','PUT'].includes(request.method())) {
        profilePayload=request.postDataJSON();
        return route.fulfill({json:{ok:true,id:'new-profile'}});
      }
      if(url.pathname==='/pc-deploy/api/jobs/domain-join/release') {
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        releasePayload=request.postDataJSON();
        for(const id of releasePayload.job_ids){
          const job=fixture.jobs.find(job=>job.id===id);
          job.domain_join.released_at=fixture.server_time;job.updated=fixture.server_time;
        }
        return route.fulfill({json:{ok:true,count:releasePayload.job_ids.length}});
      }
      if(url.pathname==='/pc-deploy/api/jobs/preview') {
        previewPayload=request.postDataJSON();
        const profile=fixture.profiles.find(p=>p.id===previewPayload.profile_id);
        const previewNames=new Set();
        const targets=previewPayload.targets.map(t=>{const device=fixture.devices.find(d=>d.id===t.device_id),disk=device.disks[0];
          let name=t.employee_id;
          if(/^\d+$/.test(name)||previewNames.has(name))name+='A';
          previewNames.add(name);
          return {serial:device.serial,boot_code:device.boot_code,disk,partitions:{windows:disk.partitions[0]},employee_id:t.employee_id,computer_name:name};});
        return route.fulfill({json:{id:'preview-1',profile:'WIM preserve',source:'Custom WIM',warning:'只格式化所选 Windows 分区，保留其他分区，更新同盘 EFI。',
          domain_join:profile.domain_join,targets}});
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


      if(/^\/pc-deploy\/api\/jobs\/[^/]+\/review$/.test(url.pathname)){
        assert.equal(request.method(),'POST');
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        jobReviewPayload=request.postDataJSON();
        const id=decodeURIComponent(url.pathname.split('/')[4]),job=fixture.jobs.find(j=>j.id===id);
        job.review={...jobReviewPayload,operator:'test-admin',reviewed_at:fixture.server_time};
        (jobLogEvents[id] ||= []).unshift({id:1000,job_id:id,kind:'review',created:fixture.server_time,message:'人工核对：'+jobReviewPayload.note});
        return route.fulfill({json:{ok:true}});
      }
      if(/^\/pc-deploy\/api\/jobs\/[^/]+\/events$/.test(url.pathname)){
        if(jobLogError) return route.fulfill({status:503,json:{error:'fixture log unavailable'}});
        const id=decodeURIComponent(url.pathname.split('/')[4]);
        const job=fixture?.jobs.find(j=>j.id===id);
        if(!job) return route.fulfill({status:400,json:{error:'任务不存在'}});
        const before=url.searchParams.has('before')?Number(url.searchParams.get('before')):Infinity;
        const events=(jobLogEvents[id]||[]).filter(e=>e.id<before).sort((a,b)=>b.id-a.id);
        if(jobLogGate){const gate=jobLogGate;jobLogGate=null;await gate;}
        return route.fulfill({json:{job,events:events.slice(0,100),next_before:events.length>100?events[99].id:null,server_time:fixture.server_time}});
      }
      if(url.pathname==='/pc-deploy/api/dashboard') {
        const snapshot=JSON.parse(JSON.stringify(fixture||{devices:[],sources:[],profiles:[],jobs:[],events:[],settings,
          boot_files:{wimboot:false,'boot.wim':false,BCD:false,'boot.sdi':false},enrollments:[{id:'a'.repeat(64),expires_at:enrollmentExpires,uses:1}],media,server_time:1793347200}));
        if(dashboardGate){const gate=dashboardGate;dashboardGate=null;await gate;}
        return route.fulfill({json:snapshot});
      }
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
    const failureLog=page.locator('.log-message').first();
    assert.equal(await failureLog.textContent(),failureText);checks++;
    assert.equal(await failureLog.evaluate(el=>getComputedStyle(el).whiteSpace),'pre-wrap');checks++;
    assert.equal(await page.locator('.log img').count(),0);checks++;
    assert.equal(await page.evaluate(()=>window.logInjected),undefined);checks++;
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));checks++;

    fixture.jobs=[{id:'progress-job',device_id:'laptop-1',model:'Fixture Laptop',serial:'TEST-LAPTOP',disk,
      profile:'WIM preserve',kind:'wim',state:'installing',created:1793345800,started_at:1793346000,finished_at:null,updated:1793347300,stale:false,
      progress:{stage:'applying',percent:37,updated:1793347300}}];
    await page.setViewportSize({width:1440,height:1000});
    await page.locator('#refresh').click();
    const liveProgress=page.locator('.job-progress');
    await liveProgress.waitFor();
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),'37');checks++;
    assert.ok((await liveProgress.textContent()).includes('37%'));checks++;
    assert.equal(await page.locator('[data-action=reconcile-job]').count(),0);checks++;
    fixture.jobs[0].stale=true;
    await page.locator('#refresh').click();
    await page.getByRole('button',{name:'结束异常记录',exact:true}).waitFor();
    assert.equal(await page.locator('[data-action=reconcile-job]').count(),1);checks++;
    fixture.jobs[0].stale=false;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>!document.querySelector('[data-action=reconcile-job]'));

    // Real task time is independent of the browser clock and stops at the recorded finish.
    assert.ok((await page.locator('.job-timing').textContent()).includes('安装用时 20分'));checks++;
    assert.ok(await page.locator('.duration-warning').isVisible());checks++;
    const firstElapsed=await page.locator('[data-job-timer]').textContent();
    await page.waitForFunction(text=>document.querySelector('[data-job-timer]')?.textContent!==text,firstElapsed);
    assert.ok((await page.locator('[data-job-timer]').textContent()).startsWith('安装用时 '));checks++;
    await page.evaluate(()=>{window.savedProgress=document.querySelector('.job-progress progress');});
    fixture.jobs[0].progress.percent=100;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress progress')?.getAttribute('value')==='100');
    assert.ok(!(await liveProgress.textContent()).includes('安装后系统已回报'));checks++;
    assert.ok(await page.evaluate(()=>window.savedProgress===document.querySelector('.job-progress progress')));checks++;
    fixture.jobs[0].progress={stage:'boot_files',percent:null,updated:1793347400};
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress')?.textContent.includes('配置 UEFI'));
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),'100');checks++;
    fixture.jobs[0].state='awaiting_report';
    fixture.jobs[0].progress.stage='awaiting_report';
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress')?.textContent.includes('等待新系统回报'));
    assert.ok((await liveProgress.textContent()).includes('最后回报'));checks++;
    fixture.jobs[0].state='completed';
    fixture.jobs[0].finished_at=1793346610;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress')?.textContent.includes('安装后系统已回报'));
    assert.equal(await liveProgress.locator('progress').getAttribute('value'),'100');checks++;
    assert.equal(await page.locator('[data-job-timer]').textContent(),'安装耗时 10分10秒');checks++;
    await page.evaluate(()=>new Promise(resolve=>setTimeout(resolve,1100)));
    assert.equal(await page.locator('[data-job-timer]').textContent(),'安装耗时 10分10秒');checks++;
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



    fixture.jobs[0].state='installing';
    fixture.jobs[0].progress={stage:'applying',percent:null,updated:1793347200};
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-progress progress')?.getAttribute('value')==='0');
    assert.ok((await page.locator('.job-progress').textContent()).includes('等待真实进度'));checks++;
    assert.equal(await page.locator('progress:indeterminate').count(),0);checks++;
    fixture.jobs[0].progress=null;
    fixture.jobs[0].state='failed';

    // A row opens only its own durable task history, including older attempts on the same PC.
    fixture.events=[{id:900,job_id:null,kind:'source',created:1793347200,message:'platform source saved'}];
    fixture.jobs=[{...fixture.jobs[0],id:'progress-job',state:'failed'},
      {...fixture.jobs[0],id:'older-job',state:'completed',created:1793347100}];
    jobLogEvents['progress-job']=[{id:306,job_id:'progress-job',kind:'failed',created:1793347400,message:failureText},
      ...Array.from({length:205},(_,i)=>({id:i+1,job_id:'progress-job',kind:'installing',created:1793347200+i,message:'task step '+i}))];
    jobLogEvents['older-job']=[];
    await page.setViewportSize({width:1440,height:1000});
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelectorAll('[data-action=job-logs]').length===2);
    assert.equal(await page.locator('[data-action=job-logs]').count(),2);checks++;
    assert.ok((await page.locator('#page-content').textContent()).includes('平台操作记录'));checks++;
    assert.ok(!(await page.locator('#page-content').textContent()).includes('Access denied'));checks++;
    const rowColors=await page.locator('.job-row>td:nth-child(3)>.badge').evaluateAll(els=>els.map(el=>getComputedStyle(el).color));
    assert.notEqual(rowColors[0],rowColors[1]);checks++;
    await page.locator('[data-action=job-logs][data-id=progress-job]').click();
    await page.locator('#job-log .log').first().waitFor();
    assert.ok((await page.locator('#job-log').textContent()).includes('TEST-LAPTOP'));checks++;
    assert.ok((await page.locator('#job-log').textContent()).includes('progress-job'));checks++;
    assert.equal(await page.locator('#job-log .log').count(),100);checks++;
    assert.equal(await page.locator('#job-log .log-message').first().textContent(),failureText);checks++;
    assert.equal(await page.locator('#job-log .log img').count(),0);checks++;
    assert.equal(await page.locator('#job-log .log-message').first().evaluate(el=>getComputedStyle(el).whiteSpace),'pre-wrap');checks++;
    assert.notEqual(await page.locator('#job-log .event-bad .badge').first().evaluate(el=>getComputedStyle(el).color),
      await page.locator('#job-log .event-blue .badge').first().evaluate(el=>getComputedStyle(el).color));checks++;
    await page.locator('[data-action=older-job-logs]').click();
    await page.getByText('正在查看历史记录',{exact:true}).waitFor();
    assert.ok(!(await page.locator('#job-log').textContent()).includes('Access denied'));checks++;
    await page.locator('[data-action=older-job-logs]').click();
    await page.locator('[data-action=older-job-logs]').waitFor({state:'visible'});
    await page.waitForFunction(()=>document.querySelector('#job-log .log-message:last-child') && [...document.querySelectorAll('#job-log .log-message')].some(el=>el.textContent==='task step 0'));
    assert.ok(await page.locator('[data-action=older-job-logs]').isDisabled());checks++;
    await page.locator('[data-action=refresh-job-logs]').click();
    await page.locator('#job-log .event-bad').waitFor();
    assert.equal(await page.locator('#job-log .log').count(),100);checks++;
    jobLogError=true;
    await page.locator('[data-action=refresh-job-logs]').click();
    await page.locator('#job-log-error:not([hidden])').waitFor();
    assert.ok((await page.locator('#job-log-error').textContent()).includes('fixture log unavailable'));checks++;
    assert.equal(await page.locator('#job-log .log-message').first().textContent(),failureText);checks++;
    jobLogError=false;
    await page.locator('[data-action=refresh-job-logs]').click();
    await page.locator('#job-log-error').waitFor({state:'hidden'});
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.locator('#modal').evaluate(el=>el.scrollWidth<=el.clientWidth+1));checks++;
    await page.locator('#close-modal').click();
    await page.locator('[data-action=job-logs][data-id=older-job]').click();
    await page.getByText('此任务暂无操作记录',{exact:true}).waitFor();
    assert.ok(!(await page.locator('#job-log').textContent()).includes('Access denied'));checks++;
    await page.locator('#close-modal').click();

    // The live log and its table row must share a snapshot, even while the modal is open.
    Object.assign(fixture.jobs[0],{state:'installing',updated:1793347500,
      progress:{stage:'applying',percent:95,updated:1793347500}});
    fixture.server_time=1793347510;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-row .job-progress progress')?.value===95);
    await page.evaluate(()=>{window.savedTableProgress=document.querySelector('.job-row .job-progress progress');});
    await page.locator('[data-action=job-logs][data-id=progress-job]').click();
    await page.locator('#job-log .event-bad').waitFor();
    Object.assign(fixture.jobs[0],{state:'awaiting_report',updated:1793347600,
      progress:{stage:'awaiting_report',percent:null,updated:1793347600}});
    fixture.server_time=1793347610;
    jobLogEvents['progress-job'].unshift({id:400,job_id:'progress-job',kind:'awaiting_report',created:1793347600,message:'automatic task update'});
    await page.getByText('automatic task update',{exact:true}).waitFor({timeout:12000});
    assert.equal(await page.locator('#job-log .log-message').first().textContent(),'automatic task update');checks++;
    assert.equal(await page.locator('.job-row').first().getAttribute('data-state'),'awaiting_report');checks++;
    assert.equal(await page.locator('.job-row .job-progress progress').getAttribute('value'),'100');checks++;
    assert.equal(await page.locator('.job-row .job-progress').first().textContent(),await page.locator('#job-log .job-progress').textContent());checks++;
    assert.equal(await page.locator('#job-log .badge').first().textContent(),'等待安装后回报');checks++;
    assert.ok(await page.evaluate(()=>window.savedTableProgress===document.querySelector('.job-row .job-progress progress')));checks++;

    // An older dashboard response arriving after a newer log must not roll the task back.
    let releaseDashboard;
    dashboardGate=new Promise(resolve=>{releaseDashboard=resolve;});
    const pendingDashboard=page.waitForRequest(r=>r.url().endsWith('/api/dashboard'));
    const delayedRefresh=page.evaluate(()=>refresh());
    await pendingDashboard;
    Object.assign(fixture.jobs[0],{state:'completed',updated:1793347700,finished_at:1793347700});
    fixture.server_time=1793347710;
    jobLogEvents['progress-job'].unshift({id:401,job_id:'progress-job',kind:'completed',created:1793347700,message:'installation acknowledged'});
    await page.locator('[data-action=refresh-job-logs]').click();
    await page.getByText('installation acknowledged',{exact:true}).waitFor();
    assert.equal(await page.locator('.job-row').first().getAttribute('data-state'),'completed');checks++;
    assert.equal(await page.locator('.job-row [data-job-timer]').first().textContent(),await page.locator('#job-log [data-job-timer]').textContent());checks++;
    assert.ok((await page.locator('.job-row [data-job-timer]').first().textContent()).startsWith('安装耗时 '));checks++;
    releaseDashboard();
    await delayedRefresh;
    assert.equal(await page.locator('.job-row').first().getAttribute('data-state'),'completed');checks++;
    assert.equal(await page.locator('#job-log .badge').first().textContent(),'安装后已回报');checks++;
    assert.equal(await page.locator('.job-row .job-progress').first().textContent(),await page.locator('#job-log .job-progress').textContent());checks++;

    // Closing the log immediately refreshes other rows, without waiting for the poll timer.
    Object.assign(fixture.jobs[1],{state:'failed',updated:1793347800});
    fixture.server_time=1793347810;
    await Promise.all([page.waitForResponse(r=>r.url().endsWith('/api/dashboard'),{timeout:2500}),page.locator('#close-modal').click()]);
    await page.waitForFunction(()=>document.querySelectorAll('.job-row')[1]?.dataset.state==='failed');
    assert.equal(await page.locator('.job-row').nth(1).getAttribute('data-state'),'failed');checks++;

    // Late requests from a closed task must not replace another task's dialog.
    let releaseLog;
    jobLogGate=new Promise(resolve=>{releaseLog=resolve;});
    const pendingLog=page.waitForRequest(r=>r.url().includes('/jobs/older-job/events'));
    await page.locator('[data-action=job-logs][data-id=older-job]').click();
    await pendingLog;
    await page.locator('#close-modal').click();
    await page.locator('[data-action=job-logs][data-id=progress-job]').click();
    await page.getByText('automatic task update',{exact:true}).waitFor();
    const lateLog=page.waitForResponse(r=>r.url().includes('/jobs/older-job/events'));
    releaseLog();
    await lateLog;
    assert.ok((await page.locator('#job-log').textContent()).includes('progress-job'));checks++;
    assert.equal(await page.evaluate(()=>window.logInjected),undefined);checks++;
    await page.locator('#close-modal').click();


    fixture.jobs[0].state='failed';
    fixture.jobs[0].model='HKD-WXX';
    fixture.jobs[0].manufacturer='HUAWEI';
    fixture.jobs[0].system_family='MateBook';
    fixture.jobs[0].product_version='M1010';
    fixture.jobs[0].stale=false;
    await page.locator('#refresh').click();
    await page.waitForFunction(()=>document.querySelector('.job-row .cell-title')?.textContent==='HUAWEI MateBook 14s (HKD-WXX)');
    await page.locator('[data-action=review-job][data-id=progress-job]').waitFor();
    assert.ok((await page.locator('.job-row').first().textContent()).includes('HUAWEI MateBook 14s (HKD-WXX)'));checks++;
    assert.equal(await page.locator('[data-action=reconcile-job]').count(),0);checks++;
    await page.locator('[data-action=review-job][data-id=progress-job]').click();
    assert.equal(await page.locator('#job-review-form [name=confirmation]').count(),0);checks++;
    await page.locator('#job-review-form [name=outcome]').selectOption('installed');
    await page.locator('#job-review-form [name=physical_confirmed]').check();
    await page.locator('#job-review-form [name=note]').fill('已进入 Windows <img src=x onerror="window.reviewInjected=true">');
    await page.locator('#job-review-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    await page.getByText('人工核对已安装',{exact:true}).waitFor();
    assert.equal(jobReviewPayload.outcome,'installed');checks++;
    assert.equal(jobReviewPayload.physical_confirmed,true);checks++;
    assert.equal(await page.locator('.job-row').first().getAttribute('data-state'),'failed');checks++;
    assert.equal(await page.locator('.job-row').first().locator('.job-progress').count(),0);checks++;
    await page.locator('[data-action=job-logs][data-id=progress-job]').click();
    await page.locator('#job-log .log-message').first().waitFor();
    assert.ok((await page.locator('#job-log .log-message').first().textContent()).includes('<img src=x'));checks++;
    assert.equal(await page.locator('#job-log img').count(),0);checks++;
    assert.equal(await page.evaluate(()=>window.reviewInjected),undefined);checks++;
    await page.locator('#close-modal').click();

    // Optional domain join binds the operator's employee ID to each specific device.
    const joinSettings={domain:'corp.test',ou_path:'OU=Workstations,DC=corp,DC=test',username:'join-service@corp.test'};
    fixture.profiles[1].domain_join=joinSettings;
    fixture.profiles[1].has_domain_join_password=true;
    settings.public_url='http://deploy.test/pc-deploy';
    await page.locator('#refresh').click();
    await page.locator('[data-view=profiles]').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.ok(await page.locator('#domain-join-enabled').isChecked());checks++;
    assert.equal(await page.locator('[name=join_password]').inputValue(),'');checks++;
    assert.ok(await page.locator('[name=join_password]').evaluate(el=>!el.required));checks++;
    assert.ok(await page.locator('[name=join_password]').isDisabled());checks++;
    const priorProfilePayload=profilePayload;
    await page.locator('#profile-form [type=submit]').click();
    await page.locator('#form-error').filter({hasText:'HTTPS'}).waitFor();
    assert.equal(profilePayload,priorProfilePayload);checks++;
    assert.ok(!(await page.locator('#domain-join-http').isChecked()));checks++;
    await page.locator('#domain-join-http').check();
    assert.ok(await page.locator('[name=join_user]').isEnabled());checks++;
    assert.ok(await page.locator('[name=join_password]').isEnabled());checks++;
    assert.ok(await page.locator('#domain-join-http-notice').isVisible());checks++;
    assert.ok(await page.locator('#domain-join-https-error').isHidden());checks++;
    await page.locator('[name=join_password]').fill('Fixture-only-http-join-password');
    await page.locator('#profile-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    assert.equal(profilePayload.domain_join.allow_http,true);checks++;
    assert.equal(profilePayload.domain_join_password,'Fixture-only-http-join-password');checks++;
    assert.ok(!('join_allow_http' in profilePayload));checks++;
    fixture.profiles[1].domain_join={...joinSettings,allow_http:true};
    await page.locator('#refresh').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.ok(await page.locator('#domain-join-http').isChecked());checks++;
    assert.ok(await page.locator('[name=join_password]').isEnabled());checks++;
    await page.locator('#domain-join-http').uncheck();
    assert.ok(await page.locator('[name=join_password]').isDisabled());checks++;
    await page.locator('#profile-form [data-action=close]').click();
    settings.http_allowed=false;
    await page.locator('#refresh').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.ok(await page.locator('#domain-join-http').isDisabled());checks++;
    assert.ok(await page.locator('[name=join_password]').isDisabled());checks++;
    assert.ok((await page.locator('#domain-join-https-error').textContent()).includes('服务器禁止'));checks++;
    await page.locator('#profile-form [data-action=close]').click();
    settings.http_allowed=true;
    settings.public_url='https://deploy.test/pc-deploy';
    fixture.profiles[1].domain_join=joinSettings;

    await page.goto('https://ad-menu.test/pc-deploy/');
    await page.locator('#workspace:not([hidden])').waitFor();
    await page.locator('#profile-choice').selectOption('wim-profile');
    const employee=page.locator('[data-employee=laptop-1]');
    assert.ok(await employee.isVisible());checks++;
    await page.locator('[data-disk=laptop-1]').selectOption('disk-7');
    await page.locator('[data-partition=laptop-1]').selectOption('partition-3');
    await page.locator('[data-device=laptop-1]').check();
    const previewsBefore=requests.filter(p=>p==='/pc-deploy/api/jobs/preview').length;
    await page.locator('#preview-button').click();
    await page.locator('#toast').filter({hasText:'请为每台选中的电脑填写员工工号'}).waitFor();
    assert.equal(requests.filter(p=>p==='/pc-deploy/api/jobs/preview').length,previewsBefore);checks++;
    await employee.fill('BAD/ID');
    await page.locator('#preview-button').click();
    await page.locator('#toast').filter({hasText:'工号须为 1–14 位'}).waitFor();
    assert.equal(requests.filter(p=>p==='/pc-deploy/api/jobs/preview').length,previewsBefore);checks++;
    await employee.fill('12345');
    await page.locator('#preview-button').click();
    await page.locator('#commit-form').waitFor();
    assert.equal(previewPayload.targets[0].employee_id,'12345');checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('预计 12345A'));checks++;
    await page.locator('#commit-form [data-action=close]').click();
    await employee.fill('wfq101755');
    await employee.evaluate(el=>el.setSelectionRange(3,3));
    await page.evaluate(()=>refresh());
    assert.equal(await employee.evaluate(el=>document.activeElement===el&&el.selectionStart===3),true);checks++;
    await page.waitForFunction(()=>document.querySelector('[data-employee=laptop-1]')?.value==='WFQ101755');
    assert.equal(await employee.inputValue(),'WFQ101755');checks++;
    await page.locator('#preview-button').click();
    await page.locator('#commit-form').waitFor();
    assert.equal(previewPayload.targets[0].employee_id,'WFQ101755');checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('WFQ101755'));checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('corp.test'));checks++;
    assert.ok(await page.locator('#commit-form [type=submit]').isDisabled());checks++;
    await page.locator('#commit-form [data-action=close]').click();
    fixture.devices.push({...fixture.devices[0],id:'laptop-2',serial:'SECOND-LAPTOP'});
    await page.locator('#refresh').click();
    await page.locator('[data-employee=laptop-2]').waitFor();
    await page.locator('[data-disk=laptop-2]').selectOption('disk-7');
    await page.locator('[data-partition=laptop-2]').selectOption('partition-3');
    await page.locator('[data-employee=laptop-2]').fill('WFQ101755');
    await page.locator('[data-device=laptop-2]').check();
    await page.locator('#preview-button').click();
    await page.locator('#commit-form').waitFor();
    assert.deepEqual(previewPayload.targets.map(t=>t.employee_id),['WFQ101755','WFQ101755']);checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('预计 WFQ101755A'));checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('最终名称同步到任务与日志'));checks++;
    const previewsAfterDuplicate=requests.filter(p=>p==='/pc-deploy/api/jobs/preview').length;
    await page.locator('#commit-form [data-action=close]').click();
    await page.locator('[data-employee=laptop-2]').fill('WFQ101756');
    await page.locator('#preview-button').click();
    await page.locator('#commit-form').waitFor();
    assert.equal(requests.filter(p=>p==='/pc-deploy/api/jobs/preview').length,previewsAfterDuplicate+1);checks++;
    assert.deepEqual(previewPayload.targets.map(t=>[t.device_id,t.employee_id]),
      [['laptop-1','WFQ101755'],['laptop-2','WFQ101756']]);checks++;
    assert.ok((await page.locator('#modal-body').textContent()).includes('SECOND-LAPTOP'));checks++;
    await page.locator('#commit-form [data-action=close]').click();

    await page.locator('[data-view=profiles]').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    // Saved credentials remain reusable for an OU-only edit; identity changes require a new password.
    const joinPassword=page.locator('[name=join_password]'),joinStatus=page.locator('#domain-join-password-status');
    const joinHelp=page.locator('#domain-join-password-help');
    assert.equal(await joinStatus.textContent(),'已保存');checks++;
    assert.ok((await joinHelp.textContent()).includes('无需再次填写'));checks++;
    assert.equal(await joinPassword.getAttribute('aria-describedby'),'domain-join-password-help');checks++;
    assert.equal(await joinPassword.inputValue(),'');checks++;
    await page.locator('[name=join_ou]').fill('OU=Other,DC=corp,DC=test');
    assert.ok(await joinPassword.evaluate(el=>!el.required));checks++;
    await page.locator('[name=join_domain]').fill(' CORP.TEST ');
    assert.equal(await joinStatus.textContent(),'已保存');checks++;
    await page.locator('[name=join_user]').fill(' '+joinSettings.username+' ');
    assert.ok(await joinPassword.evaluate(el=>!el.required));checks++;
    await page.locator('[name=join_domain]').fill(joinSettings.domain);
    await page.locator('[name=join_user]').fill('different-user@corp.test');
    assert.equal(await joinStatus.textContent(),'需重新填写');checks++;
    assert.ok(await joinPassword.evaluate(el=>el.required));checks++;
    const savedPayload=profilePayload;
    await page.locator('#profile-form [type=submit]').click();
    assert.equal(profilePayload,savedPayload);checks++;
    assert.ok(await joinPassword.evaluate(el=>el.validity.valueMissing));checks++;
    await page.locator('[name=join_user]').fill(joinSettings.username);
    assert.equal(await joinStatus.textContent(),'已保存');checks++;
    await page.locator('[name=join_domain]').fill('other.test');
    assert.ok(await joinPassword.evaluate(el=>el.required));checks++;
    assert.equal(await joinStatus.textContent(),'需重新填写');checks++;
    await page.locator('[name=join_domain]').fill(joinSettings.domain);
    assert.ok(await joinPassword.evaluate(el=>!el.required));checks++;
    await joinPassword.fill('Fixture-only-replacement-password');
    assert.equal(await joinStatus.textContent(),'待更新');checks++;
    assert.ok((await joinHelp.textContent()).includes('保存方案后生效'));checks++;
    await joinPassword.fill('');
    assert.equal(await joinStatus.textContent(),'已保存');checks++;
    await page.locator('#profile-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    assert.equal(profilePayload.domain_join_password,'');checks++;
    assert.equal(profilePayload.domain_join.ou_path,'OU=Other,DC=corp,DC=test');checks++;
    assert.equal(profilePayload.domain_join.username,joinSettings.username);checks++;

    fixture.profiles[1].has_domain_join_password=false;
    await page.locator('#refresh').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.equal(await joinStatus.textContent(),'未设置');checks++;
    assert.ok(await joinPassword.evaluate(el=>el.required));checks++;
    await joinPassword.fill('Fixture-only-new-password');
    assert.equal(await joinStatus.textContent(),'待保存');checks++;
    await page.locator('#profile-form [data-action=close]').click();
    fixture.profiles[1].has_domain_join_password=true;
    await page.locator('#refresh').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.equal(await joinStatus.textContent(),'已保存');checks++;
    assert.equal(await joinPassword.inputValue(),'');checks++;
    await joinPassword.fill('Fixture-only-join-password');
    await page.locator('#profile-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    assert.equal(profilePayload.domain_join.domain,'corp.test');checks++;
    assert.equal(profilePayload.domain_join_password,'Fixture-only-join-password');checks++;
    assert.ok(!('join_password' in profilePayload));checks++;
    assert.ok(!('password' in profilePayload));checks++;

    Object.assign(fixture.jobs[0],{state:'awaiting_report',review:null,computer_name:'WFQ101755',updated:1793347900,
      domain_join:{state:'joining',domain:'corp.test',computer_name:'WFQ101755',updated:1793347900,os_installed:true}});
    fixture.server_time=1793347910;
    await page.locator('#refresh').click();
    await page.locator('[data-view=jobs]').click();
    await page.getByText('自动加域中',{exact:true}).waitFor();
    assert.ok((await page.locator('.job-row').first().textContent()).includes('工号电脑名：WFQ101755'));checks++;
    await page.locator('[data-action=job-logs][data-id=progress-job]').click();
    await page.locator('#job-log').getByText('自动加域中',{exact:true}).waitFor();
    assert.ok((await page.locator('#job-log').textContent()).includes('正在加入 AD 域'));checks++;
    fixture.jobs[0].state='completed';
    fixture.jobs[0].domain_join.state='verified';
    fixture.jobs[0].updated=1793348000;
    fixture.jobs[0].finished_at=1793348000;
    fixture.server_time=1793348010;
    await page.locator('[data-action=refresh-job-logs]').click();
    await page.locator('#job-log').getByText('安装并加域完成',{exact:true}).waitFor();
    assert.equal(await page.locator('.job-row').first().locator('.badge').first().textContent(),'安装并加域完成');checks++;
    await page.locator('#close-modal').click();
    fixture.jobs[0].state='failed';
    fixture.jobs[0].domain_join.state='failed';
    fixture.jobs[0].updated=1793348100;
    fixture.server_time=1793348110;
    await page.locator('#refresh').click();
    await page.getByText('系统已安装，加域失败',{exact:true}).waitFor();
    assert.ok((await page.locator('.job-row').first().textContent()).includes('不会重新装机'));checks++;


    // Manual mode keeps installed devices idle until an explicit, confirmed batch release.
    fixture.profiles[1].domain_join={...joinSettings,mode:'manual'};
    await page.locator('[data-view=profiles]').click();
    await page.locator('#refresh').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.equal(await page.locator('#domain-join-mode').inputValue(),'manual');checks++;
    assert.equal(await page.locator('#domain-join-password-status').textContent(),'已保存');checks++;
    await page.locator('#disk-mode').selectOption('wipe_disk');
    await page.locator('#partition-layout').selectOption('split');
    assert.equal(await page.locator('[name=system_gib]').inputValue(),'256');checks++;
    await page.locator('[name=system_gib]').fill('320');
    await page.locator('[name=system_gib]').blur();
    assert.ok((await page.locator('#partition-plan-help').textContent()).includes('旧 C/D 盘数据都会清空'));checks++;
    await page.locator('#profile-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    assert.equal(profilePayload.system_gib,320);checks++;
    assert.equal(profilePayload.disk_mode,'wipe_disk');checks++;
    assert.equal(profilePayload.domain_join.mode,'manual');checks++;
    assert.ok(!('partition_layout' in profilePayload)&&!('join_mode' in profilePayload));checks++;
    fixture.profiles[1].system_gib=320;fixture.profiles[1].disk_mode='wipe_disk';
    await page.locator('#refresh').click();
    await page.locator('[data-action=edit-profile][data-id=wim-profile]').click();
    assert.equal(await page.locator('#partition-layout').inputValue(),'split');checks++;
    await page.locator('#disk-mode').selectOption('system_partition');
    assert.ok(await page.locator('[name=system_gib]').isDisabled());checks++;
    assert.ok(await page.locator('#partition-layout').isDisabled());checks++;
    assert.ok((await page.locator('#partition-plan-help').textContent()).includes('不调整 C 盘容量'));checks++;
    await page.locator('#disk-mode').selectOption('wipe_disk');
    assert.equal(await page.locator('[name=system_gib]').inputValue(),'320');checks++;
    await page.locator('#profile-form [data-action=close]').click();

    const manualTime=fixture.server_time;
    fixture.jobs=[1,2,3].map(index=>({...fixture.jobs[0],id:'manual-join-'+index,serial:'MANUAL-PC-'+index,
      state:'awaiting_report',review:null,started_at:manualTime-500,installed_at:manualTime-100,
      updated:manualTime,expires_at:index===3?manualTime-1:manualTime+7200,computer_name:'WFQ10175'+index,
      domain_join:{state:'waiting_release',domain:'corp.test',computer_name:'WFQ10175'+index,updated:manualTime,os_installed:true}}));
    await page.locator('[data-view=jobs]').click();
    await page.locator('#refresh').click();
    await page.locator('[data-job-join="manual-join-1"]').waitFor();
    assert.equal(await page.locator('[data-job-join]').count(),2);checks++;
    assert.ok(await page.locator('#release-selected-joins').isDisabled());checks++;
    assert.ok((await page.locator('#page-content').textContent()).includes('Windows 已安装，待统一加域'));checks++;
    const installedDuration=await page.locator('[data-job-timer]').first().textContent();
    fixture.server_time+=60;
    await page.locator('#refresh').click();
    assert.equal(await page.locator('[data-job-timer]').first().textContent(),installedDuration);checks++;
    await page.locator('[data-job-join="manual-join-1"]').check();
    await page.locator('#refresh').click();
    assert.ok(await page.locator('[data-job-join="manual-join-1"]').isChecked());checks++;
    await page.locator('#select-all-joins').check();
    assert.ok((await page.locator('#release-selected-joins').textContent()).includes('2 台'));checks++;
    await page.locator('#release-selected-joins').click();
    assert.ok((await page.locator('#modal-body').textContent()).includes('MANUAL-PC-1'));checks++;
    assert.ok(!(await page.locator('#modal-body').textContent()).includes('MANUAL-PC-3'));checks++;
    await page.locator('#domain-join-release-form [type=submit]').click();
    assert.equal(releasePayload,null);checks++;
    await page.locator('[name=restart_confirmed]').check();
    await page.locator('#domain-join-release-form [type=submit]').click();
    await page.locator('#modal').waitFor({state:'hidden'});
    assert.deepEqual(releasePayload,{job_ids:['manual-join-1','manual-join-2'],restart_confirmed:true});checks++;
    assert.equal(await page.locator('[data-job-join]').count(),0);checks++;
    assert.ok((await page.locator('#page-content').textContent()).includes('已授权，等待加域'));checks++;


    // A historical firmware-only Huawei code has a verified product-family label.
    fixture.jobs=[{...fixture.jobs[0],id:'model-history',model:'HKD-WXX',manufacturer:'',system_family:'',
      product_name:'',product_version:'',oem_model:'',serial:'MODEL-CHECK',state:'failed',review:null,
      updated:fixture.server_time+1,domain_join:{state:'failed',domain:'corp.test',computer_name:'WFQ101755',updated:fixture.server_time}}];
    await page.locator('#refresh').click();
    await page.locator('[data-action=job-logs][data-id=model-history]').waitFor();
    await page.locator('.job-row .cell-title').filter({hasText:'HUAWEI MateBook 14s'}).waitFor();
    assert.ok((await page.locator('.job-row .cell-title').textContent()).includes('(HKD-WXX)'));checks++;
    await page.locator('[data-action=job-logs][data-id=model-history]').click();
    await page.waitForFunction(()=>document.querySelector('#job-log .detail-grid dd')?.textContent.includes('HUAWEI MateBook 14s (HKD-WXX)'));
    assert.ok((await page.locator('#job-log').textContent()).includes('域：corp.test'));checks++;
    await page.locator('#close-modal').click();
    assert.ok(!(await page.evaluate(()=>deviceLabel({model:'HKD-WXX',manufacturer:'Dell'}))).includes('MateBook'));checks++;
    assert.equal(await page.evaluate(()=>deviceLabel({model:'VENDOR-123',manufacturer:'Vendor',
      oem_model:'Vendor Product 15',product_version:'1.0'})),'Vendor Product 15 (VENDOR-123)');checks++;

    assert.deepEqual(errors,[]);checks++;
    console.log(`${checks} nested menu, embedded page, HTTP form, role, message origin, lifecycle, mobile, WIM restore and per-task log UI checks passed. No live system contacted.`);
  }finally{await browser.close();}
}
run().catch(error=>{console.error(error);process.exitCode=1;});
