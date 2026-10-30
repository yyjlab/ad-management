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
    let role='super_admin',expired=false,saves=0;
    const settings={public_url:'http://ad-menu.test/pc-deploy',enabled:false,concurrency:2,ca_pem:''};
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
      if(url.pathname==='/pc-deploy/api/dashboard') return route.fulfill({json:{devices:[],sources:[],profiles:[],jobs:[],events:[],settings,
        boot_files:{wimboot:false,'boot.wim':false,BCD:false,'boot.sdi':false},server_time:1793347200}});
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
    await frame.locator('#public-url').fill('http://192.0.2.10/pc-deploy');
    await frame.locator('#settings-form [type=submit]').click();
    await page.waitForFunction(()=>document.getElementById('pcDeployFrame').contentDocument?.getElementById('toast')?.textContent==='设置已保存');
    assert.equal(saves,1);checks++;
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
    assert.deepEqual(errors,[]);checks++;
    console.log(`${checks} nested menu, embedded page, HTTP form, role, message origin, lifecycle and mobile checks passed. No live system contacted.`);
  }finally{await browser.close();}
}
run().catch(error=>{console.error(error);process.exitCode=1;});
