// All HTTP responses are isolated fixtures; no AD, SMB, or device is contacted.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function run() {
  const browser = await chromium.launch({channel:'msedge', headless:true});
  let checks = 0;
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    const errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    let role = 'super_admin', expired = false, saves = 0;
    const settings = {public_url:'https://ad-merge.test/pc-deploy',enabled:false,concurrency:2,ca_pem:''};
    const adHtml = fs.readFileSync(path.join(__dirname,'admin_manage.html'),'utf8');
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url());
      requests.push(url.pathname);
      if (url.pathname === '/admin/manage') return route.fulfill({contentType:'text/html',body:adHtml});
      if (url.pathname === '/pc-deploy/') return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(__dirname,'pc_deploy/static/index.html'),'utf8')});
      if (url.pathname.startsWith('/pc-deploy/static/')) {
        const name = path.basename(url.pathname);
        if (!['app.js','app.css'].includes(name)) return route.fulfill({status:404,body:''});
        return route.fulfill({contentType:name.endsWith('.js')?'application/javascript':'text/css',body:fs.readFileSync(path.join(__dirname,'pc_deploy/static',name),'utf8')});
      }
      if (url.pathname === '/api/admin/check') return route.fulfill({json:{logged_in:true,username:'test-super-admin',role,permissions:['view_user','view_dashboard','view_computers','view_logs','manage_admins','system_settings','password_policy']}});
      if (url.pathname === '/pc-deploy/api/session') return route.fulfill(expired ? {status:401,json:{error:'请先登录 AD 管理后台'}} : {json:{authenticated:true,username:'test-super-admin',csrf:'fixture-csrf',test_mode:true}});
      if (url.pathname === '/pc-deploy/api/dashboard') return route.fulfill({json:{devices:[],sources:[],profiles:[],jobs:[],events:[],settings,boot_files:{wimboot:false,'boot.wim':false,BCD:false,'boot.sdi':false},server_time:1793347200}});
      if (url.pathname === '/pc-deploy/api/settings') {
        assert.equal(request.headers()['x-csrf-token'],'fixture-csrf');
        const payload = request.postDataJSON();
        assert.equal(payload.public_url,'https://new-ad-merge.test/pc-deploy');
        assert.equal(payload.enabled,false);
        Object.assign(settings,payload); saves++;
        return route.fulfill({json:{ok:true}});
      }
      if (url.pathname.startsWith('/pc-deploy/')) return route.fulfill({status:404,json:{error:'unused fixture route'}});
      return route.fulfill({json:{success:false,message:'Unused isolated AD fixture endpoint'}});
    });
    await page.goto('http://ad-merge.test/admin/manage');
    await page.locator('#pcDeployMenu').waitFor({state:'visible'});
    const menuNames = await page.locator('.sidebar .menu-item').allTextContents();
    assert.deepEqual(menuNames,['数据概览','AD用户管理','计算机管理','域密码策略','组策略管理','密码到期提醒','日志中心','审批中心','用户中心','登录审计','系统设置','备份恢复','电脑装机']); checks++;
    await page.locator('#pcDeployMenu').click();
    await page.waitForURL('**/pc-deploy/');
    await page.locator('#workspace:not([hidden])').waitFor();
    assert.equal(await page.locator('#auth-password').count(),0); checks++;
    assert.equal(await page.locator('#live-badge').textContent(),'真实下发关闭'); checks++;
    await page.locator('[data-view=sources]').click();
    assert.equal(await page.getByText('下载检测脚本 ↓',{exact:true}).getAttribute('href'),'/pc-deploy/api/tools/inspect-source'); checks++;
    await page.locator('[data-view=settings]').click();
    await page.locator('#public-url').fill('https://new-ad-merge.test/pc-deploy');
    await page.locator('#settings-form [type=submit]').click();
    await page.waitForFunction(()=>document.querySelector('#toast').textContent==='设置已保存');
    assert.equal(saves,1); checks++;
    assert.ok(!requests.some(p=>['/api/session','/api/dashboard','/api/settings','/api/login','/api/setup'].includes(p))); checks++;
    await page.getByText('返回 AD 后台',{exact:true}).click();
    await page.waitForURL('**/admin/manage');
    await page.locator('#pcDeployMenu').waitFor({state:'visible'});
    assert.deepEqual(await page.locator('.sidebar .menu-item').allTextContents(),menuNames); checks++;
    for (const deniedRole of ['admin','readonly']) {
      role=deniedRole;
      await page.reload();
      await page.waitForFunction(r=>document.querySelector('#loginUser').textContent.includes(r),deniedRole==='admin'?'（管理员）':'（只读用户）');
      assert.ok(await page.locator('#pcDeployMenu').isHidden()); checks++;
    }
    expired=true;
    await page.goto('http://ad-merge.test/pc-deploy/');
    await page.locator('#auth:not([hidden])').waitFor();
    assert.ok(await page.locator('#workspace').isHidden()); checks++;
    assert.equal(await page.getByText('前往 AD 后台登录',{exact:true}).getAttribute('href'),'/admin'); checks++;
    assert.deepEqual(errors,[]); checks++;
    console.log(`${checks} merged navigation, roles, session, URL and form checks passed. No live system contacted.`);
  } finally { await browser.close(); }
}
run().catch(error=>{console.error(error);process.exitCode=1;});
