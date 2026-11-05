'use strict';
const $ = (s, root = document) => root.querySelector(s);
const h = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const size = bytes => `${(Number(bytes) / 1024 ** 3).toFixed(1)} GiB`;
const date = seconds => new Date(seconds * 1000).toLocaleString('zh-CN', {hour12:false});
const activeStates = ['queued','preflight','installing','awaiting_report'];
const labels = {devices:['设备工作台','选择设备和目标系统硬盘，确认后自动完成 Windows 安装。'],sources:['安装源','原版安装文件或封装 WIM 通过专用只读 SMB 账号访问，快速读取镜像版本和索引，不扫描整份镜像。'],profiles:['装机方案','选择原版安装或封装 WIM 还原；封装镜像沿用其账号、软件和系统设置。'],jobs:['任务记录','安装成功以安装后系统回报为准；断线任务不会自动重装。'],settings:['启动与设置','现有 Ventoy 可作为备用引导；纯网络启动使用 iPXE / wimboot。']};
const API_BASE = '/pc-deploy';
const embedParams = new URLSearchParams(location.search);
const embedded = embedParams.get('embedded') === '1' && window.parent !== window;
if (embedded) document.documentElement.classList.add('embedded');
let csrf = '', data = null, view = Object.hasOwn(labels, embedParams.get('view')) ? embedParams.get('view') : 'devices', busy = false;
let joinSelection = new Set();
let chosen = new Set(), disks = new Map(), partitions = new Map(), employeeIds = new Map(), profileId = '', search = '', filter = 'all', previewId = null;
let toastTimer, settingsDirty = false, jobLog = null, deviceDialog = null, serverTime = 0, serverSample = 0;
const jobSnapshots = new Map();
function latestJob(job, sampledAt) {
  const previous = jobSnapshots.get(job.id);
  const version = Math.max(Number(job.updated) || 0, Number(job.review?.reviewed_at) || 0);
  if (previous && (version < previous.version || (version === previous.version && sampledAt < previous.sampledAt))) return previous.job;
  jobSnapshots.set(job.id, {job, version, sampledAt});
  return job;
}

function toast(message) { $('#toast').textContent = message; $('#toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('#toast').hidden = true, 6000); }
async function api(path, method = 'GET', payload) {
  const r = await fetch(API_BASE + path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:payload === undefined ? undefined : JSON.stringify(payload)});
  const result = await r.json();
  if (!r.ok) { if (r.status === 401) showAuth(); throw new Error(result.error || '请求失败'); }
  return result;
}
function showAuth(message = '登录已失效，请返回 AD 后台重新登录。') { $('#workspace').hidden = true; $('#auth').hidden = false; $('#auth-error').textContent = message; }
async function init() {
  try {
    const s = await api('/api/session'); csrf = s.csrf;
    if (s.test_mode) { document.title = '测试环境 · PC Deploy'; $('#test-mode').hidden = false; }
    await enter();
  } catch (e) { showAuth(e.message); }
}
async function enter() { $('#auth').hidden = true; $('#workspace').hidden = false; await refresh(); }
async function refresh() {
  if (busy || $('#workspace').hidden) return;
  busy = true;
  try {
    const snapshot = await api('/api/dashboard');
    snapshot.jobs = snapshot.jobs.map(job => latestJob(job, snapshot.server_time));
    data = snapshot;
    const retained = new Set(data.jobs.map(job => job.id));
    if (jobLog) retained.add(jobLog.id);
    for (const id of jobSnapshots.keys()) if (!retained.has(id)) jobSnapshots.delete(id);
    syncServerClock(data.server_time);
    chosen = new Set([...chosen].filter(id => data.devices.some(d => d.id === id && selectable(d))));
    $('#connection-error').hidden = true;
    $('#live-badge').textContent = data.settings.enabled ? '真实下发已开启' : '真实下发关闭';
    $('#live-badge').className = `badge ${data.settings.enabled ? 'good' : 'muted'}`;
    $('#last-updated').textContent = '更新于 ' + date(data.server_time);
    if (!(view === 'settings' && settingsDirty)) render();
    else if ($('#media-status')) $('#media-status').innerHTML=renderMediaStatus();
    if (jobLog?.result) {
      jobLog.result.job = latestJob(jobLog.result.job, jobLog.result.server_time);
      renderJobLogs();
    }
    if (deviceDialog && $('#modal').open) renderJobDeviceDetail();
  } catch (e) { $('#connection-error').textContent = '数据读取失败：' + e.message; $('#connection-error').hidden = false; }
  finally { busy = false; }
}
function badge(state) { const colors = {completed:'good',failed:'bad',preflight:'blue',installing:'blue',awaiting_report:'warn',queued:'muted',cancelled:'muted'}; return `<span class="badge ${colors[state] || 'muted'}">${h(({queued:'等待领取',preflight:'安装前检查',installing:'Windows 安装中',awaiting_report:'等待安装后回报',completed:'安装后已回报',failed:'失败，需核对',cancelled:'已取消'})[state] || state)}</span>`; }
function firmwareText(value) {
  const text = String(value ?? '').trim();
  return /^(unknown|none|not (?:specified|applicable)|default string|system (?:manufacturer|family|product name|version)|to be filled by o\.?e\.?m\.?)$/i.test(text) ? '' : text;
}
function knownModel(raw, vendor) {
  // Huawei's official model list maps HKD to MateBook 14s.
  // https://consumer.huawei.com/cn/support/content/zh-cn15945089/
  return /^HKD(?:-|$)/i.test(raw)&&(!vendor||/huawei|华为/i.test(vendor))?'HUAWEI MateBook 14s':'';
}
function deviceLabel(device) {
  const current = device.id && data?.jobs.find(job=>job.device_id===device.id);
  const meta = key => firmwareText(device[key]) || firmwareText(current?.[key]);
  const raw = firmwareText(device.model) || firmwareText(device.product_name) || '型号未提供';
  const vendor = meta('manufacturer'), family = meta('system_family');
  const version = meta('product_version'), code = /^[a-z0-9][a-z0-9._-]{2,30}$/i.test(raw);
  const readable = [meta('oem_model'),version,meta('product_name')].find(value=>value!==vendor&&value!==family&&/[A-Za-z\u4e00-\u9fff]/.test(value)&&/[\s\u4e00-\u9fff]/.test(value));
  const main = code && (readable||knownModel(raw,vendor)) || (vendor.toLowerCase() === 'lenovo' && version ? version : raw);
  const parts = [];
  if (vendor && !main.toLowerCase().includes(vendor.toLowerCase())) parts.push(vendor);
  if (code && family && !main.toLowerCase().includes(family.toLowerCase())) parts.push(family);
  parts.push(main);
  return parts.join(' ');
}
function modelHint(device) {
  return /^[a-z0-9][a-z0-9._-]{2,30}$/i.test(device.model || '') && !firmwareText(device.manufacturer) && !knownModel(device.model, '') ?
    '<span class="cell-sub">BIOS 上报型号；品牌 / 系列未上报</span>' : '';
}
function jobBadge(job) {
  const join=job.domain_join;
  if(join?.state==='verified' && job.state==='completed')return '<span class="badge good">安装并加域完成</span>';
  if(join?.state==='waiting_release' && activeStates.includes(job.state))return '<span class="badge '+(join.released_at?'blue':'warn')+'">'+(join.released_at?'已授权，等待加域':'Windows 已安装，待统一加域')+'</span>';
  if(join?.state==='failed'&&!job.review)return '<span class="badge bad">系统已安装，加域失败</span>';
  if(join && ['checking','joining','restarting','verified'].includes(join.state) && activeStates.includes(job.state))return '<span class="badge blue">'+(join.state==='restarting'?'加域后重启验证中':join.state==='verified'?'加域已验证，等待完成回报':'自动加域中')+'</span>';
  if (job.state !== 'failed' || !job.review) return badge(job.state);
  return '<span class="badge '+(job.review.outcome === 'installed'?'good':'bad')+'">'+
    (job.review.outcome === 'installed'?'人工核对已安装':'失败，已核对')+'</span><span class="cell-sub">原任务报告失败 · '+h(job.review.operator)+' · '+h(date(job.review.reviewed_at))+'</span>';
}
function reviewJob(id) {
  const job = data.jobs.find(j=>j.id===id); if (!job || job.state !== 'failed') return;
  modal('人工核对安装结果', '<form id="job-review-form" data-id="'+h(id)+'"><p><strong>'+h(deviceLabel(job))+'</strong><br><span class="mono">'+h(job.serial)+'</span></p><p class="modal-help">登记现场实际结果，保留原任务的失败日志。此操作不会重新安装或操作电脑硬盘。</p><div class="field"><label>现场结果</label><select name="outcome" required><option value="">请选择实际情况</option><option value="installed">已能进入 Windows</option><option value="not_installed">仍未安装完成</option></select></div><div class="field"><label>核对备注（可选）</label><input name="note" maxlength="500" value="'+h(job.review?.note || '')+'"></div><label class="check-label"><input name="physical_confirmed" type="checkbox" required>已现场核对这台电脑的序列号和实际安装结果</label><div id="form-error" class="error" role="alert"></div><div class="form-actions"><button type="button" data-action="close">返回</button><button class="primary" type="submit">保存核对结果</button></div></form>');
}
function currentJob(d) { return data.jobs.find(j => j.device_id === d.id && activeStates.includes(j.state)); }
function selectable(d) { return d.online && !d.consumed && !currentJob(d) && d.firmware === 'UEFI' && d.architecture === 'amd64' && d.disks.some(x => x.eligible); }
function empty(title, caption = '') { return `<div class="empty"><h3>${h(title)}</h3>${caption ? `<p>${h(caption)}</p>` : ''}</div>`; }
function render() {
  if (!data) return;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  $('#page-title').textContent = labels[view][0]; $('#page-subtitle').textContent = labels[view][1];
  $('#breadcrumb').textContent = '部署管理 / ' + labels[view][0];
  $('#page-actions').innerHTML = view === 'sources' ? '<a class="button-link" href="/pc-deploy/api/tools/inspect-source">下载检测脚本 ↓</a><button class="primary" data-action="new-source">＋ 添加安装源</button>' : view === 'profiles' ? '<button class="primary" data-action="new-profile">＋ 新建方案</button>' : '';
  ({devices:renderDevices,sources:renderSources,profiles:renderProfiles,jobs:renderJobs,settings:renderSettings})[view]();
  if (embedded) window.parent.postMessage({type:'pc-deploy:view', view}, location.origin);
}
function filteredDevices() { return data.devices.filter(d => (!search || [d.serial,deviceLabel(d),...d.macs].join(' ').toLowerCase().includes(search.toLowerCase())) && (filter === 'all' || (filter === 'online' ? d.online : filter === 'ready' ? selectable(d) : !d.online))); }
function renderDevices() {
  const editing=document.activeElement?.dataset.employee;
  const caret=editing?[document.activeElement.selectionStart,document.activeElement.selectionEnd]:null;
  const active = data.jobs.filter(j => activeStates.includes(j.state));
  $('#page-content').innerHTML = `<div class="stats"><div class="stat"><span>已登记设备</span><strong>${data.devices.length}</strong></div><div class="stat"><span>在线待部署</span><strong class="good-text">${data.devices.filter(selectable).length}</strong></div><div class="stat"><span>进行中任务</span><strong>${active.length}</strong></div><div class="stat"><span>待核对失败</span><strong class="bad-text">${data.jobs.filter(j=>j.state==='failed'&&!j.review).length}</strong></div></div>
    <div class="toolbar"><div class="toolbar-left"><input id="search" class="search" aria-label="搜索设备" placeholder="搜索序列号、机型或 MAC" value="${h(search)}"><select id="filter" class="filter" aria-label="设备状态"><option value="all">全部设备</option><option value="online">在线设备</option><option value="ready">可选设备</option><option value="offline">离线设备</option></select></div><div class="toolbar-right"><select id="profile-choice" class="profile-select" aria-label="装机方案"><option value="">选择装机方案</option>${data.profiles.map(p=>`<option value="${h(p.id)}">${h(p.name)}</option>`).join('')}</select><button id="preview-button" class="primary" data-action="preview">创建安装批次${chosen.size ? ` (${chosen.size})` : ''}</button></div></div>
    <div class="table-wrap"><table class="devices-table"><thead><tr><th class="check-cell"><input id="select-all" type="checkbox" aria-label="全选可选设备"></th><th>设备 / 整机序列号</th>${selectedProfile()?.domain_join?'<th>员工工号</th>':''}<th>启动环境</th><th>目标物理硬盘</th><th>状态</th><th>校验码 / 最近上线</th></tr></thead><tbody id="device-rows"></tbody></table><div id="device-empty"></div></div>
    <div class="subheading"><h3>当前任务</h3><small>最多同时安装 ${data.settings.concurrency} 台 · 不自动重试</small></div><div class="queue-list">${active.length ? active.slice(0,8).map(j=>`<div class="queue-row"><div class="queue-main"><strong>${h(deviceLabel(j))} · ${h(j.serial)}</strong><p>${h(j.profile)} · 硬盘 ${h(j.disk.number)} / ${h(size(j.disk.size_bytes))}${j.stale ? ' · 长时间未回报，请现场核对' : ''}</p></div><div class="queue-state">${jobBadge(j)}<button class="small" data-action="view-jobs">查看任务</button></div></div>`).join('') : empty('暂无进行中的任务')}</div>`;
  $('#filter').value = filter; $('#profile-choice').value = profileId; renderDeviceRows();
  if(editing){
    const input=document.querySelector('[data-employee="'+CSS.escape(editing)+'"]');
    if(input&&!input.disabled){input.focus({preventScroll:true});input.setSelectionRange(...caret);}
  }
}
function selectedProfile() { return data.profiles.find(p=>p.id===profileId); }
function preservesPartitions() { return selectedProfile()?.disk_mode==='system_partition'; }
function partitionChoice(d) {
  if (!preservesPartitions()) return '';
  const disk = d.disks.find(k=>k.key===disks.get(d.id));
  const list = (disk?.partitions||[]).filter(p=>p.windows && p.filesystem==='NTFS' && p.gpt_type==='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7');
  return `<select aria-label="${h(d.serial)} 的 Windows 分区" data-partition="${h(d.id)}"><option value="">明确选择要格式化的 Windows 分区</option>${list.map(p=>`<option value="${h(p.key)}" ${partitions.get(d.id)===p.key?'selected':''}>分区 ${p.number} · ${h(size(p.size_bytes))} · 偏移 ${h(size(p.offset))}</option>`).join('')}</select><span class="cell-sub">${list.length?'只格式化所选分区，保留其他数据分区':'未识别到可选 Windows 分区；需新版 PE 和 GPT / NTFS 分区'}</span>`;
}
function renderDeviceRows() {
  const list = filteredDevices();
  $('#device-rows').innerHTML = list.map(d=>{
    const job = currentJob(d), eligible = selectable(d);
    return `<tr class="${chosen.has(d.id)?'selected':''}"><td class="check-cell"><input type="checkbox" data-device="${h(d.id)}" aria-label="选择 ${h(d.serial)}" ${chosen.has(d.id)?'checked':''} ${!eligible?'disabled':''}></td><td class="device-name"><button class="inline-link cell-title" data-action="device-detail" data-id="${h(d.id)}">${h(deviceLabel(d))}</button><span class="cell-sub mono">${h(d.serial)}</span>${modelHint(d)}</td>${selectedProfile()?.domain_join?'<td><input class="filter" data-employee="'+h(d.id)+'" aria-label="'+h(d.serial)+' 的员工工号" placeholder="如 WFQ101755" maxlength="14" value="'+h(employeeIds.get(d.id)||'')+'" '+(!eligible?'disabled':'')+'><span class="cell-sub">重名追加 A–Z；纯数字从 A 开始</span></td>':''}<td><span class="badge ${d.firmware==='UEFI'?'good':'warn'}">${h(d.firmware)} · ${h(d.architecture)}</span><span class="cell-sub">TPM 2.0 ${d.tpm2?'✓':'—'} / Secure Boot ${d.secure_boot?'✓':'—'}</span></td><td><select class="disk-select" aria-label="${h(d.serial)} 的目标硬盘" data-disk="${h(d.id)}" ${!eligible?'disabled':''}><option value="">请选择目标硬盘，不自动猜测</option>${d.disks.map(k=>`<option value="${h(k.key)}" ${disks.get(d.id)===k.key?'selected':''} ${!k.eligible?'disabled':''}>磁盘 ${k.number} · ${h(size(k.size_bytes))} · ${h(k.model || k.serial || k.bus)}${!k.eligible?'（不可选）':''}</option>`).join('')}</select>${partitionChoice(d)}<span class="cell-sub">${preservesPartitions()?'同盘 EFI 引导文件会更新':d.disks.filter(k=>k.eligible).length>1?'多硬盘：只清除手动选中的这一块':d.disks.every(k=>!k.eligible)?'没有符合保护规则的内置硬盘':'所选物理盘上的全部分区会被清空'}</span></td><td>${job?jobBadge(job):`<span class="badge ${d.online?'good':'muted'}">${d.online?(d.consumed?'本次启动已执行':'等待确认'):'离线'}</span>`}</td><td><span class="mono">${h(d.boot_code)}</span><span class="cell-sub">${h(date(d.last_seen))}</span></td></tr>`;
  }).join('');
  $('#device-empty').innerHTML = list.length ? '' : empty(data.devices.length?'没有匹配的设备':'等待设备进入 WinPE',data.devices.length?'':'连接网线后，还需从网络或 Ventoy 启动部署环境。');
  $('#select-all').checked = list.filter(selectable).length>0 && list.filter(selectable).every(d=>chosen.has(d.id));
  updateSelection();
}
function updateSelection() { const b = $('#preview-button'); if(b){ b.disabled = !chosen.size || !profileId; b.textContent = `创建安装批次${chosen.size ? ` (${chosen.size})` : ''}`; } }
function renderSources() {
  $('#page-content').innerHTML = data.sources.length ? `<div class="record-grid">${data.sources.map(s=>`<article class="record"><div class="record-top"><h3>${h(s.name)}</h3><span class="badge blue">${s.family==='windows11'?'Windows 11':'Windows 10'}</span></div><p class="mono">${h(s.path)}${s.kind==='wim'?' / '+h(s.image_file):''}</p><span class="badge muted">${s.kind==='wim'?'封装 WIM 直接还原':'原版 Setup 安装'}</span><span class="badge muted">待装机客户端复核</span><dl><dt>镜像索引</dt><dd>${s.images.length} 个 x64 版本</dd><dt>读取账号</dt><dd>${h(s.smb_user)}</dd><dt>检测方式</dt><dd>快速检测 · 版本与索引</dd></dl><div class="form-actions"><button class="small" data-action="edit-source" data-id="${h(s.id)}">编辑安装源</button></div></article>`).join('')}</div>` : empty('尚未添加安装源','原版 ISO 解压目录和单个封装 WIM 均支持；运行检测脚本后导入清单。');
}
function renderProfiles() {
  $('#page-content').innerHTML = data.profiles.length ? `<div class="record-grid">${data.profiles.map(p=>`<article class="record"><div class="record-top"><h3>${h(p.name)}</h3><span class="badge good">UEFI / GPT</span></div><dl><dt>安装源</dt><dd>${h(data.sources.find(s=>s.id===p.source_id)?.name || '安装源不存在')}</dd><dt>镜像索引</dt><dd>${p.image_index}</dd><dt>分区方案</dt><dd>${p.disk_mode==='system_partition'?'保留分区布局，仅还原所选 Windows 分区':(p.system_gib?`C 盘 ${p.system_gib} GiB + D 盘剩余空间`:'单 C 盘，使用可用空间')}<br><small>${p.disk_mode==='system_partition'?'更新同盘 EFI 引导':'重建 EFI / MSR / 恢复分区'}</small></dd><dt>本地账号</dt><dd>${p.preserve_image_settings?'沿用镜像内账号':h(p.username)+' · 密码已保护'}</dd><dt>计算机名</dt><dd>${p.domain_join?'按每台填写的员工工号 · '+(p.domain_join.mode==='manual'?'平台统一加域':'安装后自动加域'):p.preserve_image_settings?'沿用镜像内名称':h(p.computer_prefix)+'-设备标识'}</dd></dl><div class="form-actions"><button class="small" data-action="edit-profile" data-id="${h(p.id)}">编辑方案</button></div></article>`).join('')}</div>` : empty('尚未配置装机方案','先添加安装源，再配置系统版本、分区和临时本地账号。');
}
function syncServerClock(seconds) {
  if (Number.isFinite(seconds) && seconds >= serverTime) { serverTime = seconds; serverSample = performance.now(); }
}
function serverNow() { return serverTime ? serverTime + (performance.now()-serverSample)/1000 : Date.now()/1000; }
function duration(seconds) {
  const total = Math.max(0, Math.floor(seconds)), hours = Math.floor(total/3600), minutes = Math.floor(total%3600/60);
  return (hours ? hours+'小时'+String(minutes).padStart(2,'0') : minutes)+'分'+String(total%60).padStart(2,'0')+'秒';
}
function renderPhasedJobTiming(job) {
  const t=job.timings, stamp=value=>Number.isFinite(value)&&value>0?value:null;
  const terminal=!activeStates.includes(job.state), finished=stamp(t.finished_at);
  const requested=stamp(t.requested_at) ?? job.created, restored=stamp(t.restore_finished_at);
  const ready=stamp(t.windows_ready_at), joinStart=stamp(t.join_started_at), joinEnd=stamp(t.join_finished_at);
  const row=(key,label,start,end,placeholder='未开始',missing=false)=>{
    if (missing) return '<div class="job-time-row"><span>'+label+'</span><b>缺少阶段回报</b></div>';
    if (start===null) return '<div class="job-time-row"><span>'+label+'</span><b>'+placeholder+'</b></div>';
    const active=end===null&&!terminal, until=end ?? (terminal?finished:null);
    return '<div class="job-time-row"><span>'+label+'</span><b data-phase-timer="'+key+'" data-start="'+h(start)+'" data-end="'+h(until ?? '')+'" data-active="'+active+'" data-complete="'+(end!==null)+'" data-stopped="'+(terminal&&end===null)+'"></b></div>';
  };
  return '<div class="job-timing phased" data-state="'+h(job.state)+'">'+
    row('restore','① 还原及重启准备',requested,restored,'未开始',restored===null&&ready!==null)+
    row('windows','② 系统启动',restored,ready,'未开始',restored===null&&ready!==null)+
    (t.join_enabled?row('join','③ 加域及验证',joinStart,joinEnd,t.waiting_for_release?'等待统一加域':'未开始'):
      '<div class="job-time-row"><span>③ 加域及验证</span><b>未启用</b></div>')+
    '<strong data-job-timer data-start="'+h(requested)+'" data-end="'+h(finished ?? '')+'" data-installed="true" data-active="'+!terminal+'" data-timer-label="④ 总耗时 "></strong>'+
    '<small>下发：'+h(date(requested))+'</small>'+
    (t.waiting_for_release?'<small>总耗时包含等待统一加域</small>':'')+
    '<small class="duration-warning" hidden>已超过 10 分钟，请查看当前阶段与日志</small></div>';
}
function renderJobTiming(job) {
  if (job.timings) return renderPhasedJobTiming(job);
  const started = Number.isFinite(job.started_at) && job.started_at > 0 ? job.started_at : null;
  const installedAt = Number.isFinite(job.installed_at) ? job.installed_at : null;
  const active = activeStates.includes(job.state) && installedAt === null;
  const imageEnd = Number.isFinite(job.image_applied_at) ? job.image_applied_at : null;
  const deployEnd = Number.isFinite(job.deployment_finished_at) ? job.deployment_finished_at : null;
  const phaseEnd = job.kind==='wim' && started!==null ? (imageEnd ?? deployEnd) : null;
  const timerActive = active && phaseEnd===null;
  const ended = phaseEnd ?? installedAt ?? (active ? null : (job.finished_at ?? job.updated ?? job.created));
  const phaseLabel = phaseEnd===null ? '' : (imageEnd===null ? '还原及引导耗时 ' : '镜像还原耗时 ');
  let followup = '';
  if (job.kind==='wim' && deployEnd!==null) {
    const until = installedAt ?? (active ? null : (job.finished_at ?? job.updated));
    const waiting = active && installedAt===null;
    followup = '<small><span data-followup-timer data-start="'+h(deployEnd)+'" data-end="'+h(until ?? '')+'" data-active="'+waiting+'" data-label="'+(waiting?'等待 Windows 回报 ':'系统启动及回报耗时 ')+'"></span></small>';
  }
  return '<div class="job-timing" data-state="'+h(job.state)+'"><strong data-job-timer data-start="'+h(started ?? job.created)+'" data-end="'+h(ended ?? '')+'" data-installed="'+(started !== null)+'" data-active="'+timerActive+'" data-timer-label="'+h(phaseLabel)+'"></strong><small>'+
    (started === null ? '创建：'+h(date(job.created))+' · 尚未开始安装' : '开始：'+h(date(started)))+
    '</small>'+followup+'<small class="duration-warning" hidden>已超过 10 分钟，请查看当前阶段与日志</small></div>';
}
function updateJobTimers() {
  const now = serverNow();
  document.querySelectorAll('[data-job-timer]').forEach(el => {
    const active = el.dataset.active === 'true', installed = el.dataset.installed === 'true';
    const seconds = Math.max(0, (active ? now : Number(el.dataset.end))-Number(el.dataset.start));
    el.textContent = !active && !installed ? '未开始安装' : (el.dataset.timerLabel || (installed ? (active?'安装用时 ':'安装耗时 ') : '等待用时 '))+duration(seconds);
    const overdue = active && installed && seconds > 600;
    el.parentElement.classList.toggle('overdue', overdue);
    el.parentElement.querySelector('.duration-warning').hidden = !overdue;
  });
  document.querySelectorAll('[data-phase-timer]').forEach(el => {
    const end=el.dataset.active==='true'?now:Number(el.dataset.end);
    el.textContent=duration(end-Number(el.dataset.start));
  });
  document.querySelectorAll('[data-followup-timer]').forEach(el => {
    const end=el.dataset.active==='true'?now:Number(el.dataset.end);
    el.textContent=el.dataset.label+duration(end-Number(el.dataset.start));
  });
}
function captureJobProgress(root) {
  return new Map([...root.querySelectorAll('progress[data-job-progress]')].map(el=>[el.dataset.jobProgress,el]));
}
function restoreJobProgress(root, previous) {
  root.querySelectorAll('progress[data-job-progress]').forEach(fresh => {
    const old = previous.get(fresh.dataset.jobProgress);
    if (!old) return;
    const value = fresh.getAttribute('value'), label = fresh.getAttribute('aria-label');
    fresh.replaceWith(old);
    old.getBoundingClientRect(); // Keep the existing width before transitioning to the new report.
    old.setAttribute('aria-label',label);
    old.setAttribute('value',value);
  });
}
function renderJobProgress(job) {
  const join=job.domain_join;
  if(join && join.state!=='pending'){
    const stages={waiting_release:join.released_at?'管理员已授权，等待客户端领取':(job.expires_at && job.expires_at<serverNow()?'等待加域已超时，请查看日志':'可先完成现场设置，再在平台统一加域'),checking:'检查域 DNS 与电脑名',joining:'正在加入 AD 域',restarting:'等待重启后验证域信任',verified:'域信任验证已通过',failed:'加域失败，不会重新装机'};
    const tone = join.state==='verified' ? ' completed' : join.state==='failed' ? ' stopped' : (join.state==='restarting'||join.state==='waiting_release'&&!join.released_at) ? ' pending' : '';
    return '<div class="job-progress'+tone+'"><span class="job-progress-phase">Windows 已安装 · '+h(stages[join.state]||join.state)+'</span><small>工号电脑名：'+h(join.computer_name)+' · 域：'+h(join.domain)+'</small>'+(join.updated?'<small>最后回报：'+h(date(join.updated))+'</small>':'')+'</div>';
  }
  const progress = job.progress;
  if (!progress || (job.state === 'failed' && job.review)) return '';
  const stages = {applying:'正在还原 WIM',boot_files:'WIM 还原已结束 · 正在配置 UEFI 引导',awaiting_report:'镜像还原及引导已完成 · 等待新系统回报'};
  if (!Object.hasOwn(stages, progress.stage)) return '';
  const completed = job.state === 'completed', stopped = ['failed','cancelled'].includes(job.state);
  const known = Number.isInteger(progress.percent) && progress.percent >= 0 && progress.percent <= 100;
  const restored = progress.stage === 'boot_files' || (job.kind === 'wim' && progress.stage === 'awaiting_report');
  const percent = completed || restored ? 100 : known && progress.stage === 'applying' ? progress.percent : null;
  const label = completed ? '安装后系统已回报' : (stopped ? '已停止 · ' : '') + stages[progress.stage];
  const tone = completed ? ' completed' : job.state === 'failed' ? ' stopped' : job.state === 'cancelled' ? ' cancelled' : progress.stage === 'awaiting_report' ? ' pending' : '';
  return '<div class="job-progress'+tone+'"><div class="job-progress-head"><span class="job-progress-phase">'+h(label)+'</span>'+(percent === null ? '<span class="job-progress-unknown">等待真实进度</span>' : '<strong class="job-progress-percent">'+percent+'%</strong>')+'</div>' +
    '<progress max="100" value="'+(percent ?? 0)+'" data-job-progress="'+h(job.id)+'" aria-label="'+h(label)+'"></progress>'+
    (Number.isFinite(progress.updated) ? '<small>最后回报：'+h(date(progress.updated))+'</small>' : '')+'</div>';
}
function renderLogEvents(events) {
  const kinds = {queued:['任务确认','muted'],preflight:['安装前检查','blue'],installing:['安装过程','blue'],
    awaiting_report:['等待回报','warn'],completed:['完成','good'],failed:['失败','bad'],cancelled:['取消','muted'],
    security:['执行设置','warn'],device:['设备登记','muted'],source:['安装源','muted'],profile:['装机方案','muted'],bootstrap:['启动包','muted'],review:['人工核对','muted'],domain_join:['自动加域','blue']};
  return events.map(e => {
    const [label,tone] = Object.hasOwn(kinds,e.kind) ? kinds[e.kind] : ['操作','muted'];
    return '<div class="log event-'+tone+'"><time>'+h(date(e.created))+'</time><div class="log-content"><span class="badge '+tone+'">'+h(label)+'</span><span class="log-message">'+h(e.message)+'</span></div></div>';
  }).join('');
}
function renderJobLogs() {
  const current = jobLog;
  if (!current || !$('#job-log')) return;
  const result = current.result, job = result?.job;
  const scroll = $('#modal').scrollTop;
  const previous = captureJobProgress($('#job-log'));
  $('#job-log').innerHTML = (job ?
    '<dl class="detail-grid"><div><dt>设备 / 整机序列号</dt><dd>'+h(deviceLabel(job))+'<br><span class="mono">'+h(job.serial)+'</span>'+(job.computer_name?'<br>工号电脑名：'+h(job.computer_name):'')+'</dd></div><div><dt>安装时间</dt><dd>'+renderJobTiming(job)+'</dd></div><div><dt>方案 / 目标盘</dt><dd>'+h(job.profile)+'<br>磁盘 '+h(job.disk.number)+' · '+h(size(job.disk.size_bytes))+'</dd></div><div><dt>任务状态</dt><dd>'+jobBadge(job)+renderJobProgress(job)+'</dd></div></dl><p class="job-log-id">任务编号：<span class="mono">'+h(job.id)+'</span></p>' : '') +
    '<div class="job-log-toolbar"><small>'+(current.before === null ? '最新记录在前 · 进行中每 8 秒刷新' : '正在查看历史记录')+'</small><div><button class="small" data-action="refresh-job-logs" '+(current.busy?'disabled':'')+'>'+(current.before === null?'刷新日志':'返回最新')+'</button> <button class="small" data-action="older-job-logs" '+(current.busy || !result?.next_before?'disabled':'')+'>更早记录</button></div></div>' +
    '<p id="job-log-error" class="error" role="alert" '+(current.error?'':'hidden')+'>'+h(current.error)+'</p><div class="log-list job-log-list">'+
    (result ? renderLogEvents(result.events) || empty('此任务暂无操作记录','尚未收到任务日志；已保存的记录不会因其他任务增多而消失。') : '<p class="modal-help">正在读取此任务日志…</p>')+'</div>';
  restoreJobProgress($('#job-log'), previous);
  updateJobTimers();
  $('#modal').scrollTop = scroll;
}
async function loadJobLogs(before = null, automatic = false) {
  const current = jobLog;
  if (!current || current.busy || !$('#modal').open || !$('#job-log')) return;
  current.busy = true;
  if (!automatic) renderJobLogs();
  try {
    const result = await api('/api/jobs/'+encodeURIComponent(current.id)+'/events'+(before === null?'':'?before='+encodeURIComponent(before)));
    if (jobLog !== current || !$('#modal').open || !$('#job-log')) return;
    syncServerClock(result.server_time);
    result.job = latestJob(result.job, result.server_time);
    current.before = before; current.result = result; current.error = '';
    if (data) {
      data.jobs = data.jobs.map(job => job.id === result.job.id ? result.job : job);
      if (view === 'jobs' || view === 'devices') render();
    }
  } catch (e) {
    if (jobLog === current) current.error = '日志读取失败：'+e.message;
  } finally {
    current.busy = false;
    if (jobLog === current && $('#modal').open) renderJobLogs();
  }
}
async function openJobLogs(id) {
  modal('任务操作日志', '<section id="job-log"></section>');
  jobLog = {id, before:null, result:null, busy:false, error:''};
  await loadJobLogs();
}
function canReleaseDomainJoin(job) {
  return job.state==='awaiting_report' && job.domain_join?.state==='waiting_release' &&
    !job.domain_join.released_at && Number.isFinite(job.installed_at) && job.expires_at>serverNow();
}
function updateJoinSelection() {
  const button=$('#release-selected-joins'); if(!button)return;
  button.disabled=joinSelection.size===0;
  button.textContent='统一加域并重启（'+joinSelection.size+' 台）';
  const master=$('#select-all-joins'), count=document.querySelectorAll('[data-job-join]').length;
  if(master){master.checked=count>0&&joinSelection.size===count;master.indeterminate=joinSelection.size>0&&joinSelection.size<count;}
}
function releaseJoinModal(ids) {
  const jobs=data.jobs.filter(job=>ids.includes(job.id)&&canReleaseDomainJoin(job));
  if(jobs.length!==ids.length||!jobs.length){toast('请刷新后选择已安装完成、待统一加域的电脑');return;}
  modal('统一加域并重启','<form id="domain-join-release-form"><p>以下电脑已完成 Windows 安装。确认后开始按工号改名、加入各自方案指定的域，并自动重启一次。请先保存现场设置和未保存的文件。</p><ul>'+jobs.map(job=>'<li>'+h(deviceLabel(job))+' · '+h(job.serial)+' · '+h(job.computer_name)+' · '+h(job.domain_join.domain)+'</li>').join('')+'</ul><label class="check-label"><input name="restart_confirmed" type="checkbox" required>已完成并保存这些电脑的设置，允许改名、加域并重启</label><div id="form-error" class="error" role="alert"></div><div class="form-actions"><button type="button" data-action="close">返回</button><button type="submit" class="primary">开始统一加域</button></div></form>');
  $('#domain-join-release-form').dataset.jobIds=JSON.stringify(ids);
}
function renderJobs() {
  const previous = captureJobProgress($('#page-content'));
  const ready=data.jobs.filter(canReleaseDomainJoin), readyIds=new Set(ready.map(job=>job.id));
  joinSelection=new Set([...joinSelection].filter(id=>readyIds.has(id)));
  const releaseToolbar=ready.length?'<div class="notice"><strong>有 '+ready.length+' 台 Windows 已安装，等待统一加域。</strong><p>完成现场设置后，勾选下方电脑，再统一执行。等待期间不会因加域额外重启；请在任务创建后 72 小时内执行。</p><button id="release-selected-joins" data-action="release-joins" class="primary" '+(joinSelection.size?'':'disabled')+'>统一加域并重启（'+joinSelection.size+' 台）</button></div>':'';
  $('#page-content').innerHTML = releaseToolbar+`<div class="table-wrap">${data.jobs.length?`<table><thead><tr>${ready.length?'<th class="check-cell"><input id="select-all-joins" type="checkbox" aria-label="全选待统一加域电脑" '+(joinSelection.size===ready.length?'checked':'')+'></th>':''}<th>设备</th><th>方案 / 目标盘</th><th>任务状态</th><th>安装时间 / 用时</th><th>操作</th></tr></thead><tbody>${data.jobs.map(j=>`<tr class="job-row" data-state="${h(j.state)}">${ready.length?'<td class="check-cell">'+(canReleaseDomainJoin(j)?'<input type="checkbox" data-job-join="'+h(j.id)+'" aria-label="选择 '+h(j.serial)+' 统一加域" '+(joinSelection.has(j.id)?'checked':'')+'>':'')+'</td>':''}<td><button class="inline-link cell-title job-device-link" data-action="job-device-detail" data-id="${h(j.id)}" title="查看电脑详细信息">${h(deviceLabel(j))}</button><span class="cell-sub mono">${h(j.serial)}</span>${j.computer_name?'<span class="cell-sub mono">工号电脑名：'+h(j.computer_name)+'</span>':''}${modelHint(j)}</td><td>${h(j.profile)}<span class="cell-sub">磁盘 ${j.disk.number} · ${h(size(j.disk.size_bytes))}</span></td><td>${jobBadge(j)}${renderJobProgress(j)}${j.stale?'<span class="cell-sub error">长时间未回报，需现场核对</span>':''}</td><td>${renderJobTiming(j)}</td><td>${canReleaseDomainJoin(j)?'<button class="small" data-action="release-joins" data-id="'+h(j.id)+'">执行加域</button> ':''}${['queued','preflight'].includes(j.state)?`<button class="small" data-action="cancel-job" data-id="${h(j.id)}">取消任务</button>`:j.state==='failed'?`<button class="small" data-action="review-job" data-id="${h(j.id)}">${j.review?'更新核对':'人工核对'}</button>`:activeStates.includes(j.state)&&j.stale?`<button class="small" data-action="reconcile-job" data-id="${h(j.id)}">结束异常记录</button>`:''} <button class="small job-log-button" data-action="job-logs" data-id="${h(j.id)}">查看日志</button></td></tr>`).join('')}</tbody></table>`:empty('暂无安装任务')}</div><div class="subheading"><h3>平台操作记录</h3><small>最近 100 条 · 任务日志请点击对应任务查看</small></div><div class="log-list">${renderLogEvents(data.events) || empty('暂无操作记录')}</div>`;
  restoreJobProgress($('#page-content'), previous);
  updateJoinSelection();
  updateJobTimers();
}

function validityLabel(days) { return days === null ? '永不过期' : (days ?? 7) + ' 天'; }
function validityFields(days=7) {
  return '<div class="field"><label>登记有效期</label><select name="validity_mode"><option value="limited" '+(days===null?'':'selected')+'>有限期（自定义天数）</option><option value="never" '+(days===null?'selected':'')+'>永不过期</option></select></div><div class="field"><label>有效天数</label><input name="days" type="number" min="1" max="3650" value="'+h(days??7)+'" '+(days===null?'disabled':'required')+'></div>';
}
function chosenValidity(f) { return {days:f.validity_mode==='never'?null:Number(f.days)}; }
function renderEnrollments() {
  const items = data.enrollments || [];
  return '<form id="enrollment-policy-form">'+validityFields(data.settings.enrollment_days)+'<p class="modal-help">保存后用于新登记包和新 ISO。已有 ISO 在下方单独修改，无需重做。仅控制 PE 报到，不会自动装机或到期关机。</p><button type="submit">保存新包有效期</button></form>' +
    (items.length ? '<div class="table-wrap"><table><thead><tr><th>登记包编号</th><th>到期时间</th><th>已登记次数</th><th>操作</th></tr></thead><tbody>' + items.map(e=>'<tr><td class="mono">'+h(e.id.slice(0,12))+'</td><td>'+h(e.expires_at===null?'永不过期':date(e.expires_at))+'</td><td>'+h(e.uses)+'</td><td><button class="small" data-action="edit-enrollment" data-id="'+h(e.id)+'">修改有效期</button> <button class="small" data-action="extend-enrollment" data-id="'+h(e.id)+'">续期至至少 7 天后</button> <button class="small" data-action="revoke-enrollment" data-id="'+h(e.id)+'">撤销</button></td></tr>').join('')+'</tbody></table></div>' : '');
}
function renderMediaStatus() {
  const media=data.media||{builders:[],builds:[]}, labels={queued:'等待领取',building:'制作中',uploading:'上传中',ready:'可下载',failed:'失败 / 已结束'};
  return (media.builds.length?'<div class="table-wrap"><table><thead><tr><th>制作任务</th><th>状态</th><th>操作</th></tr></thead><tbody>'+media.builds.map(j=>'<tr><td>'+h(j.id.slice(0,8))+' · '+(j.registration_only?'仅登记测试':'正常装机')+'<span class="cell-sub">'+h(date(j.created))+' · 登记包 '+h(j.enrollment_id.slice(0,12))+'</span></td><td>'+h(labels[j.state]||j.state)+'<span class="cell-sub">'+h(j.stage)+(j.stale?' · 长时间未回报，请检查制作电脑':'')+'</span></td><td>'+(j.state==='ready'?'<a class="button-link" href="'+API_BASE+'/api/media/'+encodeURIComponent(j.id)+'/download">下载 ISO</a><span class="cell-sub mono">SHA256: '+h(j.sha256)+'</span>':['queued','building','uploading'].includes(j.state)?'<button class="small" data-action="cancel-media" data-id="'+h(j.id)+'">结束制作记录</button>':'查看制作电脑的任务目录与 DISM 日志')+'</td></tr>').join('')+'</tbody></table></div>':'<p class="modal-help">制作进度与 ISO 文件在本机显示。</p>');
}
function renderMedia() {
  return '<section class="section" id="media-panel"><h3>本机制作 ISO</h3><p class="modal-help">直接在当前电脑制作，不需要注册或选择电脑。下载后完整解压，双击 Start-Build.cmd，允许管理员授权即可。程序优先复用本机已有 PE 和驱动，缺少文件时才提示选择一次。</p><form id="media-form"><div class="field"><label>启动模式</label><select name="mode"><option value="install">正常装机（仍需选盘并确认任务）</option><option value="registration">仅登记测试</option></select></div><label class="check-label"><input name="include_drivers" type="checkbox" checked>额外注入本机保存的签名驱动（PE 模板原有驱动始终保留）</label><p class="modal-help">本次使用已保存的登记有效期：'+h(validityLabel(data.settings.enrollment_days))+'。修改后先保存，再下载。</p><button type="submit" class="primary">下载本机制作包</button></form><p class="modal-help">制作进度在本机窗口显示，完成后自动打开 ISO 所在文件夹。不安装常驻程序，不写入 U 盘。</p><div id="media-status">'+renderMediaStatus()+'</div></section>';
}
async function downloadPackage(route,filename,payload) {
  const r=await fetch(API_BASE+route,{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/json'},body:JSON.stringify(payload??{name:$('#field-builder_name')?.value||'Windows 制作电脑'})});
  if(!r.ok)throw new Error((await r.json()).error||'下载失败');
  const url=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),3000);
}
function renderSettings() {
  const s = data.settings;
  $('#page-content').innerHTML = `<div class="settings-layout"><div><form id="settings-form"><section class="section"><h3>部署服务器</h3><div class="field"><label for="public-url">客户端访问地址</label><input id="public-url" name="public_url" value="${h(s.public_url)}" type="url" required><small>内网支持 HTTP，也支持 HTTPS。填写客户端能够访问的完整平台地址。</small></div><div class="field"><label for="ca-pem">HTTPS 内部根 CA 公共证书（可选，PEM）</label><textarea id="ca-pem" name="ca_pem" placeholder="-----BEGIN CERTIFICATE-----">${h(s.ca_pem)}</textarea><small>使用公开信任证书可留空。不要上传私钥、PFX 或域管理员凭据。</small></div><div class="field"><label for="concurrency">同时安装上限</label><input id="concurrency" name="concurrency" type="number" min="1" max="16" value="${s.concurrency}" required></div></section><section class="section"><h3>执行保护</h3><label class="check-label"><input type="checkbox" name="enabled" ${s.enabled?'checked':''}>启用真实任务下发</label><p class="modal-help">关闭后不再授权新安装；已经启动的 Windows Setup 不会被强行中断。</p><label class="check-label"><input name="isolated_network_confirmed" type="checkbox">已确认是隔离的装机网络，安装源账号仅有读取权限</label><div class="field"><label for="enable-confirm">开启时输入 ENABLE</label><input id="enable-confirm" name="confirmation" autocomplete="off" placeholder="ENABLE"></div></section><div class="error" id="settings-error" role="alert"></div><button type="submit" class="primary">保存设置</button></form><section class="section"><h3>准备客户端</h3><button data-action="bootstrap">下载 WinPE 登记与构建包 ↓</button><p class="modal-help">登记凭据有效期 ${h(validityLabel(s.enrollment_days))}；仅用于 PE 报到，不是装机倒计时。只构建 ISO，不格式化 U 盘；已有 Ventoy 可直接存放该 ISO。</p>${renderEnrollments()}</section>${renderMedia()}</div><aside><h3>引导环境</h3><ul class="requirements"><li><span>支持架构</span><span>UEFI x64</span></li><li><span>网络模式</span><span>现有 iPXE / 备用 Ventoy</span></li><li><span>DHCP</span><span>不托管、不修改</span></li><li><span>Windows 安装</span><span>原版 Setup / 封装 WIM 还原</span></li>${Object.entries(data.boot_files).map(([k,v])=>`<li><span class="mono">${h(k)}</span><span>${v?'已准备':'尚未准备'}</span></li>`).join('')}</ul><p class="modal-help">启动文件需由你授权的 ADK / iPXE 环境准备，平台不自动下载或运行未知二进制。</p><a href="/boot.ipxe" download="boot.ipxe">下载网络启动脚本 ↓</a></aside></div>`;
}
function modal(title, html) { deviceDialog = null; jobLog = null; $('#modal-title').textContent = title; $('#modal-body').innerHTML = html; $('#modal').showModal(); }
function field(label, name, type='text', value='', extra='') { const id = `field-${name}`; return `<div class="field"><label for="${id}">${h(label)}</label><input id="${id}" name="${name}" type="${type}" value="${h(value)}" ${extra}></div>`; }
function editSource(id) {
  const s = data.sources.find(x=>x.id===id);
  const manifest = s ? Object.fromEntries(Object.entries(s).filter(([k])=>!['id','revision','has_password'].includes(k))) : null;
  modal(s?'编辑安装源':'添加安装源', `<form id="source-form" data-id="${h(id||'')}"><div class="field"><label for="manifest-file">导入检测清单</label><input id="manifest-file" type="file" accept=".json,application/json"></div><div class="field"><label for="manifest">检测清单 JSON</label><textarea id="manifest" name="manifest" rows="12" required placeholder="粘贴 Inspect-InstallSource.ps1 的 JSON 输出">${h(manifest?JSON.stringify(manifest,null,2):'')}</textarea></div>${field('安装源专用只读账号密码','password','password','','autocomplete="new-password" maxlength="128" '+(s?'':'required'))}<p class="modal-help">${s?'密码留空表示保留已有密码。':'仅使用专用只读账号，不使用域管理员。'} 安装前仅复核文件可访问性、镜像版本和索引，不做整文件 SHA256 扫描。</p><div id="form-error" class="error" role="alert"></div><div class="form-actions"><button type="button" data-action="close">取消</button><button class="primary" type="submit">保存安装源</button></div></form>`);
}
function editProfile(id) {
  if (!data.sources.length) { toast('先添加安装源'); return; }
  const p = data.profiles.find(x=>x.id===id);
  modal(p?'编辑装机方案':'新建装机方案', `<form id="profile-form" data-id="${h(id||'')}"><div class="form-grid">${field('方案名称','name','text',p?.name||'','','')}<div class="field"><label for="source-choice">安装源</label><select id="source-choice" name="source_id" required>${data.sources.map(s=>`<option value="${h(s.id)}">${h(s.name)}</option>`).join('')}</select></div><div class="field full"><label for="image-choice">Windows 版本</label><select id="image-choice" name="image_index" required></select></div>${field('C 盘容量（GiB）','system_gib','number',p?.system_gib??0,'min="80" max="4096" required')}${field('计算机名前缀','computer_prefix','text',p?.computer_prefix||'PC','maxlength="6" required')}${field('临时本地管理员账号','username','text',p?.username||'ITSetup','required maxlength="20"')}${field('临时本地管理员密码','password','password','','autocomplete="new-password" minlength="12" maxlength="64" '+(p?'':'required'))}</div><p id="setup-profile-help" class="modal-help">只清空选中的一块物理硬盘。密码会写入 Windows 安装应答文件，编码不等于加密；装机后请更换，不建议长期共用。</p><div id="form-error" class="error" role="alert"></div><div class="form-actions"><button type="button" data-action="close">取消</button><button class="primary" type="submit">保存方案</button></div></form>`);
  $('.form-grid', $('#profile-form')).insertAdjacentHTML('beforeend', `<div class="full">${field('合法安装密钥（可选）','product_key','password','','maxlength="29" autocomplete="off" placeholder="留空使用已有 OEM / 企业许可配置"')}${p?.has_product_key?'<label class="check-label"><input name="clear_product_key" type="checkbox">移除已保存的安装密钥</label>':''}<small>此处不提供激活工具或授权。密钥留空不等于自动获得 Windows 授权。</small></div>`);
  $('#profile-form [name=name]').required = true;
  $('#profile-form').dataset.originalWim=String(p?.preserve_image_settings===true);
  if (p) $('#source-choice').value = p.source_id;
  $('.form-grid', $('#profile-form')).insertAdjacentHTML('afterbegin', '<div class="field"><label for="disk-mode">封装 WIM 分区方式</label><select id="disk-mode" name="disk_mode"><option value="wipe_disk">重建所选整盘（清空全部分区）</option><option value="system_partition">仅还原指定 Windows 分区（保留其他分区）</option></select></div><p id="wim-profile-help" class="modal-help full" hidden>沿用镜像内的软件、账号与授权配置。默认保留计算机名；启用自动加域后改为每台填写的员工工号。系统分区数据仍会清空；未做 OOBE 封装的镜像需首次管理员登录后启动安装后步骤。</p>');
  if(p?.disk_mode) $('#disk-mode').value=p.disk_mode;
  $('#disk-mode').closest('.field').insertAdjacentHTML('afterend','<div id="partition-layout-field" class="field"><label for="partition-layout">自动分盘方案</label><select id="partition-layout" name="partition_layout"><option value="single">单 C 盘：使用所选硬盘的可用空间</option><option value="split">C + D 盘：指定 C 盘容量，剩余空间创建 D 盘</option></select></div><p id="partition-plan-help" class="modal-help full"></p>');
  $('#partition-layout').value=p?.system_gib?'split':'single';
  $('#profile-form').dataset.splitGib=String(p?.system_gib||256);
  const join = p?.domain_join, defaults = data.settings.domain_defaults || {};
  $('.form-grid', $('#profile-form')).insertAdjacentHTML('beforeend',
    '<section class="section full"><label class="check-label"><input id="domain-join-enabled" name="join_enabled" type="checkbox" '+(join?'checked':'')+'>按员工工号改名并加入 AD 域</label><p class="modal-help">每台设备在工作台填写员工工号，原工号保留；电脑名重名时依次追加 A–Z，纯数字从 A 开始。需要域 DNS 和具备加域权限的 AD 账号。默认使用 HTTPS；隔离内网临时使用 HTTP 时须明确勾选下方选项。自动检查同名电脑并顺延字母，不覆盖已有电脑。加域成功后额外重启一次并验证。</p><label id="domain-join-http-option" class="check-label"><input id="domain-join-http" name="join_allow_http" type="checkbox" '+(join?.allow_http?'checked':'')+'>允许隔离内网 HTTP 加域（密码将明文传输）</label><p id="domain-join-http-notice" class="error" hidden>本方案已允许 HTTP。AD 账号验证不会加密传输；此设置只作用于使用本方案新建的任务。</p><p id="domain-join-https-error" class="error" hidden></p><div id="domain-join-fields" class="form-grid"><div class="field full"><label for="domain-join-mode">加域执行方式</label><select id="domain-join-mode" name="join_mode"><option value="automatic">安装完成后立即自动加域</option><option value="manual">先完成现场设置，再由平台勾选电脑统一加域</option></select><small>统一加域模式会等待管理员操作，不会提前改名、加域或额外重启；沿用任务创建后 72 小时有效期。</small></div>'+
    field('AD 域 DNS 名称','join_domain','text',join?.domain || defaults.domain || '','maxlength="253" placeholder="例如 corp.example.com"')+
    field('目标 OU（可选）','join_ou','text',join?.ou_path || defaults.ou_path || '','maxlength="500" placeholder="留空使用域默认的电脑位置"')+
    field('AD 加域账号','join_user','text',join?.username || '','maxlength="120" autocomplete="off"')+
    '<div class="field"><label for="field-join_password">加域密码 <span id="domain-join-password-status" class="badge muted"></span></label><input id="field-join_password" name="join_password" type="password" maxlength="128" autocomplete="new-password" aria-describedby="domain-join-password-help"><small id="domain-join-password-help" aria-live="polite"></small></div>'+
    '</div></section>');
  $('#domain-join-mode').value=join?.mode||'automatic';
  $('#profile-form').dataset.joinPassword=String(p?.has_domain_join_password===true);
  $('#profile-form').dataset.joinDomain=join?.domain || '';
  $('#profile-form').dataset.joinUser=join?.username || '';
  updateDomainJoinMode();
  updateImages(p?.image_index);
}
function updateDomainJoinMode() {
  const form=$('#profile-form'); if(!form)return;
  const enabled=$('#domain-join-enabled').checked;
  const secure=location.protocol==='https:' && data.settings.public_url.startsWith('https://');
  const toggle=$('#domain-join-http');
  toggle.disabled=!enabled||data.settings.http_allowed!==true;
  $('#domain-join-http-option').hidden=!enabled;
  const allowHttp=toggle.checked&&!toggle.disabled, ready=secure||allowHttp;
  $('#domain-join-http-notice').hidden=!enabled||!allowHttp;
  $('#domain-join-https-error').textContent=data.settings.http_allowed===true?'当前网页或客户端地址未启用 HTTPS；可配置 HTTPS，或明确允许本方案使用内网 HTTP。':'服务器禁止 HTTP 加域，请使用 HTTPS 网页和客户端地址。';
  $('#domain-join-https-error').hidden=!enabled||ready;
  $('#domain-join-fields').hidden=!enabled;
  $('#domain-join-fields').querySelectorAll('input,select').forEach(input=>{
    input.disabled=!enabled||!ready;
    input.required=enabled && ready && (input.name==='join_domain'||input.name==='join_user');
  });
  updateDomainJoinPassword();
}
function updateDomainJoinPassword() {
  const form=$('#profile-form'); if(!form)return;
  const password=form.elements.join_password, saved=form.dataset.joinPassword==='true';
  const reusable=saved && form.elements.join_domain.value.trim().toLowerCase()===form.dataset.joinDomain && form.elements.join_user.value.trim()===form.dataset.joinUser;
  password.required=!password.disabled&&!reusable;
  password.placeholder=reusable?'留空使用已保存的密码':'请输入加域密码';
  const state=password.value?['blue',saved?'待更新':'待保存','已输入新密码，保存方案后生效。']:
    reusable?['good','已保存','已保存密码，无需再次填写；留空继续使用。更换域名或加域账号后需重新填写，修改 OU 无需重填。']:
    saved?['warn','需重新填写','域名或加域账号已更改，请重新填写密码后保存；修改 OU 无需重填。']:
    ['muted','未设置','请填写该 AD 加域账号的密码，保存后无需重复填写。'];
  $('#domain-join-password-status').className='badge '+state[0];
  $('#domain-join-password-status').textContent=state[1];
  $('#domain-join-password-help').textContent=state[2];
}

function updateImages(index) { const s = data.sources.find(s=>s.id===$('#source-choice').value); $('#image-choice').innerHTML=(s?.images||[]).map(i=>`<option value="${i.index}">${h(i.name)} · 索引 ${i.index} · ${i.build}</option>`).join(''); if(index) $('#image-choice').value=index; updateProfileMode(); }
function updateProfileMode() {
  const form=$('#profile-form'); if(!form)return;
  const wim=data.sources.find(s=>s.id===$('#source-choice').value)?.kind==='wim';
  $('#disk-mode').disabled=!wim;
  $('#disk-mode').closest('.field').hidden=!wim;
  $('#wim-profile-help').hidden=!wim;
  $('#setup-profile-help').hidden=wim;
  for(const name of ['username','password','computer_prefix','product_key','clear_product_key']) {
    const el=form.elements.namedItem(name); if(!el)continue;
    el.disabled=wim; el.closest('.field, .check-label').hidden=wim;
    if(['username','computer_prefix'].includes(name)) el.required=!wim;
    if(name==='password') el.required=!wim&&(!form.dataset.id||form.dataset.originalWim==='true');
  }
  const preserve=wim&&$('#disk-mode').value==='system_partition';
  updatePartitionLayout(preserve);
}
function updatePartitionLayout(preserve) {
  const form=$('#profile-form'); if(!form)return;
  if(preserve===undefined)preserve=!$('#disk-mode').disabled&&$('#disk-mode').value==='system_partition';
  const layout=form.elements.partition_layout, capacity=form.elements.system_gib;
  if(Number(capacity.value)>0)form.dataset.splitGib=capacity.value;
  layout.disabled=preserve; $('#partition-layout-field').hidden=preserve;
  const split=!preserve&&layout.value==='split';
  capacity.disabled=!split; capacity.required=split; capacity.closest('.field').hidden=!split;
  if(split&&!Number(capacity.value))capacity.value=form.dataset.splitGib||'256';
  if(!split)capacity.value='0';
  $('#partition-plan-help').textContent=preserve?'保留现有 D 盘及其他分区，只重装明确选中的 Windows 分区；此模式不调整 C 盘容量。':'将重建所选整块硬盘，旧 C/D 盘数据都会清空。'+(split?'C 盘 '+capacity.value+' GiB，扣除引导和恢复分区后，其余空间自动创建 D 盘。':'除引导和恢复分区外，其余空间作为 C 盘。')+' 其他物理硬盘不处理，请先备份。';
}
function partitionPlan(profile) {
  if(profile?.disk_mode==='system_partition')return '保留 D 盘及其他分区，仅重装所选 Windows 分区，不调整 C 盘容量。';
  return '整盘重建：旧 C/D 数据全部清空。'+(profile?.system_gib?'C 盘 '+profile.system_gib+' GiB，扣除引导和恢复分区后，剩余空间创建 D 盘。':'扣除引导和恢复分区后，其余空间作为单 C 盘。');
}
async function preview() {
  const joining=!!selectedProfile()?.domain_join;
  const targets = [...chosen].map(id=>({device_id:id,disk_key:disks.get(id),...(preservesPartitions()?{partition_key:partitions.get(id)}:{}),...(joining?{employee_id:(employeeIds.get(id)||'').trim().toUpperCase()}:{})}));
  if(joining && targets.some(t=>!t.employee_id)){toast('请为每台选中的电脑填写员工工号，作为加域电脑名');return;}
  if(joining && targets.some(t=>!/^[A-Z0-9](?:[A-Z0-9-]{0,12}[A-Z0-9])?$/.test(t.employee_id))){toast('工号须为 1–14 位字母、数字或连字符，末尾预留重名字母');return;}
  if(targets.some(t=>!t.disk_key)) { toast('请为每台选中的电脑明确选择目标硬盘'); return; }
  if(preservesPartitions()&&targets.some(t=>!t.partition_key)){toast('请明确选择每台电脑要格式化的 Windows 分区');return;}
  const r = await api('/api/jobs/preview','POST',{profile_id:profileId,targets}); previewId = r.id;
  modal('确认批量安装', `<div class="notice danger">${h(r.warning)}<br>请先完成备份；启动安装后不能远程取消，也不会自动恢复原数据。</div><p>${h(r.profile)} · ${h(r.source)} · <strong>${r.targets.length} 台电脑</strong></p><p class="notice">${h(partitionPlan(selectedProfile()))}</p>${r.domain_join?'<p class="notice">按以下员工工号改名并加入域 '+h(r.domain_join.domain)+(r.domain_join.mode==='manual'?'。先完成 Windows 安装和现场设置，再由平台统一加域；确认执行后才会额外重启一次。':'。安装完成后自动加域，成功后额外重启一次。')+'同名时依次追加 A–Z，最终名称同步到任务与日志；不会覆盖已有电脑。'+(r.domain_join.allow_http?'<br><strong>本方案允许内网 HTTP 加域，密码将明文传输。</strong>':'')+'</p>':''}<div class="table-wrap"><table class="modal-table"><thead><tr><th>整机序列号</th><th>屏幕校验码</th>${r.domain_join?'<th>工号 / 预计电脑名</th>':''}<th>将处理的硬盘 / 分区</th></tr></thead><tbody>${r.targets.map(t=>`<tr><td class="mono">${h(t.serial)}</td><td class="mono">${h(t.boot_code)}</td>${r.domain_join?'<td class="mono">'+h(t.employee_id)+'<span class="cell-sub">预计 '+h(t.computer_name)+'</span></td>':''}<td>磁盘 ${t.disk.number} · ${h(t.disk.model)} · ${h(size(t.disk.size_bytes))}<span class="cell-sub mono">${h(t.disk.serial || t.disk.unique_id)}</span>${t.partitions?`<strong>只格式化分区 ${t.partitions.windows.number} · ${h(size(t.partitions.windows.size_bytes))}</strong><span class="cell-sub mono">${h(t.partitions.windows.guid)}</span>`:''}</td></tr>`).join('')}</tbody></table></div><form id="commit-form"><div class="section"><label class="check-label"><input name="physical_confirmed" type="checkbox" required>已现场核对整机序列号、屏幕校验码和硬盘，${preservesPartitions()?'确认所选 Windows 分区数据可删除，允许更新同盘 EFI 引导':'确认所选硬盘全部数据可删除'}</label></div>${field('输入 YES 确认本批安装','confirmation','text','','required autocomplete="off" pattern="YES"')}<div id="form-error" class="error" role="alert"></div>${!data.settings.enabled?'<p class="error">真实下发尚未开启。完成隔离验证后，在启动与设置中开启。</p>':''}<div class="form-actions"><button type="button" data-action="close">返回检查</button><button class="danger-button" type="submit" ${!data.settings.enabled?'disabled':''}>确认并执行安装</button></div></form>`);
}
function deviceInfoTable(headers, rows) {
  if (!rows.length) return '<p class="modal-help">此项尚未上报。</p>';
  return '<div class="table-wrap"><table class="modal-table inventory-table"><thead><tr>'+headers.map(x=>'<th>'+h(x)+'</th>').join('')+'</tr></thead><tbody>'+
    rows.map(row=>'<tr>'+row.map(value=>'<td>'+h(value ?? '未上报')+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>';
}
function renderDeviceInformation(d, job=null) {
  const report=d.system_info || {}, windows=report.source==='windows';
  const show=value=>firmwareText(value)||'未上报';
  const capacity=value=>Number.isFinite(value)&&value>0?size(value):'未上报';
  const modules=Array.isArray(report.memory_modules)?report.memory_modules:[];
  const ram=modules.reduce((sum,m)=>sum+(Number(m.capacity_bytes)||0),0)||report.ram_bytes||d.ram_bytes;
  const field=(label,value)=>'<div><dt>'+h(label)+'</dt><dd>'+h(value)+'</dd></div>';
  const section=(label,body)=>'<section class="device-detail-section"><h3>'+h(label)+'</h3>'+body+'</section>';
  const cpus=Array.isArray(report.cpus)?report.cpus:[];
  const networks=Array.isArray(report.networks)?report.networks:[];
  const disks=Array.isArray(d.disks)?d.disks:[];
  let html='<div class="device-info-heading"><span class="badge '+(windows?'good':'blue')+'">'+(windows?'安装后系统回报':'PE 硬件快照')+'</span>'+
    (report.reported_at?'<small>最后上报：'+h(date(report.reported_at))+'</small>':'<small>尚未收到详细配置回报，先展示已有硬件信息。</small>')+'</div>'+
    '<dl class="detail-grid">'+field('电脑型号',deviceLabel(d))+field('整机序列号',show(d.serial))+
    field(windows?'实际电脑名':'PE 临时电脑名',show(report.computer_name))+
    (job?field('计划电脑名 / 员工工号',show(job.computer_name)):field('屏幕校验码',show(d.boot_code)))+
    field('厂家 / 系列',[d.manufacturer,d.system_family].map(firmwareText).filter(Boolean).join(' / ')||'未上报')+
    field('内存容量',capacity(ram))+field('硬件 UUID',show(d.hardware_uuid))+
    field('启动方式 / 架构',[d.firmware,d.architecture].filter(Boolean).join(' / ')||'未上报')+
    field('Secure Boot / TPM 2.0',(typeof d.secure_boot==='boolean'?(d.secure_boot?'已启用':'未启用'):'未上报')+' / '+(typeof d.tpm2==='boolean'?(d.tpm2?'支持':'未确认'):'未上报'))+
    field('网卡 MAC',(d.macs||[]).join(' / ')||'未上报')+'</dl>';
  if(!windows)html+='<p class="modal-help">PE 临时电脑名不代表安装后的名称；Windows 信息在安装后回报时补齐。</p>';
  html+=section('Windows 与域信息','<dl class="detail-grid">'+
    field('Windows 版本',windows?show(report.os_name):'等待安装后回报')+
    field('版本号 / 内部版本',windows?[report.os_version,report.os_build].filter(Boolean).join(' / ')||'未上报':'等待安装后回报')+
    field('系统架构',windows?show(report.os_architecture):'等待安装后回报')+
    field('实际域状态',windows?(report.part_of_domain===true?'已加入 '+show(report.domain):report.part_of_domain===false?'未加入域 · '+show(report.domain):'未上报'):'等待安装后回报')+'</dl>');
  html+=section('处理器',deviceInfoTable(['CPU 型号','核心 / 线程','最大频率（固件报告）'],cpus.map(c=>[show(c.name),(c.cores||'—')+' 核 / '+(c.threads||'—')+' 线程',c.max_mhz?c.max_mhz+' MHz':'未上报'])));
  html+=section('内存条',deviceInfoTable(['插槽','容量','速率（固件报告）','厂家 / 型号'],modules.map(m=>[show(m.slot),capacity(m.capacity_bytes),m.speed_mhz?m.speed_mhz+' MHz':'未上报',[m.manufacturer,m.part_number].filter(Boolean).join(' / ')||'未上报'])));
  html+=section('装机前物理硬盘',deviceInfoTable(['编号 / 型号','序列号 / 标识','容量','总线','分区数'],disks.map(k=>[k.number+' / '+show(k.model),k.serial||k.unique_id||'未上报',capacity(k.size_bytes),show(k.bus),k.partition_count??(Array.isArray(k.partitions)?k.partitions.length:'未上报')])));
  if(windows)html+=section('安装后本地分区',deviceInfoTable(['盘符','文件系统','总容量','剩余容量'],(report.volumes||[]).map(v=>[show(v.letter),show(v.filesystem),capacity(v.size_bytes),Number.isFinite(v.free_bytes)?size(v.free_bytes):'未上报'])));
  html+=section('网卡与网络',deviceInfoTable(['网卡','MAC','IP 地址','驱动报告链路速率'],networks.map(n=>[show(n.name),show(n.mac),(n.addresses||[]).join(' / ')||'未分配',n.link_mbps>0?n.link_mbps+' Mbps':'未上报'])));
  html+=section('显卡',deviceInfoTable(['显卡名称','驱动版本'],(report.gpus||[]).map(g=>[show(g.name),show(g.driver_version)])));
  html+=section('主板与 BIOS','<dl class="detail-grid">'+field('主板厂家 / 型号',[report.board_manufacturer,report.board_model].filter(Boolean).join(' / ')||'未上报')+
    field('主板序列号',show(report.board_serial))+field('BIOS 厂家 / 版本',[report.bios_manufacturer,report.bios_version].filter(Boolean).join(' / ')||'未上报')+
    field('固件原始型号 / 产品版本',[d.model,d.product_version].filter(Boolean).join(' / ')||'未上报')+'</dl>');
  return html;
}
function renderJobDeviceDetail() {
  const job=data.jobs.find(j=>j.id===deviceDialog?.id);
  if(!job)return;
  const d={...(job.device_info||{}),model:job.model,serial:job.serial};
  for(const key of ['manufacturer','system_family','product_name','product_version','oem_model'])d[key]=job[key];
  if(!d.disks)d.disks=job.disk?[job.disk]:[];
  const scroll=$('#modal').scrollTop;
  $('#modal-body').innerHTML=renderDeviceInformation(d,job);
  $('#modal').scrollTop=scroll;
}
function jobDeviceDetail(id) {
  if(!data.jobs.some(j=>j.id===id))return;
  modal('电脑详细信息','');
  deviceDialog={id};
  renderJobDeviceDetail();
}

function deviceDetail(id) {
  const d = data.devices.find(x=>x.id===id); if(!d)return;
  modal('电脑详细信息', renderDeviceInformation(d));
  if (d.consumed && !currentJob(d)) {
    const actions = document.createElement('div'); actions.className = 'form-actions';
    const button = document.createElement('button'); button.textContent = '允许重新登记';
    button.dataset.action = 'rearm-device'; button.dataset.id = d.id;
    actions.append(button); $('#modal-body').append(actions);
  }
}
async function downloadBootstrap() {
  const r = await fetch(API_BASE + '/api/bootstrap',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/json'},body:'{}'});
  if(!r.ok) throw new Error((await r.json()).error || '下载失败');
  const url = URL.createObjectURL(await r.blob()), a = document.createElement('a'); a.href=url; a.download='pc-deploy-bootstrap.zip'; a.click(); setTimeout(()=>URL.revokeObjectURL(url),3000); toast('已下载登记包，有效期：'+validityLabel(data.settings.enrollment_days)); await refresh();
}
document.addEventListener('click', async e=>{
  const b=e.target.closest('[data-action],[data-view]'); if(!b)return;
  if(b.dataset.view){view=b.dataset.view;render();return;}
  try {
    const a=b.dataset.action,id=b.dataset.id;
    if(a==='close')$('#modal').close();
    else if(a==='new-source'||a==='edit-source')editSource(id);
    else if(a==='new-profile'||a==='edit-profile')editProfile(id);
    else if(a==='device-detail')deviceDetail(id);
    else if(a==='job-device-detail')jobDeviceDetail(id);
    else if(a==='review-job')reviewJob(id);
    else if(a==='job-logs')await openJobLogs(id);
    else if(a==='refresh-job-logs')await loadJobLogs();
    else if(a==='older-job-logs' && jobLog?.result?.next_before)await loadJobLogs(jobLog.result.next_before);
    else if(a==='rearm-device')modal('放行重新登记',`<form id="rearm-form" data-id="${h(id)}"><p>现场核对电脑状态后，允许重新进入 WinPE 登记。旧客户端会话会失效，不会自动创建或执行安装任务。</p>${field('输入 CHECKED','confirmation','text','','required pattern="CHECKED" autocomplete="off"')}<div id="form-error" class="error" role="alert"></div><div class="form-actions"><button type="button" data-action="close">返回</button><button class="primary" type="submit">允许重新登记</button></div></form>`);
    else if(a==='preview')await preview();
    else if(a==='view-jobs'){view='jobs';render();}
    else if(a==='bootstrap')await downloadBootstrap();
    else if(a==='edit-enrollment'){
      const entry=data.enrollments.find(item=>item.id===id);
      const days=entry.expires_at===null?null:Math.max(1,Math.ceil((entry.expires_at-data.server_time)/86400));
      modal('修改现有登记包有效期','<form id="enrollment-validity-form" data-id="'+h(id)+'"><p>仅修改此登记包，现有 ISO 无需重做。有限期从保存时重新计算。</p>'+validityFields(days)+'<button type="submit" class="primary">保存此包有效期</button></form>');
    }
    else if(a==='release-joins')releaseJoinModal(id?[id]:[...joinSelection]);
    else if(a==='revoke-enrollment')modal('撤销登记包','<form id="revoke-enrollment-form" data-id="'+h(id)+'"><p>此包不能再用于新 PE 报到，已登记客户端不受影响。</p><button type="submit" class="primary">确认撤销此包</button></form>');
    else if(a==='builder-package')modal('安装 Windows 制作端','<form id="builder-package-form">'+field('制作电脑名称','builder_name','text','','required maxlength="80"')+'<p>下载后解压，在 Windows 管理员 PowerShell 7 中运行 Install-Builder.ps1，完成一次性设置。</p><button type="submit" class="primary">下载安装包</button></form>');
    else if(a==='revoke-builder'||a==='cancel-media')modal(a==='revoke-builder'?'停用制作端':'结束制作记录','<form id="media-action-form" data-id="'+h(id)+'" data-kind="'+h(a)+'"><p>停止发布该任务产物，不关机、不删除文件，也不修改其他任务。</p><button type="submit" class="primary">确认</button></form>');

    else if(a==='extend-enrollment'){
      b.disabled=true;
      try { const result=await api('/api/enrollments/'+encodeURIComponent(id)+'/extend','POST',{}); toast('登记包有效期：'+(result.expires_at===null?'永不过期':date(result.expires_at))+'，现有 ISO 可继续使用'); await refresh(); }
      finally { b.disabled=false; }
    }
    else if(a==='cancel-job'||a==='reconcile-job')modal(a==='cancel-job'?'取消安装前任务':'人工结束异常记录',`<form id="job-action-form" data-id="${h(id)}" data-kind="${a}"><p>${a==='cancel-job'?'仅允许取消尚未启动安装或还原的任务。':'客户端长时间未回报。请先现场确认电脑已停止安装，再结束这条记录。结束后将不再接受此任务的自动成功回报；不会停止电脑或重新安装。'}</p>${a==='reconcile-job'?field('输入 CHECKED','confirmation','text','','required pattern="CHECKED" autocomplete="off"'):''}<div id="form-error" class="error" role="alert"></div><div class="form-actions"><button type="button" data-action="close">返回</button><button class="primary" type="submit">确认</button></div></form>`);
  } catch(err){toast(err.message);}
});
document.addEventListener('input',e=>{if(e.target.closest('#settings-form,#enrollment-policy-form,#media-form'))settingsDirty=true;if(e.target.dataset.employee)employeeIds.set(e.target.dataset.employee,e.target.value.toUpperCase());if(e.target.closest('#profile-form')&&['join_domain','join_user','join_password'].includes(e.target.name))updateDomainJoinPassword();if(e.target.id==='search'){search=e.target.value;renderDeviceRows();}});
document.addEventListener('change',async e=>{
  const el=e.target;
  if(el.name==='validity_mode'){
    const input=el.closest('form').querySelector('[name=days]');
    input.disabled=el.value==='never';input.required=!input.disabled;
  }
  if(el.dataset.device){el.checked?chosen.add(el.dataset.device):chosen.delete(el.dataset.device);el.closest('tr').classList.toggle('selected',el.checked);updateSelection();}
  if(el.dataset.disk){disks.set(el.dataset.disk,el.value);partitions.delete(el.dataset.disk);renderDeviceRows();}
  if(el.dataset.partition)partitions.set(el.dataset.partition,el.value);
  if(el.id==='filter'){filter=el.value;renderDeviceRows();}
  if(el.id==='profile-choice'){profileId=el.value;partitions.clear();renderDevices();}
  if(el.id==='domain-join-enabled'||el.id==='domain-join-http')updateDomainJoinMode();
  if(el.closest('#profile-form')&&['join_domain','join_user','join_password'].includes(el.name))updateDomainJoinPassword();
  if(el.id==='select-all'){filteredDevices().filter(selectable).forEach(d=>el.checked?chosen.add(d.id):chosen.delete(d.id));renderDeviceRows();}
  if(el.id==='source-choice')updateImages();
  if(el.id==='disk-mode')updateProfileMode();
  if(el.id==='partition-layout'||el.name==='system_gib')updatePartitionLayout();
  if(el.dataset.jobJoin){el.checked?joinSelection.add(el.dataset.jobJoin):joinSelection.delete(el.dataset.jobJoin);updateJoinSelection();}
  if(el.id==='select-all-joins'){data.jobs.filter(canReleaseDomainJoin).forEach(job=>el.checked?joinSelection.add(job.id):joinSelection.delete(job.id));document.querySelectorAll('[data-job-join]').forEach(box=>box.checked=el.checked);updateJoinSelection();}
  if(el.id==='manifest-file'&&el.files[0]){try{if(el.files[0].size>128000)throw new Error('清单文件过大');const value=JSON.parse(await el.files[0].text());$('#manifest').value=JSON.stringify(value,null,2);}catch(err){$('#form-error').textContent='清单读取失败：'+err.message;}}
});
document.addEventListener('submit',async e=>{
  const form=e.target;e.preventDefault();const f=Object.fromEntries(new FormData(form));
  const button=$('[type="submit"]',form);if(button)button.disabled=true;
  try {
    if(form.id==='source-form'){const m=JSON.parse(f.manifest);m.password=f.password;await api('/api/sources'+(form.dataset.id?'/'+form.dataset.id:''),form.dataset.id?'PUT':'POST',m);}
    else if(form.id==='profile-form'){
      f.image_index=Number(f.image_index);f.system_gib=Number(f.system_gib||0);f.clear_product_key=!!f.clear_product_key;
      if(f.join_enabled){
        const allowHttp=!!f.join_allow_http&&data.settings.http_allowed===true;
        if((location.protocol!=='https:'||!data.settings.public_url.startsWith('https://'))&&!allowHttp)throw new Error('请使用 HTTPS，或明确允许本方案使用内网 HTTP 加域');
        f.domain_join={enabled:true,domain:f.join_domain,ou_path:f.join_ou||'',username:f.join_user,allow_http:allowHttp,mode:f.join_mode||'automatic'};
        f.domain_join_password=f.join_password||'';
      }else f.domain_join={enabled:false};
      for(const key of ['join_enabled','join_allow_http','join_mode','join_domain','join_ou','join_user','join_password','partition_layout'])delete f[key];
      await api('/api/profiles'+(form.dataset.id?'/'+form.dataset.id:''),form.dataset.id?'PUT':'POST',f);
    }
    else if(form.id==='domain-join-release-form'){await api('/api/jobs/domain-join/release','POST',{job_ids:JSON.parse(form.dataset.jobIds),restart_confirmed:!!f.restart_confirmed});joinSelection.clear();}
    else if(form.id==='commit-form'){await api('/api/jobs/commit','POST',{preview_id:previewId,confirmation:f.confirmation,physical_confirmed:!!f.physical_confirmed});chosen.clear();view='jobs';}
    else if(form.id==='enrollment-policy-form'){await api('/api/enrollment-policy','POST',chosenValidity(f));settingsDirty=false;}
    else if(form.id==='enrollment-validity-form')await api('/api/enrollments/'+encodeURIComponent(form.dataset.id)+'/validity','POST',chosenValidity(f));
    else if(form.id==='revoke-enrollment-form')await api('/api/enrollments/'+encodeURIComponent(form.dataset.id)+'/revoke','POST',{});
    else if(form.id==='media-form'){await downloadPackage('/api/local-media/package','pc-deploy-local-build.zip',{registration_only:f.mode==='registration',include_drivers:!!f.include_drivers});settingsDirty=false;toast('制作包已下载：解压后双击 Start-Build.cmd，在本机生成 ISO');await refresh();return;}
    else if(form.id==='builder-package-form'){await downloadPackage('/api/builders/package','pc-deploy-builder.zip');}
    else if(form.id==='media-action-form')await api(form.dataset.kind==='revoke-builder'?'/api/builders/'+encodeURIComponent(form.dataset.id)+'/revoke':'/api/media/'+encodeURIComponent(form.dataset.id)+'/cancel','POST',{});
    else if(form.id==='settings-form'){await api('/api/settings','POST',{...f,concurrency:Number(f.concurrency),enabled:!!f.enabled,isolated_network_confirmed:!!f.isolated_network_confirmed});settingsDirty=false;toast('设置已保存');await refresh();return;}
    else if(form.id==='job-review-form')await api('/api/jobs/'+encodeURIComponent(form.dataset.id)+'/review','POST',{outcome:f.outcome,note:f.note,physical_confirmed:!!f.physical_confirmed});
    else if(form.id==='job-action-form'){await api(`/api/jobs/${form.dataset.id}/${form.dataset.kind==='cancel-job'?'cancel':'reconcile'}`,'POST',f);}
    else if(form.id==='rearm-form'){await api(`/api/devices/${form.dataset.id}/rearm`,'POST',f);}
    else return;
    if($('#modal').open)$('#modal').close();toast('操作成功');await refresh();
  } catch(err){const output=form.id==='settings-form'?$('#settings-error'):$('#form-error');if(output)output.textContent=err.message;else toast(err.message);}
  finally {if(button)button.disabled=false;}
});
$('#close-modal').addEventListener('click',()=>$('#modal').close());
$('#refresh').addEventListener('click',refresh);
$('#modal').addEventListener('close',()=>{
  if (!$('#modal').open) {
    deviceDialog = null;
    const wasJobLog = jobLog !== null;
    jobLog = null;
    if (wasJobLog) refresh();
  }
});
setInterval(()=>{if(!document.hidden)updateJobTimers();},1000);
setInterval(()=>{
  if (document.hidden) return;
  if (!$('#modal').open || deviceDialog) refresh();
  else if (jobLog?.before === null && activeStates.includes(jobLog.result?.job.state)) loadJobLogs(null, true);
},8000);
window.addEventListener('message', event => {
  if (!embedded || event.origin !== location.origin || event.source !== window.parent) return;
  if (event.data && event.data.type === 'pc-deploy:navigate' && Object.hasOwn(labels, event.data.view)) {
    view = event.data.view;
    render();
  }
});
init();
