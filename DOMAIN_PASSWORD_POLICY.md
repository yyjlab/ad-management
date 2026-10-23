# 域密码策略

后台“域密码策略”可读取、预览并保存真实 GPO 的八项密码设置，仅超级管理员可用。其他菜单和原有 AD 域对象只读接口不变。

## 一次性接入

先在服务器原 `.env` 中补充以下配置，不覆盖现有内容。首次只启用读取：

```dotenv
GPO_PASSWORD_POLICY_ENABLED=true
GPO_PASSWORD_POLICY_WRITE_ENABLED=false
GPO_PASSWORD_POLICY_GUID=31b2f340-016d-11d2-945f-00c04fb984f9
```

默认目标为 Default Domain Policy。目标必须已启用计算机安全策略、包含安全模板、启用链接到域根，且无 WMI 筛选。不要指向 Default Domain Controllers Policy。

需要后端到同一域控的 LDAPS 和加密 SMB3（TCP 445）可用，以及目标 GPO 的 AD/SYSVOL 权限。GPO 接口强制验证域控证书：默认使用 `AD_SERVER` 和系统 CA；私有 CA 可放在持久化目录中，例如 `/app/instance/ad-ca.pem`，再配置 `GPO_LDAP_CA_CERTS_FILE` 为此容器路径。若 `AD_SERVER` 是 IP 而证书只包含 DNS 名，须将 `GPO_LDAP_SERVER` 配为同一域控的证书名称（例如 `DC01.wfq.com`），并确保容器可正确解析。不会关闭证书验证。

默认复用 `config.py` 的 AD 账号密码；若绑定账号为 `CN=...`，须另配 `GPO_SMB_USERNAME`（UPN 或 `DOMAIN\user`）和 `GPO_SMB_PASSWORD`。当前 SMB 使用 NTLM；域禁用 NTLM 时会拒绝，不会自动降低认证或加密要求。不要将密码提交到仓库。

环境变量需要重建后端容器才生效，普通 restart 不会载入新值；安排操作窗口，保留原数据挂载。确认读取的 GPO 名称、版本和域控正确后，再将 `GPO_PASSWORD_POLICY_WRITE_ENABLED` 设为 `true` 并重建后端。

正式开放写入应通过 HTTPS 访问平台，保护管理员会话；接入密码错误也可能触发 AD 账号锁定，遇到认证失败不要连续刷新重试。

## 日常使用

打开菜单读取真实配置，修改后点击“预览变更”，核对差异并输入 `YES` 保存。读取与预览不修改 AD/SYSVOL。密码最长使用期限 `0` 表示永不过期；留空表示未定义，不等于零。超过 14 字符须启用放宽限制，并确认域控版本支持。

保存只更新八个白名单设置，保留锁定、Kerberos、用户权限等其他内容，同时更新 GPO 计算机版本号。每次保存前备份原始文件和版本到持久化目录 `/app/instance/gpo_password_policy_backups/<备份编号>/`，不自动清理。开始/完成记录写入管理员审计；故障日志会包含备份编号。

保存成功仅表示 GPO 写入和回读一致，不表示域控或终端已经应用。平台不强制刷新组策略、不重启域控、不修改细粒度密码策略。其他 GPO、筛选和操作系统版本仍可能影响实际结果。将注册表策略改为“未定义”不会主动恢复已应用的注册表值。

## 故障核查

发生版本冲突先刷新，不覆盖他人的新版本。保存失败会尝试恢复并回读；若提示“结果不确定”，停止再次保存，依据备份编号同时核查 `GptTmpl.inf`、`GPT.ini` 与 AD 中的 `versionNumber`，必要时由域管理员恢复。SMB 文件锁与版本检查不能提供跨 AD、SYSVOL、复制和进程崩溃的完整事务保证，不要与 GPMC 同时编辑。

本地验证使用离线 LDAP 和模拟 SMB，未连接生产域控。正式开放写入前，须在测试域验证 GPMC 显示、域控应用、权限及故障恢复。

实现参考 [Samba GPO](https://github.com/samba-team/samba/blob/master/python/samba/netcmd/gpo.py)、[smbprotocol](https://github.com/jborean93/smbprotocol) 和微软 [安全策略协议](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/b1306ea4-6860-4da6-811e-1fe1d1815832)，未引入 Samba 或通用远程命令执行服务。

## 设备组策略

“组策略管理”与原密码策略相互独立，仅超级管理员可用。接入及日常流程如下：

1. 一次性在 GPMC 新建三个独立 GPO，例如 `AD-Office-Lock`、`AD-Office-USB`、`AD-Office-Software`，启用链接到 `wfq.com` 域根。不使用默认域策略，不与其他业务共用 GPO。创建及链接影响整个域的适用对象，应由域管理员安排操作。
2. 在 GPMC 创建并为三个 GPO 绑定同一个 WMI 筛选，命名空间为 `root\CIMv2`，仅包含查询 `SELECT * FROM Win32_OperatingSystem WHERE ProductType = 1`。这是全域办公电脑范围，不是单一 OU；域控和服务器不能通过此筛选。平台校验查询，缺失或未知筛选会拒绝读取和保存，不自动创建链接或更改筛选。
3. 后端需具备上文的 LDAPS、加密 SMB、GPO 编辑及 SYSVOL 文件权限。软件还需一个可信共享目录：域用户只读，发布管理员可写，禁止普通用户替换 EXE。软件只适合不依赖旁边 DLL、配置文件等内容的单个绿色 EXE，不上传 EXE 到 SYSVOL。

一次性在服务器原 `.env` 补充以下项目，GUID 从三个 GPO 的“详细信息”复制。先只读接入，勿覆盖原配置：

```dotenv
GPO_ENDPOINT_POLICY_ENABLED=true
GPO_ENDPOINT_POLICY_WRITE_ENABLED=false
GPO_ENDPOINT_LOCK_GUID=填写锁屏GPO的GUID
GPO_ENDPOINT_USB_GUID=填写U盘GPO的GUID
GPO_ENDPOINT_SOFTWARE_GUID=填写软件GPO的GUID
GPO_SOFTWARE_SOURCE_ROOT=\\files.wfq.com\Software
```

前后端均需更新到包含新菜单的镜像；修改 `.env` 后需在维护窗口重建后端容器，保留原有数据挂载。确认三个 GPO 读取正常，并在测试域验证后，才将 `GPO_ENDPOINT_POLICY_WRITE_ENABLED` 改为 `true` 并重建后端。日常修改在页面完成，不需要每次改 `.env`。不需要安装客户端或配置客户端领取任务。

日常选择一项策略，读取当前 GPO，修改后预览，勾选范围确认并输入 `YES` 保存。页面不是 RSoP 报告：阻止继承、安全筛选、其他 GPO、终端防护或操作系统差异均会影响结果。

- 锁屏以分钟输入、整数秒保存到安全模板。`0` 关闭此 GPO 的空闲锁屏，“未配置”不主动清除机器已应用的安全值。不会注销用户、禁用 AD 账号或修改其他屏保/电源策略；其他策略可能更早锁屏。微软文档列有重启要求，需在测试机验证，平台不主动重启。
- U盘功能只编辑可移动磁盘类别的 `Deny_Read` 和 `Deny_Write`，写入标准 `Machine\Registry.pol`，不关闭全部 USB 接口。允许读写不保证能覆盖其他拒绝策略或 BitLocker 限制。
- 软件填写共享根目录内的 `.exe` 完整 UNC 路径及说明。标准用户组策略首选项负责复制到 `%LOCALAPPDATA%\AD-<软件GPO_GUID前12位>.exe`，创建 `AD-<同一标识>` 桌面快捷方式，说明显示为快捷方式注释。以当前用户身份运行，不自动启动、不提权、不安装服务。共享软件本身及复制成功需要人工验证；平台没有终端执行回执。正在运行的 EXE 可能不能覆盖，需用户关闭后等待策略重新应用。停止下发会撤销本平台快捷方式，但不删除本地 EXE、软件数据或其他首选项。

每次写入前备份到持久化目录 `/app/instance/gpo_endpoint_backups/<备份编号>/`。`metadata.json` 记录 AD 元数据、文件路径和原文件是否存在，原文件保存为编号 `.bin`。版本冲突不覆盖；保存失败尝试恢复并回读，恢复不确定时停止操作并人工核查备份、目标文件、GPO 扩展和 AD/GPT 版本。不要与 GPMC 同时编辑；进程崩溃、域控复制以及 AD/SMB 之间无法获得完整事务保证。

当前验证为离线 LDAP、模拟 SMB 和模拟接口页面测试，未验证真实域控复制、GPMC 展示和 Windows 终端应用。格式依据微软 [空闲锁屏](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit)、[可移动存储策略](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-removablestorage) 及 [组策略首选项](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-preferences) 文档。
