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
