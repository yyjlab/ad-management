# 钉钉登录

登录页支持电脑钉钉快捷授权和扫码登录。本企业在职成员首次登录自动创建平台只读账号，不创建 AD 域账号。账号密码登录继续可用。

## 一次性配置

在钉钉企业内部应用启用网页登录，配置应用可见范围及用户个人信息、企业通讯录读取权限。回调地址填写：

```text
http://ad.wfq.com/api/admin/dingtalk/callback
```

`http://ad.wfq.com/admin` 是登录入口，不是回调接口。asset 的 `/api/v1/auth/dingtalk/callback` 也不能直接用于 AD。若共用同一个钉钉应用，应保留 asset 原回调并新增 AD 回调，不能覆盖 asset 的地址。

在服务器现有 `/app/employee_register/be/.env` 中补充配置，不覆盖已有参数；Compose 已通过 `env_file` 读取它。参考：

```dotenv
DINGTALK_LOGIN_ENABLED=true
DINGTALK_LOGIN_CLIENT_ID=填写AD所用钉钉应用的ClientID
DINGTALK_LOGIN_CLIENT_SECRET=填写该应用的ClientSecret
DINGTALK_LOGIN_REDIRECT_URI=http://ad.wfq.com/api/admin/dingtalk/callback
```

环境变量更改后需重建后端容器才会重新载入，普通 restart 不会载入新值；安排操作窗口并保留原数据挂载。正式环境建议统一使用 HTTPS，届时登录地址与回调地址一起切换。

服务器环境变量或外部 `config.Config` 使用以下同名配置。密钥不要提交到仓库。

| 配置 | 值 |
| --- | --- |
| `DINGTALK_LOGIN_ENABLED` | `true` 开启，默认 `false` |
| `DINGTALK_LOGIN_CLIENT_ID` | 企业内部应用的 Client ID / AppKey |
| `DINGTALK_LOGIN_CLIENT_SECRET` | 对应的 Client Secret / AppSecret |
| `DINGTALK_LOGIN_REDIRECT_URI` | 上面的完整回调地址，必须与登录页的协议、域名和端口一致 |
| `DINGTALK_LOGIN_STATE_TTL_SECONDS` | 可选，默认 `600`，范围 `60–1800` 秒 |
| `DINGTALK_LOGIN_TIMEOUT_SECONDS` | 可选，默认 `10`，范围 `1–30` 秒 |

更新后端 `app.py`、`dingtalk_auth.py` 和前端 `admin_login.html`、`admin_manage.html`。现有启动流程自动新增 `ding_talk_account`、`ding_talk_login_state` 两张表，数据库账号需有建表权限；已有表不需要改列。所有后端 worker 必须共用数据库和稳定的 Flask Secret Key。

Nginx 需将 `/api/admin/dingtalk/` 请求转发给后端，保留完整路径、查询参数及 Cookie。浏览器需能访问 `login.dingtalk.com`，后端需能通过 HTTPS 访问 `api.dingtalk.com`、`oapi.dingtalk.com`。

## 日常使用

打开 `/admin`，点击“钉钉快捷授权登录”；也可选择扫码。配置未启用或不完整时入口隐藏。首次登录后无需人工建平台账号。

新账号的内部用户名为 `dt_` 开头，页面显示企业通讯录姓名。现有角色和权限规则继续生效：只读角色能查看用户和数据概览。钉钉姓名相同也不会自动关联已有管理员。每次钉钉登录均重新核验成员状态；平台账号停用后拒绝再次登录。

删除平台账号会移除其钉钉对应记录；仍在企业应用范围内的成员再次登录会创建新的只读账号。需要禁止登录时使用“停用账号”。退出平台只退出平台会话，电脑钉钉可能仍保持登录。

企业成员核验发生在钉钉登录时，已登录的平台会话不会因钉钉离职立即失效；需要立即阻止访问时同时停用平台账号。更换 Client ID 后身份对应记录会变化，可能产生新的只读账号。

## 验证与排障

部署后访问 `/api/admin/dingtalk/status`，返回 `{"enabled":true}` 表示配置检查通过。再验证首次授权、重复登录、扫码及原账号密码登录。

“授权会话已过期”：重新点击登录，确认登录域名与回调地址一致、Cookie 正常、各 worker 使用同一数据库和 Secret Key。

“无法核验本企业成员”：检查应用类型、可见范围及企业通讯录权限；个人授权成功并不等于已通过企业成员核验。

本地回归测试使用内存数据库并模拟钉钉响应，不访问真实 AD 或钉钉，不修改部署数据库：

Windows 测试环境若缺少时区数据，还需安装 `tzdata`；生产 Linux 的依赖清单没有变化。

```powershell
python -B -m unittest test_dingtalk_login
```

关闭 `DINGTALK_LOGIN_ENABLED` 即可停用入口，原账号密码登录保持可用。真实授权和反向代理链路需在部署环境验证。
