# AD Management

AD 用户注册、密码修改和后台管理平台。前端静态页面与 Flask 后端分别构建镜像，不需要单独编译。

## Jenkins 构建

在仓库根目录执行，得到两个镜像；推送 SWR 时使用 Jenkins 中配置的镜像仓库和版本号。

```bash
docker build -f Dockerfile.backend -t employee-be:latest .
docker build -f Dockerfile.frontend -t employee-fe:latest .
```

后端安装依赖后才复制源码，普通代码更新可复用依赖层。前端只复制 HTML 和 Nginx 配置，不包含后端代码。

## 运行配置

后端仍需挂载服务器原有的 `config.py`，保留其中的 AD、数据库和邮件配置。钉钉参数在服务器的 `.env` 中填写，不要提交到 Git 或打进镜像：

```dotenv
DINGTALK_LOGIN_ENABLED=true
DINGTALK_LOGIN_CLIENT_ID=填写应用的ClientID
DINGTALK_LOGIN_CLIENT_SECRET=填写应用的ClientSecret
DINGTALK_LOGIN_REDIRECT_URI=https://你的平台域名/api/admin/dingtalk/callback
```

启动后端容器时传入 `--env-file /app/employee_register/be/.env`；仅创建 `.env` 文件不会自动生效。回调地址须与实际访问平台的协议、域名、端口一致，并在钉钉开发者后台配置相同地址。详细权限和排障见 [钉钉登录](DINGTALK_LOGIN.md)。

## 保留现有数据

当前服务器为 `172.168.30.202`。后续切换镜像时继续使用 `employee-be`、`employee-fe` 容器名及 `employee-net` 网络，前端发布 `80:80`，后端仅使用容器内 `5000` 端口。必须保留以下已有文件和挂载：

| 服务器原有路径 | 后端容器内路径 | 用途 |
| --- | --- | --- |
| `/app/employee_register/be/config.py` | `/app/config.py` | 原有配置，只读挂载 |
| `/app/employee_register/be/instance` | `/app/instance` | SQLite 数据目录，读写挂载 |
| `/app/employee_register/be/.flask_secret_key` | `/app/.flask_secret_key` | 原会话密钥，只读挂载 |
| `/app/employee_register/be/register.log` | `/app/register.log` | 原注册日志，读写挂载 |
| `/app/employee_register/be/reset.log` | `/app/reset.log` | 原密码日志，读写挂载 |
| `/app/employee_register/be/admin.log` | `/app/admin.log` | 原管理日志，读写挂载 |

不要删除或替换这些数据。切换前应备份 SQLite 数据目录及配置、密钥；运行中的 SQLite 应使用一致性备份，不能只复制正在写入的 `.db` 文件。现有初始化逻辑可能自动补建缺失表，不会因构建镜像而清空数据。

使用镜像里的新代码时，不再将整个 `be` 目录挂到 `/app`，也不再将整个 `fe` 目录挂到 `/usr/share/nginx/html`，否则旧源码会遮住镜像内容。服务器原目录无需删除。前端可继续单独挂载原 `nginx.conf`，但它会覆盖镜像内配置，需确认仍转发完整 `/api/` 路径到 `employee-be:5000`。

本次仅提供构建文件，不执行现有容器的停止、替换或数据迁移。

## 手动验证

部署后可用以下只读命令查看状态；健康检查只检查 Web 接口，不代表 AD 或钉钉认证成功。

```bash
docker ps --filter name=employee-
docker logs --tail 50 employee-be
docker logs --tail 50 employee-fe
curl -fsS http://127.0.0.1/api/admin/check
curl -fsS http://127.0.0.1/api/admin/dingtalk/status
```
