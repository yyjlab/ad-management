# AD Management

AD 用户注册、密码修改和后台管理平台。前端静态页面与 Flask 后端分别构建镜像，不需要单独编译。

## Jenkins 构建

在仓库根目录执行，得到两个镜像；推送 SWR 时使用 Jenkins 中配置的镜像仓库和版本号。

```bash
docker build -f Dockerfile.backend -t employee-be:latest .
docker build -f Dockerfile.frontend -t employee-fe:latest .
```

后端安装依赖后才复制源码，普通代码更新可复用依赖层。前端只复制 HTML 和 Nginx 配置，不包含后端代码。

后端默认使用官方 PyPI，下载连接超时为 120 秒、连接重试 10 次。Jenkins 下载慢或超时时，可在后端构建命令中指定清华 PyPI 镜像；只影响本次构建，不修改服务器配置：

```bash
docker build -f Dockerfile.backend --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple -t swr.cn-south-1.myhuaweicloud.com/recovery-uat/be-ad:test${BUILD_NUMBER} .
```

## 运行配置

后端仍需挂载服务器原有的 `config.py`，保留其中的 AD、数据库和邮件配置。钉钉参数在服务器的 `.env` 中填写，不要提交到 Git 或打进镜像：

```dotenv
DINGTALK_LOGIN_ENABLED=true
DINGTALK_LOGIN_CLIENT_ID=填写应用的ClientID
DINGTALK_LOGIN_CLIENT_SECRET=填写应用的ClientSecret
DINGTALK_LOGIN_REDIRECT_URI=https://你的平台域名/api/admin/dingtalk/callback
```

Compose 已通过 `env_file` 读取 `/app/employee_register/be/.env`，不使用钉钉时可参考 `.env.example` 保持关闭。回调地址须与实际访问平台的协议、域名、端口一致，并在钉钉开发者后台配置相同地址。详细权限和排障见 [钉钉登录](DINGTALK_LOGIN.md)。

## Compose 部署

服务器使用 `/opt/ad-management/compose.yaml`，只管理 AD 前后端，复用现有 `employee-net`，不创建数据库或 WUD 服务。

1. 将 `compose.yaml` 的两条 `image` 标签 `REPLACE_WITH_PUBLISHED_TEST_TAG` 分别替换为 SWR 已成功推送的 `testN`，前后端版本号可以不同。镜像地址必须直接写在 Compose 中，不能改成环境变量，否则现有 WUD 无法匹配并写回版本。
2. 在 `/app/employee_register/be/.env` 填写钉钉参数，原 `config.py`、数据和密钥不变。已有 `.env` 只补充需要的配置，不覆盖原值。
3. 首次接管前先做一致性备份并安排短暂停机。原 `employee-be`、`employee-fe` 尚存在时不能直接启动同名 Compose 容器；需确认后停用并改名保留旧容器。不要删除原数据，不运行 `down -v` 或 `--remove-orphans`。

准备后先执行只读检查，确认数据库非空、所需文件存在及 Compose 格式正确：

```bash
test -s /app/employee_register/be/instance/employee_register.db
ls -l /app/employee_register/be/{config.py,.flask_secret_key,.env,register.log,reset.log,admin.log}
docker compose -p ad-management -f /opt/ad-management/compose.yaml config --quiet
```

仅在备份、镜像版本及旧容器接管均已确认后执行启动；会启动 AD 服务并使用原 SQLite，现有初始化逻辑可能补建缺失表：

```bash
docker compose -p ad-management -f /opt/ad-management/compose.yaml pull backend web
docker compose -p ad-management -f /opt/ad-management/compose.yaml up -d --no-build --wait --wait-timeout 180 backend web
```

## 接入现有 WUD

AD 服务已配置共享触发器，只接受递增的 `testN` 标签。先验证 AD 能正常访问，再在服务器 `/opt/asset-management/compose.wud.yaml` 的 `wud.volumes` 下追加以下挂载，保留原挂载、凭据和 WUD 数据卷：

```yaml
- /opt/ad-management:/opt/ad-management:rw
```

此处只给 WUD 挂载 Compose 配置目录，不挂载 AD 数据、密钥或 `.env`。随后需单独重建 WUD 容器使挂载生效；这会短暂停止所有项目的镜像监测，不能运行资产项目的整体 `up/down`。

接入后 Jenkins 推送新版本，WUD 会更新容器并写回服务器的 Compose 镜像标签。不要用 Git 文件覆盖 WUD 已写回的服务器版本。共享触发器已有的配置备份、禁用清理和健康检查回滚继续适用；回滚容器不等于回滚数据库，前后端独立更新也不是原子发布。

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

Compose 不再将整个 `be` 目录挂到 `/app`，也不再挂载旧前端源码和旧 `nginx.conf`，否则会遮住镜像更新。服务器原目录无需删除。前端使用镜像内 Nginx 配置，通过 Docker DNS 重新解析后端地址，支持 WUD 单独替换后端；原 Nginx 如有额外自定义项，切换前需确认并合并，不能直接覆盖这套配置。

以上为部署配置和操作说明，仓库开发不执行生产容器的停止、替换或数据迁移。

## 手动验证

部署后可用以下只读命令查看状态；健康检查只检查 Web 接口，不代表 AD 或钉钉认证成功。

```bash
docker ps --filter name=employee-
docker logs --tail 50 employee-be
docker logs --tail 50 employee-fe
curl -fsS http://127.0.0.1/api/admin/check
curl -fsS http://127.0.0.1/api/admin/dingtalk/status
```
