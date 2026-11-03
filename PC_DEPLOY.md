# 电脑装机

在 AD 管理后台展开“电脑装机”，选择设备工作台、安装源、装机方案、任务记录或启动与设置，内容显示在右侧。共用后台登录，仅超级管理员可用，无需单独启动服务或设置装机平台密码。独立页面地址仍为 `/pc-deploy/`。

默认关闭真实任务下发。支持 UEFI x64、Windows 11 / Windows 10 简体中文或英语的两种方式：原版 Setup 安装、封装 WIM 直接还原。原版安装保留原有整盘流程；WIM 可选择重建整盘或只格式化明确指定的 Windows 分区。均不处理其他物理硬盘，不自动加入 AD 域。格式化不等于不可恢复的数据擦除。

## 一次性准备

1. 按主 README 构建并部署前后端镜像；普通访问与客户端请求统一经过 `/pc-deploy/`。内网管理、WinPE 登记与安装后回报支持 HTTP / HTTPS，无需为了使用 HTTP 额外修改服务器配置。平台不修改公司 DHCP，不自动调整 BIOS，不绕过 TPM / Secure Boot。
2. 使用隔离的装机交换机或 VLAN。原版方式将合法 Windows ISO 完整解压到 SMB 共享；封装方式直接使用已有 WIM 文件，无需重新制作系统 ISO。创建专用只读账号，不使用域管理员、匿名或写入账号。
3. 在“安装源”下载检测脚本，在能读取共享的 Windows 电脑上执行下面的只读检查；将输出 JSON 导入页面并填写专用读取密码。

```powershell
.\Inspect-InstallSource.ps1 -SourcePath '\\fileserver\install\Win11' -Family windows11 -Name 'Windows 11' -SmbUser 'FILESERVER\deploy-read'
```

封装 WIM 改为传入完整文件路径。下面只读取共享上的镜像并计算摘要，不修改原 WIM；将 JSON 输出导入“安装源”。Win10 文件使用同一命令，将路径、系统类型和名称改为对应值。

```powershell
.\Inspect-InstallSource.ps1 -SourcePath '\\DC01\reminst\win11.wim' -Family windows11 -Name '封装 Windows 11' -SmbUser 'WFQ\deploy-read'
```

读取账号是示例，需替换为已创建的专用只读账号；密码只在后台填写，不放在脚本或代码中。

4. 新建装机方案。原版方式选择镜像版本、本地临时账号和密码；封装 WIM 沿用镜像内软件、账号、计算机名和授权配置，不填写新账号或密钥。选择“重建所选整盘”时，C 盘容量填 `0` 为单 C 盘，填 `128` 为 C 盘 128 GiB、D 盘使用剩余空间；另建 EFI / MSR / 恢复分区；WIM 仅在镜像包含 WinRE 时配置恢复工具。WIM 的“仅还原指定 Windows 分区”不调整分区容量，保留其他分区，只格式化选中的系统分区并更新同盘 EFI 引导文件；要求现有 GPT / NTFS Windows 分区和唯一可用 FAT32 EFI 分区。原版安装密钥按实际授权填写，平台不提供镜像或激活工具。
5. 在“启动与设置”保存客户端可访问的地址，例如 `http://ad.example.com/pc-deploy`；只填域名时会自动补上 `/pc-deploy`。内部 CA 仅填写公共 PEM 根证书，不填写私钥。
6. 安装微软 ADK 的部署工具及匹配的 WinPE 附加组件。下载 WinPE 登记与构建包并解压，在管理员“部署和映像工具环境”中启动 PowerShell，进入解压目录，执行一次构建。工作目录必须不存在；缺少网卡或存储驱动时提供签名 INF 驱动目录。

```powershell
.\Build-WinPE.ps1 -WorkDirectory 'D:\PCDeployMedia\batch-001' -DriverDirectory 'D:\Drivers\WinPE'
```

仅验证设备报到时，在构建命令后加 `-RegistrationOnly`。该模式持续登记和保活，不领取安装任务、不返回安装源密码；客户端也阻止执行安装。后台需包含此模式支持，旧后端若返回任务，客户端会停止而不执行。

脚本只创建 ISO，不格式化 U 盘。将 `pc-deploy-winpe.iso` 复制到已有 Ventoy U 盘，再从目标电脑启动。登记凭据有效期 24 小时，过期需重新下载并构建介质。

纯网络启动可将 ADK 构建目录中的 `media/sources/boot.wim`、`media/Boot/BCD`、`media/Boot/boot.sdi` 及官方 `wimboot` 放到后端 `instance/pc-deploy/boot/`，由现有受控 iPXE 服务引导至 `/pc-deploy/boot.ipxe`。必须先验证所选协议的访问、使用 HTTPS 时的证书信任、Secure Boot 及退出 iPXE 后的本地系统启动回退；平台不接管初始 DHCP / TFTP。

## 每批装机

1. 目标电脑从 WinPE 启动后登记；连接网线本身不会启动安装。
2. 网页选择装机方案、设备和每台设备的目标物理盘；保留分区的 WIM 方案还必须明确选择 Windows 分区，再预览。多硬盘不自动猜测，USB、未知总线、无稳定身份、只读或离线的盘不可选。
3. 现场核对整机序列号、屏幕校验码和硬盘，确认已备份，勾选确认并输入 `YES`。首次启用真实下发，还需在“启动与设置”确认隔离网络并输入 `ENABLE`。
4. 客户端复核安装文件、镜像版本及硬盘/分区身份后执行所选方式。原版调用 Windows Setup；封装 WIM 通过网络读取并还原镜像、配置 UEFI 引导，然后自动重启。失败立即停止，不自动重试或重装。
5. WIM 沿用镜像自身首次启动行为。已做 Sysprep 封装的镜像可在 specialize 阶段启动回报；未封装的备份镜像通过首次管理员登录启动回报。平台不绕过镜像原有 OOBE、登录或激活要求。回报任务使用本机 SYSTEM，验证完成后移除一次性凭据。
6. 在“任务记录”查看结果。“安装后已回报”表示新系统报告身份、版本和 OOBE 状态匹配，仍需人工验收驱动、网络及业务软件。

## 数据与排障

装机数据库、加密密钥和启动文件保存在现有后端持久化目录的 `instance/pc-deploy/`，不合并 AD 数据库表。应整体备份该目录；丢失 `secret.key` 后原凭据无法解密，不要单独删除密钥。独立装机项目的历史数据不会自动迁移。

没有设备时检查 WinPE 启动、网卡驱动、平台证书和网络；安装前失败检查 SMB 只读账号、镜像清单及存储驱动。安装启动后不可远程强停；长时间未回报先现场检查，不重新下发清盘。原版安装检查 Panther 日志；WIM 还原检查 PE 中 `X:\PCDeploy\任务ID-阶段-标识.log` / `.err`，重启前保存所需日志。未封装镜像还需确认已管理员登录并能访问平台；回报任务和诊断脚本在新系统 `%ProgramData%\PCDeploy\任务ID\`。

新增 WIM 方式必须重新下载登记包并构建装机 PE。旧 PE 会在下发前被拒绝；`RegistrationOnly` 镜像只登记，不能通过后台开关变成安装客户端。现有原版 Setup 安装源、方案及任务接口继续保留。

默认允许内网 HTTP，生成的登记包会记录所选协议；修改平台地址后应重新下载登记包并构建 WinPE。HTTPS 继续校验证书，不跳过验证。如需强制使用 HTTPS，可在后端 `config.py` 中设置 `PC_DEPLOY_ALLOW_HTTP = False`；HTTPS 在可信上游代理终止时仍按实际代理链设置 `PC_DEPLOY_TRUST_PROXY`。

自动测试覆盖模拟磁盘执行和界面流程，未执行真实清盘或安装。代码合并与自动测试不能代替真实设备验证。ADK 构建、不同机型驱动、实际网络启动及清盘安装需在隔离环境单独验收。
