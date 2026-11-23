# 启用「开通 VPN 并发送」

适用于已启用 OpenVPN、支持网页新增用户的锐捷睿易 EG310XS-E。AD 后端从部署服务器独立登录设备，确认新增账号后才发信；不使用管理员电脑的会话。

1. 在现有后端打包命令中加 `--build-arg VPN_BROWSER=1`，其他标签和推送流程不变：

   ```bash
   docker build --build-arg VPN_BROWSER=1 -f Dockerfile.backend -t swr.cn-south-1.myhuaweicloud.com/recovery-uat/be-ad:test"$BUILD_NUMBER" .
   ```

2. 在现有后端挂载目录 `/app/employee_register/be/instance/` 创建只允许部署账号读取的 `vpn-router-password` 文件，填一行**设备登录密码**，权限设为 `600`。如设备使用私有证书，同目录放经管理员核实、从设备导出的叶证书 `vpn-router.cer`，支持 PEM 或 DER。
3. 给后端容器配置下面的环境变量。`VPN_ROUTER_URL` 只写 HTTPS 地址，不带管理路径或会话令牌。使用浏览器正常信任的设备证书时，可以省略最后一行。

   ```dotenv
   VPN_ROUTER_URL=https://192.168.110.1
   VPN_ROUTER_PASSWORD_FILE=/app/instance/vpn-router-password
   VPN_ROUTER_CERT_FILE=/app/instance/vpn-router.cer
   ```

按原流程更新后端镜像并使环境变量生效。确认后端所在网络能访问路由器管理 HTTPS，再在「账号通知 → VPN 模板 → 预览」使用一个尚不存在的测试账号。路由器回读确认后，界面会显示「VPN 账号创建成功」。

设备密码错误、路由器不可达、账号已存在或结果不明时不发信。若账号已创建但邮件失败，用原来的发送按钮单独补发。若厂商网页更新了登录或新增表单，此功能会停止并提示，不会改动已有账号。
