# 版本记录

## 1.0

首版发布：

- 单页面板，11 种入站协议（VLESS、Hysteria2、VMess、Trojan、TUIC、AnyTLS、Naive、Shadowsocks、SOCKS5、HTTP、WireGuard），一键入站、月+总双向用量。
- 在线更新：面板更新强制 sha256 校验、真 semver 比较（跳过 draft/prerelease）、并发守卫、冒烟 10 秒超时+版本精确比对；内核下载冒烟看退出码、自报版本须等于要装的 tag。
- 更新回滚轻量：只用一个固定名备份文件 `sssingbox.bak`，新版启动成功立即删掉，平时零备份；启动失败拷回旧版再退出。
- 登录安全：同一 IP 连续失败 5 次锁 15 分钟；2FA（TOTP，密钥 AES-256-GCM 加密存库）、2FA 临时凭证一次性；密码 72 字节上限；改密码验旧密码；记住登录 7 天轮换；2FA 信任 IP 30 天过期。
- 2FA 密钥损坏时登录直接拒绝（fail-closed），不再静默放行；状态接口如实报 broken；本机回环登录不受影响（SSH 菜单恢复口）；空哈希账号可用本机 CLI（`sssingbox admin reset`）修复；SSH 菜单提供 2FA 降级准备（密钥转回明文）。
- 法律声明：README 底部、面板首页底部小字、首次登录弹窗（按钮“已知晓，本人非中国大陆居民”）。
