# 版本记录

## 1.0.1

- 新协议 Snell、ShadowTLS（共 13 种）：Snell 默认 v5（客户端按 v4 拨号）、v6 可手动切；ShadowTLS 只做 v3，strict 模式强制开，握手站默认 gateway.icloud.com，内层 SS2022 走 127.0.0.1 回环。
- HY2/TUIC 端口建议跳过 443：国内运营商会拦 UDP 443，默认建议 8443；手动填 443 时前端红字提醒（只提醒，不禁止）。
- 订阅三种格式：`?format=singbox` 给完整 sing-box 客户端 JSON（Hiddify / sing-box / Karing，全部协议）、`?format=clash` 给 mihomo YAML、默认 base64 链接列表；`?format=` 优先，没给时按 User-Agent 自动识别（Hiddify 先于 ClashMeta 判断）。
- 客户端匹配修复：SS 链接改 SIP002 形态（旧整段 base64 在 Hiddify 里解析成死节点）；HY2/TUIC/AnyTLS 链接加 security=tls；ShadowTLS 载体出站加 Hiddify 的 `§hide§` 标记（列表里不再显示两个）；链接列表去掉 ShadowTLS 行（ss+plugin 形式在 sing-box 系与 mihomo 里都跑不通）；HY2 限速进订阅 JSON 时转数字；双栈机器的 v6 订阅行不再混进多行文本。
- 端口占用按协议分开查：TCP 与 UDP 端口是两套编号，建 HY2/TUIC/WireGuard 节点（改端口、端口建议也一样）时不再被 TCP 占用拦住，只查 UDP；面板里已有的 TCP 节点也不会拦住同端口的 UDP 节点（反过来也一样）。

## 1.0

首版发布：

- 单页面板，11 种入站协议（VLESS、Hysteria2、VMess、Trojan、TUIC、AnyTLS、Naive、Shadowsocks、SOCKS5、HTTP、WireGuard），一键入站、月+总双向用量。
- 在线更新：面板更新强制 sha256 校验、真 semver 比较（跳过 draft/prerelease）、并发守卫、冒烟 10 秒超时+版本精确比对；内核下载冒烟看退出码、自报版本须等于要装的 tag。
- 更新回滚轻量：只用一个固定名备份文件 `sssingbox.bak`，新版启动成功立即删掉，平时零备份；启动失败拷回旧版再退出。
- 登录安全：同一 IP 连续失败 5 次锁 15 分钟；2FA（TOTP，密钥 AES-256-GCM 加密存库）、2FA 临时凭证一次性；密码 72 字节上限；改密码验旧密码；记住登录 7 天轮换；2FA 信任 IP 30 天过期。
- 2FA 密钥损坏时登录直接拒绝（fail-closed），不再静默放行；状态接口如实报 broken；本机回环登录不受影响（SSH 菜单恢复口）；空哈希账号可用本机 CLI（`sssingbox admin reset`）修复；SSH 菜单提供 2FA 降级准备（密钥转回明文）。
- 法律声明：README 底部、面板首页底部小字、首次登录弹窗（按钮“已知晓，本人非中国大陆居民”）。
