# 版本记录

## 1.0.3（2026-11-23）

- 链式分流：单 A 多 B 分流（B1/B2/B3 + 可选兜底 B）、全局直通、A 节点切换；订阅三种格式均带链名。
- 链式静默降级全部改成报错：分流组引用的 B 节点不存在、兜底 B 节点不存在、全局直通的 B 节点不存在、入口 A 节点不存在时，应用配置直接失败并报明原因（旧配置继续跑），不再静默关链、跳组或改走直连；损坏的分流配置不再吞掉，ListChains 读到损坏的 routes JSON 时返回错误。
- Snell 可做 B 节点：ParseBLink 支持面板自己的 snell:// 链接（version=4 认作 v5，version=6 认作 v6；v5 的 HTTP 混淆进 obfs_mode/obfs_host）；sing-box 出站不认 version 5 与 obfs 字段，面板 v5 写线路版 4、v6 写 6。
- ShadowTLS 可做 B 节点：面板自定 shadowtls:// 链接格式（version/handshake/ss-method 省略时默认 3/gateway.icloud.com/2022-blake3-aes-128-gcm；内层 SS 密码必填）；SingBoxBOutbound 生成 SS 出站 + shadowtls detour 出站两个；本机 ShadowTLS 入站的分享链接改成单行 shadowtls://（可直接粘贴到另一台面板做 B 节点）；B 节点导入框支持 shadowtls://（9 种协议）；坏链接在解析或转换时即报错。
- Carbon 审查 21 项修复：面板双监听器改成异步首包探测；写锁不再包住全部列表接口；内核安装的流量统计器改用已加锁的 Reset；流量统计按“协议:端口”分键（SS 计 TCP+UDP 双份；Snell 归 TCP——实测其监听与数据面都是 TCP）；删 B 节点回归修复（分流链只剩最后一组且有兜底 B 时退化成 direct 走兜底）；Clash 订阅补外部 B 节点；ACME 按 RFC 8555 修；Clash“自动选择”分组不再是孤儿；sing-box 订阅 HY2 补 server_ports；自签证书域名/IP 变化时重签；安装脚本 .cli-credentials 写前转义 + umask、卸载清全部 sssingbox-* nft 表；前端 B 节点支持 snell://、登出后停掉延迟轮询、HY2 限速留空可清零；流量重置清全部当日记录。
- 测试中发现的两处追加修复：HY2 跳端口 nft 脚本 output 链的 priority dstnat 在 nft 里非法，改数字 -100；应用失败回滚后重应用一次（回滚后立即重应用把内核同步回库的状态）。
- Carbon 审查 6 项修复：SS 端口冲突补 UDP（新增 ProtocolsShareTransport，按传输层交集判断）；首次初始化跳转（doSetup 拿到 panel_path 后跳到新路径）；PublicIP/PublicIPv6 加锁；流量限额自动停用加锁（checkQuota 拆分，PUT 不死锁）；前端 ShadowTLS 展示同步（多行判断只剩 wireguard 与 naive）；首次登录加载顺序（refreshAll 先加载证书再渲染）。
- 4 处默认参数优化（只影响新建节点/新签证书）：WireGuard MTU 1420→1280（IPv6 最小 MTU，全网零分片；MTU 是渲染时常量，所有 WG 节点下次应用后都是 1280）；Snell v5 混淆 Host 不再默认 bing.com，改为 SNI 池随机取（bing.com / www.bing.com 永不入选）；ShadowTLS 握手站默认仍为 gateway.icloud.com，面板表单与 CLI 菜单各加随机推荐（/api/sni-random 支持多个 exclude 参数）；自签证书 RSA 2048→ECDSA P-256（老 RSA 证书仍复用，不重签）。
- README 订阅说明同步：ShadowTLS 也有单行 shadowtls:// 链接，WireGuard 仅在 Sing-box JSON 与 Clash YAML 中下发。

## 1.0.2

- 安全修复（严重）：不存在的用户凭固定占位口令可获得管理会话。`dummyHash` 以前是用源码里写死的固定明文算的 bcrypt 哈希，拿同一个明文去比对必然通过；现改成启动时用 `crypto/rand` 现抽 32 字节随机数算哈希，明文无人知晓，永远比对不上。另加纵深防御：登录里 bcrypt 比对通过后，若该用户不存在仍返回 401、不发会话（bcrypt 必须先跑完再判，避免时序上枚举账号）。新增回归测试 `TestLoginUnknownUserDummyHash`。
- 审计结论：登录限流、2FA（一次性临时凭证、fail-closed、恢复码哈希+一次性）、会话（过期清理、记住登录 7 天轮换）、改密码验旧密码、回环限定、订阅 token 定长比较、CLI 凭证 0600 均无问题；`/api/setup` 仅无用户时可用（已知 H2，按既定策略保留）。

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
