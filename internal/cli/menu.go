package cli

// 交互菜单：SSH 里直接跑 `sssingbox` 就进菜单，不用打开面板就能建节点、
// 管节点、装内核、看状态订阅登录信息、改账号密码端口、重置管理员。

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var stdin = bufio.NewReader(os.Stdin)

func prompt(msg string) string {
	fmt.Print(msg)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

// readPassword：关回显读一行（stty 不可用时退化为明文读）。
func readPassword(msg string) string {
	fmt.Print(msg)
	stty := func(args ...string) {
		cmd := exec.Command("stty", args...)
		cmd.Stdin = os.Stdin
		_ = cmd.Run()
	}
	stty("-echo")
	line, _ := stdin.ReadString('\n')
	stty("echo")
	fmt.Println()
	return strings.TrimSpace(line)
}

func promptInt(msg string, def int) int {
	for {
		s := prompt(msg)
		if s == "" {
			return def
		}
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
		fmt.Println("请输入数字")
	}
}

// pauseReturn：操作完先停一下，等用户看完输出按回车再回菜单。
// 之前是操作一完立刻重打菜单，输出被顶上去，用户还以为没反应。
func pauseReturn() {
	fmt.Print("\n按回车返回菜单")
	_, _ = stdin.ReadString('\n')
}

func runMenu(o options) int {
	c, err := newClient(o)
	if err != nil {
		fmt.Println("错误：", err)
		return 1
	}
	for {
		fmt.Println()
		fmt.Println("============ sssingbox管理 ============")
		fmt.Println("1. 创建节点")
		fmt.Println("2. 节点列表")
		fmt.Println("3. 删除节点")
		fmt.Println("4. 启用/停用节点")
		fmt.Println("5. 面板状态")
		fmt.Println("6. 订阅链接")
		fmt.Println("7. 安装/更新内核")
		fmt.Println("8. 查看登录信息")
		fmt.Println("9. 修改登录账号")
		fmt.Println("10. 修改登录密码")
		fmt.Println("11. 修改面板端口")
		fmt.Println("12. 重置管理员密码")
		fmt.Println("13. 关闭二次验证（2FA）")
		fmt.Println("14. 修改访问路径")
		fmt.Println("15. 关闭面板访问")
		fmt.Println("16. 开启面板访问")
		fmt.Println("17. 2FA 密钥转回明文（降级到旧版前用）")
		fmt.Println("0. 退出")
		choice := prompt("请选择：")
		if choice == "0" {
			return 0
		}
		switch choice {
		case "1":
			menuCreate(c)
		case "2":
			menuList(c)
		case "3":
			menuDelete(c)
		case "4":
			menuToggle(c)
		case "5":
			menuStatus(c)
		case "6":
			menuSub(c)
		case "7":
			menuCore(c)
		case "8":
			menuLogin(c)
		case "9":
			menuChangeUsername(c)
		case "10":
			menuChangePassword(c)
		case "11":
			c = menuChangePort(c, o)
		case "12":
			menuAdminResetItem(c, o)
		case "13":
			menuDisable2FA(c)
		case "14":
			menuChangePath(c)
		case "15":
			menuSetPanelEnabled(c, false)
		case "16":
			menuSetPanelEnabled(c, true)
		case "17":
			menuDowngrade2FA(c)
		default:
			fmt.Println("没有这个选项")
			continue
		}
		pauseReturn()
	}
}

func menuList(c *client) {
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	if len(nodes) == 0 {
		fmt.Println("还没有节点")
		return
	}
	for i, n := range nodes {
		state := "停用"
		if n.Enabled {
			state = "启用"
		}
		fmt.Printf("%d. %-28s %-10s %-6d %s\n", i+1, n.Name, n.Protocol, n.Port, state)
	}
}

// pickNode：列出节点让用户按序号选，返回选中的行。
func pickNode(c *client) (nodeRow, bool) {
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return nodeRow{}, false
	}
	if len(nodes) == 0 {
		fmt.Println("还没有节点")
		return nodeRow{}, false
	}
	for i, n := range nodes {
		state := "停用"
		if n.Enabled {
			state = "启用"
		}
		fmt.Printf("%d. %-28s %-10s %-6d %s\n", i+1, n.Name, n.Protocol, n.Port, state)
	}
	i := promptInt("选序号（0 取消）：", 0)
	if i < 1 || i > len(nodes) {
		return nodeRow{}, false
	}
	return nodes[i-1], true
}

func menuDelete(c *client) {
	n, ok := pickNode(c)
	if !ok {
		return
	}
	if !confirm(fmt.Sprintf("确认删除节点 %s（%s:%d）？", n.Name, n.Protocol, n.Port)) {
		fmt.Println("已取消")
		return
	}
	if _, err := c.call("DELETE", "/api/inbounds/"+n.ID, nil); err != nil {
		fmt.Println("删除失败：", err)
		return
	}
	fmt.Println("已删除")
}

func menuToggle(c *client) {
	n, ok := pickNode(c)
	if !ok {
		return
	}
	target := !n.Enabled
	word := "停用"
	if target {
		word = "启用"
	}
	if _, err := c.call("PUT", "/api/inbounds/"+n.ID, map[string]interface{}{"enabled": target}); err != nil {
		fmt.Println("操作失败：", err)
		return
	}
	fmt.Printf("已%s %s\n", word, n.Name)
}

func menuStatus(c *client) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	nodes, err := c.listNodes()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	on := 0
	for _, n := range nodes {
		if n.Enabled {
			on++
		}
	}
	fmt.Printf("面板版本：%v\n面板地址：http://%v:%v/\n节点：%d 个（启用 %d 个）\n",
		st["version"], st["public_ip"], st["panel_port"], len(nodes), on)
}

func menuSub(c *client) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	tok, _ := st["sub_token"].(string)
	if tok == "" {
		fmt.Println("订阅 token 为空")
		return
	}
	fmt.Printf("http://%v:%v/sub/%s\n", st["public_ip"], st["panel_port"], tok)
}

// menuCore：安装/更新内核。先列出内核现状，再让用户选一个装最新版
// （版本留空=最新版，没装就是安装，装了就是更新）。
func menuCore(c *client) {
	env, err := c.call("GET", "/api/cores", nil)
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	arr, _ := env["data"].([]interface{})
	if len(arr) == 0 {
		fmt.Println("没有内核信息")
		return
	}
	type coreRow struct {
		name, title, state string
	}
	var rows []coreRow
	for _, item := range arr {
		row, _ := item.(map[string]interface{})
		if row == nil {
			continue
		}
		name, _ := row["name"].(string)
		title, _ := row["title"].(string)
		if title == "" {
			title = name
		}
		state := "未安装"
		if installed, _ := row["installed"].(bool); installed {
			state = fmt.Sprintf("已安装 %v", row["version"])
			if latest, _ := row["latest"].(string); latest != "" && latest != row["version"] {
				state += fmt.Sprintf("（最新 %s）", latest)
			}
		}
		if noUpdate, _ := row["no_update"].(bool); noUpdate {
			state += "（不更新）"
			if note, _ := row["note"].(string); note != "" {
				state += "：" + note
			}
		}
		rows = append(rows, coreRow{name: name, title: title, state: state})
	}
	fmt.Println()
	for i, r := range rows {
		fmt.Printf("%d. %s：%s\n", i+1, r.title, r.state)
	}
	fmt.Println("0. 返回")
	i := promptInt("选一个安装/更新（0 取消）：", 0)
	if i < 1 || i > len(rows) {
		return
	}
	name := rows[i-1].name
	fmt.Printf("正在安装 %s 内核（最新版）…\n", name)
	data, err := c.call("POST", "/api/cores/"+name+"/install", map[string]interface{}{"version": ""})
	if err != nil {
		fmt.Println("安装失败：", err)
		return
	}
	fmt.Printf("已安装 %s %v\n", name, data["version"])
}

// menuLogin：查看登录信息。地址、账号、密码只显示在用户自己的终端上，
// 凭证来自 CLI 登录用的那份（安装器生成或 sssingbox login 保存的）。
func menuLogin(c *client) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	fmt.Printf("面板地址：http://%v:%v/%s\n账号：%s\n密码：%s\n",
		st["public_ip"], st["panel_port"], panelPathSuffix(st), c.username, c.password)
}

// panelPathSuffix：查看登录信息里打印的路径部分（有路径才带斜杠后缀）。
func panelPathSuffix(st map[string]interface{}) string {
	p, _ := st["panel_path"].(string)
	p = strings.Trim(p, "/ ")
	if p == "" {
		return ""
	}
	return p + "/"
}

// menuDisable2FA：菜单里关闭二次验证（丢了验证器时的恢复口）。
// 走面板的 reset 接口：该接口只认本机回环，菜单本来就连 127.0.0.1，
// 所以丢了 2FA 也能关——浏览器会话即使被盗也关不掉 2FA。
func menuDisable2FA(c *client) {
	v := prompt("确定关闭二次验证（2FA）？关闭后登录不再要动态码 (y/N)：")
	if v != "y" && v != "Y" {
		fmt.Println("已取消")
		return
	}
	if _, err := c.call("POST", "/api/settings/2fa/reset", map[string]interface{}{}); err != nil {
		fmt.Println("关闭失败：", err)
		return
	}
	fmt.Println("二次验证已关闭，现在用账号密码就能登录")
}

// menuDowngrade2FA：降级准备——把已加密的 2FA 密钥解密后写回明文，
// 供降级后的旧版读取（旧版把 v1: 密文当明文 base32 解码，动态码永远验不过）。
// 注意：转回明文后，下次登录读到明文会立刻重新加密——转完请立即降级，
// 不要再登录面板，否则又要重转一次。降级后请尽快重新开通 2FA（升回新版
// 后会自动重新加密）。密钥损坏时转不了，走“关闭二次验证”那条路。
func menuDowngrade2FA(c *client) {
	v := prompt("把 2FA 密钥转回明文，仅供降级到旧版前用。转完请立即降级、不要再登录面板，否则密钥会被重新加密。继续吗 (y/N)：")
	if v != "y" && v != "Y" {
		fmt.Println("已取消")
		return
	}
	data, err := c.call("POST", "/api/settings/2fa/downgrade", map[string]interface{}{})
	if err != nil {
		fmt.Println("转换失败：", err)
		return
	}
	if already, _ := data["already_plain"].(bool); already {
		fmt.Println("2FA 密钥已经是明文，无需转换，直接降级即可")
		return
	}
	fmt.Println("已转回明文。请立即降级，不要再登录面板；降级后请尽快重新开通 2FA")
}

// 改完当前会话跟上新账号，CLI 凭证文件面板侧已同步更新。
func menuChangeUsername(c *client) {
	fmt.Printf("当前账号：%s\n", c.username)
	v := prompt("新账号：")
	if v == "" || strings.ContainsAny(v, " \t\n") || len(v) > 32 {
		fmt.Println("新账号不能为空、不能含空格、不能超 32 位")
		return
	}
	data, err := c.call("POST", "/api/settings/username", map[string]interface{}{"new": v})
	if err != nil {
		fmt.Println("修改失败：", err)
		return
	}
	if name, _ := data["username"].(string); name != "" {
		c.username = name
	} else {
		c.username = v
	}
	fmt.Printf("账号已改为 %s，立即生效\n", c.username)
}

// menuChangePassword：菜单里改登录密码。SSH 本机操作，不用输旧密码——
// 能跑这个菜单就等于已经拿到服务器 shell，旧密码没有意义（Web 面板
// 改密码仍必须验旧密码）。只填两遍新密码；改完当前会话保留，其他会
// 话被吊销，CLI 凭证文件面板侧已同步更新。
func menuChangePassword(c *client) {
	p1 := readPassword("新密码：")
	p2 := readPassword("再输一次：")
	if p1 == "" || p1 != p2 {
		fmt.Println("两次密码不一致或为空")
		return
	}
	if len(p1) < 6 {
		fmt.Println("新密码至少 6 位")
		return
	}
	if _, err := c.call("POST", "/api/settings/password-local", map[string]interface{}{"new": p1, "new2": p2}); err != nil {
		fmt.Println("修改失败：", err)
		return
	}
	c.password = p1
	fmt.Println("密码已修改，立即生效")
}

// menuChangePath：菜单里改面板访问路径。路径立即生效，不用重启；
// 留空回到根目录（面板直接在 IP:端口 下），改完打印新地址。
func menuChangePath(c *client) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	cur, _ := st["panel_path"].(string)
	cur = strings.Trim(cur, "/ ")
	if cur == "" {
		fmt.Println("当前访问路径：根目录（面板直接在 IP:端口 下）")
	} else {
		fmt.Printf("当前访问路径：/%s/\n", cur)
	}
	v := prompt("新访问路径（只留英文、数字、-、_，留空=回到根目录，0 取消）：")
	if v == "0" {
		fmt.Println("已取消")
		return
	}
	v = strings.Trim(v, "/ ")
	if v == cur {
		fmt.Println("和当前路径一样，不用改")
		return
	}
	if _, err := c.call("POST", "/api/settings/panel-path", map[string]interface{}{"path": v}); err != nil {
		fmt.Println("修改失败：", err)
		return
	}
	if v == "" {
		fmt.Println("访问路径已改为根目录，立即生效")
	} else {
		fmt.Printf("访问路径已改为 /%s/，立即生效\n", v)
	}
	if st2, err := c.settings(); err == nil {
		fmt.Printf("面板地址：http://%v:%v/%s\n", st2["public_ip"], st2["panel_port"], panelPathSuffix(st2))
	}
}

// menuSetPanelEnabled：菜单里开关面板访问。关闭后只挡外网，订阅与本机
// 回环不受影响，代理照常跑；本机随时能再打开。立即生效，不用重启。
func menuSetPanelEnabled(c *client, enable bool) {
	st, err := c.settings()
	if err != nil {
		fmt.Println("错误：", err)
		return
	}
	disabled, _ := st["panel_disabled"].(bool)
	if enable && !disabled {
		fmt.Println("面板访问已经是开启状态")
		return
	}
	if !enable && disabled {
		fmt.Println("面板访问已经是关闭状态")
		return
	}
	if _, err := c.call("POST", "/api/settings/panel-enabled", map[string]interface{}{"enabled": enable}); err != nil {
		fmt.Println("操作失败：", err)
		return
	}
	if enable {
		fmt.Println("面板访问已开启，外网可以打开面板了")
	} else {
		fmt.Println("面板访问已关闭，外网打不开面板了（订阅照常、代理照常，本机菜单随时能再打开）")
	}
}

// changePanelPort：调服务端 panel-access 接口一次改端口+路径（端口要重启
// 才生效，路径立即生效）。服务端按实际服务管理类型改服务文件、重启面板，
// 菜单自己不再碰服务文件。
func changePanelPort(c *client, newPort int, curPath string) (map[string]interface{}, error) {
	return c.call("POST", "/api/settings/panel-access", map[string]interface{}{"port": newPort, "path": curPath})
}

// menuChangePort：菜单里改面板端口。走服务端 panel-access 接口：服务端按
// 实际服务管理类型（systemd/OpenRC/procd/sysvinit）改服务文件、重启面板。
// 以前菜单自己改 /etc/systemd/system/sssingbox.service，在非 systemd 机器
// 上直接报“没找到 systemd 服务文件”失败（v1.0.5 修，服务端接口自 v1.0.1
// 起已覆盖全部服务管理类型，install.sh 改端口早已走同一接口）。
func menuChangePort(c *client, o options) *client {
	fmt.Printf("当前面板端口：%d\n", o.port)
	n := promptInt("新端口（0 取消）：", 0)
	if n == 0 {
		fmt.Println("已取消")
		return c
	}
	if n < 1 || n > 65535 {
		fmt.Println("端口范围 1-65535")
		return c
	}
	if n == o.port {
		fmt.Println("和当前端口一样，不用改")
		return c
	}
	// 当前路径一起提交：服务端一次改端口+路径，避免两步改的 404 窗口。
	// settings 里必须有 panel_path 这一项才敢提交，缺项时宁可不改，也
	// 不能把服务端现有的路径误清成空。
	st, err := c.settings()
	if err != nil {
		fmt.Println("读当前设置失败：", err)
		return c
	}
	v, ok := st["panel_path"]
	if !ok {
		fmt.Println("读当前设置失败：设置里没有 panel_path，没改")
		return c
	}
	curPath, _ := v.(string)
	resp, err := changePanelPort(c, n, curPath)
	if err != nil {
		fmt.Println("修改失败：", err)
		return c
	}
	if rr, _ := resp["restart_required"].(bool); rr {
		// 服务文件已写入新端口，但面板没自动重启（daemon-reload 失败等）。
		if note, _ := resp["note"].(string); note != "" {
			fmt.Println(note)
		}
		fmt.Printf("面板端口已写入 %d，面板仍在旧端口运行，重启面板后生效\n", n)
		return c
	}
	// 等新端口起来再重连，最多 30 秒。
	up := false
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(n), 2*time.Second)
		if err == nil {
			conn.Close()
			up = true
			break
		}
		time.Sleep(time.Second)
	}
	if !up {
		fmt.Printf("面板端口已改为 %d，但 30 秒还没探到新端口，请手动确认服务状态\n", n)
		return c
	}
	nc, err := newClient(options{dataDir: o.dataDir, port: n})
	if err != nil {
		fmt.Printf("面板端口已改为 %d，但菜单重连失败（%v），请退出后重进菜单\n", n, err)
		return c
	}
	fmt.Printf("面板端口已改为 %d，菜单已切到新端口\n", n)
	return nc
}

// menuAdminResetItem：菜单里重置管理员密码（忘密码时用）。直接写库，
// 不走面板会话；成功后菜单登录信息同步成新的那份。
func menuAdminResetItem(c *client, o options) {
	if rc := runAdminReset(o); rc != 0 {
		return
	}
	if cred, err := loadCredentials(o.dataDir); err == nil {
		c.username = cred.Username
		c.password = cred.Password
	}
}

var protocols = []struct {
	key  string
	name string
}{
	{"vless", "VLESS"},
	{"hy2", "Hysteria2"},
	{"vmess", "VMess"},
	{"ss", "Shadowsocks"},
	{"socks", "SOCKS5"},
	{"http", "HTTP 代理"},
	{"trojan", "Trojan"},
	{"wireguard", "WireGuard"},
	{"tuic", "TUIC"},
	{"anytls", "AnyTLS"},
	{"naive", "Naive"},
}

func menuCreate(c *client) {
	fmt.Println()
	fmt.Println("选择协议：")
	for i, p := range protocols {
		fmt.Printf("%d. %s\n", i+1, p.name)
	}
	fmt.Println("0. 返回")
	i := promptInt("请选择：", 0)
	if i < 1 || i > len(protocols) {
		return
	}
	proto := protocols[i-1].key
	port := promptInt("端口（留空自动分配）：", 0)
	name := prompt("节点名（留空自动）：")
	sni := ""
	adv := map[string]interface{}{}
	switch proto {
	case "vless":
		fmt.Println("传输方式：1. Reality  2. WS  3. H2  4. HTTPUpgrade")
		m := prompt("请选择（默认 1）：")
		mode := map[string]string{"": "reality", "1": "reality", "2": "ws", "3": "h2", "4": "httpupgrade"}[m]
		if mode == "" {
			fmt.Println("没有这个选项")
			return
		}
		sni = prompt("伪装域名/SNI（Reality 留空自动推荐，TLS 档留空用服务器 IP）：")
		path := ""
		if mode != "reality" {
			path = prompt("路径（留空自动生成）：")
		}
		adv = map[string]interface{}{"mode": mode, "path": path, "flow": "xtls-rprx-vision", "fingerprint": "chrome", "spider_x": "/"}
	case "vmess":
		fmt.Println("传输方式：1. TCP  2. CF  3. HTTP  4. QUIC  5. H2  6. HTTPUpgrade")
		m := prompt("请选择（默认 1）：")
		mode := map[string]string{"": "tcp", "1": "tcp", "2": "cf", "3": "http", "4": "quic", "5": "h2", "6": "httpupgrade"}[m]
		if mode == "" {
			fmt.Println("没有这个选项")
			return
		}
		if mode != "tcp" {
			for {
				sni = prompt("域名（CF 模式必填，其他留空用服务器 IP）：")
				if mode != "cf" || sni != "" {
					break
				}
				fmt.Println("CF 模式必须填已接入 Cloudflare 的域名")
			}
		}
		path := ""
		if mode == "cf" || mode == "http" || mode == "h2" || mode == "httpupgrade" {
			path = prompt("路径（留空自动生成）：")
		}
		adv = map[string]interface{}{"mode": mode, "path": path}
	case "trojan":
		fmt.Println("传输方式：1. Reality  2. CF  3. H2  4. HTTPUpgrade")
		m := prompt("请选择（默认 1）：")
		mode := map[string]string{"": "reality", "1": "reality", "2": "cf", "3": "h2", "4": "httpupgrade"}[m]
		if mode == "" {
			fmt.Println("没有这个选项")
			return
		}
		if mode == "reality" {
			sni = prompt("伪装域名（留空自动推荐）：")
		} else {
			for {
				sni = prompt("域名（CF 模式必填，其他留空用服务器 IP）：")
				if mode != "cf" || sni != "" {
					break
				}
				fmt.Println("CF 模式必须填已接入 Cloudflare 的域名")
			}
		}
		path := ""
		if mode != "reality" {
			path = prompt("路径（留空自动生成）：")
		}
		adv = map[string]interface{}{"mode": mode, "path": path}
	case "hy2", "tuic", "anytls":
		sni = prompt("SNI（留空自动推荐）：")
	case "naive":
		for {
			sni = prompt("域名（必填，CA 证书上的域名，须解析到本机）：")
			if sni != "" {
				break
			}
			fmt.Println("Naive 必须填真实域名")
		}
	case "ss":
		fmt.Println("加密方式：1. 2022-blake3-aes-128-gcm  2. 2022-blake3-aes-256-gcm  3. aes-256-gcm  4. chacha20-ietf-poly1305")
		m := prompt("请选择（默认 1）：")
		method := map[string]string{"": "2022-blake3-aes-128-gcm", "1": "2022-blake3-aes-128-gcm", "2": "2022-blake3-aes-256-gcm", "3": "aes-256-gcm", "4": "chacha20-ietf-poly1305"}[m]
		if method == "" {
			fmt.Println("没有这个选项")
			return
		}
		adv = map[string]interface{}{"method": method}
	}
	data, err := c.call("POST", "/api/inbounds", createPayload(proto, port, name, sni, adv))
	if err != nil {
		fmt.Println("创建失败：", err)
		if strings.Contains(err.Error(), "内核还没安装") {
			fmt.Printf("先装内核再创建：sssingbox core install sing-box\n")
		}
		return
	}
	inb, _ := data["inbound"].(map[string]interface{})
	fmt.Printf("已创建：%v（端口 %v）\n链接：%v\n", inb["name"], inb["port"], data["link"])
	if l6, _ := data["link6"].(string); l6 != "" {
		fmt.Printf("IPv6 链接：%v\n", l6)
	}
	if proto == "naive" {
		certFile := prompt("证书文件路径（.crt，留空则建好后去面板上传）：")
		keyFile := ""
		if certFile != "" {
			keyFile = prompt("密钥文件路径（.key）：")
		}
		if certFile != "" && keyFile != "" {
			cb, err1 := os.ReadFile(certFile)
			kb, err2 := os.ReadFile(keyFile)
			id, _ := inb["id"].(string)
			if err1 != nil || err2 != nil {
				fmt.Println("证书文件读不到，建好后请在面板里上传证书")
			} else if _, err := c.call("POST", "/api/inbounds/"+id+"/cert", map[string]string{"cert": string(cb), "key": string(kb)}); err != nil {
				fmt.Println("证书上传失败：", err)
			} else {
				fmt.Println("证书已上传，节点已生效")
			}
		} else if certFile != "" {
			fmt.Println("只填了证书没填密钥，建好后请在面板里上传证书")
		} else {
			fmt.Println("提醒：Naive 需要 CA 证书，建好后请在面板节点菜单里上传证书")
		}
	}
}
