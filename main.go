package main

import (
	"crypto/rand"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sssingbox/internal/cli"
	"sssingbox/internal/server"
	"sssingbox/internal/stats"
	"sssingbox/internal/store"
	"sssingbox/internal/version"
)

//go:embed web
var webFS embed.FS

func main() {
	// 不带参数时：在终端里直接进交互菜单（sssingbox = sssingbox menu）；
	// 非终端（systemd、脚本、管道）仍按老样子起面板，不抢服务启动。
	if len(os.Args) == 1 && stdinIsTerminal() {
		os.Exit(cli.Run([]string{"menu"}))
	}
	// CLI 子命令（sssingbox menu / node / status / sub / login / admin / version）：
	// 第一个参数是不带 - 的子命令名时走 CLI，不启动面板。
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "menu", "node", "status", "sub", "login", "admin", "version", "core":
			os.Exit(cli.Run(os.Args[1:]))
		}
	}
	dataDir := flag.String("data", "/var/lib/sssingbox", "数据目录")
	port := flag.Int("port", 18081, "面板端口")
	showVersion := flag.Bool("version", false, "打印面板版本号并退出")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sssingbox %s\n", version.Version)
		return
	}

	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		fatal(err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "sssingbox.db"))
	if err != nil {
		// 读库失败可能是新版二进制的毛病：先试着把更新留下的旧版拷回来，
		// 再退出让 systemd 重启跑旧版。没有 .bak 时 Restore 是空操作。
		rollbackExe()
		fatal(err)
	}
	defer st.Close()

	// 用量统计的 nft 表按数据目录区分实例（生产与测试实例同机时互不抢表）。
	// 必须在 NewApp 之前定好：后台轮询一启动就可能读表，顺序反了
	// 首轮会读到默认表名（与别的实例抢表）。
	stats.SetDataDir(*dataDir)
	app := server.NewApp(st, *dataDir)
	// first run: no admin is created here any more. The first time the
	// panel is opened with zero users, the setup page asks for a username
	// and password (twice) and creates the first admin there.
	if st.UserCount() == 0 {
		fmt.Println("sssingbox首次启动：还没有管理员，首次打开面板时请设置账号密码")
	}
	if tok, err := st.GetSettingErr("sub_token"); err != nil {
		// 读失败时绝不生成新 token 覆盖：DB 抖动一次就会让已发出的订阅全失效。
		fmt.Printf("启动警告：订阅 token 读取失败（%v），本次不覆盖旧 token\n", err)
	} else if tok == "" {
		if err := st.SetSetting("sub_token", randHex(12)); err != nil {
			fmt.Printf("启动警告：订阅 token 写入失败（%v），本次启动订阅不可用\n", err)
		}
	}
	if err := st.SetSetting("panel_port", fmt.Sprintf("%d", *port)); err != nil {
		fmt.Printf("启动警告：面板端口记录失败（%v），建议端口功能可能不准\n", err)
	}

	// restore configs + start cores
	if err := app.ApplyAll(); err != nil {
		fmt.Printf("启动恢复警告：%v\n", err)
	}

	sub, _ := fs.Sub(webFS, "web")
	srv := server.New(app, http.FS(sub))
	srv.StartBackground()

	// 回滚（轻量设计）：更新只留一个固定名备份 sssingbox.bak，
	// 新版首次监听成功就删掉它，稳态零备份；新版启动失败时把 .bak 拷回
	// 二进制路径再退出，systemd 重启后跑回旧版。
	srv.SetOnFirstListen(func() {
		server.DeletePanelBackup(currentExe())
		// 顺手清掉旧版攒下的带时间戳备份：从旧版升上来时，
		// 旧版更新器留下的 .bak-<时间戳> 还在磁盘上，不清就违背“零备份”。
		server.CleanupStaleBackups(currentExe())
	})

	// 监听循环：默认 HTTP；用户在设置里选证书并启用 HTTPS 后才切 TLS，
	// 监听方式与端口（:%d）本身不变——部署新版绝不自动上 HTTPS。
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(fmt.Sprintf(":%d", *port), srv.Routes()) }()

	// graceful shutdown: stop cores
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case err := <-serveErr:
		// 启动失败（首次监听就失败）：尝试回滚到更新前的旧版再退出，
		// 让 systemd 重启后跑回旧版。没有 .bak 时（不是更新后的启动）
		// Restore 是空操作，直接报错退出。
		fmt.Printf("面板启动失败：%v\n", err)
		rollbackExe()
		os.Exit(1)
	}
	fmt.Println("正在停止面板与内核…")
	// 停核封顶 30 秒：单个僵进程不能把面板退出无限期卡住；
	// 超时则直接退出，残留进程由系统回收（面板重启时会重新接管）。
	stopped := make(chan struct{})
	go func() {
		app.Sup.StopAll()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(30 * time.Second):
		fmt.Println("停止超时，强制退出")
	}
	srv.Shutdown()
}

// stdinIsTerminal：是不是在交互终端里。两条路都认：
// ① stdin 本身是 pts/tty（SSH 终端）；
// ② stdin 是管道，但进程有控制终端、/dev/tty 能打开（网页终端就是这样：
//
//	按键走管道进 shell，但 /dev/tty 照样能读，安装菜单就是靠它弹出来的）。
//
// 两条都不满足才是真非交互（systemd 默认 stdin 是 /dev/null 且无控制终端），
// 裸命令在那种环境下仍起面板，不会误进菜单。
func stdinIsTerminal() bool {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		name := os.Stdin.Name()
		if strings.HasPrefix(name, "/dev/pts/") || strings.HasPrefix(name, "/dev/tty") {
			return true
		}
	}
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
		return true
	}
	return false
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误：", err)
	os.Exit(1)
}

// currentExe：当前二进制的真实路径（解掉符号链接，更新时写 .bak 的
// 目标就是它）。
func currentExe() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe
}

// rollbackExe：启动失败时的回滚。把 sssingbox.bak（更新留下的旧版）
// 拷回二进制路径；没有 .bak 时什么都不做（不是更新后的启动），
// 拷回失败时只打日志，调用方继续按原流程退出——回滚失败不比启动
// 失败本身更值得拦。
func rollbackExe() {
	exe := currentExe()
	if exe == "" {
		return
	}
	if err := server.RestorePanelBackup(exe); err != nil {
		if err == server.ErrNoBackup {
			return
		}
		fmt.Printf("回滚失败：%v\n", err)
		return
	}
	fmt.Println("已回滚到更新前的旧版，退出后由 systemd 重启")
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
