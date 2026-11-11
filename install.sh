#!/bin/sh
# sssingbox面板一键安装脚本。
#
# 一键命令（默认自动生成面板账号密码，不用打开初始化页面）：
#   curl -fsSL https://raw.githubusercontent.com/SSStingg/SSSing-box/main/install.sh | sh
#   （bash 也一样；脚本是 POSIX sh，dash / busybox ash 都能跑，OpenWrt 不用装 bash）
# 自定义（环境变量写在 sh 前面，不设则账号密码都随机生成）：
#   curl -fsSL https://raw.githubusercontent.com/SSStingg/SSSing-box/main/install.sh | SSSINGBOX_USER=xxxx SSSINGBOX_PASS=xxxx SSSINGBOX_PORT=18081 sh
# 本地安装包模式：
#   sh install.sh --from-file sssingbox-linux-amd64.tar.gz [--port 18081] [--data-dir /var/lib/sssingbox]
#   安装包是 tar.gz，根目录含一个 sssingbox 二进制。
# 卸载（保留数据目录，彻底删除见提示；卸载也接受 --data-dir 指定当初的数据目录）：
#   curl -fsSL https://raw.githubusercontent.com/SSStingg/SSSing-box/main/install.sh | sh -s uninstall
#   本地已有 install.sh 时，sh install.sh uninstall 也一样。
#
# 支持的服务管理：systemd（Debian / Ubuntu / CentOS / Fedora / Arch 等）、
# OpenRC（Alpine / Gentoo）、procd（OpenWrt）、sysvinit（Devuan 等），
# 以及无服务管理器的环境（容器、NAS Debian 容器等：以后台方式启动并明说）。
# 下载器 curl / wget 任一即可。重装 = 更新：已装过时备份旧二进制并重启服务，
# 已有管理员时跳过初始化，不覆盖旧账号。
#
# 注意：POSIX sh 没有 pipefail，所以这里只用 set -eu；所有管道都写成
# “最后一个命令决定成败”，可能失败的调用一律用 || true 兜底，不靠 pipefail。
set -eu

BIN_DIR="/usr/local/bin"
BIN_PATH="$BIN_DIR/sssingbox"
SERVICE="sssingbox"
PORT="${SSSINGBOX_PORT:-18081}"
DATA_DIR="/var/lib/sssingbox"
FROM_FILE=""
REPO="${SSSINGBOX_REPO:-SSSting/SSSing-box}"
INIT=""
LOG_HINT=""

# ---------- 下载与 HTTP（curl 优先，wget 兜底） ----------
dl() {
	# dl URL OUT：下载文件，失败返回非 0（调用方在 if 里或直接调用，set -e 下失败即停，与旧版 curl -fsSL 行为一致）
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}
dl_out() {
	# dl_out URL：打到 stdout，失败返回非 0，调用方自行用 || true 处理
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1"
	else
		wget -qO- "$1"
	fi
}
http_post() {
	# http_post URL DATA：打到 stdout，永不因 HTTP/连接失败中断脚本，调用方看回包判断
	if command -v curl >/dev/null 2>&1; then
		curl -s --max-time 10 -X POST "$1" -H 'Content-Type: application/json' -d "$2" || true
	else
		wget -qO- --header='Content-Type: application/json' --post-data="$2" -T 10 "$1" || true
	fi
}
http_ok() {
	# http_ok URL：HTTP 成功返回 0
	if command -v curl >/dev/null 2>&1; then
		curl -fs -o /dev/null --max-time 2 "$1"
	else
		wget -q -O /dev/null -T 2 "$1"
	fi
}

# JSON 转义（供初始化账号与菜单登录/改密共用；定义放前面，初始化 POST 就能用）
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# ---------- nftables（流量统计用）：没有就自动装 ----------
ensure_nft() {
	if command -v nft >/dev/null 2>&1; then
		echo "nftables 已安装"
		return 0
	fi
	echo "正在安装 nftables（流量统计需要）..."
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq >/dev/null 2>&1 || true
		apt-get install -y -qq nftables >/dev/null 2>&1 || true
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y -q nftables >/dev/null 2>&1 || true
	elif command -v yum >/dev/null 2>&1; then
		yum install -y -q nftables >/dev/null 2>&1 || true
	elif command -v apk >/dev/null 2>&1; then
		apk add --quiet nftables >/dev/null 2>&1 || true
	elif command -v pacman >/dev/null 2>&1; then
		pacman -Sy --noconfirm --quiet nftables >/dev/null 2>&1 || true
	else
		echo "警告：未找到 nft 命令，且无法自动安装（未知包管理器），流量统计将不可用"
		return 0
	fi
	if command -v nft >/dev/null 2>&1; then
		echo "nftables 安装成功"
	else
		echo "警告：nftables 安装失败，流量统计将不可用"
	fi
	return 0
}
# ---------- 服务管理器检测 ----------
# 顺序有讲究：先 systemd（要求 PID1 就是 systemd，避免“装了 systemctl 但没用 systemd 启动”
# 的容器误判，例如 NAS Debian 容器 PID1 是 sshd）；再 OpenRC；再 procd；
# sysvinit 只认 PID1 是 init 的机器（容器 PID1 不是 init，不会误判）；最后是无服务管理。
detect_init() {
	P1=""
	if [ -r /proc/1/comm ]; then
		P1="$(cat /proc/1/comm 2>/dev/null || true)"
	fi
	if [ "$P1" = "systemd" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		echo "systemd"
		return
	fi
	if command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
		echo "openrc"
		return
	fi
	if [ -f /etc/openwrt_release ] || command -v procd >/dev/null 2>&1; then
		echo "procd"
		return
	fi
	if [ "$P1" = "init" ] || [ -z "$P1" ]; then
		if [ -d /etc/init.d ] && { command -v update-rc.d >/dev/null 2>&1 || command -v chkconfig >/dev/null 2>&1 || [ -d /etc/rc.d ]; }; then
			echo "sysvinit"
			return
		fi
	fi
	echo "none"
}

# ---------- 服务写入 / 开机自启 / 启动 / 状态 / 停止 ----------
svc_write() {
	case "$INIT" in
	systemd)
		cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=sssingbox面板
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH -data $DATA_DIR -port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
		;;
	openrc)
		cat > "/etc/init.d/$SERVICE" <<EOF
#!/sbin/openrc-run
name="$SERVICE"
description="sssingbox面板"
command="$BIN_PATH"
command_args="-data $DATA_DIR -port $PORT"
command_background=true
pidfile="/run/$SERVICE.pid"
output_log="/var/log/$SERVICE.log"
error_log="/var/log/$SERVICE.log"
depend() {
  need net
}
EOF
		chmod +x "/etc/init.d/$SERVICE"
		;;
	procd)
		cat > "/etc/init.d/$SERVICE" <<EOF
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10
PROG="$BIN_PATH"
start_service() {
  procd_open_instance
  procd_set_param command "\$PROG" -data "$DATA_DIR" -port "$PORT"
  procd_set_param respawn
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
		chmod +x "/etc/init.d/$SERVICE"
		;;
	sysvinit)
		cat > "/etc/init.d/$SERVICE" <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          $SERVICE
# Required-Start:    \$network \$local_fs
# Required-Stop:     \$network \$local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: sssingbox面板
### END INIT INFO
NAME="$SERVICE"
DAEMON="$BIN_PATH"
ARGS="-data $DATA_DIR -port $PORT"
PIDFILE="/var/run/$SERVICE.pid"
LOGFILE="/var/log/$SERVICE.log"
[ -x "\$DAEMON" ] || exit 0
case "\$1" in
  start)
    printf "Starting %s: " "\$NAME"
    if command -v start-stop-daemon >/dev/null 2>&1; then
      start-stop-daemon --start --quiet --background --make-pidfile --pidfile "\$PIDFILE" --exec "\$DAEMON" -- \$ARGS >>"\$LOGFILE" 2>&1
    else
      nohup "\$DAEMON" \$ARGS >>"\$LOGFILE" 2>&1 &
      echo \$! > "\$PIDFILE"
    fi
    echo "done."
    ;;
  stop)
    printf "Stopping %s: " "\$NAME"
    if command -v start-stop-daemon >/dev/null 2>&1; then
      start-stop-daemon --stop --quiet --pidfile "\$PIDFILE" || true
    elif [ -f "\$PIDFILE" ]; then
      kill "\$(cat \$PIDFILE)" 2>/dev/null || true
    fi
    rm -f "\$PIDFILE"
    echo "done."
    ;;
  restart)
    \$0 stop
    sleep 1
    \$0 start
    ;;
  status)
    if [ -f "\$PIDFILE" ] && kill -0 "\$(cat \$PIDFILE)" 2>/dev/null; then
      echo "\$NAME is running."
    else
      echo "\$NAME is not running."
      exit 1
    fi
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status}"
    exit 1
    ;;
esac
EOF
		chmod +x "/etc/init.d/$SERVICE"
		;;
	none)
		:
		;;
	esac
}

svc_enable() {
	case "$INIT" in
	systemd)
		systemctl daemon-reload
		systemctl enable "$SERVICE" >/dev/null
		;;
	openrc)
		rc-update add "$SERVICE" default
		;;
	procd)
		"/etc/init.d/$SERVICE" enable
		;;
	sysvinit)
		if command -v update-rc.d >/dev/null 2>&1; then
			update-rc.d "$SERVICE" defaults >/dev/null 2>&1 || true
		elif command -v chkconfig >/dev/null 2>&1; then
			chkconfig --add "$SERVICE" >/dev/null 2>&1 || true
			chkconfig "$SERVICE" on >/dev/null 2>&1 || true
		elif [ -f /etc/rc.d/rc.local ]; then
			if ! grep -q "/etc/init.d/$SERVICE start" /etc/rc.d/rc.local 2>/dev/null; then
				echo "/etc/init.d/$SERVICE start" >> /etc/rc.d/rc.local
			fi
		else
			echo "提示：未找到 update-rc.d / chkconfig / rc.local，开机自启未设置，面板仅本次启动。"
		fi
		;;
	none)
		:
		;;
	esac
}

svc_restart() {
	case "$INIT" in
	systemd)
		systemctl restart "$SERVICE"
		;;
	openrc)
		rc-service "$SERVICE" stop >/dev/null 2>&1 || true
		rc-service "$SERVICE" start
		;;
	procd)
		"/etc/init.d/$SERVICE" stop >/dev/null 2>&1 || true
		"/etc/init.d/$SERVICE" start
		;;
	sysvinit)
		"/etc/init.d/$SERVICE" stop >/dev/null 2>&1 || true
		sleep 1
		"/etc/init.d/$SERVICE" start
		;;
	none)
		if [ -f "$DATA_DIR/$SERVICE.pid" ]; then
			OLDPID="$(cat "$DATA_DIR/$SERVICE.pid" 2>/dev/null || true)"
			if [ -n "$OLDPID" ] && kill -0 "$OLDPID" 2>/dev/null; then
				kill "$OLDPID" 2>/dev/null || true
				sleep 2
				if kill -0 "$OLDPID" 2>/dev/null; then
					kill -9 "$OLDPID" 2>/dev/null || true
				fi
			fi
			rm -f "$DATA_DIR/$SERVICE.pid"
		fi
		nohup "$BIN_PATH" -data "$DATA_DIR" -port "$PORT" >>"$DATA_DIR/$SERVICE.log" 2>&1 &
		echo $! > "$DATA_DIR/$SERVICE.pid"
		;;
	esac
}

svc_active() {
	case "$INIT" in
	systemd)
		systemctl is-active --quiet "$SERVICE"
		;;
	openrc)
		rc-service "$SERVICE" status >/dev/null 2>&1
		;;
	procd)
		"/etc/init.d/$SERVICE" status >/dev/null 2>&1
		;;
	sysvinit)
		"/etc/init.d/$SERVICE" status >/dev/null 2>&1
		;;
	none)
		PID=""
		if [ -f "$DATA_DIR/$SERVICE.pid" ]; then
			PID="$(cat "$DATA_DIR/$SERVICE.pid" 2>/dev/null || true)"
		fi
		[ -n "$PID" ] && kill -0 "$PID" 2>/dev/null
		;;
	esac
}

# wait_active：轮询等服务起来（每秒查一次，最多 10 秒）。以前只等 2 秒
# 就判失败，慢机器/大库启动超过 2 秒会被误判成启动失败、触发回滚。
wait_active() {
	i=0
	while [ "$i" -lt 10 ]; do
		if svc_active; then return 0; fi
		sleep 1
		i=$((i+1))
	done
	svc_active
}

svc_stop() {
	case "$INIT" in
	systemd)
		systemctl stop "$SERVICE" 2>/dev/null || true
		systemctl disable "$SERVICE" 2>/dev/null || true
		systemctl daemon-reload 2>/dev/null || true
		;;
	openrc)
		rc-service "$SERVICE" stop 2>/dev/null || true
		rc-update del "$SERVICE" 2>/dev/null || true
		;;
	procd)
		"/etc/init.d/$SERVICE" stop 2>/dev/null || true
		"/etc/init.d/$SERVICE" disable 2>/dev/null || true
		;;
	sysvinit)
		"/etc/init.d/$SERVICE" stop 2>/dev/null 2>&1 || true
		if command -v update-rc.d >/dev/null 2>&1; then
			update-rc.d -f "$SERVICE" remove >/dev/null 2>&1 || true
		elif command -v chkconfig >/dev/null 2>&1; then
			chkconfig --del "$SERVICE" >/dev/null 2>&1 || true
		elif [ -f /etc/rc.d/rc.local ]; then
			sed -i "\|/etc/init.d/$SERVICE start|d" /etc/rc.d/rc.local 2>/dev/null || true
		fi
		;;
	none)
		if [ -f "$DATA_DIR/$SERVICE.pid" ]; then
			PID="$(cat "$DATA_DIR/$SERVICE.pid" 2>/dev/null || true)"
			if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; fi
			rm -f "$DATA_DIR/$SERVICE.pid"
		fi
		;;
	esac
}

usage() {
	echo "用法：sh install.sh [--from-file 安装包.tar.gz] [--port 端口] [--data-dir 数据目录] [uninstall]"
	echo "  --from-file  本地安装包（tar.gz，根目录含 sssingbox 二进制）"
	echo "  --port       面板端口（默认 18081）"
	echo "  --data-dir   数据目录（默认 /var/lib/sssingbox）"
	echo "  uninstall    卸载（保留数据目录；可配 --data-dir 指定当初的数据目录）"
	echo "  环境变量 SSSINGBOX_REPO=owner/repo：默认 SSSting/SSSing-box，不设就用默认仓库下载；--from-file 时用本地安装包，不走 Forgejo。"
}

UNINSTALL=""
while [ $# -gt 0 ]; do
	case "$1" in
		--from-file)
			if [ -z "${2:-}" ]; then echo "错误：--from-file 需要一个值"; exit 1; fi
			FROM_FILE="$2"; shift 2 ;;
		--port)
			if [ -z "${2:-}" ]; then echo "错误：--port 需要一个值"; exit 1; fi
			PORT="$2"; shift 2 ;;
		--data-dir)
			if [ -z "${2:-}" ]; then echo "错误：--data-dir 需要一个值"; exit 1; fi
			DATA_DIR="$2"; shift 2 ;;
		uninstall) UNINSTALL=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "未知参数：$1"; usage; exit 1 ;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "错误：请用 root 运行（需要写 /usr/local/bin 与服务配置）"
	exit 1
fi

if [ -n "$UNINSTALL" ]; then
	echo "正在卸载sssingbox..."
	INIT="$(detect_init)"
	svc_stop
	# 两处服务文件都清（防止换过服务管理器的残留）
	rm -f "/etc/systemd/system/$SERVICE.service" "/etc/init.d/$SERVICE"
	if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload 2>/dev/null || true; fi
	# 面板自有 nft 表（端口跳跃用）随卸载清掉，不留孤儿转发规则；
	# Guijia/Docker 等其他表一律不动。
	nft delete table inet sssingbox-hop 2>/dev/null || true
	rm -f "$BIN_PATH" "/usr/bin/$SERVICE"
	echo "已卸载。数据目录 $DATA_DIR 已保留，彻底删除请执行：rm -rf $DATA_DIR"
	exit 0
fi

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
	echo "错误：需要 curl 或 wget（Debian/Ubuntu：apt install curl；Alpine：apk add curl；OpenWrt：opkg install curl）"
	exit 1
fi
if ! command -v tar >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
	echo "错误：需要 tar 与 sha256sum"
	exit 1
fi

# nftables：流量统计需要，没有就自动装（装不上也不中止安装）。
ensure_nft

ARCH="$(uname -m)"
case "$ARCH" in
	x86_64|amd64) ARCH="amd64" ;;
	aarch64|arm64) ARCH="arm64" ;;
	*) echo "错误：不支持的架构 $ARCH（只支持 amd64/arm64）" ; exit 1 ;;
esac

WORK="$(mktemp -d 2>/dev/null || true)"
if [ -z "$WORK" ]; then
	WORK="/tmp/sssingbox-$$"
	mkdir -p "$WORK"
fi
trap 'rm -rf "$WORK"' EXIT

if [ -n "$FROM_FILE" ]; then
	echo "本地安装包模式：$FROM_FILE"
	tar xzf "$FROM_FILE" -C "$WORK"
else
	echo "Forgejo 发布模式：$REPO（linux-$ARCH）"
	ASSET="sssingbox-linux-$ARCH.tar.gz"
	TAG="$(dl_out "https://998919.xyz/api/v1/repos/$REPO/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
	if [ -n "$TAG" ]; then
		echo "下载 $TAG/$ASSET ..."
		dl "https://998919.xyz/$REPO/releases/download/$TAG/$ASSET" "$WORK/$ASSET"
		# sha256 校验是强制的：没有校验文件就中止安装，绝不跳过。
		if ! dl "https://998919.xyz/$REPO/releases/download/$TAG/$ASSET.sha256" "$WORK/$ASSET.sha256" 2>/dev/null; then
			echo "错误：该发布没有提供 sha256 校验文件，中止安装。"
			exit 1
		fi
		(cd "$WORK" && sha256sum -c "$ASSET.sha256")
	else
		# /latest 拿不到 tag 时再试 releases 列表（Forgejo 没有 GitHub 那种 latest/download 重定向）。
		echo "API 取不到最新 tag，改从 releases 列表取 ..."
		TAG="$(dl_out "https://998919.xyz/api/v1/repos/$REPO/releases?limit=1" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
		if [ -z "$TAG" ]; then
			echo "错误：无法从 Forgejo 获取最新版本，请检查网络或稍后重试"
			exit 1
		fi
		echo "下载 $TAG/$ASSET ..."
		dl "https://998919.xyz/$REPO/releases/download/$TAG/$ASSET" "$WORK/$ASSET"
		if ! dl "https://998919.xyz/$REPO/releases/download/$TAG/$ASSET.sha256" "$WORK/$ASSET.sha256" 2>/dev/null; then
			echo "错误：该发布没有提供 sha256 校验文件，中止安装。"
			exit 1
		fi
		(cd "$WORK" && sha256sum -c "$ASSET.sha256")
	fi
	tar xzf "$WORK/$ASSET" -C "$WORK"
fi

if [ ! -x "$WORK/sssingbox" ]; then
	echo "错误：安装包里没有可执行的 sssingbox 二进制"
	exit 1
fi
echo "二进制自检：$("$WORK/sssingbox" -version)"

mkdir -p "$DATA_DIR"
# 轻量备份：只用一个固定名文件 sssingbox.bak，成功后删掉，平时零备份；带时间戳的旧备份随后清理。
BAK=""
if [ -x "$BIN_PATH" ]; then
	BAK="$BIN_DIR/sssingbox.bak"
	cp "$BIN_PATH" "$BAK"
	echo "旧二进制已备份到 $BAK"
fi
install -m 0755 "$WORK/sssingbox" "$BIN_PATH"
# /usr/local/bin 不在 PATH 时（常见于 OpenWrt），补一个 /usr/bin 软链，让 sssingbox 命令直接可用。
case ":$PATH:" in
	*":$BIN_DIR:"*) : ;;
	*) ln -sf "$BIN_PATH" "/usr/bin/$SERVICE" 2>/dev/null || true ;;
esac

INIT="$(detect_init)"
case "$INIT" in
systemd) LOG_HINT="journalctl -u $SERVICE -n 50" ;;
openrc) LOG_HINT="/var/log/$SERVICE.log（rc-service $SERVICE status 查状态）" ;;
procd) LOG_HINT="logread -e $SERVICE" ;;
sysvinit) LOG_HINT="/var/log/$SERVICE.log" ;;
none) LOG_HINT="$DATA_DIR/$SERVICE.log" ;;
esac
echo "检测到服务管理：$INIT"
svc_write
svc_enable
svc_restart || true
if ! wait_active; then
	if [ -n "$BAK" ] && [ -f "$BAK" ]; then
		echo "新二进制启动失败，正在回滚到旧版本..."
		cp "$BAK" "$BIN_PATH"
		svc_restart || true
		if wait_active; then
			echo "已回滚到旧版本，面板仍在运行（本次升级失败）"
			rm -f "$BAK"
			rm -f "$BIN_DIR"/sssingbox.bak-*
			exit 1
		fi
	fi
	echo "错误：服务启动失败，看日志：$LOG_HINT"
	exit 1
fi
# 新二进制起来了：删掉固定名备份，并清理遗留的带时间戳旧备份，平时零备份。
if [ -n "$BAK" ]; then rm -f "$BAK"; fi
rm -f "$BIN_DIR"/sssingbox.bak-*
if [ "$INIT" = "none" ]; then
	echo "提示：未检测到服务管理器（容器 / 无 init 环境），面板已以后台方式启动；重启后不会自动启动，如需开机自启请把启动命令加入容器启动配置。"
fi
echo "等待面板端口就绪..."
for i in $(seq 1 30); do
	if http_ok "http://127.0.0.1:$PORT/"; then
		break
	fi
	sleep 1
	if [ "$i" = "30" ]; then
		echo "警告：面板 30 秒还没响应 HTTP，但服务已在运行，请稍后打开面板或看日志：$LOG_HINT"
	fi
done

# 初始化账号：已有管理员时（升级重装）跳过，不覆盖旧账号。
# 账号密码默认都自动生成（账号绝不默认 admin），不用打开初始化页面；
# CLI 凭证一并写好，sssingbox 命令开箱即用。
USER_NAME="${SSSINGBOX_USER:-}"
USER_GENERATED=""
if [ -z "$USER_NAME" ]; then
	USER_NAME="$(head -c 256 /dev/urandom | tr -dc 'abcdefghjkmnpqrstuvwxyz' | head -c 1)$(head -c 256 /dev/urandom | tr -dc 'abcdefghjkmnpqrstuvwxyz23456789' | head -c 7)"
	USER_GENERATED=1
fi
PASS="${SSSINGBOX_PASS:-}"
GENERATED=""
if [ -z "$PASS" ]; then
	PASS="$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)"
	GENERATED=1
fi
SETUP_OUT="$(http_post "http://127.0.0.1:$PORT/api/setup" "{\"username\":\"$(json_escape "$USER_NAME")\",\"password\":\"$(json_escape "$PASS")\",\"password2\":\"$(json_escape "$PASS")\"}")"
SETUP_OK=0
SETUP_STATUS="exists"
if echo "$SETUP_OUT" | grep -q '"ok":true'; then
	printf '{"username":"%s","password":"%s"}' "$USER_NAME" "$PASS" > "$DATA_DIR/.cli-credentials"
	chmod 600 "$DATA_DIR/.cli-credentials"
	SETUP_OK=1
	SETUP_STATUS="ok"
elif [ -z "$SETUP_OUT" ]; then
	SETUP_STATUS="noresp"
	echo "初始化接口无响应（面板已启动，请打开面板手动设置账号）"
else
	echo "面板已有管理员，跳过初始化（旧账号不变）"
fi

# 防火墙放行（尽力而为，失败不中断安装）
if command -v ufw >/dev/null 2>&1; then ufw allow "$PORT/tcp" >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; fi

IP=""
if command -v curl >/dev/null 2>&1; then IP="$(curl -s --max-time 5 ifconfig.me || true)"; else IP="$(wget -qO- -T 5 ifconfig.me 2>/dev/null || true)"; fi
if [ -z "$IP" ]; then IP="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1 || true)"; fi
if [ -z "$IP" ]; then IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"; fi
if [ -z "$IP" ]; then IP="服务器IP"; fi
# 新装默认根路径：初始设置接口回包里带 panel_path，地址里带上它。
PANEL_PATH="$(echo "$SETUP_OUT" | grep -o '"panel_path":"[^"]*"' | cut -d'"' -f4 || true)"
if [ -n "$PANEL_PATH" ]; then PANEL_URL="http://$IP:$PORT/$PANEL_PATH/"; else PANEL_URL="http://$IP:$PORT/"; fi
echo ""
echo "================ SSSing-box安装完成 ================"
echo "面板地址：$PANEL_URL"
if [ "$SETUP_STATUS" = "ok" ]; then
	echo "面板账号：$USER_NAME"
	echo "面板密码：$PASS"
	if [ -n "$GENERATED" ] || [ -n "$USER_GENERATED" ]; then echo "（账号/密码为自动生成，请保存好）"; fi
elif [ "$SETUP_STATUS" = "noresp" ]; then
	echo "面板账号：初始化接口无响应，请打开面板手动设置（首次设置页）"
else
	echo "面板账号：沿用旧账号（CLI 凭证没动过的话，sssingbox 命令仍可用；改过密码请跑 sssingbox login）"
fi
echo "SSH 管理：sssingbox（直接进菜单，不用打开面板就能管节点、改账号密码端口）"
echo "卸载：curl -fsSL https://raw.githubusercontent.com/SSStingg/SSSing-box/main/install.sh | sh -s uninstall（数据目录保留）"
echo "=============================================="

# 安装后改账号/密码：刚建好管理员且能交互时才出现。管道安装（curl | sh）
# 的 stdin 是脚本本身，不能直接 read，改走 /dev/tty；无终端时自动跳过。
# 交互菜单要 cookie：curl 全功能；wget 需支持 cookie 保存/读取，否则跳过菜单
# （面板里仍可改账号密码，安装本身不受影响）。
read_secret() {
	stty -echo < /dev/tty 2>/dev/null || true
	read -r SECRET_VAL < /dev/tty || SECRET_VAL=""
	stty echo < /dev/tty 2>/dev/null || true
}
post_jar() {
	# post_jar URL DATA JAR save|send
	if command -v curl >/dev/null 2>&1; then
		if [ "$4" = "save" ]; then
			curl -s --max-time 10 -c "$3" -X POST "$1" -H 'Content-Type: application/json' -d "$2" || true
		else
			curl -s --max-time 10 -b "$3" -X POST "$1" -H 'Content-Type: application/json' -d "$2" || true
		fi
	else
		if [ "$4" = "save" ]; then
			wget -qO- --save-cookies="$3" --keep-session-cookies --header='Content-Type: application/json' --post-data="$2" -T 10 "$1" || true
		else
			wget -qO- --load-cookies="$3" --header='Content-Type: application/json' --post-data="$2" -T 10 "$1" || true
		fi
	fi
}
MENU_OK=0
if command -v curl >/dev/null 2>&1; then
	MENU_OK=1
elif wget --help 2>&1 | grep -q "keep-session-cookies"; then
	MENU_OK=1
fi
# 注意：这里不能用 `: < /dev/tty` 探 tty——`:` 是特殊内建命令，POSIX 规定特殊内建命令
# 的重定向失败会直接导致脚本退出（dash 下实测退出码 2，装完面板却报失败）。
# 也不能直接写 `head -c 0 < /dev/tty 2>/dev/null`：重定向按顺序处理，< /dev/tty 先失败时
# 报错走的还是原 stderr，2>/dev/null 还没生效，照样漏一行报错（功能对了，但会吓用户一跳）。
# 所以把探测放进子 shell 并先把子 shell 的 stderr 指到 /dev/null：打不开就是无终端，
# 静默跳过菜单，不影响安装结果；有真终端时照常进菜单。
if [ "$SETUP_OK" = "1" ] && (head -c 0 < /dev/tty) 2>/dev/null; then
	if [ "$MENU_OK" = "0" ]; then
		echo "提示：当前只有 wget 且不支持 cookie 保存，已跳过安装后交互改密；如需改账号密码请在面板设置里改。"
	else
		JAR="$(mktemp)"
		if post_jar "http://127.0.0.1:$PORT/api/login" "{\"username\":\"$(json_escape "$USER_NAME")\",\"password\":\"$(json_escape "$PASS")\"}" "$JAR" save | grep -q '"ok":true'; then
			while true; do
				echo ""
				echo "是否修改账号、密码、端口或访问路径？（当前账号：$USER_NAME）"
				echo "  1) 修改账号  2) 修改密码  3) 修改端口  4) 修改访问路径  5) 快捷修改  6) 退出"
				printf "请选择 [1/2/3/4/5/6]（直接回车=退出）："
				read -r CHOICE < /dev/tty || CHOICE="6"
				# 输错只重问一行，不重打整块菜单；空回车直接退出（装完误碰回车不再跳第二次）。
				while [ "$CHOICE" != "1" ] && [ "$CHOICE" != "2" ] && [ "$CHOICE" != "3" ] && [ "$CHOICE" != "4" ] && [ "$CHOICE" != "5" ] && [ "$CHOICE" != "6" ] && [ -n "$CHOICE" ]; do
					printf "请输入 1、2、3、4、5 或 6（直接回车=退出）："
					read -r CHOICE < /dev/tty || CHOICE="6"
				done
				case "$CHOICE" in
				1)
					printf "新账号："
					read -r NEW_USER < /dev/tty || NEW_USER=""
					if [ -z "$NEW_USER" ]; then echo "新账号不能为空"; continue; fi
					if post_jar "http://127.0.0.1:$PORT/api/settings/username" "{\"new\":\"$(json_escape "$NEW_USER")\"}" "$JAR" send | grep -q '"ok":true'; then
						USER_NAME="$NEW_USER"
						echo "账号已改为 $USER_NAME"
					else
						echo "修改失败：新账号为空、含空格、超 32 位或已存在"
					fi
					;;
				2)
					# 本机安装器改密码：不用输旧密码（装完就在本机 shell 上，旧密码没有意义），
					# 直接走 password-local（仅回环）。Web 面板改密码仍必须验旧密码。
					printf "新密码："
					read_secret; NEW_PASS="$SECRET_VAL"; echo ""
					printf "再输一次："
					read_secret; NEW_PASS2="$SECRET_VAL"; echo ""
					if [ "$NEW_PASS" != "$NEW_PASS2" ]; then echo "两次输入不一致"; continue; fi
					if [ "${#NEW_PASS}" -lt 6 ]; then echo "新密码至少 6 位"; continue; fi
					if post_jar "http://127.0.0.1:$PORT/api/settings/password-local" "{\"new\":\"$(json_escape "$NEW_PASS")\",\"new2\":\"$(json_escape "$NEW_PASS2")\"}" "$JAR" send | grep -q '"ok":true'; then
						PASS="$NEW_PASS"
						echo "密码已修改"
					else
						echo "修改失败"
					fi
					;;
				3)
					printf "新端口（当前 %s，0 取消）：" "$PORT"
					read -r NEW_PORT < /dev/tty || NEW_PORT="0"
					if [ "$NEW_PORT" = "0" ] || [ -z "$NEW_PORT" ]; then echo "已取消"; continue; fi
					case "$NEW_PORT" in *[!0-9]*) echo "端口只能是数字"; continue ;; esac
					if [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then echo "端口范围 1-65535"; continue; fi
					if [ "$NEW_PORT" = "$PORT" ]; then echo "和当前端口一样，不用改"; continue; fi
					if post_jar "http://127.0.0.1:$PORT/api/settings/panel-access" "{\"port\":$NEW_PORT,\"path\":\"$(json_escape "$PANEL_PATH")\"}" "$JAR" send | grep -q '"ok":true'; then
						PORT="$NEW_PORT"
						if [ -n "$PANEL_PATH" ]; then PANEL_URL="http://$IP:$PORT/$PANEL_PATH/"; else PANEL_URL="http://$IP:$PORT/"; fi
						echo "面板端口已改为 $PORT，正在等面板在新端口上起来…"
						# 面板改端口后会重启，会话失效；等新端口起来后重新登录，菜单不断线。
						UP=0; i=0
						while [ "$i" -lt 30 ]; do
							if command -v curl >/dev/null 2>&1; then
								if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/api/setup-status"; then UP=1; break; fi
							elif wget -qO- -T 2 "http://127.0.0.1:$PORT/api/setup-status" >/dev/null 2>&1; then UP=1; break; fi
							i=$((i+1)); sleep 1
						done
						if [ "$UP" = "1" ]; then
							if post_jar "http://127.0.0.1:$PORT/api/login" "{\"username\":\"$(json_escape "$USER_NAME")\",\"password\":\"$(json_escape "$PASS")\"}" "$JAR" save | grep -q '"ok":true'; then
								echo "面板地址已改为 $PANEL_URL"
							else
								echo "面板端口已改为 $PORT，但重新登录失败，请退出后用新地址打开面板"
							fi
						else
							echo "面板端口已改为 $PORT，但 30 秒还没探到新端口，请手动确认服务状态"
						fi
					else
						echo "修改失败：端口可能已被占用"
					fi
					;;
				4)
					if [ -n "$PANEL_PATH" ]; then echo "当前访问路径：/$PANEL_PATH/"; else echo "当前访问路径：根目录"; fi
					printf "新访问路径（只留英文、数字、-、_，留空=回到根目录，0 取消）："
					read -r NEW_PATH < /dev/tty || NEW_PATH="0"
					if [ "$NEW_PATH" = "0" ]; then echo "已取消"; continue; fi
					NEW_PATH="$(printf '%s' "$NEW_PATH" | sed 's:^/*::;s:/*$::')"
					if [ "$NEW_PATH" = "$PANEL_PATH" ]; then echo "和当前路径一样，不用改"; continue; fi
					if post_jar "http://127.0.0.1:$PORT/api/settings/panel-path" "{\"path\":\"$(json_escape "$NEW_PATH")\"}" "$JAR" send | grep -q '"ok":true'; then
						PANEL_PATH="$NEW_PATH"
						if [ -n "$PANEL_PATH" ]; then PANEL_URL="http://$IP:$PORT/$PANEL_PATH/"; else PANEL_URL="http://$IP:$PORT/"; fi
						echo "访问路径已修改，立即生效"
						echo "面板地址：$PANEL_URL"
					else
						echo "修改失败：路径只能是 1-32 位英文、数字、-、_，不能用 sub、api"
					fi
					;;
				5)
					# 快捷修改：一行输入账号/密码/端口/访问路径，一次改完。
					# 格式：admin/123456/28081/in，哪段留空=不改那项；密码里不能含 /，含 / 请用选项 2 单独改。
					printf "输入账号/密码/端口/访问路径（如 admin/123456/28081/in，留空=不改）："
					IFS='/' read -r QA QB QC QD < /dev/tty || true
					if [ -z "$QA" ] && [ -z "$QB" ] && [ -z "$QC" ] && [ -z "$QD" ]; then echo "已取消"; continue; fi
					# 先全验过再动手，任何一段格式不合格就整行不改。
					if [ -n "$QA" ]; then
						case "$QA" in *[' ']*) echo "账号不能含空格"; continue ;; esac
						if [ "${#QA}" -gt 32 ]; then echo "账号不能超 32 位"; continue; fi
					fi
					if [ -n "$QB" ]; then
						if [ "${#QB}" -lt 6 ]; then echo "新密码至少 6 位"; continue; fi
						if [ "${#QB}" -gt 72 ]; then echo "新密码不能超过 72 字节"; continue; fi
					fi
					if [ -n "$QC" ]; then
						case "$QC" in *[!0-9]*) echo "端口只能是数字"; continue ;; esac
						if [ "$QC" -lt 1 ] || [ "$QC" -gt 65535 ]; then echo "端口范围 1-65535"; continue; fi
					fi
					QD="$(printf '%s' "$QD" | sed 's:^/*::;s:/*$::')"
					# 账号（和当前一样就不改）
					if [ -n "$QA" ] && [ "$QA" != "$USER_NAME" ]; then
						if post_jar "http://127.0.0.1:$PORT/api/settings/username" "{\"new\":\"$(json_escape "$QA")\"}" "$JAR" send | grep -q '"ok":true'; then
							USER_NAME="$QA"
						else
							echo "账号修改失败：新账号为空、含空格、超 32 位或已存在"
						fi
					fi
					# 密码（本机改，不用旧密码）
					if [ -n "$QB" ]; then
						if post_jar "http://127.0.0.1:$PORT/api/settings/password-local" "{\"new\":\"$(json_escape "$QB")\",\"new2\":\"$(json_escape "$QB")\"}" "$JAR" send | grep -q '"ok":true'; then
							PASS="$QB"
						else
							echo "密码修改失败"
						fi
					fi
					# 端口+路径（一次请求，照选项 3 的办法：端口变了要等新端口起来、重新登录）
					PORT_CHANGED=0
					if [ -n "$QC" ] && [ "$QC" != "$PORT" ]; then PORT_CHANGED=1; fi
					NEW_PORT="$PORT"; NEW_PATH="$PANEL_PATH"
					if [ -n "$QC" ]; then NEW_PORT="$QC"; fi
					if [ -n "$QD" ]; then NEW_PATH="$QD"; fi
					if [ "$PORT_CHANGED" = "1" ] || [ "$NEW_PATH" != "$PANEL_PATH" ]; then
						if post_jar "http://127.0.0.1:$PORT/api/settings/panel-access" "{\"port\":$NEW_PORT,\"path\":\"$(json_escape "$NEW_PATH")\"}" "$JAR" send | grep -q '"ok":true'; then
							PORT="$NEW_PORT"; PANEL_PATH="$NEW_PATH"
							if [ -n "$PANEL_PATH" ]; then PANEL_URL="http://$IP:$PORT/$PANEL_PATH/"; else PANEL_URL="http://$IP:$PORT/"; fi
							if [ "$PORT_CHANGED" = "1" ]; then
								echo "面板端口已改为 $PORT，正在等面板在新端口上起来…"
								UP=0; i=0
								while [ "$i" -lt 30 ]; do
									if command -v curl >/dev/null 2>&1; then
										if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/api/setup-status"; then UP=1; break; fi
									elif wget -qO- -T 2 "http://127.0.0.1:$PORT/api/setup-status" >/dev/null 2>&1; then UP=1; break; fi
									i=$((i+1)); sleep 1
								 done
								if [ "$UP" = "1" ]; then
									if post_jar "http://127.0.0.1:$PORT/api/login" "{\"username\":\"$(json_escape "$USER_NAME")\",\"password\":\"$(json_escape "$PASS")\"}" "$JAR" save | grep -q '"ok":true'; then
										echo "已重新登录"
									else
										echo "面板端口已改为 $PORT，但重新登录失败，请退出后用新地址打开面板"
									fi
								else
									echo "面板端口已改为 $PORT，但 30 秒还没探到新端口，请手动确认服务状态"
								fi
							fi
						else
							echo "端口或路径修改失败：端口可能已被占用，或路径只能是 1-32 位英文、数字、-、_，不能用 sub、api"
						fi
					fi
					echo ""
					echo "已修改，新的登录信息："
					echo "面板地址：$PANEL_URL"
					echo "面板账号：$USER_NAME"
					echo "面板密码：$PASS"
					;;
				*) break ;;
				esac
			done
			echo ""
			echo "面板地址：$PANEL_URL"
			echo "面板账号：$USER_NAME"
		fi
		rm -f "$JAR"
	fi
fi
