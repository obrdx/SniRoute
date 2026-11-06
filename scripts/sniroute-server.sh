#!/bin/sh
# SniRoute 观测端（服务端）一键脚本 —— 单文件、纯 POSIX sh。
#
# 一行运行（交互选择临时运行或永久安装）：
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-server.sh)"
#
#   · 临时运行：下载到临时目录，退出即删除（配置与数据保存在 ~/.sniroute，下次接着用）
#   · 永久安装：二进制进 /usr/local/lib/sniroute，systemd（Debian/Ubuntu/RHEL/CentOS 等）
#               或 OpenRC（Alpine）服务开机自启、崩溃重启；
#               之后直接输入 `sniroute` 就启动（确保服务在跑，然后打开管理菜单）
#
# 安装时落盘的两个脚本（启动器 / systemd 单元）都写在下面的变量里，原样写出，
# 卸载与审计都能看到完整内容。
#
#   sh sniroute-server.sh                 交互选择
#   sh sniroute-server.sh --temp          临时运行
#   sh sniroute-server.sh --install       永久安装（需要 root）
#   sh sniroute-server.sh --status        查看状态
#   sh sniroute-server.sh --uninstall [--purge]
#   sh sniroute-server.sh --dry-run ...   只打印将要做什么
#
# 可用环境变量：
#   SR_BIN=/path/to/sniroute    用本地二进制（离线 / 自己编译时）
#   SR_BIN_URL=...              改下载地址，支持 {os} {arch} 占位符
#   SR_SHA256=...               校验下载文件的 sha256
#   SR_PROBE_ADDR / SR_CONTROL_ADDR / SR_DATA / SR_ETC / SR_PREFIX / SR_UNIT_DIR / SR_INIT_DIR
#   SR_STATE_DIR=~/.sniroute    临时模式的状态目录
#   SR_NO_SYSTEMD=1             不碰 systemctl（容器 / 无 systemd 环境）
#   SR_ALLOW_UNPRIVILEGED=1     允许非 root 安装到自制前缀（测试用）
set -u

# ════════════════════════ 变量 ════════════════════════
readonly SCRIPT_VERSION="v1"
APP="sniroute"
REPO="${SR_REPO:-obrdx/SniRoute}"
# 本脚本的规范地址：非 root 选「永久安装」时，用它下载后交给 sudo 重跑
SCRIPT_URL="${SR_SCRIPT_URL:-https://raw.githubusercontent.com/${REPO}/main/scripts/sniroute-server.sh}"
# 下载地址：{os} {arch} 会被替换成 linux/darwin 与 amd64/arm64
BIN_URL_TEMPLATE="https://github.com/${REPO}/releases/latest/download/sniroute_{os}_{arch}"
BIN_URL_TEMPLATE="${SR_BIN_URL:-$BIN_URL_TEMPLATE}"
LOCAL_BIN="${SR_BIN:-}"
BIN_SHA256="${SR_SHA256:-}"
DL_TIMEOUT="${SR_DOWNLOAD_TIMEOUT:-300}"

# 永久安装的位置
PREFIX="${SR_PREFIX:-/usr/local}"
LIB_DIR="$PREFIX/lib/$APP"
BIN_LINK="$PREFIX/bin/$APP"
ETC_DIR="${SR_ETC:-/etc/sniroute}"
DATA_DIR="${SR_DATA:-/var/lib/sniroute}"
UNIT_DIR="${SR_UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="$APP.service"
INIT_DIR="${SR_INIT_DIR:-/etc/init.d}"
INIT_NAME="$APP"
CFG_PERM="$ETC_DIR/server.yaml"

# 临时模式的配置与数据（退出不删除，否则每次都要重新初始化、节点全部丢失）
STATE_DIR="${SR_STATE_DIR:-$HOME/.sniroute}"

# 默认监听
DEFAULT_PROBE_ROOT=":443"      # :443 需要 root；客户端会自动发现探测端口
DEFAULT_PROBE_USER=":8444"     # 非 root 临时运行时的默认探测端口
DEFAULT_CONTROL=":8443"

NO_SYSTEMD="${SR_NO_SYSTEMD:-0}"
ALLOW_UNPRIV="${SR_ALLOW_UNPRIVILEGED:-0}"

# ════════════════════════ 安装时落盘的脚本 ════════════════════════
# 启动器：装到 $PREFIX/bin/sniroute。不带参数 = 确保服务在跑 + 打开管理菜单。
emit_launcher() {
	cat <<'LAUNCHER'
#!/bin/sh
# 由 sniroute-server.sh 安装。请勿手改：重装会覆盖。
set -u
readonly SCRIPT_VERSION="v1"
BIN="@LIB@/sniroute"
CONFIG="@CONFIG@"
UNIT="@UNIT@"
USE_SYSTEMD="@SYSTEMD@"
USE_OPENRC="@OPENRC@"
SVC="sniroute"
if [ "$USE_SYSTEMD" = "1" ]; then
	export SNIROUTE_SYSTEMD_UNIT="$UNIT"
	export SNIROUTE_SYSTEMD_CONFIG="$CONFIG"
else
	unset SNIROUTE_SYSTEMD_UNIT SNIROUTE_SYSTEMD_CONFIG
fi

usage() {
	cat <<EOF
SniRoute 观测端

用法：
  sniroute                    确保服务在运行，并打开管理菜单
  sniroute start|stop|restart|status    控制系统服务（systemd / OpenRC）
  sniroute logs               跟踪服务日志（journalctl -f）
  sniroute <子命令>           其余参数透传给 ${BIN}（已带上 -config）

配置文件：$CONFIG
数据目录：@DATA@
探测监听：@PROBE@（必须可直接连接，不要放在 CDN / 反向代理后面）
控制接口：@CONTROL@（HTTPS）
EOF
}

if [ $# -eq 0 ]; then
	if [ "$USE_SYSTEMD" = "1" ]; then
		systemctl is-enabled --quiet "$UNIT" 2>/dev/null || systemctl enable "$UNIT" >/dev/null 2>&1 || true
		if ! systemctl is-active --quiet "$UNIT"; then
			echo "启动 $UNIT ..."
			systemctl start "$UNIT" || { echo "启动失败，可看：sniroute logs" >&2; exit 1; }
		fi
	elif [ "$USE_OPENRC" = "1" ]; then
		rc-service "$SVC" status >/dev/null 2>&1 || {
			echo "启动 $SVC ..."
			rc-service "$SVC" start || { echo "启动失败，可看：sniroute logs" >&2; exit 1; }
		}
	else
		state=$("$BIN" server status -config "$CONFIG") || exit 1
		[ "$state" != "stopped" ] || "$BIN" server start -config "$CONFIG" || exit 1
	fi
	exec "$BIN" server menu -config "$CONFIG"
fi

case "$1" in
start | stop | restart | status)
	if [ "$USE_SYSTEMD" = "1" ]; then
		cmd=$1
		shift
		exec systemctl "$cmd" "$UNIT" "$@"
	fi
	if [ "$USE_OPENRC" = "1" ]; then
		exec rc-service "$SVC" "$1"
	fi
	# 没有 systemd（容器 / 非 Linux）：用二进制自带的 pid 文件后台模式。
	exec "$BIN" server "$1" -config "$CONFIG"
	;;
logs)
	if [ "$USE_SYSTEMD" = "1" ]; then
		exec journalctl -u "$UNIT" -n 100 -f
	fi
	LOG="@DATA@/server.log"
	[ -f "$LOG" ] || { echo "没有日志：$LOG" >&2; exit 1; }
	tail -n 100 -f "$LOG"
	;;
-h | --help | help)
	usage
	exit 0
	;;
genkey | version)
	exec "$BIN" "$@"
	;;
reports)
	echo "观测端不再提供历史报告，请在客户端查看本地报告。" >&2
	exit 1
	;;
server | client)
	# 其余子命令：若调用方没显式给 -config，就补上安装位置的那份。
	for a in "$@"; do
		case "$a" in
		-config | --config | -config=* | --config=*) exec "$BIN" "$@" ;;
		esac
	done
	exec "$BIN" "$@" -config "$CONFIG"
	;;
*)
	exec "$BIN" server "$@" -config "$CONFIG"
	;;
esac

exec "$BIN" "$@"
LAUNCHER
}
LAUNCHER_TEMPLATE=$(emit_launcher)

# systemd 单元：开机自启 + 崩溃重启。数据目录写在 ReadWritePaths 里，
# 其余路径对服务只读。
emit_unit() {
	cat <<'UNIT'
[Unit]
Description=SniRoute observer (egress routing / access restriction probe)
Documentation=https://github.com/@REPO@
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=@LIB@/sniroute server run -config @CONFIG@
WorkingDirectory=@DATA@
Restart=always
RestartSec=3
LimitNOFILE=65535
KillSignal=SIGTERM
TimeoutStopSec=15
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=@DATA@

[Install]
WantedBy=multi-user.target
UNIT
}
UNIT_TEMPLATE=$(emit_unit)

# OpenRC 服务（Alpine 等）：supervise-daemon 守护，崩溃自动重启。
emit_openrc() {
	cat <<'OPENRC'
#!/sbin/openrc-run
description="SniRoute observer (egress routing / access restriction probe)"
command="@LIB@/sniroute"
command_args="server run -config @CONFIG@"
supervisor=supervise-daemon
pidfile="/run/sniroute.pid"
output_log="@DATA@/server.log"
error_log="@DATA@/server.log"
directory="@DATA@"
depend() {
	need net
}
OPENRC
}
OPENRC_TEMPLATE=$(emit_openrc)

# ════════════════════════ 小工具 ════════════════════════
TMP_DIR=""
BIN=""
OS=""
ARCH=""
interrupted=0
TEMP_CONFIG=""

# ANSI colors follow the terminal palette; redirected output stays plain.
color_line() {
	if [ -t 1 ] && [ "${NO_COLOR+x}" != x ] && [ -n "${TERM:-}" ] && [ "$TERM" != dumb ] && [ -n "$1" ]; then
		printf '\033[%sm%s\033[0m\n' "$1" "$2"
	else
		printf '%s\n' "$2"
	fi
}
say() {
	sr_tone=""
	case "$*" in
	已中断* | 提醒：*) sr_tone=33 ;;
	SniRoute* | 被测端* | 临时运行* | 下一步) sr_tone='1;36' ;;
	已* | 服务已* | 二进制版本：*) sr_tone=32 ;;
	下载：* | 使用本地二进制：* | [0-9]\)*) sr_tone=36 ;;
	esac
	color_line "$sr_tone" "$*"
}
warn() { color_line 33 "提示：$*" >&2; }
die() {
	color_line 31 "错误：$*" >&2
	exit 1
}
rule() { color_line 90 "──────────────────────────────────────────────"; }
have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" = "0" ]; }

# 服务管理方式：systemd（Debian/Ubuntu/RHEL/CentOS 等）、OpenRC（Alpine）；
# 都没有时退回二进制自带的 pid 文件后台模式（没有开机自启）。
service_mode() {
	if [ "$NO_SYSTEMD" = "1" ]; then
		printf 'none'
	elif have systemctl; then
		printf 'systemd'
	elif have rc-service || [ -x /sbin/openrc ]; then
		printf 'openrc'
	else
		printf 'none'
	fi
}

cleanup() {
	rc=$?
	if [ "$interrupted" = "1" ]; then
		say ""
		say "已中断。"
	fi
	if [ -n "$TEMP_CONFIG" ]; then
		state=$("$BIN" server status -config "$TEMP_CONFIG" 2>/dev/null) || state=""
		if [ "$state" != "stopped" ] && [ -n "$state" ]; then
			"$BIN" server stop -config "$TEMP_CONFIG" || warn "临时服务未能停止，请检查 server.pid 与运行日志。"
		fi
	fi
	if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
		rm -rf "$TMP_DIR"
	fi
	if [ -f "$STATE_DIR/server.yaml" ] && [ ! -f "$CFG_PERM" ]; then
		say "配置与数据保留在：${STATE_DIR}（临时模式，下次直接再跑本脚本即可）"
	fi
	exit $rc
}

usage() {
	cat <<EOF
SniRoute 观测端部署脚本

  --temp            临时运行：下载到临时目录，退出即清理
  --install         永久安装：$BIN_LINK + 服务（systemd 或 OpenRC，开机自启、崩溃重启）
  --uninstall       卸载（保留配置与数据；加 --purge 一并删除）
  --status          查看状态
  --purge           卸载时同时删除 $ETC_DIR 与 ${DATA_DIR}（会丢节点与历史任务）
  --yes             不询问确认
  --dry-run         只打印将要做什么
  -h, --help        本帮助

环境变量见脚本头部注释。
EOF
}

detect_platform() {
	OS=$(uname -s | tr '[:upper:]' '[:lower:]')
	case "$OS" in
	linux | darwin) ;;
	*) die "不支持的系统：${OS}（只发布 linux / darwin 二进制）" ;;
	esac
	ARCH=$(uname -m)
	case "$ARCH" in
	x86_64 | amd64) ARCH="amd64" ;;
	aarch64 | arm64) ARCH="arm64" ;;
	*) die "不支持的架构：$ARCH" ;;
	esac
}

sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	elif have shasum; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		return 1
	fi
}

fetch() {
	# fetch URL DEST
	if have curl; then
		case "$1" in
		https://*)
			curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time "$DL_TIMEOUT" -o "$2" "$1"
			;;
		*)
			curl -fsSL --connect-timeout 20 --max-time "$DL_TIMEOUT" -o "$2" "$1"
			;;
		esac
	elif have wget; then
		wget -q -T 20 -O "$2" "$1"
	else
		warn "需要 curl 或 wget 才能下载"
		return 1
	fi
}

# resolve_bin 把可执行文件放进临时目录，并验证它能跑。
resolve_bin() {
	[ -n "$TMP_DIR" ] || TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sniroute-server.XXXXXX") || die "无法创建临时目录"
	if [ -n "$LOCAL_BIN" ]; then
		[ -f "$LOCAL_BIN" ] || die "找不到本地二进制：$LOCAL_BIN"
		cp "$LOCAL_BIN" "$TMP_DIR/sniroute" || die "复制失败：$LOCAL_BIN"
		say "使用本地二进制：$LOCAL_BIN"
	else
		url=$(printf '%s' "$BIN_URL_TEMPLATE" | sed -e "s/{os}/$OS/g" -e "s/{arch}/$ARCH/g")
		say "下载：$url"
		fetch "$url" "$TMP_DIR/sniroute" || die "下载失败：$url
  可以设置 SR_BIN=/path/to/sniroute 后重新运行本脚本，使用本地二进制。
  或把 SR_BIN_URL 指向你自己的下载地址。"
		if [ -n "$BIN_SHA256" ]; then
			sum=$(sha256_of "$TMP_DIR/sniroute") || die "系统没有 sha256sum/shasum，无法校验（去掉 SR_SHA256）"
			[ "$sum" = "$BIN_SHA256" ] || die "校验失败：期望 ${BIN_SHA256}，实际 $sum"
			say "sha256 校验通过"
		fi
	fi
	BIN="$TMP_DIR/sniroute"
	chmod 700 "$BIN" || die "无法设置可执行权限"
	v=$("$BIN" version 2>/dev/null) || die "下载的二进制无法运行（架构不符或文件损坏）
  本机：$OS/${ARCH}。同一平台可以自己 go build -o /tmp/sniroute ./cmd/sniroute 后
  用 SR_BIN=/tmp/sniroute 再跑本脚本。"
	[ "$MODE" = "install" ] || say "二进制版本：$v"
}

# render_stdin 把模板里的占位符换成这台机器的实际路径。
RENDER_PROBE="${SR_PROBE_ADDR:-$DEFAULT_PROBE_ROOT}"
RENDER_CONTROL="${SR_CONTROL_ADDR:-$DEFAULT_CONTROL}"
RENDER_SYSTEMD=1
RENDER_OPENRC=0
if [ "$NO_SYSTEMD" = "1" ]; then
	RENDER_SYSTEMD=0
elif ! have systemctl && { have rc-service || [ -x /sbin/openrc ]; }; then
	RENDER_SYSTEMD=0
	RENDER_OPENRC=1
fi
render_stdin() {
	sed -e "s|@LIB@|$LIB_DIR|g" -e "s|@CONFIG@|$CFG_PERM|g" \
		-e "s|@DATA@|$DATA_DIR|g" -e "s|@UNIT@|$UNIT_NAME|g" -e "s|@REPO@|$REPO|g" \
		-e "s|@SYSTEMD@|$RENDER_SYSTEMD|g" -e "s|@OPENRC@|$RENDER_OPENRC|g" \
		-e "s|@PROBE@|$RENDER_PROBE|g" -e "s|@CONTROL@|$RENDER_CONTROL|g"
}

# write_config 写一份“推荐配置”：自签名证书、自动生成管理密钥、探测 :443。
write_config() {
	cfg=$1
	probe=$2
	control=$3
	data=$4
	mkdir -p "$(dirname "$cfg")" || die "无法创建 $(dirname "$cfg")"
	chmod 700 "$(dirname "$cfg")" 2>/dev/null || true
	key=$("$BIN" genkey) || die "无法生成管理密钥"
	(
		umask 077
		cat >"$cfg" <<EOF
# 由 sniroute-server.sh 生成。管理密钥就在这个文件里，权限必须是 0600。
probe_addr: "$probe"
control_addr: "$control"
data_dir: "$data"
collector_id: collector-1
admin_key: "$key"
tls_self_signed: true
EOF
	) || die "写入配置失败：$cfg"
	chmod 600 "$cfg"
	[ "$MODE" = "install" ] || say "已写入推荐配置：$cfg"
}

confirm() {
	[ "$ASSUME_YES" = "1" ] && return 0
	printf '%s [y/N]: ' "$1"
	read -r a <&3 || return 1
	case "$a" in y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
}

# ════════════════════════ 临时运行 ════════════════════════
run_temp() {
	if [ "$DRY_RUN" = "1" ]; then
		say "[dry-run] 临时下载并启动服务，打开菜单；退出时停止临时服务并清理程序。"
		say "[dry-run] 配置与数据保留在：$STATE_DIR"
		return 0
	fi
	mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR" || die "无法创建 $STATE_DIR"
	resolve_bin
	cfg="$STATE_DIR/server.yaml"
	if [ ! -f "$cfg" ]; then
		if is_root; then probe="${SR_PROBE_ADDR:-$DEFAULT_PROBE_ROOT}"; else
			probe="${SR_PROBE_ADDR:-$DEFAULT_PROBE_USER}"
			warn "非 root：探测端口用 ${probe}（:443 需要 root）。客户端会自动发现该端口，不用手填。"
		fi
		write_config "$cfg" "$probe" "${SR_CONTROL_ADDR:-$DEFAULT_CONTROL}" "$STATE_DIR/data"
	fi
	rule
	say "临时运行（不安装、不常驻）"
	say "  配置：$cfg"
	say "  数据：$STATE_DIR/data"
	say "  退出菜单清理本次下载；配置与数据保留。"
	rule
	# Old temporary sessions can leave a dead/zombie/reused PID behind.
	# Remove only stale records, never signal a process based on a stale PID.
	prune_config_pid "$cfg"
	state=$("$BIN" server status -config "$cfg") || die "无法读取服务状态"
	case "$state" in
	stopped)
		TEMP_CONFIG="$cfg"
		"$BIN" server start -config "$cfg" || die "临时服务启动失败，请检查日志"
		say "已启动本次临时服务；退出菜单时自动停止。"
		;;
	running\ \(pid\ *\))
		say "检测到此配置的服务已运行，直接进入管理菜单。"
		say "退出只清理本次下载，已有服务继续运行；需要停止时请选择菜单中的停止服务。"
		;;
	*) die "无法识别服务状态：$state" ;;
	esac
	run "$BIN" server menu -config "$cfg"
	rc=$?
	[ "$rc" = "0" ] || warn "菜单以状态 $rc 退出"
	return "$rc"
}

# ════════════════════════ 永久安装 ════════════════════════
install_perm() {
	if ! is_root && [ "$ALLOW_UNPRIV" != "1" ]; then
		die "永久安装需要 root（要监听 :443、写 $PREFIX 与 ${UNIT_DIR}）。请用 sudo 运行，或选临时运行。"
	fi
	if [ "$DRY_RUN" = "1" ]; then
		rule
		say "[dry-run] 永久安装计划（服务方式：$(service_mode)）"
		say "  二进制：${LOCAL_BIN:-$BIN_URL_TEMPLATE} → $LIB_DIR/sniroute"
		say "  命令：  ${BIN_LINK}（不带参数 = 确保服务运行 + 打开管理菜单）"
		say "  配置：  ${CFG_PERM}（缺则写入推荐配置）"
		say "  数据：  $DATA_DIR"
		case "$(service_mode)" in
		systemd)
			say "  单元：  $UNIT_DIR/$UNIT_NAME"
			say "  启用：  systemctl enable --now $UNIT_NAME"
			;;
		openrc)
			say "  服务：  $INIT_DIR/$INIT_NAME"
			say "  启用：  rc-update add $INIT_NAME default && rc-service $INIT_NAME start"
			;;
		*)
			say "  服务：  无（没有 systemd / OpenRC：pid 文件后台模式，没有开机自启）"
			;;
		esac
		return 0
	fi

	resolve_bin
	mkdir -p "$LIB_DIR" "$PREFIX/bin" "$DATA_DIR" "$ETC_DIR" ||
		die "无法创建安装目录"
	case "$(service_mode)" in
	systemd) mkdir -p "$UNIT_DIR" || die "无法创建 $UNIT_DIR" ;;
	openrc) mkdir -p "$INIT_DIR" || die "无法创建 $INIT_DIR" ;;
	esac
	chmod 700 "$DATA_DIR" "$ETC_DIR"

	cp "$BIN" "$LIB_DIR/sniroute.new" || die "无法写入 $LIB_DIR/sniroute.new"
	chmod 755 "$LIB_DIR/sniroute.new" || die "无法设置程序权限"
	mv -f "$LIB_DIR/sniroute.new" "$LIB_DIR/sniroute" || die "无法替换程序"

	if [ -f "$CFG_PERM" ]; then
		chmod 600 "$CFG_PERM"
	else
		write_config "$CFG_PERM" "${SR_PROBE_ADDR:-$DEFAULT_PROBE_ROOT}" "${SR_CONTROL_ADDR:-$DEFAULT_CONTROL}" "$DATA_DIR"
	fi

	printf '%s\n' "$LAUNCHER_TEMPLATE" | render_stdin >"$BIN_LINK" || die "无法写入 $BIN_LINK"
	chmod 755 "$BIN_LINK"
	say "SniRoute $v 安装完成（输入 sniroute 打开管理菜单）。"

	case "$(service_mode)" in
	systemd)
		printf '%s\n' "$UNIT_TEMPLATE" | render_stdin >"$TMP_DIR/$UNIT_NAME" || die "无法生成 $UNIT_NAME"
		cp "$TMP_DIR/$UNIT_NAME" "$UNIT_DIR/$UNIT_NAME" || die "无法写入 $UNIT_DIR/$UNIT_NAME"
		chmod 644 "$UNIT_DIR/$UNIT_NAME"
		systemctl daemon-reload || die "systemctl daemon-reload 失败"
		systemctl enable "$UNIT_NAME" || die "设置开机启动失败"
		systemctl restart "$UNIT_NAME" || die "启动服务失败（看：journalctl -u $UNIT_NAME -n 50）"
		sleep 1
		if systemctl is-active --quiet "$UNIT_NAME"; then
			say "服务已启动并设为开机自启（崩溃自动重启）。"
		else
			warn "服务没有进入 running 状态；看 journalctl -u $UNIT_NAME -n 50"
		fi
		;;
	openrc)
		printf '%s\n' "$OPENRC_TEMPLATE" | render_stdin >"$TMP_DIR/$INIT_NAME" || die "无法生成 $INIT_NAME"
		cp "$TMP_DIR/$INIT_NAME" "$INIT_DIR/$INIT_NAME" || die "无法写入 $INIT_DIR/$INIT_NAME"
		chmod 755 "$INIT_DIR/$INIT_NAME"
		rc-update add "$INIT_NAME" default >/dev/null 2>&1 ||
			warn "rc-update add 失败：开机自启未设置（可手动：rc-update add $INIT_NAME default）"
		rc-service "$INIT_NAME" restart >/dev/null 2>&1 || rc-service "$INIT_NAME" start ||
			die "启动服务失败（看：rc-service $INIT_NAME status 与 $DATA_DIR/server.log）"
		say "服务已启动并设为开机自启（supervise-daemon 崩溃自动重启）。"
		;;
	*)
		warn "没有 systemd / OpenRC：不写服务，因此没有开机自启与崩溃重启。
  用 $BIN_LINK start|stop|status 管理后台进程，或 $LIB_DIR/sniroute server run -config $CFG_PERM 前台运行。"
		;;
	esac

	rule
	say "下一步"
	say "  1) 输入 sniroute            → 打开管理菜单（会自动确保服务在跑）"
	say "  2) 菜单 1                   → 生成注册链接，发给被测机器"
	say ""
	probe_port=$(cfg_value "$CFG_PERM" probe_addr)
	control_port=$(cfg_value "$CFG_PERM" control_addr)
	say "提醒：请在防火墙和云安全组放行 TCP ${probe_port##*:}、${control_port##*:} 端口。"
}

# ════════════════════════ 卸载 ════════════════════════
uninstall() {
	if ! is_root && [ "$ALLOW_UNPRIV" != "1" ]; then
		die "卸载需要 root"
	fi
	if [ "$DRY_RUN" = "1" ]; then
		rule
		say "[dry-run] 将停止服务并删除：$UNIT_DIR/$UNIT_NAME $BIN_LINK $LIB_DIR"
		[ "$PURGE" = "1" ] && say "[dry-run] 并删除：$ETC_DIR $DATA_DIR"
		return 0
	fi
	if [ "$NO_SYSTEMD" != "1" ] && have systemctl && [ -f "$UNIT_DIR/$UNIT_NAME" ]; then
		systemctl disable --now "$UNIT_NAME" || die "停止服务失败，保留程序文件；请检查 systemctl status $UNIT_NAME 后重试。"
	elif [ "$NO_SYSTEMD" != "1" ] && { have rc-service || [ -x /sbin/openrc ]; } && [ -f "$INIT_DIR/$INIT_NAME" ]; then
		rc-service "$INIT_NAME" stop >/dev/null 2>&1 || true
		rc-update del "$INIT_NAME" default >/dev/null 2>&1 || true
	elif [ -x "$LIB_DIR/sniroute" ] && [ -f "$CFG_PERM" ]; then
		state=$("$LIB_DIR/sniroute" server status -config "$CFG_PERM") || die "无法读取服务状态"
		[ "$state" = "stopped" ] || "$LIB_DIR/sniroute" server stop -config "$CFG_PERM" || die "停止服务失败，保留程序文件。"
	fi
	rm -f "$UNIT_DIR/$UNIT_NAME" "$INIT_DIR/$INIT_NAME" "$BIN_LINK"
	rm -rf "$LIB_DIR"
	have systemctl && [ "$NO_SYSTEMD" != "1" ] && systemctl daemon-reload >/dev/null 2>&1 || true
	say "已删除程序与单元。"
	if [ "$PURGE" = "1" ]; then
		if confirm "确认删除配置与全部数据（${ETC_DIR}、${DATA_DIR}）？节点与历史任务都会丢失"; then
			rm -rf "$ETC_DIR" "$DATA_DIR"
			say "已删除配置与数据。"
		else
			say "保留配置与数据：$ETC_DIR  $DATA_DIR"
		fi
	else
		say "保留配置与数据：$ETC_DIR  ${DATA_DIR}（彻底删除：--uninstall --purge）"
	fi
}

# ════════════════════════ 状态 ════════════════════════
cfg_value() {
	[ -f "$1" ] || return 1
	sed -n "s/^$2:[[:space:]]*//p" "$1" | sed -e 's/^"//' -e 's/"$//' | head -n 1
}

# Resolve data_dir the same way as the binary: relative to the config file.
config_pid_file() {
	sr_pid_dir=$(cfg_value "$1" data_dir) || return 1
	[ -n "$sr_pid_dir" ] || return 1
	case "$sr_pid_dir" in
	/*) ;;
	*) sr_pid_dir="$(dirname "$1")/$sr_pid_dir" ;;
	esac
	printf '%s/server.pid\n' "$sr_pid_dir"
}

prune_config_pid() {
	sr_pid_file=$(config_pid_file "$1") || return 0
	[ -f "$sr_pid_file" ] || return 0
	sr_old_pid=$(cat "$sr_pid_file" 2>/dev/null) || return 0
	sr_pid_stale=0
	case "$sr_old_pid" in
	''|*[!0-9]*|0|1) sr_pid_stale=1 ;;
	*)
		if ! kill -0 "$sr_old_pid" 2>/dev/null; then
			# EPERM must not be mistaken for a dead process.
			if [ -d /proc ]; then
				[ -d "/proc/$sr_old_pid" ] || sr_pid_stale=1
			elif have ps && [ -z "$(ps -p "$sr_old_pid" -o pid= 2>/dev/null)" ]; then
				sr_pid_stale=1
			fi
		elif [ -r "/proc/$sr_old_pid/stat" ]; then
			sr_proc_state=$(sed 's/^.*) //' "/proc/$sr_old_pid/stat" | cut -d ' ' -f 1)
			case "$sr_proc_state" in Z|X) sr_pid_stale=1 ;; esac
			if [ "$sr_pid_stale" = 0 ] && [ -r "/proc/$sr_old_pid/cmdline" ]; then
				sr_proc_args=$(tr '\000' '\n' <"/proc/$sr_old_pid/cmdline" | tail -n 4)
				sr_expected_args=$(printf 'server\nrun\n-config\n%s' "$1")
				[ "$sr_proc_args" = "$sr_expected_args" ] || sr_pid_stale=1
			fi
		fi
		;;
	esac
	if [ "$sr_pid_stale" = 1 ]; then
		# Do not remove a PID record changed by another launcher in the meantime.
		if [ "$(cat "$sr_pid_file" 2>/dev/null)" = "$sr_old_pid" ]; then
			rm -f "$sr_pid_file" || die "无法清理失效的服务记录：$sr_pid_file"
		fi
	fi
}

show_status() {
	rule
	say "SniRoute 观测端状态"
	if [ -x "$LIB_DIR/sniroute" ]; then
		say "  永久安装：$LIB_DIR/sniroute（版本 $("$LIB_DIR/sniroute" version 2>/dev/null || echo '?')）"
		say "  命令：    $BIN_LINK"
	else
		say "  永久安装：无"
	fi
	pid=""
	status_cfg="$CFG_PERM"
	[ -f "$status_cfg" ] || status_cfg="$STATE_DIR/server.yaml"
	if [ -f "$status_cfg" ]; then
		prune_config_pid "$status_cfg"
		status_pid_file=$(config_pid_file "$status_cfg") || status_pid_file=""
		[ ! -f "$status_pid_file" ] || pid=$(cat "$status_pid_file" 2>/dev/null)
	fi
	if [ -f "$UNIT_DIR/$UNIT_NAME" ] && have systemctl; then
		a=$(systemctl is-active "$UNIT_NAME" 2>/dev/null || true)
		e=$(systemctl is-enabled "$UNIT_NAME" 2>/dev/null || true)
		say "  服务：    ${a:-unknown}（开机自启：${e:-unknown}）"
	elif [ -f "$INIT_DIR/$INIT_NAME" ] && { have rc-service || [ -x /sbin/openrc ]; }; then
		a=$(rc-service "$INIT_NAME" status 2>/dev/null || true)
		say "  服务：    ${a:-unknown}（OpenRC）"
	elif [ -n "$pid" ]; then
		say "  服务：    后台进程运行中（pid ${pid}）"
	else
		say "  服务：    未运行"
	fi
	if [ -f "$CFG_PERM" ]; then
		say "  配置：    $CFG_PERM"
		say "            探测 $(cfg_value "$CFG_PERM" probe_addr)   控制 $(cfg_value "$CFG_PERM" control_addr)   数据 $(cfg_value "$CFG_PERM" data_dir)"
	elif [ -f "$STATE_DIR/server.yaml" ]; then
		say "  配置：    $STATE_DIR/server.yaml（临时模式留下的）"
		say "            探测 $(cfg_value "$STATE_DIR/server.yaml" probe_addr)   控制 $(cfg_value "$STATE_DIR/server.yaml" control_addr)"
	else
		say "  配置：    无（还没初始化）"
	fi
	rule
}

# ════════════════════════ 交互 ════════════════════════
require_tty() {
	[ -t 3 ] || die "这一项需要交互终端。也可以直接用 --temp / --install 等参数运行。"
}

# 非 root 选「永久安装」时：把本脚本下载到临时目录，用 sudo 重新运行。
# 临时文件随 TMP_DIR 在退出时一并清理。
sudo_install() {
	[ -n "$TMP_DIR" ] || TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sniroute-server.XXXXXX") || die "无法创建临时目录"
	SUDO_SCRIPT="$TMP_DIR/sniroute-server.sh"
	say "下载脚本后用 sudo 重新运行安装（可能要求输入密码）..."
	fetch "$SCRIPT_URL" "$SUDO_SCRIPT" || die "下载脚本失败：$SCRIPT_URL
  也可以手动执行：curl -fsSLO <脚本地址> && sudo sh sniroute-server.sh --install"
	chmod 700 "$SUDO_SCRIPT"
	sudo sh "$SUDO_SCRIPT" --install <&3
}

interactive() {
	require_tty
	show_status
	say "1) 临时运行（不安装；退出即清理下载与临时文件）"
	say "2) 永久安装（systemd / OpenRC：开机自启、崩溃重启；之后输入 sniroute 就启动）"
	say "3) 卸载"
	say "4) 查看状态"
	say "0) 退出"
	printf '选择：'
	read -r ans <&3 || exit 0
	case "$ans" in
	1) run_temp ;;
	2)
		MODE="install"
		if is_root; then
			install_perm
		else
			say "永久安装需要 root（要监听 :443、写 $PREFIX 与 ${UNIT_DIR}）。"
			printf '是否下载脚本并用 sudo 重新运行安装？[y/N]：'
			read -r ans <&3 || exit 0
			case "$ans" in
			y | Y | yes | YES) sudo_install ;;
			*) die "已取消。也可以手动运行：sudo sh sniroute-server.sh --install" ;;
			esac
		fi
		;;
	3) uninstall ;;
	4) show_status ;;
	0 | "") exit 0 ;;
	*) die "无效选择：$ans" ;;
	esac
}

forward_signal() {
	interrupted=1
	signal_count=$((signal_count + 1))
	if [ "$signal_count" -ge 2 ]; then
		kill -KILL "$child" 2>/dev/null || true
	else
		kill -INT "$child" 2>/dev/null || true
	fi
}

run() {
	if [ -t 3 ]; then
		# 终端会把 Ctrl+C 同时交给前台程序与脚本；不重复转发，以免
		# 程序将同一次按键当作第二次强退。前台执行也保留菜单输入。
		trap 'interrupted=1' INT
		"$@" <&3
		rc=$?
		trap 'exit 130' INT
		return "$rc"
	fi
	signal_count=0
	# 显式保留 stdin，避免非交互 shell 将后台命令的输入改成 /dev/null。
	"$@" <&3 &
	child=$!
	trap forward_signal INT HUP TERM
	# wait 会被信号打断；必须等程序真正退出、写完部分报告后才能清理。
	while :; do
		wait "$child"
		rc=$?
		kill -0 "$child" 2>/dev/null || break
	done
	trap 'exit 130' INT
	trap 'exit 143' TERM
	trap 'exit 129' HUP
	return "$rc"
}

# ════════════════════════ 入口 ════════════════════════
MODE=""
ASSUME_YES=0
PURGE=0
DRY_RUN=0
while [ $# -gt 0 ]; do
	case "$1" in
	--temp) MODE="temp" ;;
	--install) MODE="install" ;;
	--uninstall) MODE="uninstall" ;;
	--status) MODE="status" ;;
	--purge) PURGE=1 ;;
	--yes | -y) ASSUME_YES=1 ;;
	--dry-run) DRY_RUN=1 ;;
	-h | --help | help) usage; exit 0 ;;
	*) die "未知参数：$1（--help 看用法）" ;;
	esac
	shift
done

exec 3<&0
# 被 curl | sh 调用时 stdin 是脚本本身：接回终端，否则菜单读不到输入。
if [ ! -t 0 ] && ( : </dev/tty ) 2>/dev/null; then
	exec 3</dev/tty
fi

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

detect_platform
for install_path in "$PREFIX" "$ETC_DIR" "$DATA_DIR" "$UNIT_DIR" "$STATE_DIR"; do
	case "$install_path" in
	/*) ;;
	*) die "目录必须使用绝对路径：$install_path" ;;
	esac
	case "$install_path" in
	*[!a-zA-Z0-9_./:-]* | *//* | */ | */../* | */.. | */./* | */.) die "目录包含不支持的字符或路径段：$install_path；请使用不含空格的简单绝对路径" ;;
	esac
done
for delete_path in "$LIB_DIR" "$ETC_DIR" "$DATA_DIR"; do
	case "$delete_path" in
	/ | /etc | /usr | /usr/local | /var | /var/lib | /bin | /tmp | "$HOME")
		die "目录过于宽泛：$delete_path；请指定 sniroute 专用子目录" ;;
	esac
done
case "$MODE" in
temp) run_temp ;;
install) install_perm ;;
uninstall) uninstall ;;
status) show_status ;;
"") interactive ;;
esac
