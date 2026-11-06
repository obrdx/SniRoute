#!/bin/sh
# SniRoute 被测端（客户端）一次性脚本 —— 单文件、纯 POSIX sh。
#
# 一行运行：
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-client.sh)"
#
# 客户端始终是“临时”的：脚本与下载的二进制只在本次运行期间存在于临时目录，
# 无论测试正常结束、中途 Ctrl+C、SSH 断开还是出错，退出时都会清理。
#
# 保留的只有两样：
#   · 报告     写在当前目录（运行本脚本时所在目录）的 <任务>-report.md
#   · 身份     client.yaml（节点密钥）与 client.db（待补交记录）留在 ~/.sniroute
#              否则每次都要重新贴注册链接，而链接是一次性的
#
#   sh sniroute-client.sh                       首次：粘贴注册链接；之后：主菜单
#   sh sniroute-client.sh --link 'https://…'    带上注册链接（省一次粘贴）
#   sh sniroute-client.sh --probe [参数…]       非交互跑一次测试（用记住的域名选择）
#   sh sniroute-client.sh --dry-run             只打印将要做什么
#
# 可用环境变量：
#   SR_BIN=/path/to/sniroute    用本地二进制（离线 / 自己编译时）
#   SR_BIN_URL=...              改下载地址，支持 {os} {arch} 占位符
#   SR_SHA256=...               校验下载文件的 sha256
#   SR_STATE_DIR=~/.sniroute    身份与队列的保存位置
#   SR_REG_LINK=...             同 --link
set -u

# ════════════════════════ 变量 ════════════════════════
readonly SCRIPT_VERSION="v1"
APP="sniroute"
REPO="${SR_REPO:-obrdx/SniRoute}"
BIN_URL_TEMPLATE="https://github.com/${REPO}/releases/latest/download/sniroute_{os}_{arch}"
BIN_URL_TEMPLATE="${SR_BIN_URL:-$BIN_URL_TEMPLATE}"
LOCAL_BIN="${SR_BIN:-}"
BIN_SHA256="${SR_SHA256:-}"
DL_TIMEOUT="${SR_DOWNLOAD_TIMEOUT:-300}"

# 身份与本地队列（不随脚本清理，见文件头）
STATE_DIR="${SR_STATE_DIR:-$HOME/.sniroute}"
CLIENT_CFG="$STATE_DIR/client.yaml"

# ════════════════════════ 小工具 ════════════════════════
TMP_DIR=""
BIN=""
OS=""
ARCH=""
WORK_DIR=$(pwd)
interrupted=0

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

cleanup() {
	rc=$?
	if [ "$interrupted" = "1" ]; then
		say ""
		say "已中断：未执行的尝试不计为网络失败；已有证据与待补交记录保留，可在历史报告中查看或补交。"
	fi
	# 收尾提示：本次新写出的 Markdown 报告
	if [ -n "$TMP_DIR" ] && [ -f "$TMP_DIR/stamp" ]; then
		news=$(find "$WORK_DIR" -maxdepth 1 -name '*-report.md' -newer "$TMP_DIR/stamp" -print 2>/dev/null | sort)
		if [ -n "$news" ]; then
			say ""
			say "报告保留在："
			printf '  %s\n' "$news"
		fi
	fi
	if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
		rm -rf "$TMP_DIR"
		say "已清理本次临时程序与文件：$TMP_DIR"
	fi
	exit $rc
}

usage() {
	cat <<EOF
SniRoute 被测端（临时运行，不安装）

  --link URL | 空          注册链接（也可以用 SR_REG_LINK，或运行时粘贴）
  --probe [参数…]          非交互跑一次测试，其余参数透传给 client probe
  --reports [参数…]        历史报告 / 补交队列
  --state-dir DIR          身份与队列目录（默认 ${STATE_DIR}）
  --dry-run                只打印将要做什么
  -h, --help               本帮助

报告写在当前目录：$WORK_DIR
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

resolve_bin() {
	[ -n "$TMP_DIR" ] || TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sniroute-client.XXXXXX") || die "无法创建临时目录"
	touch "$TMP_DIR/stamp"
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
	say "二进制版本：$v"
}

# run 把信号转发给子进程：第一次 Ctrl+C 让 sniroute 自己优雅中断并取回报告，
# 第二次直接结束；无论哪种方式，退出后都会清理临时目录。
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
MODE="menu"
LINK="${SR_REG_LINK:-}"
DRY_RUN=0
while [ $# -gt 0 ]; do
	case "$1" in
	--link)
		[ $# -ge 2 ] || die "--link 需要一个注册链接"
		LINK=$2
		shift 2
		;;
	--probe) MODE="probe"; shift ;;
	--reports) MODE="reports"; shift ;;
	--state-dir)
		[ $# -ge 2 ] || die "--state-dir 需要一个目录"
		STATE_DIR=$2
		CLIENT_CFG="$STATE_DIR/client.yaml"
		shift 2
		;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help | help) usage; exit 0 ;;
	*) break ;;
	esac
done

exec 3<&0
# `curl | sh` 时 stdin 是脚本本身：接回终端，否则菜单读不到输入。
if [ ! -t 0 ] && [ "$MODE" = "menu" ] && ( : </dev/tty ) 2>/dev/null; then
	exec 3</dev/tty
fi

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

detect_platform
say "被测端（临时运行）　本机：$OS/${ARCH}　报告目录：$WORK_DIR"

if [ "$DRY_RUN" = "1" ]; then
	BIN="${LOCAL_BIN:-<临时目录>/sniroute}"
else
	if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
		die "无法创建 ${STATE_DIR}（可用 --state-dir 指定别处）"
	fi
	chmod 700 "$STATE_DIR" 2>/dev/null || true
	resolve_bin
fi

if [ -n "$LINK" ]; then
	if [ "$DRY_RUN" = "1" ]; then
		say "[dry-run] 将执行：$BIN client enroll -link '<注册链接>' -config $CLIENT_CFG"
	else
		run "$BIN" client enroll -link "$LINK" -config "$CLIENT_CFG" ||
			die "注册失败（链接可能已被使用或过期；请让观测端重新生成一个）"
	fi
fi

case "$MODE" in
probe)
	if [ "$DRY_RUN" = "1" ]; then
		say "[dry-run] 将执行：$BIN client probe -config $CLIENT_CFG $*"
		exit 0
	fi
	run "$BIN" client probe -config "$CLIENT_CFG" "$@"
	;;
reports)
	if [ "$DRY_RUN" = "1" ]; then
		say "[dry-run] 将执行：$BIN reports $* -config ${CLIENT_CFG}（历史报告与本地队列）"
		exit 0
	fi
	run "$BIN" client reports "$@" -config "$CLIENT_CFG"
	;;
*)
	if [ "$DRY_RUN" = "1" ]; then
		say "[dry-run] 将执行：$BIN client menu -config $CLIENT_CFG"
		exit 0
	fi
	say ""
	rule
	run "$BIN" client menu -config "$CLIENT_CFG"
	;;
esac
