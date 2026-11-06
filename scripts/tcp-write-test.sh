#!/bin/sh
# Run on the tested VPS, with the experimental binary next to this script.
set -eu
trap 'exit 130' INT
trap 'exit 143' TERM
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
binary=${SNIROUTE_TCP_BIN:-"$script_dir/sniroute_tcp_linux_amd64"}
config=${SNIROUTE_TCP_CONFIG:-"$HOME/.sniroute/client.yaml"}
target=${SNIROUTE_TCP_TARGET:-23.150.4.186:443}
baseline=${SNIROUTE_TCP_BASELINE:-asfefawefa.4805787.xyz}
if [ ! -f "$binary" ]; then
  printf '找不到实验程序：%s。请将 Linux amd64 实验程序放在脚本同一目录。\n' "$binary" >&2
  exit 1
fi
if [ ! -f "$config" ]; then
  printf '找不到客户端配置：%s。请先用客户端菜单完成登记，再运行本脚本。\n' "$config" >&2
  exit 1
fi
chmod 700 "$binary"
probe() {
  "$binary" client probe -config "$config" -target "$target" \
    -baseline "$baseline" -sni www.google.com -sni github.com \
    -rounds 3 -concurrency 1 -seed 7 -timeout 8s -show-full-ip "$@"
}
printf 'TCP 写入对照：2 个域名 + 1 个基线；13 个独立任务，共计划 117 次连接。\n'
printf '各任务自动保存 Markdown 报告；只显示受控探测出口，不代表真实网站出口。\n'
printf '\n===== 普通模式 =====\n'
probe
for position in inside-sni after-sni; do
  for delay in 0ms 20ms 100ms; do
    printf '\n===== TCP 分次写入：%s / %s =====\n' "$position" "$delay"
    probe -tcp-write-split-at "$position" -tcp-write-delay "$delay"
    printf '\n===== 普通模式对照 =====\n'
    probe
  done
done
