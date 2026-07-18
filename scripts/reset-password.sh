#!/bin/sh
set -eu

PANEL_BIN="${PANEL_BIN:-/home/wwwroot/Kunpanel.456.life/tryallfun-panel}"
DATA_DIR="${TAF_DATA_DIR:-/var/lib/tryallfun-panel}"

if [ ! -x "$PANEL_BIN" ]; then
    echo "找不到面板程序：$PANEL_BIN" >&2
    exit 1
fi

printf "请输入新的管理员密码（至少 16 位，含大小写、数字和特殊字符）："
stty -echo
IFS= read -r password
stty echo
printf "\n请再次输入："
stty -echo
IFS= read -r confirm
stty echo
printf "\n"

if [ "$password" != "$confirm" ]; then
    echo "两次密码不一致。" >&2
    exit 1
fi

printf "%s\n" "$password" | TAF_DATA_DIR="$DATA_DIR" "$PANEL_BIN" reset-password
