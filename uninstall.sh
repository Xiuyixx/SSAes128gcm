#!/usr/bin/env bash
set -euo pipefail

log_info() { echo "[信息] $*"; }
log_ok() { echo "[成功] $*"; }
log_warn() { echo "[警告] $*" >&2; }

die() { echo "[错误] $*" >&2; exit 1; }

if [[ ${EUID:-0} -ne 0 ]]; then
  die "请以 root 运行：sudo bash $0"
fi

SERVICE_NAME="shadowsocks-server.service"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
BIN_PATH="/usr/local/bin/ssserver"
CONFIG_DIR="/etc/shadowsocks"
SS_USER="shadowsocks"

log_info "=== 开始卸载 Shadowsocks（shadowsocks-rust）==="

if systemctl list-unit-files | grep -q "^${SERVICE_NAME}"; then
  log_info "停止并禁用服务：${SERVICE_NAME}"
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
fi

if [[ -f "$UNIT_PATH" ]]; then
  log_info "移除 systemd unit：${UNIT_PATH}"
  rm -f "$UNIT_PATH"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [[ -d "$CONFIG_DIR" ]]; then
  log_info "移除配置目录：${CONFIG_DIR}"
  rm -rf "$CONFIG_DIR"
fi

if [[ -f "$BIN_PATH" ]]; then
  log_info "移除二进制：${BIN_PATH}"
  rm -f "$BIN_PATH"
fi

if id -u "$SS_USER" >/dev/null 2>&1; then
  log_info "移除系统用户：${SS_USER}"
  userdel "$SS_USER" >/dev/null 2>&1 || true
fi

log_ok "卸载完成"
log_warn "提示：如果你之前手动放行过端口（云安全组/防火墙），需要你自行回收规则。"
