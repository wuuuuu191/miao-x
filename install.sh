#!/usr/bin/env bash
# ============================================================
# miaowu 一键部署脚本（Linux 主控 master / 子节点 agent）
#
# 主控（VPS-A）:
#   curl -fsSL <本脚本URL> -o install.sh && sudo bash install.sh master
#   # 二进制不在 GitHub 时，先指定下载地址：
#   sudo MMW_BASE_URL="https://your-host/dl" bash install.sh master
#
# 子节点（VPS-B）—— 参数与主控面板「接入命令」一致:
#   sudo MMW_BASE_URL="https://your-host/dl" bash install.sh agent \
#        http://<主控IP>:12889 <server-token> <master_pub_key>
#
# 卸载: sudo bash install.sh uninstall [-y]   （-y 静默彻底清除；默认逐项确认，需终端 TTY）
#       sudo bash install.sh uninstall master|agent [-y]
# ============================================================
set -euo pipefail

INSTALL_DIR="/opt/miaowu"
SERVICE_NAME=""
BIN_NAME="miaowu"
# 下载镜像回退链（国内 VPS 直连 GitHub 失败时自动切换）
MIRRORS=(
  "https://github.com"
  "https://mirror.gh-proxy.com/https://github.com"
  "https://ghfast.top/https://github.com"
)

log()  { echo -e "\033[32m[ miaowu ]\033[0m $*"; }
warn() { echo -e "\033[33m[ miaowu ]\033[0m $*"; }
die()  { echo -e "\033[31m[ miaowu ]\033[0m $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 sudo 运行（root 用户直接 bash install.sh 即可）"
command -v systemctl >/dev/null 2>&1 || die "需要 systemd（Ubuntu/Debian/CentOS 等）"

# 依赖预检：全新最小系统可能没有 curl，自动补装（Debian/Ubuntu/CentOS/Alpine）
ensure_deps() {
  command -v curl >/dev/null 2>&1 && return 0
  warn "未检测到 curl，自动安装..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl ca-certificates || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl || true
  elif command -v apk >/dev/null 2>&1; then
    apk add curl ca-certificates || true
  fi
  command -v curl >/dev/null 2>&1 || die "curl 自动安装失败，请手动执行: apt-get install -y curl"
}
ensure_deps

arch_of() {
  case "$(uname -m)" in
    x86_64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
}

# download <relative-path> <输出文件>（S7: 附带 sha256sums.txt 校验，防镜像/自建源投毒）
download() {
  local rel="$1" out="$2" dir url
  dir="$(dirname "$rel")"
  fetch_one() { # $1=完整URL $2=输出
    curl -fSL --connect-timeout 8 --max-time 300 -o "$2" "$1"
  }
  if [[ -n "${MMW_BASE_URL:-}" ]]; then
    fetch_one "$MMW_BASE_URL/$rel" "$out" || die "从 $MMW_BASE_URL 下载失败: $rel"
  else
    local repo="${MMW_REPO:-wuuuuu191/miao-x}"
    local ok=0
    for m in "${MIRRORS[@]}"; do
      if fetch_one "$m/$repo/releases/latest/download/$rel" "$out"; then ok=1; break; fi
    done
    [[ $ok == 1 ]] || die "下载失败: $rel —— 请用 MMW_BASE_URL 指定二进制下载地址，或先发布 GitHub Release"
  fi
  # S7: 校验和验证（sha256sums.txt 与二进制同源）
  local sums="$out.sha256.tmp"
  if [[ -n "${MMW_BASE_URL:-}" ]]; then
    fetch_one "$MMW_BASE_URL/$dir/sha256sums.txt" "$sums" 2>/dev/null || fetch_one "$MMW_BASE_URL/sha256sums.txt" "$sums" || true
  else
    local repo2="${MMW_REPO:-wuuuuu191/miao-x}"
    for m in "${MIRRORS[@]}"; do
      fetch_one "$m/$repo2/releases/latest/download/sha256sums.txt" "$sums" 2>/dev/null && break
    done
  fi
  if [[ -s "$sums" ]]; then
    # 防御：兼容 Windows 生成的 CRLF 清单
    tr -d '\r' < "$sums" > "$sums.fix" && mv "$sums.fix" "$sums"
    local want got
    want="$(grep -E "[0-9a-f]{64}  $(basename "$rel")\$" "$sums" | awk '{print $1}' | head -1)" || want=""
    got="$(sha256sum "$out" | awk '{print $1}')"
    rm -f "$sums"
    if [[ -z "$want" ]]; then
      die "校验和文件中找不到 $(basename "$rel") 的哈希，拒绝安装（供应链保护）"
    fi
    if [[ "$want" != "$got" ]]; then
      rm -f "$out"
      die "SHA256 校验失败！下载内容与发布清单不符（expected=$want got=$got），已删除。请检查下载源是否被篡改"
    fi
    log "SHA256 校验通过"
  else
    rm -f "$sums"
    die "未取到 sha256sums.txt，拒绝安装（供应链保护）。请确认发布物包含校验和文件，或自建源补充它"
  fi
}

install_bin() {
  local arch dest="$1"
  arch="$(arch_of)"
  log "下载 miaowu-linux-$arch ..."
  download "miaowu-linux-$arch" "$dest"
  chmod +x "$dest"
}

write_systemd() { # $1=服务名 $2=工作目录 $3=ExecStart
  cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=miaowu ($1)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$3
Restart=on-failure
RestartSec=5
WorkingDirectory=$2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$1"
}

# ---------------- master ----------------
install_master() {
  SERVICE_NAME="miaowu"
  mkdir -p "$INSTALL_DIR/master/data"
  install_bin "$INSTALL_DIR/$BIN_NAME"

  cat > "$INSTALL_DIR/master/config.yaml" <<EOF
mode: master
port: "${MMW_PORT:-12889}"
data_dir: "$INSTALL_DIR/master/data"
EOF
  # 可选: 安装时直接配置面板域名 → 内置 ACME 自动申请证书(3X-UI 式)
  if [[ -n "${MMW_DOMAIN:-}" ]]; then
    echo "domain: \"${MMW_DOMAIN}\"" >> "$INSTALL_DIR/master/config.yaml"
    [[ -n "${MMW_EMAIL:-}" ]] && echo "email: \"${MMW_EMAIL}\"" >> "$INSTALL_DIR/master/config.yaml"
    # ACME HTTP-01 需要 80 端口
    if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp >/dev/null 2>&1 || true; fi
    if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 || true; fi
  fi

  write_systemd miaowu "$INSTALL_DIR/master" \
    "$INSTALL_DIR/$BIN_NAME -c $INSTALL_DIR/master/config.yaml"

  # 防火墙放行（尽力而为）
  if command -v ufw >/dev/null 2>&1; then ufw allow "${MMW_PORT:-12889}/tcp" >/dev/null 2>&1 || true; fi
  if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --add-port="${MMW_PORT:-12889}/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 || true; fi

  sleep 1
  local ip
  ip="$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo '<服务器IP>')"

  log "──────────────────────────────────────────────"
  log "主控已启动: http://$ip:${MMW_PORT:-12889}"
  if [[ -n "${MMW_DOMAIN:-}" ]]; then
    log "面板地址(HTTPS): https://${MMW_DOMAIN}:${MMW_PORT:-12889}"
    log "证书将由内置 ACME 在首次访问时自动申请（需域名已解析到本机且 80 端口可达）"
  fi
  log "首次访问网页 → 初始化管理员账号"
  log "主控公钥（agent 接入用）: journalctl -u miaowu | grep 公钥"
  log "随后在面板「服务器」添加服务器，用生成的接入命令部署 agent"
  log "常用: systemctl {status|restart} miaowu · journalctl -u miaowu -f"
  log "──────────────────────────────────────────────"
}

# ---------------- agent ----------------
install_agent() {
  [[ $# -ge 3 ]] || die "用法: install.sh agent <master_url> <token> <master_pub_key>"
  local master_url="$1" token="$2" pub="$3"
  SERVICE_NAME="miaowu-agent"
  # S2: 明文传输告警 —— 公网地址走 http:// 时 token 可被链路嗅探
  if [[ "$master_url" == http://* ]]; then
    local host="${master_url#http://}"; host="${host%%:*}"
    if [[ "$host" != "localhost" && "$host" != 127.* && "$host" != 10.* && "$host" != 192.168.* && "$host" != 172.16.* && "$host" != 172.17.* && "$host" != 172.18.* && "$host" != 172.19.* && "$host" != 172.2* && "$host" != 172.30.* && "$host" != 172.31.* ]]; then
      warn "⚠️  master_url 是公网 http:// —— server token 将明文传输，链路上的任何设备都可窃取后接管此节点！"
      warn "    强烈建议先在主控配置域名证书（面板「设置」），再用 https:// 地址接入"
      if [[ "${MMW_FORCE_INSECURE:-0}" != "1" ]]; then
        die "已中止。确认风险后可加 MMW_FORCE_INSECURE=1 强制继续"
      fi
    fi
  fi
  mkdir -p "$INSTALL_DIR/agent/xray-config"
  install_bin "$INSTALL_DIR/$BIN_NAME"

  cat > "$INSTALL_DIR/agent/config.yaml" <<EOF
mode: agent
master_server: "$master_url"
token: "$token"
master_pub_key: "$pub"
listen_port: 62789
xray_path: ""
xray_config_dir: "$INSTALL_DIR/agent/xray-config"
data_dir: "$INSTALL_DIR/agent"
EOF

  # xray 内核（agent 管理 xray 进程，必需）
  if ! command -v xray >/dev/null 2>&1 && [[ ! -x /usr/local/bin/xray ]]; then
    warn "未检测到 xray，安装官方内核..."
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install \
      || { for m in "${MIRRORS[@]}"; do
             bash -c "$(curl -fsSL "$m/XTLS/Xray-install/raw/main/install-release.sh")" @ install && break
           done; } \
      || warn "xray 自动安装失败，请手动安装后: systemctl restart miaowu-agent"
  fi
  # 官方安装脚本会注册并启用 xray.service —— xray 进程由 miaowu-agent 托管，
  # 系统服务必须停用，否则双进程抢端口/浪费内存
  if systemctl list-unit-files xray.service --no-legend 2>/dev/null | grep -q .; then
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    log "已停用系统 xray.service（由 miaowu-agent 托管 xray）"
  fi

  write_systemd miaowu-agent "$INSTALL_DIR/agent" \
    "$INSTALL_DIR/$BIN_NAME -c $INSTALL_DIR/agent/config.yaml"

  sleep 2
  log "──────────────────────────────────────────────"
  log "agent 已启动，回连 $master_url"
  log "到主控面板确认该服务器显示「在线」，然后下发 Xray 配置"
  log "常用: systemctl {status|restart} miaowu-agent · journalctl -u miaowu-agent -f"
  log "──────────────────────────────────────────────"
}

uninstall() {
  # 用法: uninstall [master|agent|all] [-y|--yes]
  #   默认交互式确认；-y 完全静默，彻底清除全部内容（含数据与 xray 内核）
  local what="all" assume=0
  for a in "$@"; do
    case "$a" in
      master|agent|all) what="$a" ;;
      -y|--yes) assume=1 ;;
      *) die "uninstall 未知参数: $a" ;;
    esac
  done
  ASSUME_YES="$assume"

  confirm() { # confirm "提示" → 0=继续；从 /dev/tty 读，防 curl|bash 时误吞脚本
    if [[ "${ASSUME_YES:-0}" == "1" ]]; then return 0; fi
    local _a=""
    read -r -p "$1 [y/N] " _a < /dev/tty 2>/dev/null || _a=""
    [[ "$_a" == "y" || "$_a" == "Y" ]]
  }

  local removed_any=0

  # ---- 1. 停止并禁用服务 ----
  stop_service() {
    if systemctl list-unit-files "$1.service" --no-legend 2>/dev/null | grep -q .; then
      log "停止服务 $1 ..."
      systemctl disable --now "$1" 2>/dev/null || true
      rm -f "/etc/systemd/system/$1.service"
      removed_any=1
    fi
  }
  [[ "$what" == "all" || "$what" == "master" ]] && stop_service miaowu
  [[ "$what" == "all" || "$what" == "agent"  ]] && stop_service miaowu-agent

  # ---- 2. 清残留进程 ----
  if pgrep -f "$INSTALL_DIR/$BIN_NAME" >/dev/null 2>&1; then
    log "结束残留进程..."
    pkill -f "$INSTALL_DIR/$BIN_NAME" 2>/dev/null || true
    sleep 1
  fi

  # ---- 3. 数据备份（交互模式可选） ----
  if [[ -d "$INSTALL_DIR" && "${ASSUME_YES:-0}" != "1" ]]; then
    if confirm "删除前导出数据备份到 /root/miaowu-backup-*.tar.gz ？(含数据库/配置/密钥)"; then
      local bak="/root/miaowu-backup-$(date +%Y%m%d%H%M%S).tar.gz"
      tar -czf "$bak" -C "$(dirname "$INSTALL_DIR")" "$(basename "$INSTALL_DIR")" 2>/dev/null || true
      log "已备份: $bak"
    fi
  fi

  # ---- 4. 删除安装目录（二进制+配置+数据+xray配置） ----
  if [[ -d "$INSTALL_DIR" ]]; then
    if [[ "${ASSUME_YES:-0}" == "1" ]] || confirm "彻底删除 $INSTALL_DIR（二进制/配置/数据库/Ed25519密钥，不可恢复）？"; then
      log "删除 $INSTALL_DIR ..."
      rm -rf "$INSTALL_DIR"
      removed_any=1
    else
      warn "保留 $INSTALL_DIR（服务已停止，可稍后手动删除）"
    fi
  fi

  # ---- 5. xray 内核（agent 装的官方包） ----
  if [[ "$what" == "all" || "$what" == "agent" ]]; then
    if [[ -x /usr/local/bin/xray ]] || systemctl list-unit-files xray.service --no-legend 2>/dev/null | grep -q .; then
      if [[ "${ASSUME_YES:-0}" == "1" ]] || confirm "同时卸载 xray 内核？(若本机有其他程序在用 xray 请选 N)"; then
        log "卸载 xray ..."
        bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null \
          || { for m in "${MIRRORS[@]}"; do
                 bash -c "$(curl -fsSL "$m/XTLS/Xray-install/raw/main/install-release.sh")" @ remove --purge 2>/dev/null && break
               done; } \
          || { warn "官方卸载脚本不可用，手动清理..."
               systemctl disable --now xray 2>/dev/null || true
               rm -f /usr/local/bin/xray /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
               rm -rf /usr/local/share/xray /usr/local/etc/xray /var/log/xray; }
        removed_any=1
      fi
    fi
  fi

  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed 2>/dev/null || true

  log "──────────────────────────────────────────────"
  if [[ "$removed_any" == "1" ]]; then
    log "卸载完成：服务/进程/systemd 定义已清除"
  else
    log "未发现已安装的 miaowu 组件"
  fi
  [[ -d "$INSTALL_DIR" ]] && warn "注意: $INSTALL_DIR 仍保留（你选择了保留或备份确认未过）"
  log "──────────────────────────────────────────────"
}

case "${1:-}" in
  master)    install_master ;;
  agent)     shift; install_agent "$@" ;;
  uninstall) shift; uninstall "$@" ;;
  *) sed -n '2,17p' "$0"; exit 1 ;;
esac
