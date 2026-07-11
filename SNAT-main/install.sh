#!/bin/bash
# SNAT Manager 一键安装脚本
# 支持交互和非交互模式
#
# 非交互用法：
#   ./install.sh --type web   [--password 密码]
#   ./install.sh --type agent [--port 8888] [--token TOKEN]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[x]${NC} $1"; }

REPO_URL="${SNAT_REPO_URL:-https://github.com/lucifer988/SNAT.git}"
REPO_BRANCH="${SNAT_REPO_BRANCH:-main}"
WORK_DIR="${SNAT_INSTALL_SRC:-/tmp/snat-manager-src}"

echo "======================================"
echo "  SNAT Manager 安装脚本"
echo "======================================"
echo

INSTALL_TYPE=""
ADMIN_PASSWORD=""
AGENT_PORT="8888"
AGENT_TOKEN=""
DEPLOY_MODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)     INSTALL_TYPE="$2"; shift 2 ;;
        --password) ADMIN_PASSWORD="$2"; shift 2 ;;
        --port)     AGENT_PORT="$2"; shift 2 ;;
        --token)    AGENT_TOKEN="$2"; shift 2 ;;
        --mode)     DEPLOY_MODE="$2"; shift 2 ;;
        *) log_error "未知参数: $1"; exit 1 ;;
    esac
done

if [ ! -f /etc/debian_version ]; then
    log_error "此脚本仅支持 Debian/Ubuntu"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log_error "请使用 sudo 运行此脚本"
    exit 1
fi

if [ -z "$INSTALL_TYPE" ]; then
    echo "请选择安装类型："
    echo "  1) Web 管理端"
    echo "  2) Agent 客户端"
    read -p "请输入 [1/2]: " INSTALL_TYPE < /dev/tty
fi

log_info "安装系统依赖..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-flask python3-requests python3-cryptography gunicorn git iptables >/dev/null

# 拉源代码（一次拉，安装 web/agent 共用）
log_info "拉取源代码 (${REPO_URL} @ ${REPO_BRANCH})..."
rm -rf "$WORK_DIR"
git clone --depth=1 --branch "$REPO_BRANCH" "$REPO_URL" "$WORK_DIR" >/dev/null 2>&1 || {
    log_error "git clone 失败"
    exit 1
}

install_web() {
    log_info "安装 Web 管理端..."

    if [ -z "$ADMIN_PASSWORD" ]; then
        read -p "请输入管理员初始密码（留空自动生成强密码）: " ADMIN_PASSWORD < /dev/tty
    fi

    mkdir -p /opt/snat-manager/web
    cp -r "$WORK_DIR/web/." /opt/snat-manager/web/
    # 干掉 .pyc / __pycache__，避免被旧版本干扰
    find /opt/snat-manager/web -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

    if [ -z "$ADMIN_PASSWORD" ]; then
        ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')
    fi

    if [ -z "$DEPLOY_MODE" ]; then
        echo "请选择 Web 部署模式："
        echo "  1) 内网直连（HTTP，可配白名单，监听 0.0.0.0）"
        echo "  2) 反向代理/公网（推荐，监听 127.0.0.1，强制 HTTPS）"
        read -p "请输入 1 或 2 [默认 1]: " DEPLOY_MODE < /dev/tty
        [ -z "$DEPLOY_MODE" ] && DEPLOY_MODE=1
    fi

    if [ "$DEPLOY_MODE" = "2" ] || [ "$DEPLOY_MODE" = "proxy" ] || [ "$DEPLOY_MODE" = "public" ]; then
        WEB_HOST="127.0.0.1"
        FORCE_HTTPS_VALUE="1"
        TRUST_PROXY_VALUE="1"   # 反向代理需要信任 X-Forwarded-*
        ACCESS_HINT="访问地址：https://你的域名（Web 仅监听 127.0.0.1，请通过 Nginx/Caddy 反向代理）"
    else
        WEB_HOST="0.0.0.0"
        FORCE_HTTPS_VALUE="0"
        TRUST_PROXY_VALUE="0"
        ACCESS_HINT="访问地址：http://宿主机内网IP:5000（建议在面板中配置 IP 白名单）"
    fi

    SNAT_SECRET_KEY=$(openssl rand -hex 32)
    SNAT_TOKEN_SECRET=$(openssl rand -hex 32)

    cat > /etc/systemd/system/snat-web.service <<EOF
[Unit]
Description=SNAT Manager Web
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/snat-manager
Environment="APP_ENV=production"
Environment="FORCE_HTTPS=${FORCE_HTTPS_VALUE}"
Environment="TRUST_PROXY=${TRUST_PROXY_VALUE}"
Environment="SNAT_ADMIN_PASSWORD=${ADMIN_PASSWORD}"
Environment="SNAT_SECRET_KEY=${SNAT_SECRET_KEY}"
Environment="SNAT_TOKEN_SECRET=${SNAT_TOKEN_SECRET}"
Environment="BACKUP_DIR=/var/backups/snat-manager"
Environment="WEB_HOST=${WEB_HOST}"
Environment="WEB_PORT=5000"
ExecStartPre=/bin/mkdir -p /var/backups/snat-manager
# 单 worker + 多线程：登录锁定/限流/日志缓冲是进程内内存态，多 worker 会各自为政。
ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager --workers 1 --threads 8 --timeout 60 --bind ${WEB_HOST}:5000 --access-logfile - web.wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable snat-web
    systemctl start snat-web

    sleep 2
    if ! systemctl is-active --quiet snat-web; then
        log_error "snat-web 启动失败，查看日志：journalctl -u snat-web -n 50"
        exit 1
    fi

    echo
    log_info "Web 管理端安装完成"
    echo "${ACCESS_HINT}"
    echo "管理员账号：admin"
    echo "管理员密码：${ADMIN_PASSWORD}"
}

install_agent() {
    log_info "安装 Agent 客户端..."

    if [ -z "$AGENT_PORT" ]; then
        read -p "请输入 Agent 端口 [默认 8888]: " AGENT_PORT < /dev/tty
        [ -z "$AGENT_PORT" ] && AGENT_PORT=8888
    fi

    if ! echo "$AGENT_PORT" | grep -qE '^[0-9]+$' || [ "$AGENT_PORT" -lt 1 ] || [ "$AGENT_PORT" -gt 65535 ]; then
        log_error "端口无效"
        exit 1
    fi

    # 公网直连场景：让 Agent 只接受来自面板出口 IP 的请求（纵深防御，挡住全网扫描）。
    # 交互式询问；非交互可用环境变量 AGENT_ALLOWED_IPS 预置。
    if [ -z "${AGENT_ALLOWED_IPS:-}" ]; then
        echo
        echo "Agent 将直接暴露在公网端口 ${AGENT_PORT}。强烈建议填写"面板出口公网 IP"做来源白名单。"
        echo "（可填多个，逗号分隔，支持 CIDR，例如 1.2.3.4 或 1.2.3.0/24；留空=仅靠签名，风险更高）"
        read -p "允许访问 Agent 的面板 IP/网段: " AGENT_ALLOWED_IPS < /dev/tty
    fi

    mkdir -p /opt/snat-manager/agent
    cp -r "$WORK_DIR/agent/." /opt/snat-manager/agent/
    find /opt/snat-manager/agent -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

    log_info "安装 conntrack..."
    apt-get install -y conntrack 2>/dev/null || log_warn "conntrack 安装失败，将回退到 ss"

    if [ -z "$AGENT_TOKEN" ]; then
        AGENT_TOKEN=$(openssl rand -base64 48 | tr -d '/+=' | head -c 48)
    fi

    cat > /etc/systemd/system/snat-agent.service <<EOF
[Unit]
Description=SNAT Manager Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/snat-manager/agent
Environment="AGENT_TOKEN=${AGENT_TOKEN}"
Environment="DNS_REFRESH_INTERVAL=60"
# 公网直连：AGENT_HOST 保持 0.0.0.0（对外监听），靠 AGENT_ALLOWED_IPS 做来源白名单。
# 无公网/走隧道：把 AGENT_HOST 改成本机 WireGuard 内网 IP（如 10.66.66.2）并清空白名单。
Environment="AGENT_HOST=${AGENT_HOST:-0.0.0.0}"
Environment="AGENT_PORT=${AGENT_PORT}"
# 只接受来自面板出口 IP/网段的请求（留空=不限制来源，仅靠签名）。
Environment="AGENT_ALLOWED_IPS=${AGENT_ALLOWED_IPS}"
# 默认仅签名严格模式；仅当对接的是无法签名的老面板时才临时设为 1。
Environment="AGENT_ALLOW_BEARER=0"
ExecStartPre=/bin/mkdir -p /var/lib/snat-agent /var/log
# 必须单 worker、且不开 --preload：避免多进程同改 iptables / DNS 刷新线程在 fork 后丢失。
ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager/agent --workers 1 --threads 4 --timeout 60 --bind ${AGENT_HOST:-0.0.0.0}:${AGENT_PORT} --access-logfile - wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable snat-agent
    systemctl start snat-agent

    sleep 2
    if ! systemctl is-active --quiet snat-agent; then
        log_error "snat-agent 启动失败，查看日志：journalctl -u snat-agent -n 50"
        exit 1
    fi

    LOCAL_IP=$(hostname -I | awk '{print $1}')
    PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "$LOCAL_IP")

    echo
    log_info "Agent 客户端安装完成"
    echo "Agent 地址：http://${PUBLIC_IP}:${AGENT_PORT}"
    echo "Token: ${AGENT_TOKEN}"
    if [ -n "${AGENT_ALLOWED_IPS}" ]; then
        echo "来源白名单：${AGENT_ALLOWED_IPS}（仅这些 IP 可访问 Agent）"
    else
        log_warn "未设置来源白名单：Agent 端口对全网开放，仅靠签名校验。强烈建议补充 AGENT_ALLOWED_IPS 或防火墙规则。"
    fi
    echo
    echo "请将此服务器信息添加到 Web 管理端："
    echo "  名称：$(hostname)"
    echo "  地址：${PUBLIC_IP}"
    echo "  端口：${AGENT_PORT}"
    echo "  Token：${AGENT_TOKEN}"
    echo
    log_warn "公网直连注意："
    log_warn "  1) 面板↔Agent 走明文 HTTP，token 虽不落链路(HMAC)，但规则内容可被链路观测；"
    log_warn "     若介意，建议在 Agent 前置 Caddy/Nginx 做 HTTPS，或仍用 WireGuard 隧道。"
    log_warn "  2) 已默认开启来源 IP 白名单机制，请确保填入的是面板真实出口公网 IP。"
}

case "$INSTALL_TYPE" in
    1|web)   install_web ;;
    2|agent) install_agent ;;
    *) log_error "无效的选择，请输入 1 或 2"; exit 1 ;;
esac

# 清理源码缓存
rm -rf "$WORK_DIR"

echo
log_info "安装完成"
