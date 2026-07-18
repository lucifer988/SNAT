#!/bin/bash
# SNAT Manager 一键安装脚本
# 支持交互和非交互模式
#
# 非交互用法：
#   SNAT_COMMIT_SHA=$(git rev-parse HEAD) ./install.sh --type web
# 密码和 Token 不接受命令行参数，避免泄露到历史记录和进程列表。

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
REPO_COMMIT="${SNAT_COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}"
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
        --password|--token) log_error "$1 已禁用；请使用交互式隐藏输入"; exit 1 ;;
        --port)     AGENT_PORT="$2"; shift 2 ;;
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

if ! [[ "$REPO_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]]; then
    log_error "必须通过 SNAT_COMMIT_SHA 指定完整 40 位提交 SHA"
    exit 1
fi
REPO_COMMIT=${REPO_COMMIT,,}

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
git -C "$WORK_DIR" fetch --depth=1 origin "$REPO_COMMIT" >/dev/null 2>&1 || { log_error "无法获取指定提交"; exit 1; }
git -C "$WORK_DIR" checkout --detach "$REPO_COMMIT" >/dev/null 2>&1
[ "$(git -C "$WORK_DIR" rev-parse HEAD)" = "$REPO_COMMIT" ] || { log_error "提交校验失败"; exit 1; }

install_web() {
    log_info "安装 Web 管理端..."

    if [ -z "$ADMIN_PASSWORD" ]; then
        read -s -p "请输入管理员初始密码（留空自动生成强密码）: " ADMIN_PASSWORD < /dev/tty
        echo
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

    case "$ADMIN_PASSWORD" in *$'\n'*|*$'\r'*) log_error "管理员密码不能包含换行符"; exit 1;; esac
    ADMIN_PASSWORD_ENV=${ADMIN_PASSWORD//\\/\\\\}; ADMIN_PASSWORD_ENV=${ADMIN_PASSWORD_ENV//\"/\\\"}

    id -u snat-web >/dev/null 2>&1 || useradd --system --home /opt/snat-manager --shell /usr/sbin/nologin snat-web
    install -d -o root -g root -m 0711 /etc/snat-manager
    install -d -o snat-web -g snat-web -m 0700 /opt/snat-manager/web /var/backups/snat-manager
    chown -R snat-web:snat-web /opt/snat-manager/web /var/backups/snat-manager
    cat > /etc/snat-manager/web.env <<EOF
APP_ENV=production
FORCE_HTTPS=${FORCE_HTTPS_VALUE}
TRUST_PROXY=${TRUST_PROXY_VALUE}
SNAT_ADMIN_PASSWORD="${ADMIN_PASSWORD_ENV}"
SNAT_SECRET_KEY=${SNAT_SECRET_KEY}
SNAT_TOKEN_SECRET=${SNAT_TOKEN_SECRET}
BACKUP_DIR=/var/backups/snat-manager
WEB_HOST=${WEB_HOST}
WEB_PORT=5000
EOF
    chown snat-web:snat-web /etc/snat-manager/web.env
    chmod 0600 /etc/snat-manager/web.env

    cat > /etc/systemd/system/snat-web.service <<EOF
[Unit]
Description=SNAT Manager Web
After=network.target

[Service]
Type=simple
User=snat-web
Group=snat-web
WorkingDirectory=/opt/snat-manager
EnvironmentFile=/etc/snat-manager/web.env
# 会话有效期（小时，滑动续期）。公网面板建议偏短，默认 12h：
#Environment="SNAT_SESSION_LIFETIME_HOURS=12"
# 敏感操作（导出含 token/恢复备份/改密钥/批量删除…）二次认证有效期（秒），默认 600：
#Environment="SNAT_REAUTH_MAX_AGE=600"
# 仅接受 Agent 的字面量 IP、拒绝域名（强烈建议公网+WireGuard 部署开启，防 DNS 重绑定）：
#Environment="SNAT_AGENT_HOST_IP_ONLY=1"
# 签名请求默认不再附带明文 Bearer；仅对接只认 Bearer 的老 Agent 时才设 1：
#Environment="SNAT_AGENT_SEND_BEARER=1"
ExecStartPre=/bin/mkdir -p /var/backups/snat-manager
# 单 worker + 多线程：登录锁定/限流/日志缓冲是进程内内存态，多 worker 会各自为政。
ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager --workers 1 --threads 8 --timeout 60 --bind ${WEB_HOST}:5000 --access-logfile - web.wsgi:app
Restart=always

# --- systemd 沙箱硬化：Web 无需任何特权，进程即使被打穿，落地面也很小 ---
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
# 只放行本机需要写入的目录（DB / 密钥 / 日志 / 备份）
ReadWritePaths=/opt/snat-manager /var/backups/snat-manager
# Web 不需要任何 Linux capability，全部丢弃
CapabilityBoundingSet=
AmbientCapabilities=
# 仅允许常见网络协议族
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

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

    # 初始口令仅用于首次建库；随后从长期服务环境中移除。
    sed -i '/^SNAT_ADMIN_PASSWORD=/d' /etc/snat-manager/web.env
    systemctl restart snat-web
    install -m 0600 /dev/null /root/.snat-manager-initial-password
    printf 'admin:%s\n' "$ADMIN_PASSWORD" > /root/.snat-manager-initial-password

    echo
    log_info "Web 管理端安装完成"
    echo "${ACCESS_HINT}"
    echo "管理员账号：admin"
    echo "初始密码保存在 /root/.snat-manager-initial-password（root 0600，登录后请删除）"
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

    # 选择 Agent 暴露方式：默认倾向“非公网暴露”。
    AGENT_EXPOSURE_MODE="${AGENT_EXPOSURE_MODE:-}"
    if [ -z "$AGENT_EXPOSURE_MODE" ]; then
        echo
        echo "请选择 Agent 暴露方式："
        echo "  1) 内网 / WireGuard（推荐）  -> Agent 仅监听内网/WG IP"
        echo "  2) 公网直连（高风险）      -> Agent 监听 0.0.0.0，必须配来源白名单/防火墙"
        read -p "请输入 [1/2，默认 1]: " AGENT_EXPOSURE_MODE < /dev/tty
        [ -z "$AGENT_EXPOSURE_MODE" ] && AGENT_EXPOSURE_MODE=1
    fi

    AGENT_HOST_VALUE="${AGENT_HOST:-}"
    if [ "$AGENT_EXPOSURE_MODE" = "1" ] || [ "$AGENT_EXPOSURE_MODE" = "private" ] || [ "$AGENT_EXPOSURE_MODE" = "wg" ]; then
        if [ -z "$AGENT_HOST_VALUE" ]; then
            echo
            echo "请输入 Agent 要监听的内网/WireGuard IP（例如 10.66.66.2）。"
            echo "不要填 0.0.0.0；否则会重新暴露到公网。"
            read -p "AGENT_HOST: " AGENT_HOST_VALUE < /dev/tty
        fi
        if [ -z "$AGENT_HOST_VALUE" ] || [ "$AGENT_HOST_VALUE" = "0.0.0.0" ]; then
            log_error "内网/WireGuard 模式下必须指定一个非 0.0.0.0 的监听 IP"
            exit 1
        fi
        AGENT_ALLOWED_IPS="${AGENT_ALLOWED_IPS:-}"
    else
        AGENT_HOST_VALUE="0.0.0.0"
        echo
        log_warn "你选择了"公网直连"：Agent 将在公网端口 ${AGENT_PORT} 上监听。"
        log_warn "这会让 Agent 进入全网扫描面。即使有签名鉴权，也强烈建议改用 WireGuard/内网模式。"
        if [ -z "${AGENT_ALLOWED_IPS:-}" ]; then
            echo "请至少填写面板出口公网 IP / 网段作为来源白名单。"
            echo "（支持 CIDR，例如 1.2.3.4 或 1.2.3.0/24；留空 = 高风险，不允许继续）"
            read -p "允许访问 Agent 的面板 IP/网段: " AGENT_ALLOWED_IPS < /dev/tty
        fi
        if [ -z "${AGENT_ALLOWED_IPS:-}" ]; then
            log_error "公网直连模式下必须设置 AGENT_ALLOWED_IPS；拒绝继续安装"
            exit 1
        fi
    fi

    mkdir -p /opt/snat-manager/agent
    cp -r "$WORK_DIR/agent/." /opt/snat-manager/agent/
    find /opt/snat-manager/agent -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

    log_info "安装 conntrack..."
    apt-get install -y conntrack 2>/dev/null || log_warn "conntrack 安装失败，将回退到 ss"

    if [ -z "$AGENT_TOKEN" ]; then
        read -s -p "请输入 Agent Token（留空自动生成）: " AGENT_TOKEN < /dev/tty
        echo
        [ -z "$AGENT_TOKEN" ] && AGENT_TOKEN=$(openssl rand -base64 48 | tr -d '/+=' | head -c 48)
    fi
    case "$AGENT_TOKEN" in *$'\n'*|*$'\r'*) log_error "Agent Token 不能包含换行符"; exit 1;; esac
    AGENT_TOKEN_ENV=${AGENT_TOKEN//\\/\\\\}; AGENT_TOKEN_ENV=${AGENT_TOKEN_ENV//\"/\\\"}

    install -d -o root -g root -m 0711 /etc/snat-manager
    cat > /etc/snat-manager/agent.env <<EOF
AGENT_TOKEN="${AGENT_TOKEN_ENV}"
DNS_REFRESH_INTERVAL=60
AGENT_HOST=${AGENT_HOST_VALUE}
AGENT_PORT=${AGENT_PORT}
AGENT_ALLOWED_IPS=${AGENT_ALLOWED_IPS}
AGENT_ALLOW_BEARER=0
EOF
    chmod 0600 /etc/snat-manager/agent.env

    cat > /etc/systemd/system/snat-agent.service <<EOF
[Unit]
Description=SNAT Manager Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/snat-manager/agent
EnvironmentFile=/etc/snat-manager/agent.env
# 推荐：仅监听内网/WireGuard IP；只有显式选择"公网直连"时才监听 0.0.0.0。
# DNAT 目标默认拒绝回环/私网/CGNAT/ULA/云元数据，降低面板失守后的内网横向风险。
# 若本机的 SNAT 目标就在私网/回环（常见的“公网端口→内网服务”），取消下一行注释放行：
#Environment="AGENT_TARGET_ALLOW_PRIVATE=1"
# 或用精确白名单只放行确需的网段（优先级最高，逗号分隔 CIDR）：
#Environment="AGENT_TARGET_ALLOW_CIDRS=10.8.0.0/24"
# nonce 防重放默认开启（需配合已升级的面板）；与不发 nonce 的老面板混跑时才临时设 0：
#Environment="AGENT_REQUIRE_NONCE=0"
ExecStartPre=/bin/mkdir -p /var/lib/snat-agent /var/log
# 必须单 worker、且不开 --preload：避免多进程同改 iptables / DNS 刷新线程在 fork 后丢失。
ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager/agent --workers 1 --threads 4 --timeout 60 --bind ${AGENT_HOST_VALUE}:${AGENT_PORT} --access-logfile - wsgi:app
Restart=always

# --- systemd 沙箱硬化：Agent 需要改 iptables/sysctl，权限高但不必“无限权限” ---
# 只保留 iptables / conntrack / sysctl(net) 真正需要的两个 capability，其余全部丢弃。
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
# 只放行 Agent 需要写入的目录（规则文件 / 日志）。
ReadWritePaths=/var/lib/snat-agent /var/log
# 注意：不设 ProtectKernelTunables，否则 /proc/sys 只读会让 sysctl 打开 ip_forward 失败。
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
# 需要 AF_NETLINK 供 iptables/conntrack 与内核通信。
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

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
    if [ "$AGENT_HOST_VALUE" = "0.0.0.0" ]; then
        echo "Agent 地址：http://${PUBLIC_IP}:${AGENT_PORT}"
    else
        echo "Agent 监听地址：http://${AGENT_HOST_VALUE}:${AGENT_PORT}"
    fi
    if [ -n "${AGENT_ALLOWED_IPS}" ]; then
        echo "来源白名单：${AGENT_ALLOWED_IPS}（仅这些 IP 可访问 Agent）"
    elif [ "$AGENT_HOST_VALUE" = "0.0.0.0" ]; then
        log_warn "未设置来源白名单：Agent 端口对全网开放，仅靠签名校验。强烈建议补充 AGENT_ALLOWED_IPS 或防火墙规则。"
    fi
    echo
    echo "请将此服务器信息添加到 Web 管理端："
    echo "  名称：$(hostname)"
    if [ "$AGENT_HOST_VALUE" = "0.0.0.0" ]; then
        echo "  地址：${PUBLIC_IP}"
    else
        echo "  地址：${AGENT_HOST_VALUE}"
    fi
    echo "  端口：${AGENT_PORT}"
    echo "  Token：保存在 /etc/snat-manager/agent.env（root 0600），按需读取，勿复制到日志"
    echo
    if [ "$AGENT_HOST_VALUE" = "0.0.0.0" ]; then
        log_warn "公网直连注意："
        log_warn "  1) 面板↔Agent 走明文 HTTP，token 虽不落链路(HMAC)，但规则内容可被链路观测；"
        log_warn "     若介意，建议优先使用 WireGuard/内网模式。"
        log_warn "  2) 已强制要求来源白名单，请确保填入的是面板真实出口公网 IP。"
    else
        log_info "当前为内网/WireGuard 模式：请在面板中填写上面的内网/WG 地址，不要填写公网 IP。"
    fi
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
