#!/bin/bash
# SNAT Manager - WireGuard 隧道一键脚本（hub-and-spoke）
#
# 拓扑：面板 = hub（有公网 IP + 监听端口，agent 拨入），各 Agent = spoke。
# 隧道建好后，面板用 Agent 的 WG 内网 IP（10.66.66.X）访问 Agent，
# 全程加密，token 与转发规则都不再出现在公网明文里。
#
# 用法：
#   在面板机：   sudo ./wireguard_setup.sh hub [监听端口默认51820] [hub内网IP默认10.66.66.1]
#   加一个 Agent：sudo ./wireguard_setup.sh add-peer <名字> <Agent公钥> <AgentWG内网IP>
#   在 Agent 机： sudo ./wireguard_setup.sh agent <hub公网IP> <hub公钥> <本机WG内网IP> [hub监听端口默认51820]
#
# 典型流程：
#   1) 面板机跑 hub，记下打印出的 [hub 公钥] 和 [公网 IP:端口]
#   2) 每台 Agent 机跑 agent ...，记下打印出的 [Agent 公钥]
#   3) 回到面板机，对每台 Agent 跑一次 add-peer
#   4) 在面板里把该 Agent 的「地址」填成它的 WG 内网 IP（如 10.66.66.2），端口照旧
#   5) 把 Agent 的 systemd 环境改成 AGENT_HOST=<它的WG内网IP> 后重启 snat-agent

set -e
WG_IF="${WG_IF:-wg0}"
WG_CONF="/etc/wireguard/${WG_IF}.conf"

need_root() { [ "$EUID" -eq 0 ] || { echo "请用 sudo 运行"; exit 1; }; }
ensure_wg() {
    command -v wg >/dev/null 2>&1 && return
    echo "[*] 安装 wireguard..."
    apt-get update -qq && apt-get install -y wireguard >/dev/null
}
gen_keys() {
    umask 077
    mkdir -p /etc/wireguard
    [ -f /etc/wireguard/${WG_IF}.priv ] || wg genkey | tee /etc/wireguard/${WG_IF}.priv | wg pubkey > /etc/wireguard/${WG_IF}.pub
}

cmd_hub() {
    need_root; ensure_wg; gen_keys
    local port="${1:-51820}" addr="${2:-10.66.66.1}"
    local priv; priv=$(cat /etc/wireguard/${WG_IF}.priv)
    if [ ! -f "$WG_CONF" ]; then
        cat > "$WG_CONF" <<EOF
[Interface]
Address = ${addr}/24
ListenPort = ${port}
PrivateKey = ${priv}
EOF
        chmod 600 "$WG_CONF"
    fi
    systemctl enable "wg-quick@${WG_IF}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${WG_IF}"
    local pub; pub=$(cat /etc/wireguard/${WG_IF}.pub)
    local pubip; pubip=$(curl -s4 ifconfig.co 2>/dev/null || echo "<本机公网IP>")
    echo
    echo "==================== hub 已就绪 ===================="
    echo "  hub 公钥   : ${pub}"
    echo "  公网端点   : ${pubip}:${port}   (UDP，请在云防火墙放行)"
    echo "  hub 内网 IP: ${addr}"
    echo
    echo "在每台 Agent 机执行："
    echo "  sudo ./wireguard_setup.sh agent ${pubip} ${pub} 10.66.66.X ${port}"
    echo "拿到 Agent 公钥后，回这台机执行："
    echo "  sudo ./wireguard_setup.sh add-peer <名字> <Agent公钥> 10.66.66.X"
}

cmd_add_peer() {
    need_root
    local name="$1" peer_pub="$2" peer_ip="$3"
    [ -z "$peer_pub" ] || [ -z "$peer_ip" ] && { echo "用法: add-peer <名字> <Agent公钥> <AgentWG内网IP>"; exit 1; }
    grep -q "$peer_pub" "$WG_CONF" 2>/dev/null && { echo "该 peer 已存在"; exit 0; }
    cat >> "$WG_CONF" <<EOF

# peer: ${name}
[Peer]
PublicKey = ${peer_pub}
AllowedIPs = ${peer_ip}/32
EOF
    wg set "$WG_IF" peer "$peer_pub" allowed-ips "${peer_ip}/32"
    echo "✓ 已加入 Agent [${name}] -> ${peer_ip}。面板里把该服务器地址填 ${peer_ip} 即可。"
}

cmd_agent() {
    need_root; ensure_wg; gen_keys
    local hub_ip="$1" hub_pub="$2" my_ip="$3" port="${4:-51820}"
    [ -z "$hub_ip" ] || [ -z "$hub_pub" ] || [ -z "$my_ip" ] && {
        echo "用法: agent <hub公网IP> <hub公钥> <本机WG内网IP> [hub监听端口]"; exit 1; }
    local priv; priv=$(cat /etc/wireguard/${WG_IF}.priv)
    cat > "$WG_CONF" <<EOF
[Interface]
Address = ${my_ip}/24
PrivateKey = ${priv}

[Peer]
PublicKey = ${hub_pub}
Endpoint = ${hub_ip}:${port}
AllowedIPs = 10.66.66.0/24
PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONF"
    systemctl enable "wg-quick@${WG_IF}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${WG_IF}"
    local pub; pub=$(cat /etc/wireguard/${WG_IF}.pub)
    echo
    echo "==================== Agent 隧道已配置 ===================="
    echo "  Agent 公钥 : ${pub}"
    echo "  本机 WG IP : ${my_ip}"
    echo
    echo "请在面板机执行（把 Agent 注册进 hub）："
    echo "  sudo ./wireguard_setup.sh add-peer $(hostname) ${pub} ${my_ip}"
    echo
    echo "然后让 Agent 只在隧道内监听（编辑 /etc/systemd/system/snat-agent.service）："
    echo "  Environment=\"AGENT_HOST=${my_ip}\""
    echo "  systemctl daemon-reload && systemctl restart snat-agent"
}

case "$1" in
    hub)       shift; cmd_hub "$@" ;;
    add-peer)  shift; cmd_add_peer "$@" ;;
    agent)     shift; cmd_agent "$@" ;;
    *) echo "用法: $0 {hub|add-peer|agent} ..."; echo "详见脚本头部注释"; exit 1 ;;
esac
