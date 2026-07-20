#!/bin/bash
# SNAT Manager - WireGuard 面板↔Agent 专用隧道（split tunnel）
#
# 设计目标：WireGuard 只承载面板与 Agent 的管理通信；不接管公网默认路由，
# 不修改 Agent 的普通直连、测速、SNAT 转发或其它出站流量。
#
# 面板：  ./wireguard_setup.sh hub [UDP端口=51820] [WG网关IP=10.66.66.1]
# Agent： ./wireguard_setup.sh agent <面板公网IP> <面板公钥> <本机WG IP> [UDP端口=51820] [面板WG IP=10.66.66.1]
# 面板： ./wireguard_setup.sh add-peer <名称> <Agent公钥> <AgentWG IP>
# 面板： ./wireguard_setup.sh remove-peer <Agent公钥>
# 任意： ./wireguard_setup.sh status
#
# Agent 端 AllowedIPs 只写面板 WG /32；因此只有 Agent↔面板流量走 WG。

set -Eeuo pipefail
WG_IF="${WG_IF:-wg0}"
WG_DIR=/etc/wireguard
WG_CONF="$WG_DIR/${WG_IF}.conf"
PRIV_FILE="$WG_DIR/${WG_IF}.priv"
PUB_FILE="$WG_DIR/${WG_IF}.pub"
LOCK_FILE="/run/lock/snat-wg-peer.lock"

fail() { echo "[x] $*" >&2; exit 1; }
need_root() { [ "${EUID:-$(id -u)}" -eq 0 ] || fail "请用 root 运行"; }
lock_wg() { exec 9>"$LOCK_FILE"; flock -x 9; }
need_arg() { [ -n "${1:-}" ] || fail "$2"; }
ensure_wg() {
    command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 && return
    command -v apt-get >/dev/null 2>&1 || fail "未找到 apt-get，无法自动安装 wireguard-tools"
    echo "[*] 安装 wireguard-tools..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools >/dev/null
}
validate_ipv4() { ipaddress="$1"; python3 - "$ipaddress" <<'PY'
import ipaddress,sys
try:
    ip=ipaddress.ip_address(sys.argv[1])
    if ip.version != 4: raise ValueError
except ValueError: raise SystemExit(1)
PY
}
validate_ip() { validate_ipv4 "$1" || fail "无效 IPv4 地址：$1"; }
validate_port() {
    case "$1" in ''|*[!0-9]*) fail "无效端口：$1";; esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ] || fail "端口必须为 1-65535：$1"
}
validate_pubkey() {
    decoded=$(printf '%s' "$1" | base64 -d 2>/dev/null) || fail "无效 WireGuard 公钥"
    [ "${#decoded}" -eq 32 ] || fail "无效 WireGuard 公钥长度"
    [ "${#1}" -eq 44 ] || fail "无效 WireGuard 公钥长度"
}
prepare_keys() {
    umask 077
    install -d -m 0700 "$WG_DIR"
    if [ ! -s "$PRIV_FILE" ] || [ ! -s "$PUB_FILE" ]; then
        wg genkey > "$PRIV_FILE"
        chmod 600 "$PRIV_FILE"
        wg pubkey < "$PRIV_FILE" > "$PUB_FILE"
        chmod 644 "$PUB_FILE"
    fi
}
atomic_write() {
    local target="$1"; local tmp
    tmp=$(mktemp "$target.tmp.XXXXXX")
    cat > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$target"
}
parse_cidr() {
    python3 - "$1" "$2" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]); net=ipaddress.ip_network(sys.argv[2],strict=False)
if ip not in net: raise SystemExit(1)
PY
}
cmd_hub() {
    need_root; ensure_wg; prepare_keys
    local port="${1:-51820}" addr="${2:-10.66.66.1}"
    validate_port "$port"; validate_ip "$addr"
    local net; net=$(python3 - "$addr" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]+'/24',strict=False))
PY
)
    parse_cidr "$addr" "$net" || fail "WG 网关地址不在网段 $net"
    local priv; priv=$(<"$PRIV_FILE")
    if [ -f "$WG_CONF" ] && ! grep -q '^\[Interface\]' "$WG_CONF"; then fail "已有配置格式异常：$WG_CONF"; fi
    if [ ! -f "$WG_CONF" ]; then
        atomic_write "$WG_CONF" <<EOF
[Interface]
Address = ${addr}/24
ListenPort = ${port}
PrivateKey = ${priv}
EOF
    else
        existing_addr=$(awk -F'= ' '/^Address = /{print $2; exit}' "$WG_CONF" | cut -d/ -f1)
        existing_port=$(awk -F'= ' '/^ListenPort = /{print $2; exit}' "$WG_CONF")
        [ "$existing_addr" = "$addr" ] || fail "已有 hub 地址为 $existing_addr，与请求的 $addr 不一致"
        [ "$existing_port" = "$port" ] || fail "已有 hub 端口为 $existing_port，与请求的 $port 不一致"
        echo "[*] 保留已有 $WG_CONF，不覆盖现有 peers"
    fi
    systemctl enable "wg-quick@${WG_IF}" >/dev/null
    systemctl restart "wg-quick@${WG_IF}"
    local pub public_ip
    pub=$(<"$PUB_FILE")
    public_ip=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || echo '<面板公网IP>')
    echo
    echo "==================== WireGuard hub 已就绪 ===================="
    echo "面板 WG 公钥：$pub"
    echo "面板公网端点：${public_ip}:${port}/udp"
    echo "面板 WG 地址：$addr"
    echo "云安全组/防火墙必须放行 UDP $port；不会接管默认路由。"
    echo
}
cmd_agent() {
    need_root; ensure_wg; prepare_keys
    local hub_public="$1" hub_pub="$2" my_ip="$3" port="${4:-51820}" hub_wg_ip="${5:-10.66.66.1}"
    validate_ip "$hub_public"; validate_pubkey "$hub_pub"; validate_ip "$my_ip"; validate_ip "$hub_wg_ip"; validate_port "$port"
    local net; net=$(python3 - "$hub_wg_ip" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]+'/24',strict=False))
PY
)
    parse_cidr "$my_ip" "$net" || fail "Agent WG 地址必须位于 $net"
    [ "$my_ip" != "$hub_wg_ip" ] || fail "Agent WG 地址不能与面板相同"
    local priv; priv=$(<"$PRIV_FILE")
    atomic_write "$WG_CONF" <<EOF
[Interface]
Address = ${my_ip}/32
PrivateKey = ${priv}

[Peer]
PublicKey = ${hub_pub}
Endpoint = ${hub_public}:${port}
# 关键：只把面板 WG 地址放入隧道；不使用 0.0.0.0/0，不接管其它流量
AllowedIPs = ${hub_wg_ip}/32
PersistentKeepalive = 25
EOF
    systemctl enable "wg-quick@${WG_IF}" >/dev/null
    systemctl restart "wg-quick@${WG_IF}"
    local pub; pub=$(<"$PUB_FILE")
    echo
    echo "==================== WireGuard Agent 已就绪 ===================="
    echo "Agent WG 公钥：$pub"
    echo "Agent WG 地址：$my_ip"
    echo "面板 WG 地址：$hub_wg_ip"
    echo "仅面板↔Agent 管理流量走 WireGuard，其余流量保持原路由。"
    echo
    echo "回到面板机执行："
    echo "  ./wireguard_setup.sh add-peer $(hostname) $pub $my_ip"
}
cmd_add_peer() {
    need_root; ensure_wg; lock_wg
    local name="${1:-}" peer_pub="${2:-}" peer_ip="${3:-}"
    need_arg "$name" "用法：add-peer <名称> <Agent公钥> <AgentWG IP>"
    need_arg "$peer_pub" "用法：add-peer <名称> <Agent公钥> <AgentWG IP>"
    need_arg "$peer_ip" "用法：add-peer <名称> <Agent公钥> <AgentWG IP>"
    validate_pubkey "$peer_pub"; validate_ip "$peer_ip"
    [ -f "$WG_CONF" ] || fail "hub 配置不存在，请先执行 hub"
    grep -Fq "PublicKey = $peer_pub" "$WG_CONF" && { echo "该 peer 已存在，无需重复添加"; exit 0; }
    local hub_ip; hub_ip=$(awk -F'= ' '/^Address = /{print $2; exit}' "$WG_CONF" | cut -d/ -f1)
    [ -n "$hub_ip" ] || fail "无法从 hub 配置读取 Address"
    local net; net=$(python3 - "$hub_ip" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1]+'/24',strict=False))
PY
)
    parse_cidr "$peer_ip" "$net" || fail "peer 地址必须位于 $net"
    [ "$peer_ip" != "$hub_ip" ] || fail "peer 地址不能与 hub 相同"
    backup=$(mktemp)
    cp -a "$WG_CONF" "$backup"
    if ! wg set "$WG_IF" peer "$peer_pub" allowed-ips "${peer_ip}/32"; then
        rm -f "$backup"
        fail "运行时加入 peer 失败，未修改持久配置"
    fi
    cat >> "$WG_CONF" <<EOF

# peer: ${name}
[Peer]
PublicKey = ${peer_pub}
AllowedIPs = ${peer_ip}/32
EOF
    rm -f "$backup"
    echo "✓ 已加入 peer [$name]：$peer_ip"
}
cmd_remove_peer() {
    need_root; ensure_wg; lock_wg
    local peer_pub="${1:-}"; need_arg "$peer_pub" "用法：remove-peer <Agent公钥>"; validate_pubkey "$peer_pub"
    [ -f "$WG_CONF" ] || fail "hub 配置不存在"
    wg set "$WG_IF" peer "$peer_pub" remove 2>/dev/null || fail "运行时删除 peer 失败，未修改持久配置"
    python3 - "$WG_CONF" "$peer_pub" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); key=sys.argv[2]; lines=p.read_text().splitlines(); out=[]; i=0
while i<len(lines):
    if lines[i].strip()=='[Peer]':
        block=[]; j=i
        while j<len(lines) and (j==i or not (lines[j].strip() in ('[Peer]','[Interface]'))): block.append(lines[j]); j+=1
        if any(x.strip()==f'PublicKey = {key}' for x in block): i=j; continue
    out.append(lines[i]); i+=1
p.write_text('\n'.join(out).rstrip()+'\n'); p.chmod(0o600)
PY
    systemctl restart "wg-quick@${WG_IF}"
    echo "✓ peer 已删除"
}
cmd_status() {
    need_root; ensure_wg
    systemctl is-active "wg-quick@${WG_IF}" || true
    wg show "$WG_IF" 2>/dev/null || true
    ip -4 route show dev "$WG_IF" 2>/dev/null || true
}
case "${1:-}" in
  hub) shift; cmd_hub "$@";;
  agent) shift; [ "$#" -ge 3 ] || fail "用法：agent <面板公网IP> <面板公钥> <本机WG IP> [端口] [面板WG IP]"; cmd_agent "$@";;
  add-peer) shift; cmd_add_peer "$@";;
  remove-peer) shift; cmd_remove_peer "$@";;
  status) cmd_status;;
  *) fail "用法：$0 {hub|agent|add-peer|remove-peer|status}";;
esac
