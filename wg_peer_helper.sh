#!/bin/bash
# root-only helper called by snat-web through sudo. Never accepts shell fragments.
set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
WG_IF="${WG_IF:-wg0}"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
fail(){ echo "[x] $*" >&2; exit 1; }
[ "${EUID:-$(id -u)}" -eq 0 ] || fail "root required"
[ "$#" -eq 4 ] || fail "usage: add <name> <public-key> <ipv4>"
[ "$1" = add ] || fail "only add is allowed"
name="$2"; pub="$3"; ip="$4"
[[ "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "invalid peer name"
[ "${#pub}" -eq 44 ] && printf '%s' "$pub" | base64 -d >/dev/null 2>&1 || fail "invalid public key"
python3 - "$ip" "$WG_CONF" <<'PY'
import ipaddress,re,sys
ip=ipaddress.ip_address(sys.argv[1])
if ip.version != 4: raise SystemExit('IPv4 required')
text=open(sys.argv[2]).read()
m=re.search(r'^Address\s*=\s*([^/\s]+)/([0-9]+)',text,re.M)
if not m: raise SystemExit('hub address missing')
net=ipaddress.ip_network(f'{m.group(1)}/{m.group(2)}',strict=False)
if ip not in net or ip == ipaddress.ip_address(m.group(1)): raise SystemExit('peer IP outside hub subnet')
for old in re.findall(r'^AllowedIPs\s*=\s*([^/\s]+)/32',text,re.M):
    if ip == ipaddress.ip_address(old): raise SystemExit('peer IP already used')
PY
if grep -Fq "PublicKey = $pub" "$WG_CONF"; then fail "public key already used"; fi
cat >> "$WG_CONF" <<EOF

# peer: $name
[Peer]
PublicKey = $pub
AllowedIPs = $ip/32
EOF
chmod 600 "$WG_CONF"
wg set "$WG_IF" peer "$pub" allowed-ips "$ip/32"
printf 'added %s %s\n' "$name" "$ip"
