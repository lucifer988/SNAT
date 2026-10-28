#!/bin/bash
# SNAT Manager Agent 卸载脚本

set -e

echo "======================================"
echo "  SNAT Manager Agent 卸载"
echo "======================================"
echo

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误：请使用 sudo 运行此脚本"
    exit 1
fi

# 确认卸载
read -p "确定要卸载 SNAT Agent 吗？(y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

echo "[*] 停止服务..."
systemctl stop snat-agent 2>/dev/null || true
systemctl disable snat-agent 2>/dev/null || true

echo "[*] 删除服务文件..."
rm -f /etc/systemd/system/snat-agent.service

echo "[*] 删除程序文件..."
rm -rf /opt/snat-manager/agent

echo "[*] 删除数据和日志..."
rm -rf /var/lib/snat-agent
rm -f /var/log/snat-agent.log

echo "[*] 清理 SNAT iptables 规则..."
# 只删除 SNAT 相关的规则，保留其他服务的规则
# 删除 PREROUTING 中的 DNAT 规则
iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep DNAT | tac | while read line; do
    num=$(echo $line | awk '{print $1}')
    if [[ $num =~ ^[0-9]+$ ]]; then
        iptables -t nat -D PREROUTING $num 2>/dev/null || true
    fi
done

# 删除 POSTROUTING 中的 MASQUERADE 规则（只删除特定目标的）
iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null | grep "dpt:" | tac | while read line; do
    num=$(echo $line | awk '{print $1}')
    if [[ $num =~ ^[0-9]+$ ]]; then
        iptables -t nat -D POSTROUTING $num 2>/dev/null || true
    fi
done

echo "[*] 重载 systemd..."
systemctl daemon-reload

echo
echo "======================================"
echo "  ✓ Agent 卸载完成"
echo "======================================"
echo
echo "注意：请在 Web 管理端删除对应的服务器记录"
