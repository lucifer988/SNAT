#!/bin/bash
# SNAT Manager Web 卸载脚本

set -e

echo "======================================"
echo "  SNAT Manager Web 卸载"
echo "======================================"
echo

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误：请使用 sudo 运行此脚本"
    exit 1
fi

# 确认卸载
read -p "确定要卸载 SNAT Web 管理端吗？(y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

echo "[*] 停止服务..."
systemctl stop snat-web 2>/dev/null || true
systemctl disable snat-web 2>/dev/null || true

echo "[*] 删除服务文件..."
rm -f /etc/systemd/system/snat-web.service

echo "[*] 删除程序文件..."
rm -rf /opt/snat-manager/web

echo "[*] 删除数据库（可选）..."
read -p "是否删除数据库？(y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f /opt/snat-manager/web/snat_manager.db
    echo "  ✓ 数据库已删除"
else
    echo "  - 数据库已保留"
fi

echo "[*] 重载 systemd..."
systemctl daemon-reload

echo
echo "======================================"
echo "  ✓ Web 管理端卸载完成"
echo "======================================"
