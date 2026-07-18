#!/bin/bash
# SNAT Manager 一键更新脚本（带自动回滚）

set -e

REPO_URL="${SNAT_REPO_URL:-https://github.com/lucifer988/SNAT.git}"
REPO_BRANCH="${SNAT_REPO_BRANCH:-main}"
WORK_DIR="${SNAT_UPDATE_SRC:-/tmp/snat-manager-src}"

echo "======================================"
echo "  SNAT Manager 更新脚本"
echo "======================================"
echo

if [ "$EUID" -ne 0 ]; then
    echo "错误：请使用 sudo 运行此脚本"
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "[*] 安装 git..."
    apt-get update -qq
    apt-get install -y git >/dev/null
fi

if ! command -v gunicorn >/dev/null 2>&1; then
    echo "[*] 安装 gunicorn（生产 WSGI 服务器，替换 Flask 开发服务器）..."
    apt-get update -qq
    apt-get install -y gunicorn >/dev/null || pip3 install gunicorn >/dev/null
fi

echo "[*] 备份当前安装..."
BACKUP_DIR="/opt/snat-manager.backup.$(date +%Y%m%d_%H%M%S)"
cp -r /opt/snat-manager "$BACKUP_DIR" || {
    echo "✗ 备份失败"
    exit 1
}
echo "备份保存在: $BACKUP_DIR"

rollback() {
    echo
    echo "✗ 更新失败: $1"
    echo "[*] 正在回滚..."
    rm -rf /opt/snat-manager
    mv "$BACKUP_DIR" /opt/snat-manager
    systemctl restart snat-web snat-agent 2>/dev/null || true
    echo "✓ 已回滚到备份版本"
    exit 1
}

echo "[*] 拉取最新源代码 (${REPO_URL} @ ${REPO_BRANCH})..."
rm -rf "$WORK_DIR"
git clone --depth=1 --branch "$REPO_BRANCH" "$REPO_URL" "$WORK_DIR" >/dev/null 2>&1 \
    || rollback "git clone 失败"

# 更新 Web
if [ -d "/opt/snat-manager/web" ]; then
    echo "[*] 更新 Web 管理端..."
    # 保留 DB 和 secret_key
    cp /opt/snat-manager/web/snat_manager.db /tmp/snat_manager.db.upd 2>/dev/null || true
    cp /opt/snat-manager/web/.secret_key /tmp/.secret_key.upd 2>/dev/null || true

    # 删除旧代码（保留 DB 由 cp 覆盖时不动）
    find /opt/snat-manager/web -maxdepth 1 -type f -name "*.py" -delete
    rm -rf /opt/snat-manager/web/blueprints /opt/snat-manager/web/__pycache__

    cp -r "$WORK_DIR/web/." /opt/snat-manager/web/

    # 还原 DB 和 secret_key
    [ -f /tmp/snat_manager.db.upd ] && mv /tmp/snat_manager.db.upd /opt/snat-manager/web/snat_manager.db
    [ -f /tmp/.secret_key.upd ] && mv /tmp/.secret_key.upd /opt/snat-manager/web/.secret_key

    # 数据库迁移
    if [ -f "$WORK_DIR/migrate_db.sh" ]; then
        echo "[*] 执行数据库迁移..."
        bash "$WORK_DIR/migrate_db.sh" || rollback "数据库迁移失败"
    fi

    # 升级 systemd unit 到 gunicorn（兼容历史的 app.py / -m web.app 两种 ExecStart）
    WEB_UNIT=/etc/systemd/system/snat-web.service
    if [ -f "$WEB_UNIT" ] && grep -q "ExecStart=/usr/bin/python3" "$WEB_UNIT" 2>/dev/null; then
        echo "[*] 升级 snat-web unit 到 gunicorn..."
        WEB_BIND=$(grep -oE 'WEB_HOST=[^"]+' "$WEB_UNIT" | head -1 | cut -d= -f2)
        [ -z "$WEB_BIND" ] && WEB_BIND="0.0.0.0"
        sed -i \
            -e 's|WorkingDirectory=/opt/snat-manager/web|WorkingDirectory=/opt/snat-manager|' \
            -e "s|ExecStart=/usr/bin/python3 .*|ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager --workers 1 --threads 8 --timeout 60 --bind ${WEB_BIND}:5000 --access-logfile - web.wsgi:app|" \
            "$WEB_UNIT"
        systemctl daemon-reload
    fi

    systemctl restart snat-web || rollback "重启 snat-web 失败"
    sleep 2
    systemctl is-active --quiet snat-web || rollback "snat-web 服务未正常启动"

    echo "✓ Web 管理端更新完成"
fi

# 更新 Agent
if [ -d "/opt/snat-manager/agent" ]; then
    echo "[*] 更新 Agent 客户端..."

    AGENT_UNIT=/etc/systemd/system/snat-agent.service
    # 历史版本把监听端口 sed 进了源码 (app.run(port=NNNN))；新版本改用 AGENT_PORT 环境变量。
    # 先从备份的旧 agent.py 里把端口捞出来，避免更新后端口被重置为 8888。
    OLD_PORT=$(grep -oE 'port=[0-9]+' "$BACKUP_DIR/agent/agent.py" 2>/dev/null | tail -1 | cut -d= -f2)
    [ -z "$OLD_PORT" ] && OLD_PORT=$(grep -oE 'AGENT_PORT=[0-9]+' "$AGENT_UNIT" 2>/dev/null | head -1 | cut -d= -f2)
    [ -z "$OLD_PORT" ] && OLD_PORT=8888

    find /opt/snat-manager/agent -maxdepth 1 -type f -name "*.py" -delete
    rm -rf /opt/snat-manager/agent/__pycache__

    cp -r "$WORK_DIR/agent/." /opt/snat-manager/agent/

    # 升级 agent unit 到 gunicorn，并补齐 AGENT_HOST/AGENT_PORT/AGENT_ALLOW_BEARER/AGENT_ALLOWED_IPS
    if [ -f "$AGENT_UNIT" ] && grep -q "ExecStart=/usr/bin/python3" "$AGENT_UNIT" 2>/dev/null; then
        echo "[*] 升级 snat-agent unit 到 gunicorn (保留端口 ${OLD_PORT})..."
        grep -q 'AGENT_HOST=' "$AGENT_UNIT" || sed -i '/Environment="DNS_REFRESH_INTERVAL/a Environment="AGENT_HOST=0.0.0.0"' "$AGENT_UNIT"
        grep -q 'AGENT_PORT=' "$AGENT_UNIT" || sed -i "/Environment=\"AGENT_HOST/a Environment=\"AGENT_PORT=${OLD_PORT}\"" "$AGENT_UNIT"
        # 升级路径保留 Bearer 回退(=1)，避免旧面板升级中途断连；面板确认走签名后请手动改 0。
        grep -q 'AGENT_ALLOW_BEARER=' "$AGENT_UNIT" || sed -i '/Environment="AGENT_PORT/a Environment="AGENT_ALLOW_BEARER=1"' "$AGENT_UNIT"
        # 来源 IP 白名单默认留空(=不限制)，保持升级不破坏现有连通性；公网直连请手动填面板出口 IP。
        grep -q 'AGENT_ALLOWED_IPS=' "$AGENT_UNIT" || sed -i '/Environment="AGENT_ALLOW_BEARER/a Environment="AGENT_ALLOWED_IPS="' "$AGENT_UNIT"
        sed -i \
            -e "s|ExecStart=/usr/bin/python3 .*|ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager/agent --workers 1 --threads 4 --timeout 60 --bind 0.0.0.0:${OLD_PORT} --access-logfile - wsgi:app|" \
            "$AGENT_UNIT"
        systemctl daemon-reload
    fi

    systemctl restart snat-agent || rollback "重启 snat-agent 失败"
    sleep 2
    systemctl is-active --quiet snat-agent || rollback "snat-agent 服务未正常启动"

    if systemctl cat snat-agent | grep -q "DNS_REFRESH_INTERVAL"; then
        interval=$(systemctl cat snat-agent | grep "DNS_REFRESH_INTERVAL" | head -1 | sed -E 's/.*=([0-9]+).*/\1/')
        echo "[*] DNS 刷新间隔: ${interval} 秒"
    fi

    echo "✓ Agent 客户端更新完成"
fi

# 清理
rm -rf "$WORK_DIR"

echo
echo "======================================"
echo "  更新完成"
echo "======================================"
echo
echo "如需回滚："
echo "  rm -rf /opt/snat-manager"
echo "  mv $BACKUP_DIR /opt/snat-manager"
echo "  systemctl restart snat-web snat-agent"
