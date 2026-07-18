#!/bin/bash
# SNAT Manager 一键更新脚本（带自动回滚）

set -e

REPO_URL="${SNAT_REPO_URL:-https://github.com/lucifer988/SNAT.git}"
REPO_BRANCH="${SNAT_REPO_BRANCH:-main}"
REPO_COMMIT="${SNAT_COMMIT_SHA:-}"
WORK_DIR="${SNAT_UPDATE_SRC:-/tmp/snat-manager-src}"

echo "======================================"
echo "  SNAT Manager 更新脚本"
echo "======================================"
echo

if [ "$EUID" -ne 0 ]; then
    echo "错误：请使用 sudo 运行此脚本"
    exit 1
fi

if ! [[ "$REPO_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "错误：必须显式设置完整 SNAT_COMMIT_SHA，禁止自动追踪可变分支"
    exit 1
fi
REPO_COMMIT=${REPO_COMMIT,,}

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
WEB_UNIT=/etc/systemd/system/snat-web.service
AGENT_UNIT=/etc/systemd/system/snat-agent.service
[ -f "$WEB_UNIT" ] && cp -a "$WEB_UNIT" "$BACKUP_DIR/snat-web.service"
[ -f "$AGENT_UNIT" ] && cp -a "$AGENT_UNIT" "$BACKUP_DIR/snat-agent.service"

rollback() {
    echo
    echo "✗ 更新失败: $1"
    echo "[*] 正在回滚..."
    rm -rf /opt/snat-manager
    mv "$BACKUP_DIR" /opt/snat-manager
    [ -f /opt/snat-manager/snat-web.service ] && mv /opt/snat-manager/snat-web.service "$WEB_UNIT"
    [ -f /opt/snat-manager/snat-agent.service ] && mv /opt/snat-manager/snat-agent.service "$AGENT_UNIT"
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart snat-web snat-agent 2>/dev/null || true
    echo "✓ 已回滚到备份版本"
    exit 1
}

echo "[*] 拉取最新源代码 (${REPO_URL} @ ${REPO_BRANCH})..."
rm -rf "$WORK_DIR"
git clone --depth=1 --branch "$REPO_BRANCH" "$REPO_URL" "$WORK_DIR" >/dev/null 2>&1 \
    || rollback "git clone 失败"
git -C "$WORK_DIR" fetch --depth=1 origin "$REPO_COMMIT" >/dev/null 2>&1 || rollback "无法获取指定提交"
git -C "$WORK_DIR" checkout --detach "$REPO_COMMIT" >/dev/null 2>&1 || rollback "无法检出指定提交"
[ "$(git -C "$WORK_DIR" rev-parse HEAD)" = "$REPO_COMMIT" ] || rollback "提交校验失败"

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
    if id -u snat-web >/dev/null 2>&1; then
        chown -R snat-web:snat-web /opt/snat-manager/web
    fi

    # 数据库迁移
    if [ -f "$WORK_DIR/migrate_db.sh" ]; then
        echo "[*] 执行数据库迁移..."
        bash "$WORK_DIR/migrate_db.sh" || rollback "数据库迁移失败"
    fi

    # 升级 systemd unit 到 gunicorn（兼容历史的 app.py / -m web.app 两种 ExecStart）
    # 迁移旧版 unit：秘密移入 0600 EnvironmentFile，Web 改为专用非 root 用户。
    if [ -f "$WEB_UNIT" ] && ! grep -q '^EnvironmentFile=/etc/snat-manager/web.env' "$WEB_UNIT"; then
        id -u snat-web >/dev/null 2>&1 || useradd --system --home /opt/snat-manager --shell /usr/sbin/nologin snat-web
        install -d -o root -g root -m 0711 /etc/snat-manager
        : > /etc/snat-manager/web.env
        for key in APP_ENV FORCE_HTTPS TRUST_PROXY SNAT_SECRET_KEY SNAT_TOKEN_SECRET BACKUP_DIR WEB_HOST WEB_PORT; do
            value=$(sed -n "s/^Environment=\"${key}=\(.*\)\"$/\1/p" "$WEB_UNIT" | head -1)
            [ -n "$value" ] && printf '%s="%s"\n' "$key" "$value" >> /etc/snat-manager/web.env
        done
        chown snat-web:snat-web /etc/snat-manager/web.env
        chmod 0600 /etc/snat-manager/web.env
        sed -i -E '/^Environment="(APP_ENV|FORCE_HTTPS|TRUST_PROXY|SNAT_ADMIN_PASSWORD|SNAT_SECRET_KEY|SNAT_TOKEN_SECRET|BACKUP_DIR|WEB_HOST|WEB_PORT)=/d' "$WEB_UNIT"
        sed -i '/^WorkingDirectory=/a EnvironmentFile=/etc/snat-manager/web.env' "$WEB_UNIT"
        sed -i 's/^User=.*/User=snat-web/' "$WEB_UNIT"
        grep -q '^Group=' "$WEB_UNIT" || sed -i '/^User=snat-web/a Group=snat-web' "$WEB_UNIT"
        chown -R snat-web:snat-web /opt/snat-manager/web
    fi
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
        OLD_HOST=$(grep -oE 'AGENT_HOST=[^" ]+' "$AGENT_UNIT" | head -1 | cut -d= -f2)
        [ -n "$OLD_HOST" ] || rollback "无法确定旧 Agent 监听地址；为避免 fail-open，请先显式配置 AGENT_HOST"
        grep -q 'AGENT_PORT=' "$AGENT_UNIT" || sed -i "/Environment=\"AGENT_HOST/a Environment=\"AGENT_PORT=${OLD_PORT}\"" "$AGENT_UNIT"
        # 升级默认保持严格 HMAC 模式，不得自动打开 Bearer 回退。
        grep -q 'AGENT_ALLOW_BEARER=' "$AGENT_UNIT" || sed -i '/Environment="AGENT_PORT/a Environment="AGENT_ALLOW_BEARER=0"' "$AGENT_UNIT"
        # 来源 IP 白名单默认留空(=不限制)，保持升级不破坏现有连通性；公网直连请手动填面板出口 IP。
        grep -q 'AGENT_ALLOWED_IPS=' "$AGENT_UNIT" || sed -i '/Environment="AGENT_ALLOW_BEARER/a Environment="AGENT_ALLOWED_IPS="' "$AGENT_UNIT"
        sed -i \
            -e "s|ExecStart=/usr/bin/python3 .*|ExecStart=/usr/bin/gunicorn --chdir /opt/snat-manager/agent --workers 1 --threads 4 --timeout 60 --bind ${OLD_HOST}:${OLD_PORT} --access-logfile - wsgi:app|" \
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
