#!/bin/bash
# 数据库迁移脚本 - 添加字段

DB_FILE="/opt/snat-manager/web/snat_manager.db"

# 检查并安装 sqlite3
if ! command -v sqlite3 &> /dev/null; then
    echo "安装 sqlite3..."
    apt-get install -y sqlite3 -qq
fi

if [ -f "$DB_FILE" ]; then
    # 添加 last_check 字段到 servers 表
    if ! sqlite3 "$DB_FILE" "PRAGMA table_info(servers);" | grep -q "last_check"; then
        echo "添加 servers.last_check 字段..."
        sqlite3 "$DB_FILE" "ALTER TABLE servers ADD COLUMN last_check TIMESTAMP;"
    fi
    
    # 添加 last_iptables_bytes 字段到 rules 表
    if ! sqlite3 "$DB_FILE" "PRAGMA table_info(rules);" | grep -q "last_iptables_bytes"; then
        echo "添加 rules.last_iptables_bytes 字段..."
        sqlite3 "$DB_FILE" "ALTER TABLE rules ADD COLUMN last_iptables_bytes INTEGER DEFAULT 0;"
    fi

    # 添加 remark 字段到 rules 表
    if ! sqlite3 "$DB_FILE" "PRAGMA table_info(rules);" | grep -q "remark"; then
        echo "添加 rules.remark 字段..."
        sqlite3 "$DB_FILE" "ALTER TABLE rules ADD COLUMN remark TEXT DEFAULT '';"
    fi

    # 添加 target_host 字段到 rules 表
    if ! sqlite3 "$DB_FILE" "PRAGMA table_info(rules);" | grep -q "target_host"; then
        echo "添加 rules.target_host 字段..."
        sqlite3 "$DB_FILE" "ALTER TABLE rules ADD COLUMN target_host TEXT DEFAULT '';"
    fi

    # 清理重复规则并添加唯一约束
    echo "清理重复规则（按 server_id + local_port 保留最新）..."
    sqlite3 "$DB_FILE" "DELETE FROM rules WHERE id NOT IN (SELECT MAX(id) FROM rules GROUP BY server_id, local_port);"
    if ! sqlite3 "$DB_FILE" "PRAGMA index_list(rules);" | grep -q "idx_rules_server_port"; then
        echo "添加 rules 唯一约束 (server_id, local_port)..."
        sqlite3 "$DB_FILE" "CREATE UNIQUE INDEX idx_rules_server_port ON rules(server_id, local_port);"
    fi
    
    echo "✓ 迁移完成"
fi
