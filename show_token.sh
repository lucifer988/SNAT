#!/bin/bash
# 查看 Agent Token

echo "======================================"
echo "  SNAT Agent Token 查看"
echo "======================================"
echo

if [ ! -f "/etc/systemd/system/snat-agent.service" ]; then
    echo "错误：未找到 Agent 服务"
    exit 1
fi

TOKEN=$(sed -n 's/^AGENT_TOKEN="\(.*\)"$/\1/p' /etc/snat-manager/agent.env 2>/dev/null)

if [ -n "$TOKEN" ]; then
    echo "Agent Token: $TOKEN"
    echo
    echo "请将此 Token 添加到 Web 管理端"
else
    echo "错误：未找到 Token"
    exit 1
fi

