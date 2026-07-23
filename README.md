# SNAT Manager

一个用于集中管理多台 Linux 节点 TCP 端口转发的 Web 面板。

SNAT Manager 由两部分组成：

- **Web 面板**：管理节点和转发规则，查看流量、连接数、状态、审计和告警。
- **Agent**：运行在转发节点上，负责写入 `iptables`、统计流量并持久化规则。

> 推荐架构：**Web 面板通过 HTTPS 提供服务，Web 与 Agent 之间通过 WireGuard 或可信内网通信。**

## 功能

- 多 Agent 节点统一管理
- TCP 端口转发规则新增、编辑、启停和删除
- 批量操作、规则对账和重新下发
- 流量统计、活跃连接数、单规则流量限额
- 域名目标定时解析与更新
- 规则快照、导入导出、备份恢复和审计日志
- Telegram 离线、限额和审计告警
- Agent HMAC 签名认证、nonce 防重放、来源 IP 白名单
- 失败回滚、删除确认和 `desynced/unknown` 状态提示

## 支持环境

- Debian / Ubuntu
- Python 3.11 或兼容版本
- Agent 节点需要 root、`iptables`、可选的 `conntrack`
- 当前数据面仅支持 **IPv4 TCP**；IPv6 目标会被明确拒绝

## 目录结构

```text
agent/                 Agent 程序
web/                   Web 面板
reverse-proxy/         Nginx / Caddy 示例
install.sh             systemd 一键安装
update.sh              更新与回滚
wireguard_setup.sh     WireGuard 辅助脚本
docker-compose.yml     Docker Compose 部署
DEPLOY.md              完整部署与加固说明
CHANGES.md             变更记录
tests_smoke.py         基础测试
verify_e2e.py          Agent 认证 E2E 测试
tests_round7.py        状态一致性与部署回归测试
```

# 快速开始

## 方式一：systemd 安装

先克隆仓库：

```bash
git clone https://github.com/lucifer988/SNAT.git
cd SNAT
chmod +x *.sh
```

### 安装 Web 面板

```bash
sudo ./install.sh --type web
```

安装过程会要求设置管理员密码，并询问监听方式：

- 内网环境可监听 `0.0.0.0:5000`
- 公网环境建议监听 `127.0.0.1:5000`，再使用 Nginx/Caddy 提供 HTTPS

安装完成后访问：

```text
http://服务器地址:5000
```

默认管理员用户名为 `admin`，首次登录必须修改密码。

### 安装 Agent

在每台负责转发的 Linux 节点执行：

```bash
sudo ./install.sh --type agent --port 8888
```

安装程序会生成 Agent Token。然后在 Web 面板的“服务器管理”中填写：

| 字段 | 示例 |
|---|---|
| 名称 | `node-1` |
| 地址 | `10.66.66.2` |
| 端口 | `8888` |
| Token | 安装 Agent 时生成的随机 Token |

建议让 Agent 只监听 WireGuard/内网 IP，不要直接暴露在公网。

## 方式二：Docker Compose

### 1. 创建配置

```bash
cp .env.example .env
```

至少设置以下强随机值：

```bash
openssl rand -hex 32
```

```dotenv
SNAT_ADMIN_PASSWORD=你的强管理员密码
SNAT_TOKEN_SECRET=至少32字节的随机值
SNAT_SECRET_KEY=至少32字节的随机值
AGENT_TOKEN=至少32字符的随机值
```

### 2. 启动

```bash
mkdir -p data/logs data/backups data/agent logs
sudo chown -R 10001:10001 data
docker compose up -d --build
```

Web 默认只绑定宿主机回环地址：

```text
127.0.0.1:5000
```

查看状态：

```bash
docker compose ps
docker compose logs -f snat-web
docker compose logs -f snat-agent
```

停止：

```bash
docker compose down
```

### Docker 数据位置

```text
./data/snat_manager.db     Web 数据库
./data/secret_key          Flask 会话密钥（未通过环境变量提供时）
./data/logs/               Web 日志
./data/backups/            备份
./data/agent/              Agent 规则状态
./logs/                    Agent 日志
```

Web 容器使用只读根文件系统，运行数据只写入 `/data`。

# 添加转发规则

在 Web 面板中：

1. 添加并确认 Agent 节点在线。
2. 打开“规则管理”。
3. 填写本地监听端口、目标 IPv4/域名、目标端口和可选流量限额。
4. 保存后，面板会要求 Agent 确认规则已写入。

示例：

```text
节点：node-1
本地端口：10080
目标：203.0.113.10
目标端口：80
```

客户端访问 `node-1:10080` 时，流量会转发到 `203.0.113.10:80`。

## 转发到内网目标

Agent 默认拒绝回环、RFC1918、CGNAT、ULA、链路本地和云元数据地址。如果确实需要“公网入口 → 内网服务”，在 Agent 环境中显式设置：

```ini
AGENT_TARGET_ALLOW_PRIVATE=1
```

更推荐只允许特定网段：

```ini
AGENT_TARGET_ALLOW_CIDRS=10.8.0.0/24
```

修改 systemd 环境后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl restart snat-agent
```

# 流量限额

## 本地 UI 验收 / 假 Agent

如需在没有真实 Agent / iptables 环境的情况下验证 Web UI、规则下发链路和拖拽排序，可在仓库根目录启动一个最小假 Agent：

```bash
python3 fake_agent.py
```

默认监听 `127.0.0.1:8888`，接受这些本地验收所需接口：
- `/health`
- `/add_rule`
- `/delete_rule`
- `/list_rules`
- `/get_traffic/<port>`
- `/get_connections/<port>`
- `/check_traffic_limit`

用途：
- 本地验证 Web 管理端新增规则是否成功落库 / 下发
- 验证服务器列表与规则列表在 UI 中的真实渲染与拖拽行为

说明：
- 这是开发 / 验收工具，不替代真实 SNAT Agent
- 默认 token 为 `token-qa`，可通过 `AGENT_TOKEN` 覆盖

规则可配置 `traffic_limit_gb`。限额会随规则下发到 Agent，由 Agent 本地周期检查：

- 即使 Web 面板离线，限额仍会执行
- 超限后规则标记为 `suspended`
- Agent 重启和 DNS 刷新不会自动恢复挂起规则
- 删除未被内核确认时不会假装停用，而会保留待重试状态

需要重新启用时，请在面板中明确启用或重新下发规则。

# 状态说明

| 状态 | 含义 |
|---|---|
| `active` | 面板与 Agent 状态一致 |
| `desynced` | Agent 未确认操作成功，需要执行一致性检查 |
| `unknown` | Token 无效或无法确认远端状态，远端可能仍在转发 |
| `suspended` | Agent 因流量限额在本地挂起规则 |

删除服务器时，面板会先清理远端规则。Agent 不可达时会返回失败；只有用户再次确认，才允许强制删除面板记录。强制删除后应到节点检查可能残留的 iptables 规则。

# Telegram 告警

在设置页面配置：

- Bot Token
- 允许接收命令的 Chat ID
- 离线阈值
- 日报、限额和审计告警开关

Telegram 命令功能默认关闭。即使明确开启，未填写允许的 Chat ID 时也不会处理命令。

# 推荐网络架构

```text
浏览器
  │ HTTPS
  ▼
Nginx / Caddy
  │ 127.0.0.1:5000
  ▼
SNAT Web
  │ HMAC + WireGuard/内网
  ├────────► Agent A ──► 目标服务
  ├────────► Agent B ──► 目标服务
  └────────► Agent C ──► 目标服务
```

WireGuard 示例详见 [DEPLOY.md](./DEPLOY.md)。辅助脚本示例：

```bash
sudo ./wireguard_setup.sh hub 51820 10.66.66.1
sudo ./wireguard_setup.sh agent <Hub公网IP> <Hub公钥> 10.66.66.2 51820
```

# 关键安全默认值

- `AGENT_ALLOW_BEARER=0`：默认仅接受 HMAC 签名请求
- `AGENT_SET_FORWARD_POLICY_ACCEPT=0`：不修改宿主机全局 FORWARD 策略
- Agent 弱 Token 或短于 16 字符时拒绝启动，推荐 32 字符以上
- Web API 不向浏览器返回加密 Token 密文
- Docker Web 默认只绑定 `127.0.0.1`
- Web Docker 根文件系统只读
- Agent 仅保留 `NET_ADMIN`，不授予 `NET_RAW`

> Agent 仍需要高权限操作 iptables。请将 Agent 放在可信节点，并通过 WireGuard、内网和防火墙限制访问。

# 更新与旧版迁移

systemd 部署更新：

```bash
SNAT_COMMIT_SHA=<完整40位提交SHA> sudo -E ./update.sh
```

安装与更新只接受固定提交 SHA，避免生产服务器以 root 自动执行可变 `main` 分支。systemd 安装的秘密保存在 `/etc/snat-manager/*.env`（`0600`），不会写入 unit；初始管理员密码仅写入 root-only 临时文件，首次登录后应删除。

`/metrics` 默认关闭。需要 Prometheus 时设置 `SNAT_METRICS_TOKEN`，并以 `Authorization: Bearer <token>` 请求。Web 与 Agent 必须走 WireGuard/可信加密内网；Agent 默认只监听回环地址，不能把 Agent 端口裸露公网。

Docker 更新：

```bash
git pull
docker compose up -d --build
```

从旧版 Docker Compose 升级时，旧版本可能用具名卷覆盖 `/app/web`。升级前请把旧卷中的：

- `snat_manager.db` → `./data/snat_manager.db`
- `.secret_key` → `./data/secret_key`

迁移后再使用新 Compose 启动。具体步骤见 [DEPLOY.md](./DEPLOY.md)。

# 测试

```bash
python3 tests_smoke.py
python3 tests_round7.py
python3 verify_e2e.py
node --check web/static/app.js
```

Docker 配置验证：

```bash
SNAT_ADMIN_PASSWORD=test \
SNAT_TOKEN_SECRET=0123456789abcdef0123456789abcdef \
AGENT_TOKEN=0123456789abcdef0123456789abcdef \
docker compose config
```

# 故障排查

## Agent 离线

```bash
sudo systemctl status snat-agent
sudo journalctl -u snat-agent -n 100 --no-pager
curl http://Agent地址:8888/healthz
```

## Web 无法启动

```bash
sudo systemctl status snat-web
sudo journalctl -u snat-web -n 100 --no-pager
docker compose logs snat-web
```

## 规则显示“待对账”

1. 检查 Agent 是否在线、Token 是否一致。
2. 在面板执行一致性检查。
3. 到 Agent 节点检查：

```bash
sudo iptables -t nat -S PREROUTING
sudo iptables -t nat -S POSTROUTING
sudo iptables -S FORWARD
```

## 转发无效

确认：

```bash
sysctl net.ipv4.ip_forward
sudo iptables -t nat -S
sudo iptables -S FORWARD
```

项目不会默认把宿主机全局 FORWARD 策略改成 ACCEPT，而是为每条托管规则添加精确放行项。

# 文档

- [DEPLOY.md](./DEPLOY.md)：部署、WireGuard、HTTPS 和安全加固
- [CHANGES.md](./CHANGES.md)：修复历史和行为变化
- `reverse-proxy/`：Nginx / Caddy 示例

# 许可与免责声明

请仅在你有权管理的服务器和网络中使用。端口转发会扩大服务暴露面，生产环境应配合 HTTPS、WireGuard、防火墙、强随机密钥和最小权限策略。