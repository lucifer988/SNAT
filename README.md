# SNAT Manager

一个面向多节点的 **SNAT / 端口转发管理面板**。

它由两部分组成：

- **Web 管理端**：用于管理服务器、添加/编辑/删除转发规则、查看状态/流量/连接数、导入导出、审计与告警。
- **Agent 客户端**：部署在实际承载转发的 Linux 服务器上，负责落地 `iptables` 规则、统计流量与连接数，并把规则持久化到本地。

> 当前项目以 **Debian / Ubuntu** 为主要运行环境，安装脚本、systemd 单元、WireGuard 引导均按 Debian 系设计。

---

## 1. 项目特点

### 功能面

- 多 Agent 节点统一管理
- 转发规则增删改查
- 规则启用 / 停用 / 批量操作
- 流量统计、活跃连接数统计
- 规则快照、备份恢复、重新下发、一致性检查
- 审计日志
- Telegram 告警
- 支持域名目标自动解析刷新（Agent 侧定时刷新）

### 安全面

- 面板 → Agent 统一使用 **HMAC 签名**
- 签名默认带 `X-Nonce`，防时间窗内重放
- 默认 **不再附带明文 Bearer token**
- Agent 可配置来源 IP 白名单
- Agent 默认拒绝把公网入口转发到回环 / RFC1918 / CGNAT / ULA / 云元数据地址
- 支持敏感操作二次认证（reauth）
- Web / Agent 的 systemd 单元均做了基础沙箱收紧

---

## 2. 目录结构

```text
web/                    Web 管理端
  app.py                Web 主程序
  blueprints/           各功能模块
  templates/            HTML 模板
  static/app.js         前端主逻辑

agent/
  agent.py              Agent 主程序

docker-compose.yml      Docker Compose 示例
install.sh              一键安装脚本
update.sh               一键更新脚本（带回滚）
wireguard_setup.sh      WireGuard 一键配置脚本
DEPLOY.md               部署与加固说明
CHANGES.md              安全改动总览
reverse-proxy/          Nginx / Caddy 示例配置
```

---

## 3. 运行要求

### Web 管理端

- Debian / Ubuntu
- Python 3
- gunicorn
- 可选：Nginx / Caddy（公网部署强烈推荐）

### Agent 客户端

- Debian / Ubuntu
- Python 3
- `iptables`
- `conntrack`（可选但推荐）
- root 权限运行（因为需要修改 `iptables` 与 `ip_forward`）

---

## 4. 快速开始

## 4.1 安装 Web 管理端

```bash
sudo ./install.sh --type web
```

安装脚本会提示选择两种模式：

1. **内网直连模式**
   - Web 监听 `0.0.0.0:5000`
   - 适合同一内网 / 实验环境
   - 建议再配 IP 白名单

2. **反向代理 / 公网模式（推荐）**
   - Web 监听 `127.0.0.1:5000`
   - 由 Nginx / Caddy 对外提供 HTTPS
   - 会自动设置 `FORCE_HTTPS=1`、`TRUST_PROXY=1`

安装完成后会输出：

- 管理员账号：`admin`
- 初始密码：你输入的值，或脚本自动生成的强密码

> 首次登录后必须修改密码。

---

## 4.2 安装 Agent 客户端

```bash
sudo ./install.sh --type agent --port 8888
```

安装脚本会提示选择两种暴露方式：

1. **内网 / WireGuard（推荐）**
   - Agent 只监听内网 / WireGuard IP
   - 不直接暴露公网

2. **公网直连（高风险）**
   - Agent 监听 `0.0.0.0`
   - 脚本会强制要求填写 `AGENT_ALLOWED_IPS`
   - 没有白名单就拒绝继续安装

安装完成后会输出：

- Agent 地址
- Agent 端口
- Agent Token

然后把这些信息填入 Web 管理端即可。

---

## 5. 推荐部署方式

## 5.1 最推荐：Web + Agent 之间走 WireGuard

这是当前项目最贴合的生产部署方式：

- Web 面板走 HTTPS 反代
- Agent 不暴露公网
- Web 通过 Agent 的 WireGuard 内网 IP 通信

### WireGuard 配置

面板机：

```bash
sudo ./wireguard_setup.sh hub 51820 10.66.66.1
```

Agent 机：

```bash
sudo ./wireguard_setup.sh agent <hub公网IP> <hub公钥> 10.66.66.2 51820
```

回到面板机注册 Agent：

```bash
sudo ./wireguard_setup.sh add-peer <名字> <Agent公钥> 10.66.66.2
```

然后把 Agent 的 systemd 监听地址改成 WG 内网 IP，例如：

```ini
Environment="AGENT_HOST=10.66.66.2"
```

重启：

```bash
sudo systemctl daemon-reload
sudo systemctl restart snat-agent
```

在 Web 面板里添加服务器时：

- 地址：填 `10.66.66.2`
- 端口：填 Agent 端口（如 `8888`）
- Token：填安装 Agent 时生成的 token

### WireGuard 会不会影响 Agent 自身上网？

不会明显影响。

脚本生成的 Agent 配置里：

```ini
AllowedIPs = 10.66.66.0/24
```

这意味着只有发往 WG 网段的流量走隧道，Agent 自己访问公网、apt、拉镜像等仍走原默认路由。

---

## 5.2 公网部署最小安全基线

如果你一定要公网部署，请至少做到：

### Web 管理端

- 采用安装模式 2（反向代理 / 公网）
- 外部只开放 `443`
- Web 仅监听 `127.0.0.1:5000`
- 反向代理传递：
  - `X-Forwarded-For`
  - `X-Forwarded-Proto`
- 开启：
  - `FORCE_HTTPS=1`
  - `TRUST_PROXY=1`

### Agent

- 优先不要公网暴露，尽量走 WireGuard / 内网
- 若必须公网直连：
  - `AGENT_ALLOWED_IPS` 只放行面板出口 IP
  - 保持 `AGENT_ALLOW_BEARER=0`
  - 不要轻易放开 `AGENT_TARGET_ALLOW_ALL=1`

### 凭据

必须使用强随机值：

- `SNAT_ADMIN_PASSWORD`
- `SNAT_SECRET_KEY`
- `SNAT_TOKEN_SECRET`
- `AGENT_TOKEN`

---

## 6. 当前默认安全行为（按代码）

以下是**当前代码**而不是旧文档里的历史默认值：

### Web 侧

- 默认会话有效期：**12 小时**（滑动续期）
- 默认敏感操作二次认证窗口：**600 秒**
- 默认面板 → Agent 签名请求：
  - 发 `X-Timestamp`
  - 发 `X-Nonce`
  - 发 `X-Signature`
  - **默认不发 `Authorization: Bearer ...`**

### Agent 侧

- 默认 `AGENT_ALLOW_BEARER=0`
- 默认要求签名请求带 nonce
- 默认拒绝将规则转发到：
  - 回环地址
  - RFC1918 私网
  - CGNAT
  - IPv6 ULA
  - 链路本地
  - 云元数据地址

如果你确实要允许“公网入口 → 内网服务”，需要显式开启：

```ini
AGENT_TARGET_ALLOW_PRIVATE=1
```

或更细粒度地放开：

```ini
AGENT_TARGET_ALLOW_CIDRS=10.8.0.0/24
```

---

## 7. Web 面板主要功能说明

## 7.1 服务器管理

可添加 / 编辑 / 删除 Agent 服务器。

每台服务器至少包含：

- 名称
- 地址
- Agent 端口
- Token

面板会定期/按需检查：

- `/health`
- `/list_rules`
- 流量与连接数接口

如果 token 错误，服务器状态会标记为 `token_invalid`，并按当前策略停用对应规则。

---

## 7.2 规则管理

每条规则包含：

- 目标服务器
- 本地端口
- 目标 IP / 目标主机
- 目标端口
- 备注
- 流量限制

支持：

- 新增规则
- 编辑规则
- 删除规则
- 批量启用 / 停用 / 删除
- 一致性检查（reconcile）
- 重新下发规则（reapply）

---

## 7.3 流量与连接数

Agent 侧会统计：

- 规则累计流量
- 端口当前活跃连接数

用于：

- Web 看板展示
- 流量限制判断
- 运维排查

---

## 7.4 审计 / 导入导出 / 备份恢复

### 导出

- 导出服务器
- 导出规则

> 默认导出服务器时 **不含 token**。若要导出含 token 的版本，需要二次认证。

### 导入

- 导入服务器
- 导入规则

### 备份 / 快照

- 创建规则快照
- 查看 / 恢复备份
- 快照恢复后可重新下发规则

---

## 7.5 告警

目前支持 Telegram 告警。

需要配置：

- `tg_bot_token`
- `tg_chat_id`
- 离线阈值秒数

支持：

- 测试告警
- 立即检查离线/异常服务器并推送

---

## 8. 面板宕机后规则是否还有效？

**有效。**

原因：

- Agent 在本地持久化规则到 `rules.json`
- Agent 启动时会从本地规则恢复 `iptables`

所以：

- Web 面板挂了，已下发规则通常仍继续生效
- Agent 重启后也会尝试恢复本地规则
- 真正受影响的是：后续不能再新增 / 删除 / 同步规则，直到面板恢复

---

## 9. Docker Compose 说明

仓库自带了 `docker-compose.yml` 示例。

当前默认行为：

- **Web 默认只绑定到 `127.0.0.1`**
- 目的是避免 `docker compose up -d` 后直接把管理后台暴露到公网 `5000`

也就是说，Docker 部署同样推荐：

- 前置 Nginx / Caddy
- 外部只暴露 `443`
- 不直接把 Web 容器端口裸露到公网

Agent 容器使用：

- `network_mode: host`
- `NET_ADMIN` / `NET_RAW`

因为它需要修改本机 `iptables`。

---

## 10. 更新

使用一键更新脚本：

```bash
sudo ./update.sh
```

特点：

- 更新前自动备份 `/opt/snat-manager`
- 更新失败会自动回滚
- 会尝试保留数据库、密钥、旧端口配置

如需手动回滚，`update.sh` 结束时会给出回滚命令。

---

## 11. 反向代理示例

仓库内置：

- `reverse-proxy/nginx-snat.conf.example`
- `reverse-proxy/Caddyfile.example`

用于：

- Web 面板 HTTPS 反代
- 传递真实客户端 IP
- 传递 HTTPS 标志

> 注意：仓库里的 `reverse-proxy/Caddyfile.agent.example` 目前只是 **Agent TLS 终止参考模板**。
> 由于当前面板仍按 `http://{host}:{port}` 拼接 Agent URL，所以它**不能**直接表示“面板已经原生支持 HTTPS Agent 接入”。

---

## 12. 建议先读的文档

- [DEPLOY.md](./DEPLOY.md)
  - 部署方式
  - WireGuard
  - HTTPS 反代
  - 安全建议

- [CHANGES.md](./CHANGES.md)
  - 当前项目的安全改动总览
  - 为什么会有这些默认值
  - 已收口的问题类型

---

## 13. 适合的使用场景

适合：

- 多台 Linux 节点的端口转发统一管理
- 公网入口映射到不同节点上的服务
- 希望通过 Web 面板集中维护规则
- 希望保留规则审计、导入导出、快照与恢复能力

不适合：

- 无法接受 Agent 需要 root / `iptables` 权限
- 不愿意做 HTTPS / 内网 / WireGuard 这类基础安全隔离
- 需要复杂 L7 代理、负载均衡、鉴权网关场景（这不是它的目标）

---

## 14. 一条最实用的建议

**如果你是生产环境：优先选 `Web HTTPS + Agent WireGuard 内网监听`。**

这是当前项目最贴合、最省心、也最不容易踩坑的使用方式。

---

## 15. License / 说明

本 README 依据当前仓库代码、安装脚本、部署文档与安全改动整理，优先贴合当前项目实际行为；若后续代码再改，建议同步更新本文档。
