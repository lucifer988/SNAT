# SNAT Manager 部署与加固指南（内网 / 外网）

> **第七轮升级注意**
>
> 1. `AGENT_SET_FORWARD_POLICY_ACCEPT` 默认改为 `0`；项目之外的转发需求请单独配置放行规则。
> 2. Docker Web 数据改放在 `./data:/data`。旧部署升级前需把旧卷中的 `snat_manager.db` 和 `.secret_key` 分别迁移为 `./data/snat_manager.db`、`./data/secret_key`。
> 3. Agent 拒绝弱 Token 和短于 16 字符的 Token，推荐使用 `openssl rand -hex 32`。

本文档对应一次安全加固改造，核心变化：

1. **Agent 强制 HMAC 验签 + 防重放 + 常量时间比较** —— 面板下发的每个请求（含 GET）都带
   `X-Timestamp` / `X-Signature`，Agent 校验签名与时间戳后才执行，杜绝静态 token 被重放/伪造。
2. **面板所有调用统一签名** —— `agent_get` / `agent_post` 两个辅助函数，覆盖
   list_rules / health / get_traffic / get_connections / add_rule / delete_rule / check_traffic_limit
   等全部面板→Agent 调用。
3. **生产用 gunicorn** —— 不再用 Flask 自带开发服务器。面板与 Agent 均为**单 worker + 多线程**
   （进程内的登录锁定 / 限流 / 日志缓冲依赖单进程；Agent 还要避免多进程同改 iptables 与 DNS 线程丢失）。
4. **监听地址可配** —— `AGENT_HOST` / `AGENT_PORT` 环境变量，外网部署绑定到 WireGuard 内网 IP。
5. **命令执行健壮化** —— iptables/conntrack 缺失不再让 Agent 崩溃。

> 同步（面板改 → Agent 跟着动）与上报（Agent 状态/流量/连接数 → 面板看到）的原有逻辑**完全保留**，
> 改造只是在调用上加了签名头、在 Agent 上加了验签，对这两条链路是透明的。

---

## 一、内网部署（同一可信内网 / VPC）

最简单。面板和 Agent 在同一可信网段，直接用内网 IP 即可。

```bash
# 面板机
sudo ./install.sh --type web --mode 1          # 模式1：监听 0.0.0.0:5000，建议再配 IP 白名单
# Agent 机
sudo ./install.sh --type agent --port 8888
```

签名机制在内网同样生效（防止内网横向重放）。无需 WireGuard。

---

## 二、外网部署（跨机房 / 公网，**安装器自动配置 WireGuard**）

公网部署时，安装器默认询问并配置面板 hub 与 Agent spoke。WireGuard 只承载面板↔Agent 管理流量；Agent 不使用默认路由隧道，普通公网、测速和 SNAT 转发仍直连直出。

### 自动安装流程

面板安装时接受默认的 WireGuard 询问：

```bash
sudo ./install.sh --type web --mode 2
```

记录输出的面板公钥、公网 IP 和 UDP 端口。Agent 安装时接受默认的 WireGuard 询问，填写面板公网 IP、面板公钥和本机分配的 WG 地址（例如 `10.66.66.2`）。安装器会自动写入 `wg0.conf`，并让 Agent 只监听该 WG 地址。最后回到面板机把 Agent 公钥加入 peer，在面板服务器地址中填写 Agent WG 地址。

真正无人值守接入时，先由已登录管理员调用 `POST /api/wireguard/enrollment` 创建 10 分钟有效的一次性注册码；Agent 安装通过环境变量 `WG_ENROLL_TOKEN` 和 `--wg-enroll-url` 提交公钥。注册码成功使用一次后立即失效，面板通过只允许 `add` 的 root helper 写入 peer：

```bash
WG_ENROLL_TOKEN='<一次性注册码>' sudo -E ./install.sh --type agent --wireguard yes \
  --wg-enroll-url https://panel.example.com \
  --wg-panel-public-ip <面板公网IP> --wg-panel-public-key <面板公钥> \
  --wg-agent-ip 10.66.66.2 --wg-hub-ip 10.66.66.1 --wg-port 51820
```

注册码不接受命令行参数，避免进入 shell history；建议使用临时环境并在安装后 `unset WG_ENROLL_TOKEN`。

显式参数方式：

```bash
sudo ./install.sh --type web --mode 2 --wireguard yes --wg-port 51820 --wg-hub-ip 10.66.66.1
sudo ./install.sh --type agent --wireguard yes --wg-panel-public-ip <面板公网IP> \
  --wg-panel-public-key <面板公钥> --wg-agent-ip 10.66.66.2 \
  --wg-hub-ip 10.66.66.1 --wg-port 51820
```

> Agent 的 `AllowedIPs` 只包含面板 WG 地址 `/32`，不会使用 `0.0.0.0/0`，因此不会接管默认路由。

首次部署或手工维护 peer 时，仍可使用 `wireguard_setup.sh`：

### 1) 面板机（hub，需有公网 IP + 放行一个 UDP 端口）
```bash
sudo ./wireguard_setup.sh hub 51820 10.66.66.1
# 记下输出的 [hub 公钥] 和 [公网IP:51820]
```

### 2) 每台 Agent 机（spoke）
```bash
sudo ./wireguard_setup.sh agent <hub公网IP> <hub公钥> 10.66.66.2 51820
# 记下输出的 [Agent 公钥]
```

### 3) 回到面板机，把每台 Agent 注册进隧道
```bash
sudo ./wireguard_setup.sh add-peer hk-node-1 <Agent公钥> 10.66.66.2
```

### 4) 让 Agent 只在隧道内监听（关键）
编辑 `/etc/systemd/system/snat-agent.service`：
```ini
Environment="AGENT_HOST=10.66.66.2"
```
```bash
systemctl daemon-reload && systemctl restart snat-agent
```
这样 Agent 的端口**完全不暴露在公网**，只能从隧道内（即面板）访问。

### 5) 在面板里添加服务器
- 地址：填 Agent 的 **WG 内网 IP**（`10.66.66.2`），而不是公网 IP
- 端口：照旧（如 8888）
- Token：安装 Agent 时生成的强 token

> 替代方案：若你已有自己的内网/IPsec/Tailscale，跳过 1–4，直接用对端内网 IP，并用云防火墙
> 把 Agent 端口只放行给面板 IP 即可。

---

## 三、迁移与「仅签名」严格模式

Agent 默认 `AGENT_ALLOW_BEARER=0`，只接受带 nonce 的 HMAC 签名请求。仅在迁移旧面板时，
才临时显式设置 `AGENT_ALLOW_BEARER=1` 兼容 Bearer 请求（会打 WARNING 日志）。

升级顺序建议：
1. 先 `update.sh` 升级所有 **Agent**（此时同时兼容新旧面板）。
2. 再 `update.sh` 升级 **面板**（升级后面板一律发签名）。
3. 全部就绪后，把每台 Agent 的 `AGENT_ALLOW_BEARER` 改成 `0` 并重启，进入**仅签名严格模式**：
   ```ini
   Environment="AGENT_ALLOW_BEARER=0"
   ```
   ```bash
   systemctl daemon-reload && systemctl restart snat-agent
   ```

`update.sh` 会自动：安装 gunicorn、把旧的 `python3 ...` systemd 单元改写成 gunicorn、
并从旧 `agent.py` 里恢复你原来的自定义监听端口（写进 `AGENT_PORT`，避免被重置回 8888）。

---

## 四、相关环境变量速查

| 变量 | 端 | 默认 | 说明 |
|------|----|------|------|
| `AGENT_HOST` | Agent | `127.0.0.1` | 默认仅回环；远程面板对接时显式设为 WG/可信内网 IP |
| `AGENT_PORT` | Agent | `8888` | 监听端口 |
| `AGENT_ALLOW_BEARER` | Agent | `0` | 严格签名模式；迁移旧面板时才临时设 `1` |
| `AGENT_SIGNED_REQUEST_TTL` | Agent | `300` | 签名有效期（秒），防重放窗口 |
| `AGENT_TOKEN` | Agent | 无（必填） | 与面板共享的密钥，签名与认证的根 |
| `AGENT_TARGET_ALLOW_ALL` | Agent | `0` | 置 1 可放行任意 DNAT 目标（含链路本地/元数据）。默认拒绝 169.254/fe80 |
| `AGENT_TARGET_DENY_CIDRS` | Agent | 空 | 追加禁止的 DNAT 目标网段（逗号分隔 CIDR），如想连私网也禁可加 `10.0.0.0/8` 等 |
| `AGENT_SET_FORWARD_POLICY_ACCEPT` | Agent | `0` | 置 1 才会把 FORWARD 默认策略设为 ACCEPT；默认仅放行受管流 |
| `SNAT_SECRET_KEY` | 面板 | 无 | Flask session 密钥；不设则落盘到 `.secret_key`。设置后可集中托管/轮换 |
| `WEB_MAX_CONTENT_LENGTH` | 面板 | `4194304` | 请求体大小上限（字节），防超大 import body 撑爆单进程 |
| `SNAT_TOKEN_SECRET` | 面板 | 无（生产必填） | Agent token 落库加密密钥 |
| `FORCE_HTTPS` / `TRUST_PROXY` | 面板 | `0` | 反代/公网面板时开启 |

---

## 五、面板侧 HTTPS 反代（公网面板必做）

面板按**模式 2**安装（监听 `127.0.0.1:5000`，`FORCE_HTTPS=1`，`TRUST_PROXY=1`），前面套反代终止 TLS：

```bash
sudo ./install.sh --type web --mode 2
```

现成配置在 `reverse-proxy/`：
- `Caddyfile.example` —— Caddy，自动签发/续期 Let's Encrypt，最省心。
- `nginx-snat.conf.example` —— nginx + certbot。

> 本次已修复一个反代相关的隐患：`TRUST_PROXY=1` 时面板会用 `ProxyFix` 读取 `X-Forwarded-For`
> 还原真实客户端 IP。否则限流 / 登录锁定 / IP 白名单都会把所有人当成代理本机（127.0.0.1）。
> 反代务必传 `X-Forwarded-For` 与 `X-Forwarded-Proto`（两份示例配置都已带上）。

## 六、其它运维加固

- 云安全组：Agent 的 WG UDP 端口仅放行必要来源；Agent 业务端口不对公网开放。
- 定期轮换 `AGENT_TOKEN`（面板里更新该服务器 token 即可，会自动用 enc2 加密落库）。
