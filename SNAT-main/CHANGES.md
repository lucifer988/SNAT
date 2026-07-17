# 安全加固改动总览（CHANGES）

本项目在原版基础上完成了五轮安全审计与修复，所有改动已合入代码。自动化测试全部通过。

## 第五轮加固（本次：越权/重放/横向移动 收口 + 二次认证 + 系统级沙箱）

签名与链路：
- **仅签名模式名副其实**：`build_agent_headers()` 默认不再附带 `Authorization: Bearer <token>`，只发 `X-Timestamp + X-Nonce + X-Signature`，减少明文 token 在链路/日志/抓包/错误转储里出现的机会。仅对接只认 Bearer 的老 Agent 时才 `SNAT_AGENT_SEND_BEARER=1`。
- **HMAC 防重放补 nonce**：签名消息改为 `method\n path\n ts\n nonce\n body`，面板每次生成一次性 `X-Nonce`；Agent 与面板反向回报端各维护有界 TTL 去重缓存，堵住“时间窗内原样重放”。默认要求 nonce（`AGENT_REQUIRE_NONCE` / `SNAT_REQUIRE_INBOUND_NONCE`）。

设备/横向移动：
- **DNAT 目标默认拒绝私网/回环**：`is_target_ip_allowed` 由“只拒链路本地”改为默认拒绝回环、RFC1918、CGNAT(100.64/10)、IPv6 ULA(fc00::/7)、链路本地/云元数据、未指定/多播/保留地址。显著降低面板失守后把公网入口转发进内网的横向风险。确需转发到私网/回环时用 `AGENT_TARGET_ALLOW_PRIVATE=1` 或精确白名单 `AGENT_TARGET_ALLOW_CIDRS`。

面板 SSRF / DNS：
- **仅 IP 模式**：新增 `SNAT_AGENT_HOST_IP_ONLY=1`，服务器地址只接受字面量 IP、拒绝域名，直接消除 DNS 重绑定/TOCTOU 一类不确定性（配合 WireGuard 固定 IP）。默认关闭以兼容既有域名部署，公网部署强烈建议开启。

会话与二次认证：
- **敏感操作二次认证（step-up）**：登录态与高危操作权限分离。导出含 token、恢复备份/快照、导入服务器/规则、改服务器 token、删除服务器、批量删除规则、改告警 token 等，要求会话在最近 `SNAT_REAUTH_MAX_AGE`（默认 600s）内经 `POST /api/reauth` 重新验证过密码；前端命中 `reauth_required` 会自动弹密码框并重试。
- **会话寿命收紧**：`PERMANENT_SESSION_LIFETIME` 由 7 天降到默认 12 小时（`SNAT_SESSION_LIFETIME_HOURS` 可调），并开启每次请求滑动续期（相当于闲置超时）。

导出收紧：
- **导出默认不含 token**：`/api/export/servers` 默认脱敏 token；需含 token 必须 `?include_tokens=1` 且通过二次认证，且单独审计并在日志标红。

系统级沙箱（install.sh systemd 单元）：
- Web 单元：`NoNewPrivileges/PrivateTmp/ProtectSystem=strict/ProtectHome/ProtectKernel*`，丢弃全部 capability，限制地址族与系统调用，`ReadWritePaths` 只放行数据目录。
- Agent 单元：同类沙箱，capability 收敛到仅 `CAP_NET_ADMIN CAP_NET_RAW`（iptables/sysctl/conntrack 所需），保留 `/proc/sys` 可写以设置 ip_forward，`ReadWritePaths` 只放行 `/var/lib/snat-agent /var/log`。

测试：新增 nonce 重放拒绝、缺 nonce 拒绝等用例；既有签名用例同步到带 nonce 的新消息格式。

---

## 前四轮已修复的问题（按类别）

安全类：
- 存储型 XSS：前端所有 `innerHTML` 插值点统一 `escapeHtml` 转义；CSP 移除 `script-src 'unsafe-inline'`，改用 per-request nonce + 事件委托。
- SSRF：面板→Agent 请求禁止跟随重定向；主机名解析校验（拒绝解析到云元数据/链路本地段）；Agent 侧 DNAT 目标校验 + DNS 刷新时重新校验（防 DNS 重绑定）。
- 登录暴力破解：登录纳入全局限流；IP:用户名 与 纯 IP 双维度锁定；存储加容量上限（防内存放大）。
- 会话安全：登录成功 `session.clear()`（防会话固定）；运行时按 `force_https` 动态设置 `SESSION_COOKIE_SECURE`；`.secret_key` 以 0600 原子创建。
- CSRF：常量时间比较；集中内置于 `login_required`，写操作自动受保护。
- 弱口令：新增常见弱口令字典 + 字符单一度校验。
- Agent 公网直连：来源 IP 白名单（`AGENT_ALLOWED_IPS`）；默认仅签名严格模式（`AGENT_ALLOW_BEARER=0`）；可选 HTTPS 反代示例。
- 命令注入：`run_cmd` 拒绝字符串命令、强制 list 形式；目标经 `resolve_target` 保证合法 IP 才进 iptables。
- 路径遍历：备份恢复用 `realpath` + `commonpath` 双重校验。
- 主机枚举侧信道：`report_connections` 常量时间比较。

稳定性/一致性类：
- 备份/恢复改用 SQLite 在线 backup API（WAL 一致性快照，避免整库损坏）。
- Agent `rules.json` 损坏自动隔离 + 空规则继续（由面板对账自愈）。
- `import_rules` / `import_servers` 增加与手动新增一致的字段校验。
- 全部 `sqlite3.connect` 统一加 `timeout=10`（避免并发 `database is locked`）。
- `/api/*` 响应加 `Cache-Control: no-store`。

功能修复：
- 修复原项目中 `index.html` 从未引入 `app.js` 的缺陷（仪表盘按钮此前全部失效）。

性能：
- 为热点查询补充数据库索引（rules 按 server_id/enabled、audit/snapshots 按时间倒序）。

## 部署要点

公网直连 Agent（不用 WireGuard）推荐：Agent 监听本机回环 + Caddy HTTPS 反代（见 `reverse-proxy/Caddyfile.agent.example`）+ `AGENT_ALLOWED_IPS` 只放行面板出口 IP。安装脚本会交互式引导填写来源白名单。

面板务必置于 HTTPS 反代之后并设 `TRUST_PROXY=1`、`FORCE_HTTPS=1`；三个密钥（`SNAT_SECRET_KEY`、`SNAT_TOKEN_SECRET`、`AGENT_TOKEN`）用 `openssl rand -hex 32` 生成。

## 说明

代码审计有其上限，本项目已按 OWASP 主要漏洞类别系统化核验，当前未发现可利用漏洞。更高保证建议配合独立第三方渗透测试与依赖漏洞扫描（如 `pip-audit`）。
