# 安全加固改动总览（CHANGES）

本项目在原版基础上完成了四轮安全审计与修复，所有改动已合入代码。48 个自动化测试全部通过。

## 已修复的问题（按类别）

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
