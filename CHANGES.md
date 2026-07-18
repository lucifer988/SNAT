# 安全加固改动总览（CHANGES）

本项目在原版基础上完成了多轮安全审计与功能修复，所有改动已合入代码。自动化测试全部通过。

## 第七轮（状态一致性 / 流量限额 / 部署收敛）

- Agent 不再默认修改宿主机全局 `FORWARD` 策略；规则下发按阶段执行，失败自动回滚并校验 DNAT。
- 删除规则逐组件确认；共享目标的 `MASQUERADE` 按引用保留，避免误删其它映射。
- 流量限额下沉到 Agent 本地执行；超限规则持久化为 `suspended`，DNS 刷新、重启和对账均不会绕过限额。
- 面板编辑、批量操作、超限停止及节点退役都要求 Agent 明确确认；失败时保留记录并标记 `desynced/unknown`。
- 服务器列表不再回传 Token 密文；Token 留空编辑保持原值；Telegram 命令默认关闭且未配置 Chat ID 时拒绝处理。
- Web 容器改为 `/data` 独立数据卷、只读根文件系统；Agent 移除 `NET_RAW`；`cryptography` 要求 `>=46.0.7,<47`。

回归覆盖：`tests_round7.py` 11 项、`tests_smoke.py` 27 项、`verify_e2e.py` 22 项。

---

## 第六轮（本次：功能修复 —— 把“摆件”接成真功能）

本轮聚焦功能完整性：此前若干界面元素/脚本只是摆设（有 UI 无逻辑、或有逻辑无入口、或调用早已不存在的 DOM 而静默失败）。逐一排查并修复：

前端（web/static/app.js + index.html）：
- **活跃连接数显示彻底失效（最严重的摆件）**：`loadConnectionsSummary()` 刷新连接数后调用的 `renderRules()` 依赖页面上根本不存在的 `#rulesTable`，抛错后被 `try/catch` 吞掉 —— 结果是每条规则的“连接”永远显示 0，标题里的“总活跃连接：0”是写死的静态文案。现改为刷新树形视图 `renderRulesTree()`，并把标题汇总改为真实合计（仅统计启用规则）。
- **批量启用/禁用/删除按钮不可用**：勾选框只存在于早已废弃的表格视图渲染代码里，当前树形视图没有任何勾选入口，点批量按钮永远提示“请先选择规则”。现给每条规则卡片加勾选框、每个服务器分组头加“全组勾选”、规则区加“全选”，与既有 `selectedRuleIds` / `bulkAction` 逻辑打通。
- **规则搜索/排序纯摆设**：样式表里写了 `#ruleSearch` 的样式但页面没有这个元素；`setRuleFilter` / `setRuleSort` / `getFilteredSortedRules` 定义了却无任何入口调用。现补上搜索框与排序下拉（创建时间/端口/流量/连接数/服务器名），树形渲染统一走过滤+排序管道；搜索时自动展开全部分组并提供空态提示。
- **清理三代同堂的死渲染代码**：删除 `renderRules`（写入不存在的 `#rulesTable`）、`renderServerGroups` / `renderRulesGroup` / `renderRuleCard`（写入不存在的 `#serverGroups`）、重复定义两次且引用不存在容器的 `toggleRulesView`、以及 `checkMobileView` 中操作不存在元素的死分支。规则区从此只有树形视图一条真实渲染路径，避免再次出现“改了 A 视图、坏了 B 视图”的回归。
- **分组折叠状态跨刷新保留**：连接数每 30 秒整体重绘一次会把用户手动折叠的分组重新展开；现用集合记录折叠状态，重绘后保持不变。
- **告警提示框吞消息**：`showAlert` 在 10 秒内已有提示框时会静默丢弃新消息；现复用同一提示框刷新内容与倒计时。
- 事件接线全部沿用 data-act / data-change / data-input 事件委托，兼容无 `'unsafe-inline'` 的 CSP，未新增任何内联脚本。
- 静态资源版本号 `app.js?v=2` → `?v=3`，避免浏览器缓存旧脚本。

后端（web/app.py）：
- **修复 `python3 -m web.app` / `python3 web/app.py` 循环导入崩溃**：以 `__main__` 身份执行时，blueprints 的 `from web import app` 会把本文件再完整导入一遍，两个半初始化副本互相 import 直接 `AttributeError` 退出（此前只有 gunicorn 的 `web.wsgi` 入口能启动，开发/调试直跑必挂）。现直跑时把仓库根目录补进 `sys.path` 并把 `__main__` 登记为规范的 `web.app` 模块。

测试工具（verify_e2e.py）：
- **端到端脚本同步到第五轮签名格式**：旧脚本签名缺 `X-Nonce`，Agent 默认 `AGENT_REQUIRE_NONCE=1` 会全部拒绝，导致 6 个正常路径用例误报 FAIL。现与面板 `build_agent_headers()` 对齐（`method\n path\n ts\n nonce\n body`），并新增两条攻击路径用例：同一签名头原样重放第二次必须 401（nonce 去重）、缺 `X-Nonce` 必须 401。当前 22/22 全部通过。

发布包卫生：
- 发行归档不再携带 `web/.secret_key`、`web/snat_web.log`、数据库文件与 `__pycache__`。特别说明：旧压缩包里带出的 `.secret_key` 属于安全隐患 —— 所有按包部署且未删除该文件的实例会共用同一个会话签名密钥，任何拿到包的人都能伪造这些实例的登录会话。已部署过旧包的用户请删除 `web/.secret_key` 让其重新生成（或用 `SNAT_SECRET_KEY` 注入），重新登录即可。

回归验证：`python -m unittest tests_smoke.py` 56/56 通过；`verify_e2e.py` 22/22 通过；另以假 iptables/conntrack 环境完整走通“建服务器 → 建规则 → 启停/编辑/批量 → 流量/连接/一致性/重下发 → 快照/备份/恢复 → 导入导出 → 告警设置/测试 → 诊断/日志/审计”的全链路。

---

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
