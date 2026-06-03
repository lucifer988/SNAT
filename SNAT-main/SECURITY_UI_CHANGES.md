# 本轮安全加固 + UI 改造说明（在原 PRODUCTION_NOTES 基础上）

本轮在原作者已完成的加固（HMAC 签名/防重放、token scrypt 加密、安全响应头、登录锁定、
CSRF、容器最小权限、规则文件原子写、子进程超时等）之上，补齐仍存在的安全短板，并把前端
换成专业主题。所有改动均**只增强、不改变既有同步/上报/认证链路的行为**。

验证：`python3 -m unittest tests_smoke`（25 例）与 `python3 verify_e2e.py`（18 项）全部通过。

---

## 一、信息安全 / 设备安全

1. **SSRF 防护（新增，重点）** —— `web/app.py: validate_agent_host()`
   面板会主动向管理员录入的「服务器(Agent)」`host:port` 发起带签名请求。面板多跑在云主机上，
   若 host 被填成云元数据地址（`169.254.169.254`）等链路本地地址，签名请求会打到元数据服务，
   可能泄露云厂商临时凭证 —— 典型 SSRF。现默认拒绝链路本地段（`169.254.0.0/16`、`fe80::/10`）。
   - WireGuard 内网（10.x）、私网（192.168.x/172.16.x）、`127.0.0.1`、主机名 **不受影响**，真实部署正常。
   - 已接入：新增服务器（POST）、编辑服务器（PUT）、批量导入服务器。
   - 特殊网络需放行：设环境变量 `SNAT_AGENT_HOST_ALLOW_ALL=1`；或用 `SNAT_AGENT_HOST_DENY` 追加 CIDR。

2. **Telegram Bot Token 加密落库** —— `web/app.py` + `web/blueprints/settings.py`
   原先明文存于 `settings_kv`。现复用 server token 的 v2（scrypt KDF）加密：
   - 写入加密，读取解密（`get_secret_setting` / `set_secret_setting`）；历史明文值可无缝兼容读取。
   - 设置接口 **不再回显** Bot Token 明文，仅返回「是否已配置」；前端用占位提示，留空提交＝保持原值。

3. **Agent 反向回报 token 比较改为定时安全** —— `web/blueprints/traffic.py: report_connections()`
   `token != expected_token` 改为 `hmac.compare_digest(...)`，消除时序侧信道。

4. **CSP 收紧** —— `web/app.py: after_request()`
   前端已移除全部外链资源，`img-src` 由 `'self' data: https:` 收紧为 `'self' data:`，
   不再放行任意 https 图片来源，减少数据外泄/被第三方追踪面。
   （注：`script-src/style-src` 仍含 `'unsafe-inline'`，因页面仍有大量内联 `onclick`；
   彻底去除需把内联事件迁为事件委托，属较大前端重构，见「四、仍建议后续」。）

5. **输入校验加固（防 500 / 防脏数据 / 防锁死）**
   - `servers PUT`（编辑服务器）：必填字段、host 合法性 + SSRF、端口范围校验，返回 400 而非未捕获 500。
   - `rules PUT`（编辑规则）：必填字段与端口 1–65535 前置校验，避免按键取值 KeyError → 500。
   - `/api/whitelist POST`：IP/CIDR 格式校验，避免脏数据落库后把所有人挡在门外。
   - `import_servers`：逐行校验名称/token/端口/host(SSRF)，非法行跳过并返回 `skipped` 计数。

---

## 二、UI 改造（视觉换肤，零 DOM/逻辑改动）

- **移除外链背景图**（两页此前从 `images.unsplash.com` 拉图）—— 既是隐私/供应链风险（每次访问都
  把来访信息暴露给第三方 CDN），也拖慢首屏。改为自包含的深色渐变背景。
- **移除 `Comic Sans MS`**，统一为跨平台系统字体栈（苹方/微软雅黑/Segoe UI ...）。
- **移除雪花动画与点击粒子两段装饰脚本**（顺带减少内联脚本）。
- **追加专业主题覆盖层**：深色背景 + 白色卡片、靛蓝/翠绿/玫红语义化按钮、左侧强调条的区块标题、
  清爽的表格与弹窗、可见的键盘焦点环（可访问性）。仅靠 CSS 层叠覆盖旧样式，未改任何类名与脚本。

---

## 三、如何验证

```bash
python3 -m unittest tests_smoke -v     # 25 例
python3 verify_e2e.py                   # 18 项（真起 Agent 走 HTTP 验签）
```

---

## 四、仍建议后续推进（本轮未做，属架构级，需单独立项）

1. **去掉 CSP 的 `'unsafe-inline'`**：把 ~68 处内联 `onclick` 改为 `addEventListener` 事件委托 +
   内联 `<script>` 外置/加 nonce。这是 Web 端最大的 XSS 放大器，但属较大重构。
2. **多副本化**：当前 Web 单进程 + SQLite，限流/登录锁定/日志为进程内内存态，无法水平扩展。
   需迁移到 Redis（限流/锁定）+ Postgres（数据），方可在大规模下多实例部署。
3. **Web 容器非 root 化**：为 DB / secret_key / 日志 / 备份引入统一可配置数据目录并 chown 非 root 用户。
4. **多用户 + RBAC**：当前单 admin，审计虽全但无法区分操作人。
5. **重启后状态自收敛 + Prometheus 指标**（沿用原 PRODUCTION_NOTES 的建议）。
