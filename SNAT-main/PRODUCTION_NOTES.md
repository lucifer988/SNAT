# 生产化改造说明（PRODUCTION_NOTES）

本文件记录本轮针对生产环境做的代码与交付改造、改动理由，以及仍建议后续推进的事项。
所有改动均已通过自带测试：`python3 -m unittest tests_smoke`（25 例）与 `python3 verify_e2e.py`（18 项）全绿。

---

## 〇、本轮安全加固增量（设备 / 信息安全）

> 原则：默认不改变现有行为，新加固一律通过环境变量开启或可关闭，避免影响在跑部署。

1. **Agent DNAT 目标地址防护（设备安全，重点）**：Agent 会把入口端口 DNAT 到面板下发的
   `target_ip`。若被指向云元数据地址 `169.254.169.254`，等于把对外端口直通本机元数据服务，
   可窃取云厂商临时凭据；域名目标还可能被 **DNS 重绑定** 到该地址。现默认拒绝链路本地段
   （`169.254.0.0/16` / `fe80::/10`），并在 `add_rule` 与 **DNS 刷新** 两条路径上都校验解析后的 IP。
   正常公网/私网目标不受影响。可用 `AGENT_TARGET_ALLOW_ALL=1` 放行，或 `AGENT_TARGET_DENY_CIDRS` 追加网段。
2. **FORWARD 默认策略可关闭**：`add_snat_rule` / `restore_rules` 中的 `iptables -P FORWARD ACCEPT`
   会把本机变成开放转发。新增 `AGENT_SET_FORWARD_POLICY_ACCEPT`（默认 `1` 保持兼容），置 `0` 后
   只依赖已插在链首的按规则 `SNAT_*_FWD` ACCEPT，受管流量照常工作而不再全局放行。
3. **面板 session 密钥支持环境注入**：`_load_secret_key()` 现优先读 `SNAT_SECRET_KEY`
   （install.sh 早已注入该变量但此前代码未使用），便于集中托管与轮换，密钥可不落盘。
4. **登录计时侧信道**：用户不存在时也执行一次等价开销的密码哈希校验，消除“用户名是否存在”的
   响应时间差，挡掉用户名枚举。
5. **请求体大小上限**：面板设 `MAX_CONTENT_LENGTH`（默认 4MB，`WEB_MAX_CONTENT_LENGTH` 可调），
   防止超大 import/restore body 撑爆单进程。
6. **CSV 导出补审计**：`/api/export/servers`、`/api/export/rules` 会导出 token 密文与拓扑，
   现已写入审计日志。
7. **docker-compose 去除弱占位密钥**：原先 `change-me-now` 等占位值会让 `docker compose up`
   带着已知弱口令直接跑起来。现改为从 `.env` 注入（新增 `.env.example`），未设置时
   compose 直接报错退出（`${VAR:?...}`），杜绝弱口令上线。

---

## 一、已修复 / 已改进

### Agent 可靠性（agent/agent.py）—— 本轮重点

1. **子进程执行超时**
   `run_cmd()` 原先调用 `subprocess.run(...)` 不带超时。当 `xtables` 锁被长期占用、或 `conntrack -L` 在巨型连接表上卡住时，调用会无限阻塞，而 Agent 只有 4 个工作线程——几次卡死就能让整个 Agent 失去响应。
   现已加入 `AGENT_CMD_TIMEOUT`（默认 20s）超时，超时按命令失败处理并记录日志，不再拖垮线程。

2. **iptables 锁等待（`-w`）**
   API 线程与 DNS 刷新线程会并发调用 iptables。不加 `-w` 时并发执行会偶发 `another app is currently holding the xtables lock` 而失败。
   现已在 `run_cmd` 内对所有 iptables 命令自动注入 `-w`（对调用方与测试透明）。

3. **iptables / 规则文件并发串行化**
   新增进程内可重入锁 `STATE_LOCK`，把 `add_rule` / `delete_rule` / `check_traffic_limit` 三个写接口、DNS 刷新循环体、以及启动期 `restore_rules` 全部串行化，消除“读规则→改 iptables→写规则文件”过程中的竞态与丢更新。

4. **规则文件原子写**
   `save_rules()` 原先直接覆盖写 `rules.json`，写一半崩溃会留下损坏文件，Agent 重启后 `load_rules()` 直接抛错。
   改为“写临时文件 + `fsync` + `os.replace`”原子替换。

5. **流量限额接口类型加固**
   `check_traffic_limit` 中 `traffic_limit_gb` / `current_bytes` 现做整数强转校验，非法输入返回 400 而非 500。

### Web 端（web/）

6. **安全响应头补全（web/app.py `after_request`）**
   新增 `Content-Security-Policy`、`Referrer-Policy: no-referrer`、`Permissions-Policy`，并在 HTTPS 链路上下发 `Strict-Transport-Security`（HSTS）。
   CSP 经过实测：保留 `'unsafe-inline'`（页面含内联脚本/样式与大量 `onclick`），但禁止外部脚本源、禁止被 iframe 嵌套（防点击劫持）、限制 `form-action` / `base-uri` / `object-src`，图片放行 `https:` 以兼容现有外链背景图。不会破坏既有前端。

7. **规则创建接口前置校验（web/blueprints/rules.py）**
   原先 `data['server_id']` 等直接按键取值、`dict(c.fetchone())` 直接转字典——缺字段或服务器不存在时会抛未捕获异常返回 500。
   现已加入：必填字段校验（400）、端口整数与 1–65535 范围校验（400）、服务器存在性校验（404）。

### 交付与供应链

8. **依赖锁定**：新增 `requirements.txt`，固定 Flask / Werkzeug / requests / cryptography / gunicorn 版本，构建可复现。
9. **Dockerfile.web / Dockerfile.agent**：改为从 `requirements.txt` 安装；新增 `HEALTHCHECK`（打匿名 `/healthz`）；Agent 镜像补装 `conntrack`（活跃连接统计依赖）。
10. **docker-compose.yml 加固**：
    - 两个服务加 `restart: unless-stopped` 与 `json-file` 日志轮转（max-size/max-file）；
    - Web 加内存上限与 `no-new-privileges`；
    - **Agent 改为最小能力集**：`cap_drop: ALL` + 仅 `cap_add: NET_ADMIN, NET_RAW`，并 `no-new-privileges`，显著缩小 host 网络 + root 的爆炸半径。
11. **`.dockerignore`**：避免 `.secret_key` / `*.db` / 日志 / 脚本等进入镜像，减小体积与泄露面。
12. **CI**：新增 `.github/workflows/ci.yml`，每次 push / PR 自动跑 `pyflakes` 静态检查 + 单元测试 + 端到端验证，把原本只能手动跑的测试变成合并门禁。

---

## 二、有意未改动（避免破坏现有行为 / 超出安全改造范围）

- **Web 控制面仍是单进程单 worker + SQLite**：这是架构性约束（限流/锁定/日志为进程内内存态）。改成多副本 + Redis + Postgres 是较大重构，需配合迁移与回归测试，单独立项更稳妥。
- **Web 容器仍以 root 运行**：当前 DB / `.secret_key` / 日志写在 `web/` 目录并通过 named volume 持久化，备份目录为 bind mount。直接切非 root 会触发卷属主与写权限问题，可能让应用起不来。建议的彻底做法见下节“非 root 化”。
- **明文 HTTP + WireGuard 仍靠运维手动搭建**：链路签名（HMAC + 防重放）已足够防伪造，但明文内容仍可被嗅探，外网必须叠加传输层加密。这一点文档已强调，未改为强制。

---

## 三、仍建议后续推进（按优先级）

1. **重启后状态自收敛**：Agent 启动时（`restore_rules` 之外）主动向面板拉取期望规则做一次全量对账；面板侧增加周期性巡检，比对内核实际 iptables 与 DB，发现漂移自动 reconcile。当前 `desynced` 仍偏事件驱动，机房重启后可能静默失效。
2. **可观测性**：暴露 Prometheus 指标（规则数 / desynced 数 / Agent 在线率 / 签名失败次数 / DNS 刷新失败），结构化日志，关键自动动作（限额停规则）接外部告警。
3. **非 root 化（彻底版）**：为 DB / secret_key / 日志 / 备份引入统一可配置数据目录（环境变量），镜像内建非 root 用户并 `chown` 该目录，compose 卷相应授权；同步更新 `update.sh` 的保留逻辑。
4. **发布版本管理**：打 tag / 发 release，安装脚本校验 checksum，避免 `curl | bash` 直接拉 `main`。
5. **DB 迁移框架**：用 Alembic 之类替代手写 `migrate_db.sh`，迁移带版本号、可前进可回滚。
6. **多用户与 RBAC**：当前单 admin，审计虽全但无法区分操作人。

---

## 四、如何验证

```bash
# 静态检查（CI 同款）
python3 -m pyflakes web/app.py web/blueprints/*.py agent/agent.py

# 单元测试（25 例）
python3 -m unittest tests_smoke -v

# 端到端签名/认证链路（18 项，真起 Agent 进程走 HTTP）
python3 verify_e2e.py
```
