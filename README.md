# SNAT Manager

一个简单的 SNAT / 端口转发管理面板。

项目分为两部分：

* **Web 管理端**：提供网页面板，用来管理服务器和转发规则。
* **Agent 客户端**：部署在真正执行转发的服务器上，负责下发 `iptables` 规则。

适合用来集中管理多台机器上的 TCP 端口转发规则。

---

## 功能

* Web 面板管理多台 Agent 服务器
* 添加 / 编辑 / 删除 / 启停端口转发规则
* 查看服务器状态、流量、活跃连接数
* 支持规则批量操作
* 支持备份、快照、导入导出
* 支持 Telegram 告警
* Agent 请求带 HMAC 签名校验
* 支持 WireGuard 隧道部署，避免 Agent 裸露公网

---

## 环境要求

推荐系统：

* Debian / Ubuntu
* root 权限
* Python 3
* iptables
* systemd

默认端口：

| 服务        |        默认端口 |
| --------- | ----------: |
| Web 面板    |      `5000` |
| Agent     |      `8888` |
| WireGuard | `51820/udp` |

---

## 一键安装

先克隆项目：

```bash
git clone https://github.com/lucifer988/SNAT.git
cd SNAT
chmod +x *.sh
```

---

## 安装 Web 管理端

在“管理面板服务器”上执行：

```bash
sudo ./install.sh --type web --mode 1
```

安装完成后脚本会输出：

* 访问地址
* 管理员账号
* 管理员初始密码

默认账号是：

```text
admin
```

访问：

```text
http://你的服务器IP:5000
```

首次登录后需要修改密码。

如果 Web 面板要放到公网，建议使用反向代理和 HTTPS：

```bash
sudo ./install.sh --type web --mode 2
```

然后参考：

```text
reverse-proxy/Caddyfile.example
reverse-proxy/nginx-snat.conf.example
```

---

## 安装 Agent 客户端

在“需要做端口转发的服务器”上执行：

```bash
sudo ./install.sh --type agent --port 8888
```

安装完成后脚本会输出类似信息：

```text
Agent 地址：http://服务器IP:8888
Token: xxxxxxxxxxxxxxxxxxxxxxxx
```

把这个 Token 保存下来，后面要填到 Web 面板里。

---

## 在面板中添加服务器

登录 Web 面板后：

1. 点击 **添加服务器**
2. 填写：

   * 服务器名称：随便起，例如 `hk-node-1`
   * 服务器地址：Agent 服务器 IP
   * Agent 端口：默认 `8888`
   * Token：安装 Agent 时输出的 Token
3. 点击保存
4. 点击检查服务器状态，显示在线即可

---

## 添加转发规则

进入 Web 面板后点击 **添加规则**，填写：

| 字段    | 说明                |
| ----- | ----------------- |
| 选择服务器 | 选择一台已添加的 Agent    |
| 本地端口  | Agent 服务器上对外监听的端口 |
| 目标 IP | 要转发到的目标 IP 或域名    |
| 目标端口  | 目标服务端口            |
| 备注    | 可选                |
| 流量限制  | 单位 GB，填 `0` 表示不限制 |

示例：

```text
本地端口：10000
目标 IP：1.2.3.4
目标端口：80
```

表示访问：

```text
Agent服务器IP:10000
```

会被转发到：

```text
1.2.3.4:80
```

---

## 外网部署建议：使用 WireGuard

如果 Web 和 Agent 不在同一个可信内网，不建议把 Agent HTTP 端口直接暴露到公网。

推荐使用项目自带 WireGuard 脚本。

### 1. 在 Web 面板服务器上创建 hub

```bash
sudo ./wireguard_setup.sh hub 51820 10.66.66.1
```

记下脚本输出的：

```text
hub 公钥
公网 IP:端口
```

---

### 2. 在 Agent 服务器上加入隧道

```bash
sudo ./wireguard_setup.sh agent <hub公网IP> <hub公钥> 10.66.66.2 51820
```

记下输出的：

```text
Agent 公钥
```

---

### 3. 回到 Web 面板服务器添加 Agent peer

```bash
sudo ./wireguard_setup.sh add-peer hk-node-1 <Agent公钥> 10.66.66.2
```

---

### 4. 让 Agent 只监听 WireGuard 内网 IP

编辑 Agent 服务：

```bash
sudo nano /etc/systemd/system/snat-agent.service
```

把：

```ini
Environment="AGENT_HOST=0.0.0.0"
```

改成：

```ini
Environment="AGENT_HOST=10.66.66.2"
```

重启：

```bash
sudo systemctl daemon-reload
sudo systemctl restart snat-agent
```

然后在 Web 面板里添加服务器时，服务器地址填写：

```text
10.66.66.2
```

不要填写公网 IP。

---

## Docker Compose 部署

项目也提供了 `docker-compose.yml`。

适合单机体验或容器化部署。

### 1. 生成配置

```bash
cp .env.example .env
```

编辑 `.env`，至少填写：

```env
SNAT_ADMIN_PASSWORD=
SNAT_TOKEN_SECRET=
AGENT_TOKEN=
```

可以用下面命令生成随机值：

```bash
openssl rand -base64 24
openssl rand -hex 32
```

### 2. 启动

```bash
docker compose up -d --build
```

访问：

```text
http://服务器IP:5000
```

### 3. 查看日志

```bash
docker compose logs -f
```

### 4. 停止

```bash
docker compose down
```

---

## Docker 一键启动脚本

也可以新建一个脚本：

```bash
nano quickstart-docker.sh
```

写入：

```bash
#!/usr/bin/env bash
set -e

cp -n .env.example .env

if ! grep -q "SNAT_ADMIN_PASSWORD=." .env; then
  sed -i "s|^SNAT_ADMIN_PASSWORD=.*|SNAT_ADMIN_PASSWORD=$(openssl rand -base64 24)|" .env
fi

if ! grep -q "SNAT_TOKEN_SECRET=." .env; then
  sed -i "s|^SNAT_TOKEN_SECRET=.*|SNAT_TOKEN_SECRET=$(openssl rand -hex 32)|" .env
fi

if ! grep -q "AGENT_TOKEN=." .env; then
  sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN=$(openssl rand -hex 32)|" .env
fi

docker compose up -d --build

echo
echo "启动完成"
echo "Web 面板：http://服务器IP:5000"
echo "账号：admin"
echo "密码请查看 .env 里的 SNAT_ADMIN_PASSWORD"
echo "Agent Token 请查看 .env 里的 AGENT_TOKEN"
```

运行：

```bash
chmod +x quickstart-docker.sh
./quickstart-docker.sh
```

---

## 更新

使用项目自带更新脚本：

```bash
sudo ./update.sh
```

更新脚本会自动备份 `/opt/snat-manager`，失败时会尝试回滚。

---

## 查看 Agent Token

如果忘记 Agent Token：

```bash
sudo ./show_token.sh
```

---

## 卸载

卸载 Web 管理端：

```bash
sudo ./uninstall_web.sh
```

卸载 Agent：

```bash
sudo ./uninstall_agent.sh
```

---

## 常用服务命令

查看 Web 状态：

```bash
systemctl status snat-web
```

查看 Agent 状态：

```bash
systemctl status snat-agent
```

查看 Web 日志：

```bash
journalctl -u snat-web -f
```

查看 Agent 日志：

```bash
journalctl -u snat-agent -f
```

重启 Web：

```bash
sudo systemctl restart snat-web
```

重启 Agent：

```bash
sudo systemctl restart snat-agent
```

---

## 安全建议

1. **公网部署不要裸露 Agent 端口**

   * 推荐使用 WireGuard
   * 或者用防火墙只允许 Web 面板服务器访问 Agent 端口

2. **Web 面板公网访问必须上 HTTPS**

   * 推荐 Caddy 或 Nginx 反代
   * 示例配置在 `reverse-proxy/`

3. **首次登录后立即修改管理员密码**

4. **定期备份**

   * 面板内置备份和快照功能
   * 也可以备份 `/opt/snat-manager/web/snat_manager.db`

5. **升级完成后可关闭旧 Bearer 兼容模式**

编辑 Agent 服务：

```ini
Environment="AGENT_ALLOW_BEARER=0"
```

然后重启：

```bash
sudo systemctl daemon-reload
sudo systemctl restart snat-agent
```

---

## 项目结构

```text
.
├── web/                    # Web 管理端
├── agent/                  # Agent 客户端
├── reverse-proxy/          # Caddy / Nginx 反代示例
├── install.sh              # 一键安装脚本
├── update.sh               # 一键更新脚本
├── wireguard_setup.sh      # WireGuard 一键配置脚本
├── uninstall_web.sh        # 卸载 Web
├── uninstall_agent.sh      # 卸载 Agent
├── docker-compose.yml      # Docker Compose 部署
├── Dockerfile.web
├── Dockerfile.agent
└── requirements.txt
```

---

## 简单使用流程

```text
1. 在管理机安装 Web
2. 在转发机安装 Agent
3. 把 Agent 信息添加到 Web 面板
4. 在 Web 面板添加转发规则
5. 访问 Agent服务器IP:本地端口，流量会转发到目标IP:目标端口
```
