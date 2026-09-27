# 从你刚门里爬出的蛆（miao-x）

参照妙妙屋X 架构复刻的 **Xray 服务器管理与订阅分发系统**：单 Go 二进制双模式（master / agent），WebSocket 反向连接 + 端到端加密通道 + 反向 RPC。

> 完整的源码分析见 `../mmwx-analysis/ANALYSIS.md`。

## 架构

```
┌────────────────────────────────┐
│      miaowu master (:12889)    │
│  订阅分发 / 节点池 / 用户管理    │
│  服务器管理 / 流量归集 / 面板    │
└──────────────┬─────────────────┘
               │ WebSocket 反向连接（agent 主动连入，NAT 友好）
               │ securechan: Ed25519 验签 + X25519 ECDH + AES-256-GCM + 防重放
               │ rpc_call: 主控把 HTTP 调用转发到 agent 本地 mux（业务代码一份两用）
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐
│ agent  │ │ agent  │ │ agent  │   每台子服务器:
│ (xray) │ │ (xray) │ │ (xray) │   配置下发/重启、流量&速度&系统指标上报
└────────┘ └────────┘ └────────┘
```

## 快速开始

### 1. 编译

本机 Windows：双击 `build.bat`（产出 `release/miaowu-linux-amd64`、`release/miaowu-linux-arm64`、`miaowu.exe`）。
Linux/Mac：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o miaowu ./cmd/miaowu
```

### 2. 发布二进制（一键部署的前置条件）

把 `release/` 里的 Linux 二进制 + `install.sh` 放到 VPS 能下载到的地方，任选其一：

- **GitHub Release**（推荐）：建仓库 → `gh release create v0.1.0 release/* install.sh`
- **任意静态托管**：对象存储（R2/OSS/COS）、或另一台有 nginx 的服务器，保持 `install.sh` 与二进制同目录结构即可

### 3. 部署主控（VPS-A）

```bash
# GitHub Release 场景（脚本自动回退 ghproxy 镜像）
curl -fsSL https://raw.githubusercontent.com/<你>/miao-x/main/install.sh -o install.sh
sudo bash install.sh master

# 自建托管场景：MMW_BASE_URL 指向二进制所在目录
sudo MMW_BASE_URL="https://dl.example.com/miao-x" bash install.sh master
```

完成后访问 `http://VPS-A的IP:12889` 初始化管理员。公钥查看：`journalctl -u miaowu | grep 公钥`。

### 4. 接入子节点（VPS-B）

面板「服务器」→ 添加服务器 → 弹窗里的一键命令（或在 VPS-B 上执行）：

```bash
sudo MMW_BASE_URL="https://dl.example.com/miao-x" bash install.sh agent \
     http://VPS-A的IP:12889 <面板生成的token> <主控公钥>
```

脚本自动安装 xray 内核 → 注册 systemd → 回连主控。agent 上线后面板变绿。**「生成节点」**：选协议（VLESS+Reality / VLESS+WS / Trojan / Shadowsocks / Hysteria2）→ 填名称/SNI/端口（凭据自动生成，Reality 密钥对自动创建）→ 保存即通过加密通道下发到 agent 并自动重启 xray；入站同时**自动同步进订阅节点池**（标签=服务器名），也可用「仅重新同步」按钮手动重建。节点池页可看每个同步节点的本月流量（来自 agent 入站计数器）。

配置按 revision 单调下发（agent 拒绝乱序旧配置）；Xray 的 stats/api 保底字段（含 per-user/per-inbound 计数器开关）由 agent 自动合并。

**完全卸载**（任一台上都可用）：

```bash
sudo bash install.sh uninstall          # 交互式：停服务→清进程→(可选)备份数据→删目录→(可选)卸xray
sudo bash install.sh uninstall -y       # 静默模式：不做询问，彻底清除全部（含数据与 xray 内核）
sudo bash install.sh uninstall agent -y # 只卸子节点
```

### 5. Docker 方式（可选）

```bash
docker compose up -d --build
```

### 本地试跑（Windows/Linux 均可）

```bash
miaowu -c config.yaml   # mode: master，浏览器打开 http://127.0.0.1:12889
```

### 6. 面板域名与 SSL

三种方式任选：

**① 网页设置页（推荐）**：面板「⚙️ 设置」→ 填**域名 + 邮箱**保存 → 重启服务。内置 ACME 向 Let's Encrypt 自动申请证书（HTTP-01，需 80 端口可达），**签发、续期全自动**，证书存 `data/certs/`。

**② 安装时指定**：

```bash
sudo MMW_DOMAIN=panel.example.com MMW_EMAIL=me@example.com bash install.sh master
```

**③ 自备证书**：设置页填证书/私钥路径（如 acme.sh、宝塔签发的 fullchain.pem/privkey.pem），或直接写 config.yaml：

```yaml
# 二选一
domain: "panel.example.com"   # ACME 模式
email: "me@example.com"
# 或
cert_file: "/etc/ssl/fullchain.pem"   # 手动证书模式
key_file: "/etc/ssl/privkey.pem"
```

启用后面板、API、订阅链接全部走 https（订阅链接自动跟随协议）；证书到期时间在设置页可见，剩 21 天内标红提醒。也可继续用 nginx/Caddy 反代 127.0.0.1:12889（此时面板内不用配证书）。

### 7. 订阅分发

- 用户面板「我的订阅」复制链接：`http://master:12889/api/subscribe/<token>`
- 同一链接按 UA 自动适配：**Clash/Mihomo → YAML，sing-box → JSON，V2RayN/NG → Base64 URI**
- 响应头注入 `subscription-userinfo`（月流量）与 `profile-update-interval: 24`
- token 无效时返回带"⚠️ 订阅已过期"提示的合法 YAML（与妙妙屋同款设计）

## 与妙妙屋X 的功能对照

| 能力 | 妙妙屋X | miao-x |
|---|---|---|
| 单二进制 master/agent 双模式 | ✅ | ✅ |
| WS 反向连接 + 加密通道（验签/ECDH/GCM/防重放） | ✅ | ✅（同构实现） |
| 反向 RPC（HTTP 语义转发，流式帧） | ✅ | ✅（非流式） |
| Xray 配置下发/自动重启/stats 保底合并 | ✅ | ✅ |
| 流量/速度/系统指标上报归集 | ✅ | ✅ |
| 节点导入（ss/vmess/vless/trojan/hy2/tuic/anytls） | ✅ | ✅ |
| 订阅 UA 适配 | 10 种客户端 | 3 大格式（clash/singbox/v2ray） |
| 用户/订阅绑定、月配额、订阅链接 | ✅ | ✅ |
| ACME 证书 / 内嵌 nginx / guard 签名守护 / 探针页 / 套餐拼车 / Premium | ✅ | ❌（roadmap） |

## API 速查

```
POST /api/setup/init          首次初始化管理员
POST /api/login               登录 → Bearer token
GET  /api/admin/servers       服务器列表(+状态)
POST /api/admin/servers       添加服务器（生成 token）
PUT  /api/admin/servers/{id}/xray-config   下发 Xray 配置
POST /api/admin/servers/{id}/rpc           反向 RPC 代理
POST /api/admin/servers/{id}/token-reset   轮换 token
GET  /api/admin/nodes         节点池
POST /api/admin/nodes         批量导入节点 URI
GET/POST /api/admin/users     用户管理
GET  /api/user/profile        用户信息+订阅链接
GET  /api/subscribe/{token}   订阅分发（UA 适配）
WS   /api/agent/ws            agent 接入点（Bearer server-token）
```

## 声明

仅供学习交流，请遵守当地法律法规。
