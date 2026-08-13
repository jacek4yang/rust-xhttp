# 配置与部署教程

[English](configuration.md) · [简体中文](configuration.zh-CN.md)

`rust-xhttp` 使用接近 Xray Core 服务端的严格 JSON 配置。目前刻意只支持一个
VLESS over XHTTP 入站；未知字段、不支持的协议、冲突的证书模式和为零的关键资源
上限都会阻止启动，不会出现“写了配置但其实未生效”的情况。

## 1. 安装并创建身份

```bash
git clone https://github.com/jacek4yang/rust-xhttp.git
cd rust-xhttp
cargo build --release --locked
uuidgen
```

从源码构建需要 Rust 1.88 或更新版本。服务端 `settings.clients` 和官方 Xray 客户端
必须使用同一个 UUID。

启动前先检查 JSON 和本地资源：

```bash
./target/release/rust-xhttp check /etc/rust-xhttp/config.json
```

自动 ACME 模式只检查配置，不会联系 CA；手动 TLS 模式还会解析证书和私钥；目录
站点模式会完整预加载并校验 `dist`。

## 2. 选择证书管理方式

### 内置 ACME HTTP-01 自动 HTTPS

从 [`config.acme.example.json`](../config.acme.example.json) 开始，替换域名、邮箱、
UUID、XHTTP 路径和 Host。核心配置为：

```json
{
  "streamSettings": {
    "network": "xhttp",
    "security": "tls",
    "tlsSettings": {
      "alpn": ["h2", "http/1.1"],
      "acme": {
        "domains": ["xhttp.example.com"],
        "email": "admin@example.com",
        "directoryUrl": "https://acme-v02.api.letsencrypt.org/directory",
        "challengeListen": "0.0.0.0:80",
        "cacheDir": "/var/lib/rust-xhttp/acme",
        "renewBeforeDays": 30,
        "renewCheckHours": 12,
        "acceptTerms": true
      }
    },
    "xhttpSettings": {
      "path": "/change-this-path/",
      "host": "xhttp.example.com"
    }
  }
}
```

使用条件：

- `domains` 中所有域名必须已解析到本机；
- 公网 TCP 80 必须能到达 `challengeListen`；HTTP-01 不支持通配符证书；
- 进程要有 80/443 端口绑定权限和 `cacheDir` 写权限。仓库提供的 systemd unit
  会授予 `CAP_NET_BIND_SERVICE`，并以 `0700` 创建 `/var/lib/rust-xhttp`；
- 必须显式设置 `acceptTerms: true`，否则配置校验失败。

80 端口只在 `/.well-known/acme-challenge/` 返回 ACME token，其余 HTTP 请求永久
重定向至 HTTPS。账户凭据和私钥以受限权限原子写入。没有可用证书时，程序先完成
签发，再开放 443。后台续期失败时继续使用当前有效证书并做有上限的指数退避；
续期成功后无锁热加载，仅新 TLS 握手使用新证书，既有连接不会断开。

建议先用 Let's Encrypt staging 验证 DNS 和防火墙：

```json
"directoryUrl": "https://acme-staging-v02.api.letsencrypt.org/directory",
"cacheDir": "/var/lib/rust-xhttp/acme-staging"
```

staging 必须使用独立缓存目录，其证书不受浏览器信任。

私有或测试 ACME 服务还可以设置 `caCertificateFile`，指定仅供 ACME HTTPS 客户端
信任的 PEM 根证书；Let's Encrypt 不要设置此字段。

### 用户自己管理证书

从 [`config.example.json`](../config.example.json) 开始，配置恰好一个证书并省略
`acme`：

```json
"tlsSettings": {
  "alpn": ["h2", "http/1.1"],
  "certificates": [
    {
      "certificateFile": "/etc/rust-xhttp/tls/fullchain.pem",
      "keyFile": "/etc/rust-xhttp/tls/privkey.pem"
    }
  ]
}
```

证书文件应先放叶证书，再放中间证书，格式为 PEM。客户端提供兼容的 TLS 1.3
签名算法时，支持 RSA、ECDSA P-256/P-384 与 Ed25519 私钥。手动替换文件后重启
服务。

### nginx、Tunnel 或可信边缘终止 TLS

只绑定环回地址，设置 `security: "none"`，并删除 `tlsSettings`：

```json
{
  "listen": "127.0.0.1",
  "port": 8080,
  "streamSettings": {
    "network": "xhttp",
    "security": "none",
    "xhttpSettings": {
      "path": "/change-this-path/",
      "host": "xhttp.example.com"
    }
  }
}
```

绝不能把明文监听暴露到不可信网络。反向代理必须保留原始 Host，并关闭长连接
XHTTP 下载响应的代理缓冲。

## 3. 完整服务端配置

以下自动证书配置替换标记值即可使用：

```json
{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "tag": "vless-xhttp-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "REPLACE-WITH-UUID",
            "email": "primary-device",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2", "http/1.1"],
          "acme": {
            "domains": ["xhttp.example.com"],
            "email": "admin@example.com",
            "challengeListen": "0.0.0.0:80",
            "cacheDir": "/var/lib/rust-xhttp/acme",
            "renewBeforeDays": 30,
            "renewCheckHours": 12,
            "acceptTerms": true
          }
        },
        "xhttpSettings": {
          "path": "/REPLACE-WITH-RANDOM-PATH/",
          "host": "xhttp.example.com",
          "scMaxEachPostBytes": 1000000,
          "scMaxBufferedPosts": 30,
          "sessionGraceSeconds": 30,
          "noSSEHeader": false,
          "serverMaxHeaderBytes": 8192,
          "xPaddingBytes": "100-1000",
          "uplinkDataPlacement": "body",
          "uplinkDataKey": ""
        }
      }
    }
  ],
  "server": {
    "workers": 0,
    "tcpNodelay": true,
    "reusePort": true,
    "backlog": 4096,
    "tcpKeepaliveSeconds": 300,
    "gracefulShutdownSeconds": 30,
    "limits": {
      "maxSessions": 65536,
      "maxPendingPacketsPerSession": 30,
      "maxPendingBytesPerSession": 16777216,
      "globalBufferBytes": 1073741824,
      "maxConcurrentTargetConns": 100000,
      "handshakeTimeoutSeconds": 10,
      "targetConnectSeconds": 10,
      "udpAssociationIdleSeconds": 60
    }
  },
  "fallback": {
    "mode": "builtin",
    "site": {
      "seed": "xhttp.example.com",
      "title": "",
      "author": "",
      "description": "",
      "language": "zh-CN"
    }
  }
}
```

启动：

```bash
sudo install -d -m 700 /var/lib/rust-xhttp/acme
sudo ./target/release/rust-xhttp /etc/rust-xhttp/config.json
```

## 4. 官方 Xray Core 客户端

项目特意沿用 Xray 熟悉的 VLESS/XHTTP 字段。匹配的官方客户端可以这样写：

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "settings": { "auth": "noauth", "udp": true }
    }
  ],
  "outbounds": [
    {
      "tag": "rust-xhttp",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "xhttp.example.com",
            "port": 443,
            "users": [
              {
                "id": "REPLACE-WITH-THE-SAME-UUID",
                "encryption": "none",
                "flow": ""
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "xhttp.example.com",
          "alpn": ["h2"]
        },
        "xhttpSettings": {
          "path": "/REPLACE-WITH-RANDOM-PATH/",
          "host": "xhttp.example.com",
          "mode": "packet-up",
          "xPaddingBytes": "100-1000",
          "scMaxEachPostBytes": 1000000,
          "scMaxBufferedPosts": 30,
          "uplinkDataPlacement": "body"
        }
      }
    }
  ]
}
```

服务端支持 `body`、`header`、`cookie` 和 `auto` 四种上行承载。非 body 模式必须
在两端设置相同且非空的 `uplinkDataKey`；header 分块名为 `KEY-0`、`KEY-1`，
cookie 分块名为 `KEY_0`、`KEY_1`。

启用 VLESS Encryption 时运行 `xray vlessenc`，把输出的 `decryption` 放入服务端
`settings.decryption`，配对的 `encryption` 放入客户端用户。Vision 则在两端把
`flow` 都设为 `xtls-rprx-vision`。

## 5. 正常网页与 `dist` 目录

没有同时满足 XHTTP path、Host 和 padding 条件的流量进入 fallback 网站。
`/healthz` 与 `/readyz` 是保留的运维端点。

### 自动生成的默认博客

默认 `builtin` 模式在内存中提供美观、响应式的博客。`seed` 会稳定地选择若干套
站名、作者、配色和文章之一，因此重启不会随机变化。任意字段非空即可覆盖生成值：

```json
"fallback": {
  "mode": "builtin",
  "site": {
    "seed": "my-stable-seed",
    "title": "日常手记",
    "author": "林舟",
    "description": "关于地方、器物与普通日子的随笔。",
    "language": "zh-CN"
  }
}
```

`language: "zh-CN"` 使用内置中文版，`en` 使用英文版；元数据留空时自动生成。

### 用户自定义目录

```json
"fallback": {
  "mode": "directory",
  "dist": "/srv/www/example.com/dist",
  "index": "index.html",
  "notFound": "404.html",
  "maxFileBytes": 8388608,
  "maxTotalBytes": 134217728
}
```

程序启动时把所有普通文件读入不可变内存，预先计算 MIME、ETag 和目录首页别名。
请求热路径没有磁盘 I/O，支持 `If-None-Match` 返回 `304 Not Modified`。符号链接
不会被跟随，而是直接拒绝；缺少首页、文件不可读、单文件过大或总量超限都会阻止
启动。修改 `dist` 后需要重启。

`maxTotalBytes` 会与协议 buffer 同时占用内存，应小于服务内存限制。仓库提供的
systemd unit 已为默认 1 GiB 协议 buffer、128 MiB 站点和运行时开销保留空间。

### 认证边界

普通浏览器请求和格式错误的 HTTP/XHTTP 探测会进入网站。真正的 VLESS 认证位于
首个 XHTTP session payload 内部，此时 HTTP upload 已经接受；UUID 或加密密钥错误
会以同一形态关闭 session。若强行改写成网页响应，会破坏 XHTTP framing，并产生
认证状态旁路，因此项目不会这样做。这是刻意的安全边界。

## 6. 字段参考

| JSON 路径 | 默认值 | 作用 |
|---|---:|---|
| `log.loglevel` | `info` | `tracing` 过滤器，可用 `warn`、`info` 或完整 EnvFilter。 |
| `inbounds` | 必填 | 当前恰好支持一个入站。 |
| `inbounds[].listen` | `0.0.0.0` | 数字监听 IP。 |
| `inbounds[].port` | 必填 | 非零 TCP 端口。 |
| `inbounds[].protocol` | 必填 | 必须为 `vless`。 |
| `settings.clients` | 必填 | 非空 UUID 账户列表。 |
| `settings.decryption` | 空 | `none` 或 VLESS Encryption 服务端值。 |
| `streamSettings.network` | 必填 | 必须为 `xhttp`。 |
| `streamSettings.security` | `none` | `tls` 或 `none`。 |
| `xhttpSettings.path` | 必填 | 自动补齐首尾 `/`。 |
| `xhttpSettings.host` | 空 | 可选 Host 限制，匹配时忽略端口。 |
| `scMaxEachPostBytes` | `1000000` | 单个 packet-up 解码后最大字节数。 |
| `scMaxBufferedPosts` | `30` | XHTTP 乱序 packet 窗口上限。 |
| `sessionGraceSeconds` | `30` | 一直没有 download GET 的 session 生命周期。 |
| `noSSEHeader` | `false` | 不给下载响应发送 `text/event-stream`。 |
| `serverMaxHeaderBytes` | `8192` | request-target 与 header 总字节上限。 |
| `xPaddingBytes` | `100-1000` | padding 范围；单个整数表示固定长度。 |
| `uplinkDataPlacement` | `body` | `body`、`header`、`cookie` 或 `auto`。 |
| `uplinkDataKey` | 空 | 所有非 body 模式必填。 |
| `server.workers` | `0` | Tokio worker 数，0 为可用 CPU 并行度。 |
| `server.tcpNodelay` | `true` | 客户端和目标 TCP 禁用 Nagle。 |
| `server.reusePort` | `true` | Linux `SO_REUSEPORT`。 |
| `server.backlog` | `4096` | listen backlog。 |
| `server.tcpKeepaliveSeconds` | `300` | TCP keepalive 空闲秒数，0 为关闭。 |
| `server.gracefulShutdownSeconds` | `30` | SIGTERM 排空期限，范围 1–300 秒。 |
| `limits.maxSessions` | `65536` | 全局 XHTTP session 上限。 |
| `limits.maxPendingPacketsPerSession` | `30` | 单 session 乱序 packet 上限。 |
| `limits.maxPendingBytesPerSession` | `16777216` | 单 session 待处理字节上限。 |
| `limits.globalBufferBytes` | `1073741824` | 全局缓冲上传预算。 |
| `limits.maxConcurrentTargetConns` | `100000` | 出站 TCP/UDP 并发 semaphore。 |
| `limits.handshakeTimeoutSeconds` | `10` | TLS 和 VLESS/VLESS-Encryption 握手期限。 |
| `limits.targetConnectSeconds` | `10` | DNS 与目标 TCP 建连期限。 |
| `limits.udpAssociationIdleSeconds` | `60` | UDP/XUDP 空闲期限。 |

提高并发或内存上限之前，请先阅读[性能与可用性分析](performance-and-availability.zh-CN.md)。

## 7. 验证与排错

```bash
cargo test --locked --all-targets
bash scripts/m7_e2e.sh
bash scripts/m9_tls_h2_smoke.sh
bash scripts/m10_uplink_placements.sh
# 可选本地 CA 集成测试（需要 Pebble 源码目录）：
bash scripts/m13_acme_pebble.sh /path/to/pebble
```

- **unknown field** — 字段名区分大小写，例如 Xray 拼法是 `noSSEHeader`；
- **ACME 无法 bind** — 80 端口已被占用，或服务没有 `CAP_NET_BIND_SERVICE`；
- **ACME authorization 失败** — 检查公网 A/AAAA 和 80 端口，先用 staging，避免触发
  正式环境失败速率限制；
- **得到静态 404 而非 XHTTP** — path、Host 或 padding 不匹配；
- **HTTP 413** — body/header/cookie 所选数据层合并解码后超过
  `scMaxEachPostBytes`；
- **HTTP 431** — `serverMaxHeaderBytes` 过小，header 模式尤其需要注意；
- **上传后 session 关闭** — UUID、flow 或 VLESS Encryption 配对错误；认证失败刻意保持
  同一形态；
- **目标连接超时** — 检查 DNS、防火墙、`targetConnectSeconds` 和出站并发上限。
