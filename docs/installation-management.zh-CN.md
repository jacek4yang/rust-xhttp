# 安装与长期管理

[English](installation-management.md) | 简体中文

`rust-xhttpctl` 是 Rust 编写的服务端管理器。它单独构建，因此安装依赖、交互和在线
更新代码不会进入网络服务端的数据热路径。

## 安装前提

- 官方托管包要求使用 systemd 的 x86_64 Linux；
- 官方 `x86-64-v3` 二进制要求 Haswell/Zen 或更新 CPU，旧 CPU 要从源码构建；
- 能通过 `sudo` 获得 root 权限，并安装了 `curl`、`tar`、`sha256sum`；
- 客户端能访问 TCP 443；
- 自动证书模式要求公共 DNS 已指向服务器，且 ACME CA 能访问 TCP 80。

ACME HTTP-01 不能和已有 Web 服务共同占用 80 端口。这种情况应使用手动证书，或让
已有反代终止 TLS。

## 引导程序与信任边界

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/jacek4yang/rust-xhttp/releases/latest/download/install.sh | sudo sh
```

Release 中的 `install.sh` 会写入固定标签，只下载同标签压缩包和校验文件。它强制
HTTPS、校验 SHA-256、只解压 `rust-xhttp` 与 `rust-xhttpctl`、拒绝符号链接，再通过
`/dev/tty` 启动 Rust 安装器。SHA-256 能发现传输损坏和资产错配，但不能替代对 GitHub
仓库和 Release 工作流的信任；供应链要求更高时，应先审查脚本和 Release 来源。

持久变更全部由 Rust 向导执行：创建系统用户、原子复制文件、设置受限权限、校验
配置与资源、安装加固 unit、reload systemd，并确认设置开机启动后的服务为 active。

## 向导选项

### 自动证书

输入公共域名和联系邮箱。账户与证书保存在 `/var/lib/rust-xhttp/acme`，服务端后台
续期并原子启用新证书。

### 已有证书

输入完整证书链和私钥的来源路径。安装器复制到 `/etc/rust-xhttp/tls`；由于
`ProtectHome=true`，服务不会直接读取 `/root` 或普通用户 home。

### TLS 反代或 CDN

由 Cloudflare、nginx 或其他可信本机组件终止 TLS 时选择明文模式，默认监听
`127.0.0.1:8080`。必须监听非 loopback 地址时，应另行认证和限制源站防火墙。

### 回落网站

默认生成可配置语言和身份信息的博客。选择 `dist` 时，普通文件会复制到
`/var/lib/rust-xhttp/site`，符号链接和特殊文件会被拒绝。服务端启动时预加载，并向
未认证/非 XHTTP 请求展示；目录必须包含配置的 `index.html`。

## 服务安全模型

标准 unit 以不可登录的 `rust-xhttp` 用户运行，通过 `ExecStartPre` 预检配置，仅授予
`CAP_NET_BIND_SERVICE`，系统和配置只读，仅允许写 `/var/lib/rust-xhttp`，隐藏 home
和设备、限制地址族、禁止 core dump，并设置 FD/内存限制。自定义限制请用 drop-in，
这样 `repair` 可以安全恢复标准 unit：

```bash
sudo systemctl edit rust-xhttp
sudo systemctl daemon-reload
sudo systemctl restart rust-xhttp
```

## 配置生命周期

`sudo rust-xhttpctl edit` 使用 `$VISUAL`、`$EDITOR` 或 `vi` 编辑私有副本，校验语法和
资源，在 `/etc/rust-xhttp/backups` 创建带时间戳备份，再原子替换线上文件。重启失败
时会恢复备份并尝试拉起旧服务。

```bash
rust-xhttp check /etc/rust-xhttp/config.json
```

相对资源路径以 `/var/lib/rust-xhttp` 为基准；生产环境使用绝对路径更清晰。

## 升级与回滚

```bash
sudo rust-xhttpctl update          # 最新 Release
sudo rust-xhttpctl update v0.2.0   # 指定 Release
sudo rust-xhttpctl rollback        # 上一套二进制
```

管理器只允许 HTTPS redirect，校验标签、压缩包路径和 Release SHA-256，检查两个
二进制身份，并让下载的新服务端预检当前配置。随后把当前服务端和管理器作为一套保存，
原子替换、恢复标准 unit 并重启。启用失败会恢复两个旧二进制。系统保留一代回滚；
成功回滚会交换两套文件，因此可以反向切换。

升级不会覆盖配置、证书、ACME 状态和回落网站。

## 日常运维与恢复

```bash
rust-xhttpctl status
rust-xhttpctl logs
rust-xhttpctl doctor
sudo rust-xhttpctl service restart
sudo rust-xhttpctl repair
```

`doctor` 是只读检查，会报告文件缺失、配置/资源错误和 systemd 启用/运行状态。
`repair` 在确认二进制和配置可用后重建用户、目录、属主与 unit，不会重新生成配置。

ACME 失败时应从外部检查 DNS、80 端口公网可达性、系统时间和 challenge 端口占用。
重启失败时先运行 `rust-xhttp check` 并查看 `journalctl -u rust-xhttp`。

## 卸载与数据保留

`sudo rust-xhttpctl uninstall` 禁用 unit 并删除两个二进制，但保留配置、证书、网站和
状态，以供重装复用。`--purge` 还会删除这些目录、root-only 回滚数据、ACME 私密
材料和系统用户。彻底删除不可恢复，应先备份。

## 非交互/镜像安装

```bash
sudo rust-xhttpctl install \
  --server-binary ./rust-xhttp --ctl-binary ./rust-xhttpctl \
  --config ./config.json --yes

rust-xhttpctl install --root /tmp/rust-xhttp-image --no-start \
  --server-binary ./rust-xhttp --ctl-binary ./rust-xhttpctl \
  --config ./config.acme.example.json --yes
```

替代 root 只影响文件实际安装位置；JSON 和 unit 内仍保留生产绝对路径。
