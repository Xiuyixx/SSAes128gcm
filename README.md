# Shadowsocks 一键安装（默认：aes-128-gcm）

一个尽量“克制”的 **curl | bash** 一键安装脚本，用于部署 **Shadowsocks（shadowsocks-rust）** 服务端。

- 默认加密：`aes-128-gcm`
- 默认端口：`8388`
- 默认从 GitHub Releases 安装（默认取最新版本）
- 使用 systemd 管理，并以最小权限系统用户运行（带基础 hardening）

> 如果你更在意可复现/安全性，建议使用 `--version vX.Y.Z` 固定版本，而不是永远安装 latest。

## 支持系统

- Debian / Ubuntu（使用 `apt`）
- 架构：`x86_64`、`aarch64`
- 初始化：`systemd`

## 快速开始

### 安装最新版本（默认）

推荐写法：

```bash
curl -fsSL "https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh?nocache=$(date +%s)" | sudo bash
```

兼容写法：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash
```

### 自定义端口与密码安装

推荐写法：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash -s -- --port 12345 --password 'YOUR_STRONG_PASSWORD'
```

如需只走 TCP（不启用 UDP）：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash -s -- --port 12345 --password 'YOUR_STRONG_PASSWORD' --mode tcp_only
```

### 使用环境变量替代参数

```bash
sudo SS_PORT=12345 SS_PASSWORD='YOUR_STRONG_PASSWORD' bash <(curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh)
```

### 固定指定版本（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash -s -- --version v1.22.0 --port 12345 --password 'YOUR_STRONG_PASSWORD'
```

## 参数说明

查看帮助：

```bash
bash install.sh --help
```

常用参数：

- `--port` / `SS_PORT`
- `--password` / `SS_PASSWORD`
- `--method` / `SS_METHOD`（默认 `aes-128-gcm`）
- `--version` / `SS_VERSION`（`latest` 或 `v1.22.0` 这种 tag）
- `--mode`：传输模式（`tcp_and_udp` / `tcp_only`）
- `--no-udp`：禁用 UDP（等价于 `--mode tcp_only`）

## 其它加密方法（含 SS2022）

本脚本安装的是 `shadowsocks-rust`（`ssserver`），它支持多种加密方法。你可以通过 `--method` 切换。

SS2022 常用示例（请确保你的客户端也支持对应 method）：

- `2022-blake3-aes-128-gcm`（建议密码用 16 字节 key 的 base64）：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash -s -- --port 12345 --method 2022-blake3-aes-128-gcm --password "$(openssl rand -base64 16)"
```

- `2022-blake3-aes-256-gcm`（建议密码用 32 字节 key 的 base64）：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash -s -- --port 12345 --method 2022-blake3-aes-256-gcm --password "$(openssl rand -base64 32)"
```

## 安装后要做什么

### 1) 放行防火墙 / 安全组

你必须在 VPS / 云厂商安全组里放行你选择的端口。

`ufw` 示例：

```bash
sudo ufw allow 12345/tcp
sudo ufw allow 12345/udp
```

### 2) 查看服务状态

```bash
systemctl status shadowsocks-server.service --no-pager
journalctl -u shadowsocks-server.service -e --no-pager
```

### 3) 客户端配置

安装脚本会输出类似下面的 URI：

```
ss://aes-128-gcm:YOUR_PASSWORD@YOUR_SERVER_IP:12345
```

如果你的客户端不支持 URI 导入，就按下面字段手动填写：

- Server：`YOUR_SERVER_IP`
- Port：`12345`
- Method：`aes-128-gcm`
- Password：`YOUR_PASSWORD`
- Mode：TCP + UDP（除非使用了 `--no-udp`）

## 脚本会改动哪些内容

- 安装依赖：`ca-certificates curl jq openssl xz-utils`
- 从 `shadowsocks/shadowsocks-rust` 的 GitHub Releases 下载 `ssserver`
- 安装二进制到：`/usr/local/bin/ssserver`（可用 `--bin-dir` 覆盖）
- 写入配置到：`/etc/shadowsocks/config.json`（可用 `--config-dir` 覆盖）
- 创建系统用户：`shadowsocks`（可用 `--user` 覆盖）
- 写入 systemd unit：`/etc/systemd/system/shadowsocks-server.service`

## 升级 / 重跑

重复运行安装脚本是安全的：它会覆盖二进制、配置和 unit，然后重启服务。

- 升级到最新版本：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash
```

- 升级/固定到指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/install.sh | sudo bash -s -- --version v1.22.0
```

## 安全说明（建议阅读）

- `curl | bash` 天生有风险：你是在以 root 身份执行远程代码。更稳妥的做法是先下载 `install.sh` 审计后再运行。
- 更安全/可复现的方式是用 `--version vX.Y.Z` 固定版本。
- 安装脚本会在上游 release 提供 `.sha256` 文件时进行**尽力而为的校验**；否则会警告并继续。
- 建议用防火墙做 allowlist（只允许你的固定 IP 连接）。

## 卸载

推荐直接使用本仓库的卸载脚本（会停止服务并清理 unit/配置/二进制/用户）：

```bash
curl -fsSL "https://raw.githubusercontent.com/Xiuyixx/Shadowsocks/main/uninstall.sh?nocache=$(date +%s)" | sudo bash
```

如需手动卸载，可参考 `uninstall.sh`。

## License

本仓库已包含 `LICENSE`（MIT）。
