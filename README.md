# SniRoute

服务商**出口分流与访问限制探测工具**。从被测机器出发，用不同的 SNI 连接同一个观测端，再访问真实网站，最终在一份报告里回答：

1. 某个域名是否触发了**不同的出口**？
2. 观测到的**出口 IP**（及 ASN）是什么？
3. **真实网站**能否访问？失败发生在 DNS / TCP / TLS / HTTP 哪一层？
4. 出现异常时，有多大把握认为与被测网络的**分流或阻断**有关？

Go 单二进制（`CGO_ENABLED=0` 静态编译）· SSH 终端编号菜单 · SQLite 存储。没有 Web 面板，没有浏览器界面。
支持 Linux / macOS 的 amd64 与 arm64；在 Ubuntu、Debian、RHEL、CentOS、Alpine 上均可运行。

## 目录

- [工作方式](#工作方式)
- [快速开始](#快速开始)
- [日常使用](#日常使用)
- [读懂报告](#读懂报告)
- [命令参考](#命令参考)
- [域名库](#域名库)
- [隐私](#隐私)
- [构建与发布](#构建与发布)
- [文档](#文档)

## 工作方式

| 角色 | 部署位置 | 职责 |
| --- | --- | --- |
| **观测端**（服务端） | 独立于被测网络的服务器 | 接收探测、记录出口 IP、查询 ASN、执行参考测试 |
| **被测端**（客户端） | 要测的那台 VPS / 机器 | 发起探测、记录本地失败阶段、写出报告 |

> 要测某台 VPS 的出口，客户端必须运行在**那台 VPS 上**；在本地机器上运行，测到的是本地网络的出口。

观测端监听两个端口：

| 端口 | 默认 | 用途 |
| --- | --- | --- |
| 探测入口 | TCP/TLS `:443` | 接受带不同 SNI 的受控探测，直接暴露，不经 CDN 或改写来源地址的反代 |
| 控制接口 | HTTPS `:8443` | 仅供程序通信（注册、任务、事件、报告），不提供网页 |

一次测试的过程：

1. **基线**：用中性 SNI 探测同一个观测端 IP，在开始、中间、结束各穿插一次。
2. **主探测**：固定观测端 IP，逐个切换域名的 SNI，每域名默认 3 次独立连接，顺序打乱。
3. **真实访问**：用系统 DNS 依次检查 DNS → TCP → TLS → HTTP，分层记录失败位置。
4. **参考测试**：对异常域名，由观测端从自己的网络再测一次作对照（仅限公网目标）。
5. **判定与报告**：合并两端证据，按规则输出五个维度的结论，附依据与限制。

## 快速开始

四步：安装观测端 → 生成注册链接 → 被测机器运行客户端 → 查看报告。

### 1. 安装观测端

在一台独立于被测网络的服务器上：

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-server.sh)"
```

脚本会交互询问要做什么：

| 选项 | 说明 |
| --- | --- |
| 临时运行 | 程序放临时目录，退出时停止服务并清理；配置与数据保留在 `~/.sniroute`，下次接着用 |
| 永久安装（Linux） | 安装后输入 `sniroute` 启动服务并打开管理菜单；开机自启、崩溃自动重启；`sniroute status` / `sniroute logs` 查看状态与日志 |
| 查看状态 / 卸载 | 卸载默认保留配置与数据 |

永久安装按系统选择守护方式：systemd（Ubuntu / Debian / RHEL / CentOS）→ OpenRC（Alpine）→ pid 文件后台模式（兜底，无开机自启）。当前不是 root 时，脚本会询问是否下载自身并用 `sudo` 重新运行。

首次进入菜单只有一项「**初始化服务（推荐配置）**」，确认一次即可：自动生成自签证书与管理密钥，探测入口 `:443`，控制接口 `:8443`（`:443` 需要 root，可在自定义配置中改端口）。之后服务在后台运行，退出菜单或断开 SSH 都不影响。

### 2. 生成注册链接

在观测端菜单选择 **1 生成注册链接**，确认对外地址后得到一行：

```
https://observer.example.com:8443/join#reg_xxxx.<证书指纹>.<节点名>
```

- 凭证与证书指纹放在 URL fragment 中，浏览器、反向代理和访问日志都收不到。
- 凭证**一次性**，默认 7 天有效；菜单 **2 查看 / 管理注册链接** 可重新显示或撤销未使用的链接。

### 3. 被测机器运行客户端

在要测的机器上：

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-client.sh)"
```

第一次运行粘贴第 2 步的链接。之后进入主菜单：

```
1 开始测试          ← 按上次选择直接跑
2 选择要测试的域名   ← 从内置域名库挑
3 历史报告
4 设置
0 退出
```

客户端始终**临时运行**：程序副本在退出时清理，报告保留在当前目录，节点身份与待补交队列保留在 `~/.sniroute`，下次不需要重新注册。

### 4. 查看报告

测试结束后，当前目录会自动写入 `<任务>-report.md`，同时屏幕上显示总览与域名表。

## 日常使用

- **选域名**：`2 选择要测试的域名` 支持 `q` 快速清单、`f` 完整清单与各分类，编号可组合（如 `1 3 q`），回车沿用上次选择。记住的是分类名而不是编号，域名库更新后仍然有效。
- **开始测试**：先显示一次配置摘要（测试内容、观测端、规模、是否做真实访问、报告位置），确认后执行。
- **中断**：第一次 `Ctrl+C` 是正常中断——停止新测试、取消在途连接、上报已有结果并取回部分报告；第二次强制退出。未执行的项目**不算阻断**。
- **断线恢复**：未上传的事件存在本地 SQLite，下次进入时按 `attempt_id + event_id` 幂等补交。
- **历史报告**：查看完整报告、域名综合、按出口 IP 分组、只看访问异常、单域名证据；导出 TXT / JSON / CSV / MD；刷新出口网络归属（新建 ASN 快照，不改写旧快照）。
- **设置**：服务商标签与环境说明、探测目标、测试强度（轮数 / 并发 / 超时）、真实访问与参考测试开关、报告目录、域名库位置、重新登记。

## 读懂报告

Markdown 报告共八节：总览（冻结的测试条件、覆盖与证据、结论摘要）· 出口分组 · 出口网络分组 · 域名综合结果 · 判断依据与限制 · 真实网站访问明细 · 原始证据 · 说明。

每个域名从五个**互不排斥**的维度给出结论：出口观察、受控探测状态、真实访问状态、干预判断、证据完整性。分流与访问异常可以同时存在。

解读时请记住这些边界：

- 工具**直接确认**的只有一件事：从某被测节点、某时间、用特定目标 IP / 端口 / SNI / 地址族 / TLS 配置发起连接时，观测端**实际看到的来源 IP**。
- **受控探测的出口 ≠ 真实网站看到的出口。** 报告中的「真实网站访问出口」始终写「未直接观测」，除非目标网站回传来源地址。
- 连接没有到达观测端、也没有可信回执时，出口记为**「未观测」**，而不是「无出口」。
- 「没发现出口变化」只表示本次没有观测到差异，**不等于确定没有分流**。
- 只有「认证回执」与「ClientHello 匹配」两种证据计入出口；「SNI 相同 + 时间接近」不作为归属依据。
- HTTP 401 / 403 / 429 / 451 是应用层响应，**不是**服务商封锁的证据；没有阻断页指纹库，因此不会输出「明确阻断响应」。
- 干预判断的**原因可信度上限为「中」**：单观测端、样本有限。
- 未执行、已取消、上报丢失的尝试**不计为网络失败**。

## 命令参考

交互菜单覆盖日常使用；以下命令用于脚本和定时任务。

| 命令 | 作用 |
| --- | --- |
| `sniroute` | 总菜单（选择 client / server） |
| `sniroute client` | 客户端菜单 |
| `sniroute client enroll -link '<整行>'` | 非交互注册（或设置 `$SNIROUTE_REG_LINK`） |
| `sniroute client probe` | 按记住的域名选择跑一次完整测试，并写 `.md` |
| `sniroute client probe -sni a.example -sni b.example -rounds 3` | 指定域名与轮数 |
| `sniroute client probe -no-web` | 跳过真实访问测试 |
| `sniroute client probe -export DIR` | 同时把 TXT / JSON / CSV 写入 `DIR` |
| `sniroute client reports list\|show ID\|export ID\|asn ID\|flush` | 历史任务、查看、导出、刷新 ASN、补交队列 |
| `sniroute reports …` | 等同 `client reports` |
| `sniroute server` | 观测端管理菜单 |
| `sniroute server run` | 前台运行服务（适合 systemd） |
| `sniroute server start\|stop\|restart\|status` | 后台服务控制（pid 文件） |
| `sniroute server reports [list\|show ID\|export ID\|asn ID]` | 读数据库，查看所有节点的报告 |
| `sniroute genkey` / `sniroute version` | 生成随机密钥 / 版本 |

`sniroute <命令> -h` 查看完整参数。

## 域名库

`domains/` 随仓库携带：`quick-test.txt`（231 项）、`full-test.txt`（1100 项）、`categories/*.txt`（按类别，附服务与标签）。一份精简副本编译进二进制，单个文件即可使用。

想修改清单：编辑 `domains/` 后放到二进制同目录，客户端优先读取磁盘版本；也可以在「设置 → 域名库位置」指定目录。结构与裁剪说明见 [domains/README.md](domains/README.md)。

## 隐私

默认的 RIPEstat 查询会把观测端看到的**公网出口 IP** 发送给 RIPEstat（私网地址永不外发）。不想外发时：

- 观测端菜单 **6 服务设置 → 4 出口网络（ASN）查询 → 3 关闭查询**；或
- 在 `server.yaml` 中设置 `asn_source: none`。

也可切换为 Team Cymru（DNS TXT 查询）。

## 构建与发布

从源码构建：

```sh
go build -o sniroute ./cmd/sniroute
./sniroute version
```

使用自己编译的二进制部署（离线或发布前）：

```sh
go build -o /tmp/sniroute ./cmd/sniroute
SR_BIN=/tmp/sniroute sh scripts/sniroute-server.sh
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh
```

二进制必须匹配运行机器的系统与架构。

**发布**：推送 `v*` 标签即由 GitHub Actions 自动完成——

```sh
git tag v0.1.0 && git push origin v0.1.0
```

工作流先跑 `go test -race ./...`，再为 linux / darwin × amd64 / arm64 交叉编译 `sniroute_{os}_{arch}` 四个二进制，附上 SHA256SUMS 并创建 GitHub Release。部署脚本不指定 `SR_BIN` 时自动获取最新 Release。

开发常用命令：

```sh
go build ./...
go vet ./...
go test -race ./...
```

## 文档

- [scripts/README.md](scripts/README.md)：部署脚本参数、安装位置与清理边界
- [AGENTS.md](AGENTS.md)：完整设计、判定规则与各阶段实现记录
- [domains/README.md](domains/README.md)：域名库结构与裁剪说明
