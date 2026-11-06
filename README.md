# SniRoute

服务商**出口分流探测工具**。从被测机器出发，用不同的 SNI 连接同一个受控观测端，结合基线、多轮结果和 ASN 对照，在报告里回答：

1. 某个域名是否触发了**不同的出口**？
2. 观测到的**出口 IP**（及 ASN）是什么？
3. 出口差异是否稳定、是否与 SNI 相关，依据与限制是什么？

当前只做受控出口探测，不执行真实网站访问或参考测试。

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
| **观测端**（服务端） | 独立于被测网络的服务器 | 接收探测、记录出口 IP、查询出口网络归属、合并证据 |
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
3. **判定与报告**：合并两端证据，结合出口 IP、ASN 与失败阶段，按规则输出结论，附依据与限制。

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

脚本首次运行会自动生成推荐配置与管理密钥，服务启动时自动生成自签证书。临时模式会启动服务并打开菜单；永久安装后输入 `sniroute` 打开菜单。控制接口默认为 `:8443`；探测入口 root 默认为 `:443`，脚本以非 root 临时运行时默认为 `:8444`。客户端会自动发现探测端口。直接运行原始二进制 `./sniroute server` 且尚无配置时，才需要选择「初始化服务（推荐配置）」。

永久安装后，退出菜单或断开 SSH 不影响后台服务。临时模式退出时会停止本次服务；需要长期运行请选择永久安装。

### 2. 生成注册链接

在观测端菜单选择 **1 生成注册链接**，确认对外地址后得到一行：

```
https://observer.example.com:8443/join#<一次性凭证>.<证书指纹>.<Base64URL节点名>.<Base64URL服务商标签>
```

上面仅展示链接结构；实际使用请完整复制观测端生成的链接，不要使用示例地址或自行拼接字段。节点名与服务商标签为空时，末尾字段会省略。

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

客户端脚本始终**临时运行**：程序副本在退出时清理，报告保留在当前目录，节点身份与待补交队列保留在 `~/.sniroute`。观测端会在客户端离线满 15 分钟后清理关联数据并使旧节点密钥失效，之后需用新链接重新注册；本地历史报告仍可查看。

### 4. 查看报告

测试结束后，当前目录会自动写入 `<任务>-report.md`，同时屏幕上显示总览与域名表。

## 日常使用

- **选域名**：`2 选择要测试的域名` 中，`1`（或 `q`）选快速清单，`2`（或 `f`）选完整清单，`3` 进入内置分类选择，`4` 导入外置 JSON 清单。可组合输入（如 `1 4`），回车沿用上次选择。
- **开始测试**：先询问是否展示完整出口 IP（默认脱敏），再显示配置摘要（测试内容、观测端、规模、并发、报告位置）并确认执行。
- **中断**：第一次 `Ctrl+C` 是正常中断——停止新测试、取消在途连接、上报已有结果并取回部分报告；第二次强制退出。未执行的项目**不算阻断**。
- **断线恢复**：未上传的事件存在本地 SQLite，下次进入时按 `attempt_id + event_id` 幂等补交；须在旧节点密钥仍有效的窗口内完成。
- **历史报告**：在客户端查看完整报告、域名综合、按出口 IP 分组、只看探测异常、单域名证据；导出 TXT / JSON / CSV / MD；观测端仍保有任务时可刷新出口网络归属（新建 ASN 快照，不改写旧快照）。观测端只展示正在测试的实时连接，不提供历史报告菜单。
- **设置**：服务商标签与环境说明、探测目标、测试强度（轮数 / 并发 / 超时）、报告目录、域名库位置、重新登记。

## 读懂报告

Markdown 报告先展示出口整理、分类探测结果、结果摘要与出口分布，再展示证据摘要、出口汇总、判断依据与限制、说明。完整证据保存在数据库，可从报告菜单查看单个域名，或导出 JSON。

每个域名从四个**互不排斥**的维度给出结论：出口观察、受控探测状态、干预判断、证据完整性。已观察到出口与后续探测异常可以同时存在。

解读时请记住这些边界：

- 工具**直接确认**的只有一件事：从某被测节点、某时间、用特定目标 IP / 端口 / SNI / 地址族 / TLS 配置发起连接时，观测端**实际看到的来源 IP**。
- **受控探测的出口 ≠ 真实网站看到的出口。** 当前工具不直接观测真实网站访问出口。
- 连接没有到达观测端、也没有可信回执时，出口记为**「未观测」**，而不是「无出口」。
- 「没发现出口变化」只表示本次没有观测到差异，**不等于确定没有分流**。
- 只有「认证回执」与「ClientHello 匹配」两种证据计入出口；「SNI 相同 + 时间接近」不作为归属依据。
- 干预判断的**原因可信度上限为「中」**：单观测端、样本有限。
- 未执行、已取消、上报丢失的尝试**不计为网络失败**。

出现 `identity_mismatch` 时，工具会提示上游可能存在代理嗅探 SNI 并改写目的地
（透明转发或劫持），将连接送往真实网站或其他端点。目标地址、端口或观测端实例
配置不一致也可能造成此结果，不能仅凭该错误确定原因、代理位置或判定封锁。
没有观测端匹配证据的连接，其出口仍是“未观测”；IP 检测网站或基线的出口不能代表它。

## 命令参考

交互菜单覆盖日常使用。下面以仓库根目录运行 `go build -o sniroute ./cmd/sniroute`
生成的**原始二进制** `./sniroute` 为例；需要注册的命令应先完成客户端登记。

| 命令 | 作用 |
| --- | --- |
| `./sniroute` | 总菜单（选择 client / server） |
| `./sniroute client` | 客户端菜单 |
| `./sniroute client enroll -link '<整行注册链接>'` | 非交互注册（或设置 `$SNIROUTE_REG_LINK`） |
| `./sniroute client probe` | 按记住的域名选择跑一次受控探测，并写 `.md` |
| `./sniroute client probe -sni a.example -sni b.example -rounds 3` | 指定 SNI 与轮数；连接受控观测端，不访问这两个网站 |
| `./sniroute client probe -show-full-ip` | 展示并导出完整出口 IP；不加此参数默认脱敏 |
| `./sniroute client probe -sni chatgpt.com -tls-record-split` | 显式启用 TLS record 分片实验；须与普通模式分开对照，见[实验说明](docs/fragment-experiment.md) |
| `./sniroute client probe -sni chatgpt.com -tls-record-split-at after-sni` | 选择 SNI 扩展后的 record 分片；另支持 `before-sni`、`inside-sni` 和普通模式 `standard` |
| `./sniroute client probe -export ./reports` | 额外导出 TXT / JSON / CSV 到 `./reports`；自动 Markdown 仍写入配置的报告目录 |
| `./sniroute client reports list` | 列出客户端本地历史任务 |
| `./sniroute client reports show TASK_ID` | 查看指定任务报告 |
| `./sniroute client reports export TASK_ID -dir ./reports` | 导出 TXT / JSON / CSV / MD |
| `./sniroute client reports asn TASK_ID` | 观测端仍保有任务时，刷新 ASN 快照 |
| `./sniroute client reports flush` | 补交队列；须在节点密钥仍有效时执行 |
| `./sniroute reports list` | 等同 `./sniroute client reports list` |
| `./sniroute server` | 观测端管理菜单 |
| `./sniroute server run` | 前台运行服务（适合 systemd，先初始化配置） |
| `./sniroute server start` | 后台启动服务（先初始化配置） |
| `./sniroute server stop` | 停止服务 |
| `./sniroute server restart` | 重启服务 |
| `./sniroute server status` | 查看服务状态 |
| `./sniroute genkey` | 生成随机密钥 |
| `./sniroute version` | 查看应用版本 |

`TASK_ID` 和注册链接须替换为实际值。例如 `./sniroute client probe -h`、
`./sniroute client reports export -h`、`./sniroute server run -h` 可查看参数。

直接运行二进制与脚本的默认配置路径不同。脚本客户端使用 `~/.sniroute/client.yaml`；
如要用原始二进制读取脚本已有的登记和报告，请显式指定：

```sh
./sniroute client -config "$HOME/.sniroute/client.yaml"
./sniroute client reports list -config "$HOME/.sniroute/client.yaml"
```

服务端永久安装后的 `/usr/local/bin/sniroute` 是**启动器**：`sniroute` 打开服务端菜单，
`sniroute start`、`sniroute stop`、`sniroute restart`、`sniroute status` 控制服务，
`sniroute logs` 查看日志。这些顶层服务命令属于启动器；原始二进制使用上表中的
`./sniroute server …`。客户端建议使用客户端脚本，避免混用服务端配置。

## 域名库

`domains/` 随仓库携带：`quick-test.txt`（231 项）、`full-test.txt`（1100 项）、`categories/*.txt`（按类别，附服务与标签）。一份精简副本编译进二进制，单个文件即可使用。

想修改清单：编辑 `domains/` 后放到二进制同目录，客户端优先读取磁盘版本；也可以在「设置 → 域名库位置」指定目录。结构与裁剪说明见 [domains/README.md](domains/README.md)。

## 隐私

观测端默认向 RIPEstat 查询公网出口 IP 的 ASN，并向 IPinfo / GeoJS 查询归属地，
私网地址永不外发。若要关闭这些外部查询，在实际使用的 `server.yaml` 中设置后重启服务：

```yaml
asn_source: none
geo_sources: [none]
```

也可用 `asn_source: cymru` 切换为 Team Cymru（DNS TXT 查询）。当前服务端设置菜单
只提供监听地址和管理密钥设置，ASN 与归属地来源通过配置文件调整。

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

**发布**：打开 [Actions → Release](https://github.com/obrdx/SniRoute/actions/workflows/release.yml)，
点击 **Run workflow**，选择发布分支，填写版本号（当前为 `1.0.0`，也接受 `v1.0.0`）。
版本必须与源码 `internal/version/version.go` 中的 `Application` 一致；工作流不会修改版本。
对应版本的标签或 Release 已存在就报错，禁止重复发布或覆盖。推送分支或标签不会自动发版。

工作流运行竞态测试、版本校验和 `go vet`，为 linux / darwin × amd64 / arm64
交叉编译 `sniroute_{os}_{arch}` 四个二进制，附上 `SHA256SUMS`，然后创建正式 Release
并设为 Latest。部署脚本不指定 `SR_BIN` 或 `SR_BIN_URL` 时，从
[最新正式 Release](https://github.com/obrdx/SniRoute/releases/latest) 下载对应产物。
具体下载地址见 [部署脚本说明](scripts/README.md#下载及参数)。

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
