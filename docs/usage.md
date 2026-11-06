# 使用指南

[返回首页](../README.md) · [部署脚本](../scripts/README.md) · [自定义域名清单](external-domains.md)

## 测试条件

固定观测端 IP 和端口，切换 SNI，与穿插执行的基线比较。每个域名默认做 3 次独立连接，IPv4 与 IPv6 分开比较；不访问域名对应的真实网站。

默认并发为 6；配置文件或命令行指定的并发数继续生效。每轮结束后再开始下一轮，基线按独立阶段穿插执行。同一 SNI（含不同地址族的目标）上次探测结束后至少间隔 2 秒再测，等待期间可执行其他域名；间隔写入任务快照。

默认不读取环境代理。系统级 VPN、TUN 或透明转发仍可能影响出口，请在客户端「设置」中记录环境说明。

## 域名库

内置快速、完整及分类清单，单二进制即可使用。首次建议用快速清单，之后按需选择 AI、支付与金融、流媒体、开发者等分类。

客户端菜单「2 选择要测试的域名」支持组合编号，例如 `1 4` 合并快速清单与外置 JSON。回车沿用上次选择；外置文件的格式、下载及刷新规则见[自定义域名清单](external-domains.md)。

要修改磁盘清单，将仓库的 `domains/` 放到二进制同目录，或在「设置 → 域名库位置」指定目录；磁盘版本优先，无需重新编译。清单文件结构见[域名库说明](../domains/README.md)。

## 报告与数据保留

测试结束会自动在当前目录写一份完整的 Markdown 报告（`<任务>-report.md`）。报告按用途分类展示域名结果，并提供结果摘要、出口分布、出口汇总及判断依据的章节导航。

开始测试前会询问是否展示完整出口 IP，默认脱敏；该选择同时用于本次 SSH 输出和导出文件。脱敏时用固定出口编号区分相同前缀下的不同 IP，数据库保留完整原始证据。非交互命令默认脱敏，可加 `client probe -show-full-ip` 展示完整出口。

域名结果按用途分类（AI、支付与金融、流媒体、开发者等），未收录的域名放入「自定义 / 未分类」。终端先展示分类清单，再展示结果摘要、出口分布和阅读提示；各分类使用统一列宽，窄终端自动折行，完整 IPv6 地址与长域名不被省略。支持颜色的终端突出成功与异常，重定向输出和导出文件保持纯文本，设置 `NO_COLOR` 可关闭颜色。每行显示出口 Origin ASN 编号与组织名称；出口分布占比按同一比较组的有效观测计算（包含基线与仅握手匹配），取消和无记录分别列出。

同一份报告保存在客户端本地 SQLite，可在「历史报告」中查看、重新导出 TXT / JSON / CSV / MD，观测端清理后仍可读取已保存的报告。刷新出口网络归属需要节点密钥和观测端任务仍有效。

观测端不再提供节点管理、历史任务及报告导出。菜单「3 实时连接」每 2 秒刷新正在测试的客户端，显示控制连接来源 IP、探测进度和最近活动；超过 90 秒没有认证活动的客户端不显示为实时在线。离线满 15 分钟时密钥立即失效，数据由后台每 5 秒清理一次，启动时也会清理。服务配置、管理密钥和探测证书继续保留。

## 结论边界

- 工具**直接确认**的只有一件事：从某被测节点、某时间、用特定目标 IP / 端口 / SNI / 地址族 / TLS 配置发起连接时，观测端实际看到的来源 IP。
- **受控探测的出口 ≠ 真实网站看到的出口。** 本工具不执行真实网站访问，真实网站访问出口未直接观测。
- 连接没有到达观测端、也没有可信回执时，出口记为**「未观测」**，而不是「无出口」。
- 「没发现出口变化」只表示本次没有观测到差异，**不等于确定没有分流**。
- 只有「认证回执」与「ClientHello 匹配」两种证据会计入出口；「SNI 相同 + 时间接近」不作为归属依据。
- 干预判断的**原因可信度上限为「中」**：单观测端、样本有限。
- 未执行、已取消、上报丢失的尝试**不计为网络失败**。

## 隐私与外部查询

默认将观测到的**公网出口 IP** 发送给 RIPEstat 查询 Origin ASN，同时发送给 IPinfo 和 GeoJS 查询归属地（私网地址永不外发）。归属地以 IPinfo 为主：缺失字段由兼容的其他来源补充并标明来源；来源有差异时在括号中显示其他可能，不直接覆盖 IPinfo。归属地是 IP 数据库的估计，不代表服务器实际位置。报告只展示整理后的归属地，不附 API 原始响应或查询诊断。

所有接口均无需 API Key。IPinfo 使用 `https://ipinfo.io/<IP>/json`（Legacy 公共接口），匿名额度按请求 IP 共享，官方说明为 1,000 次/天；GeoJS 使用 `https://get.geojs.io/v1/ip/geo/<IP>.json`。每个来源独立缓存 24 小时；请求受限后暂停该来源请求，失败不影响已观测的出口 IP 或网络结论。来源说明：[IPinfo](https://support.ipinfo.io/hc/en-us/articles/34121895556242-Legacy-Free-API-vs-IPinfo-Lite)、[GeoJS](https://www.geojs.io/docs/v1/endpoints/geo/)。

服务设置菜单仅保留监听地址与管理密钥，证书、数据目录和 ASN 查询使用默认配置。需要手动调整查询来源时，可修改配置文件 `server.yaml`：`geo_sources: [ipinfo, geojs]` 为默认值，`geo_sources: [ipinfo]` 仅使用 IPinfo，`geo_sources: [none]` 仅关闭归属地查询；`asn_source: none` 关闭全部外部查询。修改配置并重启后生效，已有报告保持原样。

## 终端显示

菜单与安装脚本跟随终端调色板显示颜色。设置 `NO_COLOR=1` 可关闭，重定向输出和 `TERM=dumb` 自动使用纯文本。导出文件不包含终端颜色控制码。

## 构建与命令行

需要与 `go.mod` 匹配的 Go 工具链；发布二进制无需 Go 环境。

应用版本固定为 **1.0.0**，修改版本号须事先取得维护者明确同意。Release 由 GitHub Actions 自动构建：推送已确认的 `v*` 标签后，工作流会跑一遍测试，然后为 linux / darwin × amd64 / arm64 交叉编译出 `sniroute_{os}_{arch}` 四个二进制并附上 SHA256SUMS，创建对应的 GitHub Release。二进制以 `CGO_ENABLED=0` 静态编译，glibc 与 musl（Alpine）都能直接运行。部署脚本不指定 `SR_BIN` 时，会自动获取最新 Release。

从源码构建：

```sh
go build -o sniroute ./cmd/sniroute
./sniroute version
```

需要离线运行或使用自己编译的二进制时：

```sh
go build -o /tmp/sniroute ./cmd/sniroute
SR_BIN=/tmp/sniroute sh scripts/sniroute-server.sh
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh
```

非交互命令（用于脚本或定时任务）：

```bash
./sniroute client enroll -link 'https://…/join#…'   # 或 $SNIROUTE_REG_LINK
./sniroute client probe                             # 用记住的域名选择跑一次，并写 .md
./sniroute client probe -sni a.example -sni b.example -rounds 3
./sniroute client reports list                     # 列出本地报告
./sniroute client reports show TASK_ID             # 替换为实际任务 ID
./sniroute client reports export TASK_ID           # 重新导出
./sniroute client reports asn TASK_ID              # 刷新 ASN（节点与任务须有效）
./sniroute client reports flush                    # 补交待发送事件
```

开发检查：

```sh
go build ./...
go vet ./...
go test -race ./...
```
