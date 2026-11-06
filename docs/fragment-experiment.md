# TLS record 分片对照实验

用于研究中间设备是否因 ClientHello 的 record 分片方式不同，而改变 SNI 识别、目的地或出口选择。
这是受控 TLS 探测的实验开关，不是网站访问测试，也不承诺能绕过透明代理。

## 准备

使用包含 `-tls-record-split-at` 的源码构建实验二进制。已有正式 Release 不会随源码提交自动更新。
应用版本保持 `1.0.0`，不能仅凭版本号区分；可用 `client probe -h` 确认是否包含实验参数。

```sh
CGO_ENABLED=0 go build -trimpath -o ./sniroute ./cmd/sniroute
./sniroute client probe -h
```

客户端必须在被测机器上运行。跨平台构建时应设置匹配被测机器的 `GOOS`、`GOARCH`，再将文件复制到该机器。
观测端仍使用现有协议和跨 record 重组功能，不需要打开实验开关。

先完成登记。如果之前通过客户端脚本登记，配置默认在 `~/.sniroute/client.yaml`。
离线满 15 分钟后旧节点密钥可能已经失效，需要重新登记。

## 两次独立测试

以下为示例：将 `198.51.100.10:443` 替换成实际观测端地址；将 `probe.your-domain.tld`
替换成自己控制、真实解析到该观测端且未开启 CDN 的域名。它只用于本次基线，不会改写已保存的基线配置。

普通模式：

```sh
./sniroute client probe \
  -config "$HOME/.sniroute/client.yaml" \
  -target 198.51.100.10:443 \
  -baseline probe.your-domain.tld \
  -sni chatgpt.com \
  -rounds 3 -concurrency 1 -seed 7 -show-full-ip
```

分片模式：

```sh
./sniroute client probe \
  -config "$HOME/.sniroute/client.yaml" \
  -target 198.51.100.10:443 \
  -baseline probe.your-domain.tld \
  -sni chatgpt.com \
  -rounds 3 -concurrency 1 -seed 7 -show-full-ip \
  -tls-record-split
```

两次会产生不同任务及报告，参数快照分别记录 `client_hello_variant: standard` 和
`client_hello_variant: tls-record-sni-split`。不要将两份任务的出口混为同一组普通连接结果。
建议按普通、分片、普通、分片的顺序重复，减少测试时间不同造成的误判。

也可通过客户端脚本 `--probe` 透传这些参数，但必须用 `SR_BIN` 指向包含实验功能的本地程序。
实验模式要求显式指定 `-sni` 或 `-sni-file`，不会直接使用菜单记住的整个默认域名库。

## 分片位置对照

用 `-tls-record-split-at` 显式选择模式，不需要同时添加旧的布尔开关：

| 参数值 | TLS record 边界 | 快照中的 `client_hello_variant` |
| --- | --- | --- |
| `standard` | 保持原始 record 边界 | `standard` |
| `before-sni` | SNI 扩展的类型字段之前 | `tls-record-before-sni` |
| `inside-sni` | SNI 主机名中间，与旧开关相同 | `tls-record-sni-split` |
| `after-sni` | 完整 SNI 扩展之后 | `tls-record-after-sni` |

快照同时保存 `tls_record_split_at`，终端与 Markdown 的条件行也展示具体位置。
旧的 `-tls-record-split` 继续等价于 `inside-sni`；不能与 `-tls-record-split-at standard` 同时使用。

先用少量域名做交错对照。下面保持同一目标、域名、轮数、并发和顺序种子，仅切换分片位置：

```sh
for mode in standard before-sni standard inside-sni standard after-sni standard; do
  printf '\n===== 握手模式：%s =====\n' "$mode"
  ./sniroute client probe \
    -config "$HOME/.sniroute/client.yaml" \
    -target 198.51.100.10:443 \
    -baseline probe.your-domain.tld \
    -sni www.google.com -sni github.com \
    -rounds 3 -concurrency 1 -seed 7 -show-full-ip \
    -tls-record-split-at "$mode" || break
done
```

同样需要替换示例观测端地址和自有基线域名。每个模式单独创建任务、保存报告，出口不跨模式合并。
`after-sni` 保留完整 SNI 在前一个 record 中，是研究不同解析器处理差异的候选条件，
但不能保证中间设备仍按该域名选择出口。若结果全都使用同一 IP，也不能把它认定为真实网站出口。

## 改变的内容

- 仅在首个 ClientHello 的所选位置增加一个 TLS record 边界，不改变完整握手消息、SNI、ALPN、密码套件或公钥校验。
- 基线与域名探测都使用同一种任务模式，每次仍建立独立连接，不复用连接或恢复会话。
- 不控制 TCP 包边界，不增加分片间隔。即使多个 records 同处一个 TCP 包，TLS record 边界仍存在。
- 后续记录原样传递，包括 HelloRetryRequest 之后可能出现的第二个 ClientHello。
- ClientHello 摘要根据实际写出的字节重组计算；拆 record 不改变完整握手消息摘要的定义。
- 分片无法生成时该次尝试失败，不静默切回普通模式；只有观测端固定公钥校验成功后才发送凭证。
- 如果 SNI 扩展位于整个 ClientHello 末尾，没有剩余字节可放进下一个非空 record，`after-sni` 会明确失败；不添加填充或替换成其他分片位置。

## 解读结果

| 普通模式 | 分片模式 | 可作出的判断 |
| --- | --- | --- |
| 身份不匹配 | 认证成功 | 握手变体改变了连接能否到达预期观测端，可能存在解析能力差异或默认路径回退 |
| 身份不匹配 | 身份不匹配 | 这种分片没有恢复观测端身份匹配，不能证明中间设备不存在 |
| EOF / 超时 | EOF / 超时 | 没有足够证据解释原因，不编造出口 |
| 认证成功 | 认证成功但出口不同 | 观测到不同实验条件下的出口差异，不能单独归因为 SNI |

即使分片后取得出口，也可能是中间设备识别失败后选择了默认出口；不能宣称它就是普通访问
`chatgpt.com` 时的实际出口。报告会在明显位置和说明中保留这一限制。
观测端没有匹配记录不等于网卡没收到 TCP SYN；需要判断 SYN 是否到达时，仍应结合两端抓包。

## TCP 分次写入与间隔对照

新增 `-tcp-write-split-at before-sni|inside-sni|after-sni` 与
`-tcp-write-delay 0ms|20ms|100ms`。这项实验保留 TLS wire stream 的全部字节及
record 边界，只在首个 ClientHello 的指定位置分两次写入，中间等待指定时间；
后续握手原样发送。间隔只允许 0..1s 的整毫秒，计入每次探测超时，取消会立即中止等待。
显式设置 TCP_NODELAY；它并不保证两个 Write 对应两个 TCP 包，实际分段需要抓包确认。
这项实验不能与 TLS record 分片同时启用，也不会保存为菜单默认设置。

```sh
./sniroute client probe \
  -config "$HOME/.sniroute/client.yaml" \
  -target 198.51.100.10:443 \
  -baseline probe.your-domain.tld \
  -sni www.google.com -sni github.com \
  -rounds 3 -concurrency 1 -seed 7 -timeout 8s -show-full-ip \
  -tcp-write-split-at inside-sni -tcp-write-delay 20ms
```

替换示例目标和基线后，在相邻实验任务之间穿插不带这两个开关的普通任务。
建议先测试 inside-sni 和 after-sni，分别使用 0ms、20ms、100ms；不直接运行整个域名库。
基线也使用该任务的写入方式。

快照记录 `client_hello_variant: tcp-write-split`、`tcp_write_split_at`、
`tcp_write_delay_ms` 和 `tcp_nodelay`，报告明确标记 TCP 分次写入及其限制。
摘要仍只根据实际写出的完整 ClientHello 计算；中途取消、只写出一部分时不声称完整消息已发送。
公钥固定校验、凭证发送条件与认证回执验证不变。

这项实验检验发送方式是否影响端点身份或出口，不能据此确认透明设备的位置、实现或意图。
即使认证成功，出口也仅属于该发送方式下的受控连接，不代表普通网站访问出口。
