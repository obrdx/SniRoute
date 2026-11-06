# 独立 QUIC / SNI 出口实验

用于对照同一固定 IP、UDP 端口下，不同 SNI 能否到达受控观测端，以及到达时的来源 IP。
不访问真实网站，不使用网站回显接口，不进行 QUIC 分片实验，不把 UDP 结果当作 TCP 结果。

该目录是独立 Go module，只在这里引入固定版本的 `quic-go`。正式版 `sniroute` 的依赖、
TCP 监听、协议、节点密钥、数据库及报告保持原有实现。应用版本仍是 `1.0.0`；本程序不会发布到正式 Release。

## 构建

在本目录执行（不是仓库根目录）：

```sh
go build -trimpath -o sniroute-quic .
go vet ./...
go test -race ./...
```

跨平台构建示例：

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o sniroute_quic_linux_amd64 .
```

将对应系统、架构的同一个程序放在观测端和被测端。以下示例使用 Linux amd64；
需要 root 或相应权限才能监听 UDP 443。UDP 与 TCP 可以使用同一端口号，但防火墙需单独放行 UDP。

## 观测端

将 `198.51.100.10` 替换成观测端实际公网 IP，在独立 SSH 窗口运行：

```sh
chmod 700 /root/sniroute_quic_linux_amd64
/root/sniroute_quic_linux_amd64 server \
  -target 198.51.100.10:443 \
  -listen :443 \
  -dir /root/sniroute-quic-state
```

保持这个窗口运行。程序创建权限为 0700 的实验目录，其中包含：

- `client.json`：目标地址、观测端公钥指纹、30 分钟有效的随机实验凭证，权限 0600。
- `observations.jsonl`：只追加通过实验凭证认证的来源 IP、SNI、单次随机数及观测时间，不记录凭证。

把 `client.json` **私下复制**到被测端 `/root/quic-client.json`，不要贴入聊天或公开链接。
程序不打印凭证，也不将它放入 URL 或报告。重启实验观测端会生成新身份和凭证，需重新复制配置。
到期自动停止；`-ttl` 可设置 1 分钟到 2 小时。按 Ctrl+C 也只停止实验服务，不影响正式版 TCP 服务。

可在观测端另一个 SSH 窗口检查监听及入站流量：

```sh
ss -lnup
tcpdump -ni any 'udp dst port 443'
```

## 被测端

将自有测试域名替换成自己控制、真实解析到观测端的域名。这里将它作为一个独立 SNI 对照，不自动认定为直连或默认出口。

```sh
chmod 700 /root/sniroute_quic_linux_amd64
chmod 600 /root/quic-client.json
/root/sniroute_quic_linux_amd64 client \
  -config /root/quic-client.json \
  -sni www.google.com \
  -sni github.com \
  -sni probe.your-domain.tld \
  -rounds 3 -timeout 8s
```

每轮随机域名顺序，每次建立独立 QUIC 连接，同一个 SNI 的开始时间至少间隔 2 秒；
不复用 UDP 连接，不恢复会话，不使用 0-RTT、环境代理或 TCP 回退。固定 QUIC v1、TLS 1.3 和 ALPN `h3`。
完整来源 IP 会直接显示，并保存到当前目录自动命名的 JSON 报告（0600）；可用 `-out` 指定文件。
报告包含随机种子、测试条件、单次随机数及回执，可与服务端日志直接关联，不能只凭相同 SNI 和接近时间归属。

也可用 `-sni-file` 导入一行一个域名的清单。每次最多 4000 次尝试，轮数 1–10，单次超时 1–30 秒。
一次 Ctrl+C 停止新增尝试并保存部分报告；第二次可强制退出。未执行项不会记成网络失败。
凭证认证失败会停止新增尝试，避免把工具认证故障当作一批域名失败。

## 证据与限制

- 只在观测端固定公钥校验成功后发送实验凭证；公钥不匹配时不发送凭证。
- 服务端要求 QUIC Retry 来源验证、握手超时、64 条活动连接上限、HTTP 头 8 KiB 与请求体 1 KiB 上限。
- 短期实验凭证不等于正式版节点身份；单次随机数防重放，最多保存 4096 个已用随机数，到期终止服务。
- 来源只取真实 UDP/QUIC 对端地址，不信任 `X-Forwarded-For`；回执核对单次随机数、SNI 与来源 IP 格式。
- `receipt` 表示该 QUIC 连接经过认证，来源 IP 可用于本次实验的出口证据。
- `identity_mismatch` 表示端点身份不一致，可能存在目的地改写或其他配置问题，不判封锁。
- `timeout`、`quic_failed` 或没有回执均表示出口未观测；可能涉及 UDP 路径、过滤、MTU、监听或协议处理等原因，需要抓包区分。
- 本实验不改写 QUIC CRYPTO 帧，也不保证 ClientHello 或 SNI 位于单个数据包内。与 TCP record 分片实验的条件不同。
- 即便某 SNI 在 QUIC 下到达观测端并取得 IP，也不能证明它与普通 TCP 访问该网站使用相同出口。
- QUIC 的不同 SNI 都使用同一 IP，不等于没有 TCP 域名分流；不同 IP 也不能单独说明线路质量差异。
- 日志与报告仅针对这个独立实验，不导入正式版任务数据库，不生成封锁或服务商行为定论。

实现使用 [quic-go HTTP/3](https://quic-go.net/docs/http3/client/)，标准请求体在已验证的 QUIC/TLS 连接内交换。
