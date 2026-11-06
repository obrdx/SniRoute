# 部署与临时运行

一行下载命令可直接在部署机器执行。下面引用 `scripts/…` 的本地命令须在已克隆仓库的根目录执行；
`SR_BIN=/tmp/sniroute` 示例须先按“使用本地构建的二进制”生成对应平台的程序。

## 一行命令

```sh
# 观测端（服务端）：交互选择临时运行 / 永久安装 / 卸载 / 查看状态
sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-server.sh)"

# 被测端（客户端）：首次粘贴注册链接，之后进入主菜单
sh -c "$(curl -fsSL https://raw.githubusercontent.com/obrdx/SniRoute/main/scripts/sniroute-client.sh)"
```

服务端交互里选「永久安装」但当前不是 root 时，脚本会询问是否下载自身并用
`sudo` 重新运行安装（临时文件随退出清理）。两个脚本都支持 `curl | sh`：
菜单输入会自动接回终端。

## 脚本说明

两个脚本都是 POSIX sh，支持 Linux / macOS 的 amd64、arm64；服务端与客户端在
Ubuntu、Debian、RHEL、CentOS、Alpine 上均可运行（Alpine 用 busybox wget 下载，
二进制为静态编译，musl 直接可用）。默认从 `obrdx/SniRoute` 的最新 GitHub Release
下载 `sniroute_{os}_{arch}` **裸二进制**；Release 由 GitHub Actions 手动触发
构建（见 `.github/workflows/release.yml`）。需要离线运行或使用自己
编译的二进制时，用 `SR_BIN` 指向本地文件。

### 手动发布正式版

将工作流合入默认分支后，在 GitHub 仓库打开 **Actions → Release → Run workflow**，
选择要发布的分支，填写版本号（例如 `1.0.0` 或 `v1.0.0`），再点击运行。
版本号必须与所选提交的 `internal/version/version.go` 中 `Application` 一致；
当前应用版本为 `1.0.0`，工作流不会升级版本或通过构建参数覆盖它。

工作流先检查版本；对应版本的标签或 Release 已存在（带或不带 `v` 前缀均检查）
就报错退出，不覆盖产物。检查 API 出错也会停止发布。测试、版本校验、`go vet`
和四个平台构建全部通过后，才以所选提交创建 `v版本号` 标签及**正式 Release**
（非草稿、非预发布），并设为 Latest。推送分支或标签不会自动发版。
使用仓库自带的 `GITHUB_TOKEN`，无需额外配置 PAT；仓库须允许工作流写入 contents。

附件为 `sniroute_linux_amd64`、`sniroute_linux_arm64`、`sniroute_darwin_amd64`、
`sniroute_darwin_arm64` 和 `SHA256SUMS`，兼容部署脚本现有下载地址。

默认下载的 Release 不保证与当前源码一致；发布前验收应使用下面的本地构建方式，并在部署机器执行 `sniroute version` 核对版本。交叉编译时用 `GOOS=linux GOARCH=amd64`（或 `arm64`），将二进制复制到对应被测机器和观测端，再通过 `SR_BIN` 部署。

## 使用本地构建的二进制（离线 / 发布前）

```sh
go build -o /tmp/sniroute ./cmd/sniroute

# 服务端：选择临时运行或永久安装
SR_BIN=/tmp/sniroute sh scripts/sniroute-server.sh

# 客户端：在被测机器上运行；第一次粘贴注册链接
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh
```

二进制必须匹配运行机器的系统与架构。客户端在线时可复用节点身份；离线满 15 分钟后，观测端清理客户端及其测试数据并使节点密钥失效，需获取新的注册链接。

## 服务端

```sh
# 临时：自动启动服务并打开菜单，退出时停止本次服务、清理临时程序
SR_BIN=/tmp/sniroute sh scripts/sniroute-server.sh --temp

# 永久（Linux）：systemd 发行版写 systemd 单元，Alpine 写 OpenRC 服务；
# 输入 sniroute 即启动服务并打开菜单
sudo env SR_BIN=/tmp/sniroute sh scripts/sniroute-server.sh --install
sniroute
sniroute status
sniroute logs

# 卸载保留配置与数据；加 --purge 会询问是否删除观测端配置与数据
sudo sh scripts/sniroute-server.sh --uninstall
```

永久模式安装启动器到 `/usr/local/bin/sniroute`，程序到 `/usr/local/lib/sniroute/`，
配置在 `/etc/sniroute/server.yaml`，数据在 `/var/lib/sniroute/`。
systemd 发行版写 `/etc/systemd/system/sniroute.service`；Alpine（OpenRC）写
`/etc/init.d/sniroute`（supervise-daemon 守护，崩溃自动重启）。启动器与
服务单元内容保存在脚本的 `LAUNCHER_TEMPLATE`、`UNIT_TEMPLATE`、
`OPENRC_TEMPLATE` 变量中。确保 `/usr/local/bin` 在 `PATH` 中。
systemd / OpenRC 负责开机自启和崩溃重启；退出管理菜单不停止永久服务。

两者都没有的环境（容器等）使用 `SR_NO_SYSTEMD=1` 只安装文件，`sniroute` 会用
程序自带的 pid 文件模式启动后台服务；没有开机自启和崩溃重启。

临时模式的配置和数据库保留在 `~/.sniroute`（可设 `SR_STATE_DIR`）。已有运行中的
同配置服务时直接进入管理菜单，不重复启动，退出时不停止原服务。失效的 PID 记录会自动清理；
Linux 上也会识别僵尸进程与已被其他进程复用的 PID，不向这些进程发送停止信号。
临时模式退出只会停止本次脚本新启动的服务，
与直接运行二进制的后台模式不同。非 root 默认探测端口 `8444`，root 为 `443`，
控制端口为 `8443`；客户端自动发现探测端口。探测入口必须直连，不能经 CDN 或改写来源的反代。

## 客户端（始终临时）

```sh
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh --probe -sni example.com
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh --reports list
```

本次运行的程序副本只放在临时目录。正常结束、错误退出、Ctrl+C、SIGHUP、SIGTERM
都会清理临时目录。第一次中断等待程序保存部分报告；第二次强制退出，可能来不及生成报告。
`SIGKILL`、断电等无法执行退出清理的情况不在此保证内。

报告默认保留在启动脚本的当前目录，文件名为 `<任务>-report.md`；若在客户端设置了
报告目录，则按该设置保存。节点密钥、配置和本地待补交队列保留在 `~/.sniroute/`
（`client.yaml` / `client.db`）；测试证据和历史报告同时保存在客户端本地 SQLite。观测端离线保留窗口为 15 分钟，窗口结束后旧密钥不能再补交，已保存的本地报告仍可查看和导出。
已有的脚本源文件与 `SR_BIN` 指定的原始程序不会被删除；清理只针对本次创建的临时内容。

## 下载及参数

不指定 `SR_BIN` 时会下载 Release 文件。可通过 `SR_BIN_URL` 指向其他地址，
其中 `{os}`、`{arch}` 会替换为平台值。`SR_SHA256` 可提供预期 SHA-256 校验和。
下载失败时退出并清理，可使用 `SR_BIN` 离线运行。

默认下载地址如下（已替换占位符，可直接下载）：

| 系统 / 架构 | 二进制 |
| --- | --- |
| Linux amd64 | [sniroute_linux_amd64](https://github.com/obrdx/SniRoute/releases/latest/download/sniroute_linux_amd64) |
| Linux arm64 | [sniroute_linux_arm64](https://github.com/obrdx/SniRoute/releases/latest/download/sniroute_linux_arm64) |
| macOS amd64 | [sniroute_darwin_amd64](https://github.com/obrdx/SniRoute/releases/latest/download/sniroute_darwin_amd64) |
| macOS arm64 | [sniroute_darwin_arm64](https://github.com/obrdx/SniRoute/releases/latest/download/sniroute_darwin_arm64) |

校验文件：[SHA256SUMS](https://github.com/obrdx/SniRoute/releases/latest/download/SHA256SUMS)。
脚本从 `main` 分支获取，二进制从 Latest Release 获取，两者更新独立。
`SR_REPO` 可覆盖脚本内的默认仓库 `obrdx/SniRoute`；`SR_BIN_URL` 可直接覆盖二进制下载地址。

服务端可覆盖 `SR_PREFIX`、`SR_ETC`、`SR_DATA`、`SR_UNIT_DIR`、`SR_INIT_DIR`、
`SR_STATE_DIR`，这些目录需为不含空格、引号和路径回退段的绝对路径。
新配置的监听可用 `SR_PROBE_ADDR` / `SR_CONTROL_ADDR` 覆盖；已有配置保持原值。

两个脚本的 `--dry-run` 仅显示计划，不下载、不写配置、不启停服务。

```sh
sh scripts/sniroute-server.sh --help
sh scripts/sniroute-client.sh --help
python3 -m unittest discover -s scripts/tests -v
```

## 配置、指纹与报告

直接运行二进制时，`sniroute server -config /path/server.yaml` 与
`sniroute client -config /path/client.yaml` 可打开指定配置的菜单；`-h` 查看角色帮助。

配置中的 `probe_pin` 是注册时的缓存。每次任务使用**已验证的控制连接**下发的最新探测公钥指纹；二者不一致会显示提示。仅修改本地缓存不会导致探测身份校验失败。测试身份拒绝行为须让控制接口下发的任务指纹与探测端实际公钥不一致：应记录 `identity_mismatch`，且不发送探测凭证。

客户端自动 Markdown 报告、历史菜单导出和 `reports export` 默认使用同一个 `report_dir`（未设置则为当前工作目录）。`-dir` 可覆盖命令行导出目录；导出后显示绝对路径。

直接运行二进制时默认不会读取脚本的 `~/.sniroute/client.yaml`，请用 `-config` 指定。
客户端脚本会自动传入这一路径，因此下面的命令使用同一份登记和本地历史数据：

```sh
SR_BIN=/tmp/sniroute sh scripts/sniroute-client.sh --reports list
/tmp/sniroute client reports list -config "$HOME/.sniroute/client.yaml"
```

中断后可在节点仍有效的 15 分钟窗口内补交本地待发送证据，并查看本地部分报告；目前没有继续执行原任务未测项的入口，重新测试会创建新任务。
