# 优化后的服务商出口 / SNI / 阻断域名库

推荐：先用 `quick-test.txt`，异常再用 `full-test.txt` 或单分类测试。

所有域名均来自上传压缩包；未进行实时网络可达性验证。

## 文件

- `quick-test.txt`：快速域名清单（一行一个 hostname）
- `full-test.txt`：完整精简域名清单
- `quick.csv` / `domains.csv`：保留原九列 CSV 格式；`is_suffix` 均为 0
- `categories/`：原有各分类的简化 TXT（每行 hostname、service、tags，TAB 分隔）
- `cross-category-reference.csv`：跨分类重复域名的原始关系
- `excluded-for-review.csv`：未选入的域名，可审计、可恢复；不是失效名单
- `PRUNING_REPORT.md`：详细剪枝统计和限制

## 约定

- 同一个域名在任意类别只保留一次。
- suffix 规则不作为独立的 SNI；不再混进测试域名列表。
- 原有 `region / role / restriction / purpose` 是未经实测的标签，仅用于筛选。
- 20-custom.txt 仍为空模板。基线请优先使用自有独立测试域名。
- 对 SNI 出口探测使用受控探测端；真实网站访问需单独诊断，不能只凭 SNI 结果声称某网站被阻断。
