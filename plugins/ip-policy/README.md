# IP 策略

`ip-policy` 是一个正式双执行面插件包：control-plane RPC 进程提供专用中文管理页，Agent 上的 `nre:policy/v1` WASM guest 在 HTTP、TCP、UDP 和受管插件入口执行同一不可变策略。它不修改系统防火墙，不读取本地 MMDB，也不兼容或迁移 ForwardX 配置。IP 插件此前没有正式部署，因此安装只创建全新实例；初始模式是 typed `observe`，原始决策默认 `allow`。

管理面只调用公开 SDK 0.11 的 `dataset.control`、`dataset.binding`、`dataset.resolve/query` 与 `policy.control`。入口仅从 Host `list-entries` 列表选择，用 Host 签发的 token 调用 `inspect`/`replace-entry`/`reset-entry`；模式与完整 IP overlay 通过同一次双 CAS 原子更新。数据绑定、guest Config 和默认模式需要一起变化时，管理面使用 `DatasetBindingInstanceUpdate` 一次提交，避免发布任何中间快照。失败的下载、摘要、分类、预算或节点候选不会替换 `applied`/`last_good`。

## Configuration contract

唯一 guest Config 是一个不超过 64 KiB 的严格 JSON object：

```json
{"schema":"sakullla.ip-policy/v1","default_action":"allow","datasets":[{"id":"province-data","source_id":"dbip-cn-province","classifications":[{"id":"guangdong","name":"cn-44","kind":"region"}]}],"province_whitelist":[{"dataset_id":"province-data","classification_id":"guangdong"}],"rules":[{"id":"deny-admin","action":"deny","selector":{"type":"cidr","value":"192.0.2.0/24"}}]}
```

`datasets` 的数组位置是一基事件 `dataset_index`；每个 `classifications` 的位置是该数据集内的一基 `classification_index`。分类只包含 `id`、SDK `name` 和 `kind` (`cidr|country|region`)。policy query wire 不携带属性，所以 Config 不接受 `attributes`；GeoSite 的 `!cn` 属性可以在通用数据源目录显示，但不会混入 IP 查询目标。

规则 ID 和字典 ID 使用 `[a-z][a-z0-9-]{0,31}`。单 IP 必须是 canonical IPv4/IPv6，CIDR 必须已经 masked。classification selector 只能引用同一 Config 内存在的字典项。全局规则最多 256 条，数据集最多 4 个，每个数据集最多 64 个分类。

入口 stage payload 使用严格结构 `{"schema":"sakullla.ip-policy-overlay/v1","rules":[]}`，最多 64 条规则，并只引用基础 Config 的数据集字典。有效规则字典先放全局规则，再放入口规则；因此入口事件 `rule_index` 从 `len(global rules)+1` 开始。所有 deny 在全局和入口两层之间优先于 allow，最后才使用 `default_action`。Host 的 typed `raw-decision-v1` 设置独立控制默认和入口 `observe|enforce`，guest Config 与 overlay 都不含模式。成功响应 payload 始终为空。

`province_whitelist` 是 allow 规则之前的硬门槛：配置任一省份后，只有查询结果 `covered && matched` 的所选省份通过。其它省份、境外、未知地址族和未覆盖族都产生原始 deny；普通 `country:cn` allow 不能扩大省份白名单。省级 IPv6 当前按真实数据标为 `partial` 或 `none`，未知结果不会借用全国 IPv6 覆盖。

大陆 31 个省级分类固定为：北京 `cn-11`、天津 `cn-12`、河北 `cn-13`、山西 `cn-14`、内蒙古 `cn-15`、辽宁 `cn-21`、吉林 `cn-22`、黑龙江 `cn-23`、上海 `cn-31`、江苏 `cn-32`、浙江 `cn-33`、安徽 `cn-34`、福建 `cn-35`、江西 `cn-36`、山东 `cn-37`、河南 `cn-41`、湖北 `cn-42`、湖南 `cn-43`、广东 `cn-44`、广西 `cn-45`、海南 `cn-46`、重庆 `cn-50`、四川 `cn-51`、贵州 `cn-52`、云南 `cn-53`、西藏 `cn-54`、陕西 `cn-61`、甘肃 `cn-62`、青海 `cn-63`、宁夏 `cn-64`、新疆 `cn-65`。固定回归样例覆盖北京、江苏、广东和广西。

诊断只使用固定 `PolicySecurityEvent`：`IPRuleMatch` 或 `IPCheckFailure`、原始 `Allow|Deny`、一基字典索引，以及 `SourceUnauthenticated`、`DatasetUnavailable`、`ClassificationMissing`、`BudgetExceeded`、`DataInvalid`、`CoverageUnknown` 等枚举原因。事件不携带请求路径、header、body、凭据或其它业务载荷；最终 observe/enforce 结论由 Host 的 typed policy 事件表达。

数据源由 Host 管理并展示真实来源、许可、固定修订、版本和每分类 IPv4/IPv6 覆盖。支持现有 V2Fly GeoIP、Loyalsoldier GeoIP 与 DB-IP City Lite 省份投影；页面不会把 package metadata 当作底层数据授权证明。
