---
# Runtime 只读取这一处文件头机器区；不要在正文重复机器字段。
format: solution
# AI 在此填写非空摘要；详细内容写入下方预建章节。
summary: 把 cloudflare-dns 改成域名后缀到 Vault 引用的解析器；面板提供专门映射页；宿主 ACME/DDNS 只经统一解析入口取 Token，未命中再回退现有环境变量。
---
# Technical Solution

<!-- 正文供 current owner 与下游 reader 阅读，不参与 Runtime stage machine validation。 -->

## 目标与 Non-goals

目标（R1–R6、R9）：

- 管理员能维护多条「域名后缀 → Cloudflare DNS Token」映射；不同后缀可用不同 Token，也可共用同一 Token。
- `cloudflare-dns` 只回答「这个域名命中哪条映射」，不再以 DNS 记录增删改查作为本需求产品面。
- 面板提供专门管理页完成映射的查看、新增、改后缀、轮换 Token、删除。
- 现有 ACME DNS-01（签发与续期）和 DDNS 更新在需要 Token 时先问统一解析入口，并带上本次域名；不得各自只读环境变量来决定「这个域名用哪个 Token」。
- 未命中映射时回退现有环境变量全局 Token（别名与优先级不变）；环境变量入口本轮保留。

Non-goals（R7、R8、R10）：

- 不交付 Cloudflare DNS 记录的列出、创建、修改、删除。
- 不引入其它 DNS 厂商的映射或解析。
- 不把 `CLOUDFLARE_ZONE_API_TOKEN` 做成按域名映射，也不把它放进专门管理页。
- 不删除 `--cf-token` 或环境变量全局 Token。
- 不改 HTTP-01、手动上传证书，也不扩展角色体系。

覆盖：R1 映射与按域名供 Token；R2 最长后缀命中；R3 专门页 CRUD；R4 两处调用方改走解析入口；R5/R9 未命中回退且保留环境变量；R6 明文不可回读；R7–R10 排除项。

## 事实 owner/consumer

- **映射事实**（后缀、对应 Vault `secret_ref`、是否已配置、最近更新时间）由 `plugins/cloudflare-dns` 拥有。面板专门页与宿主解析入口只消费该事实，不另存一份平行映射表。
- **Token 材料** 由宿主 Vault 拥有。插件只在创建/轮换时写入一次材料并立即丢弃；任何列表、详情、错误、审计、UI 投影都不保存或回显明文。
- **统一解析入口** `ResolveCloudflareDNSToken(domain)` 由相邻宿主控制面拥有：先问插件是否命中映射并兑付对应 Vault 材料；未命中、插件未安装或不可用时，再按现网顺序读 `CLOUDFLARE_DNS_API_TOKEN` > `CF_DNS_API_TOKEN` > `CF_TOKEN` > `CF_Token`。ACME 签发/续期与 DDNS 更新只调用该入口，不各自读环境变量。
- **环境变量全局 Token 与可选区域 Token** 仍由现有宿主配置拥有（`config.go` 的别名合同、`CLOUDFLARE_ZONE_API_TOKEN`）。本需求不改区域 Token 的读取路径。
- **专门管理页** 由相邻宿主面板（前端路由 + 控制面 API）拥有；它调用插件的映射读写，不把 Token 写进通用插件 `config.schema.json`。
- 消费者：获授权管理员（管理页）；ACME DNS-01 与 DDNS（解析入口）。

## 设计与状态变化

1. **插件产品面改为解析器**  
   保留 RPC 生命周期、`vault-secret`、authorizer、audit、dynamic-ui 这些已有宿主适配。新增映射读写与「按域名查询命中的 `secret_ref`」。`config.schema.json` 继续只放实例身份类字段（如 generation / resource group），不放 Token 明文，也不把多条映射塞进静态 schema。`plugin.yaml` 不再把「管理 DNS 记录」写成产品描述。`dns.provider` 在本需求中只表示控制面 DNS 凭据供给，不表示记录 CRUD。

2. **后缀匹配**  
   查询域名与配置名称先规范化（小写、去掉末尾 `.`）。命中条件：查询值等于配置名，或查询值以 `.` + 配置名结尾。多条命中时取规范化后字符串更长的一条。同一规范化后缀不得重复配置。

3. **映射生命周期**  
   新增：写入后缀 + Token 材料，材料进 Vault，对外只回后缀、已配置、时间。  
   改后缀：只改匹配名，不回读旧 Token。  
   轮换 Token：写入新材料并更新 Vault 版本，不回显旧材料。  
   删除：去掉该后缀映射及其 Vault 引用。  
   列表/详情：只有非密钥字段。

4. **宿主专门页**  
   面板增加独立管理页（不是通用插件详情表单，也不为本插件新增 `ui.schema.json`，因为当前清单测试禁止该插件声明配置 UI schema）。获授权管理员可完成上述 CRUD；未授权看不到写入入口，直达地址得到明确拒绝。删除/轮换有对象确认，取消不改状态。

5. **调用方改线**  
   `cert_master_cf_dns_issuer` 的签发与续期、`DDNSService.upsertRecords` 改为对每个涉及域名调用 `ResolveCloudflareDNSToken`。映射删除或 Token 轮换后，下一次签发/续期/DDNS 使用新的解析结果。  
   DNS-01 / DDNS 是否启用：在现有 `ACME_DNS_PROVIDER=cf` 条件下，有环境变量 Token **或** 至少一条映射即可尝试；某个域名既无命中又无环境变量 Token 时该次操作失败，而不是改用其它域名的 Token。  
   插件未安装时，统一解析入口退化为现有环境变量行为，满足 R9。

6. **区域 Token**  
   `CLOUDFLARE_ZONE_API_TOKEN` / `CF_ZONE_API_TOKEN` 仍只从环境变量读取；空则保持现有「回退到本次解析得到的 DNS Token」行为，不进入映射页。

7. **跨仓**  
   映射匹配与插件 RPC 面在本仓 `sakullla-plugins`。专门页、Vault 兑付、统一解析入口、ACME/DDNS 改线在相邻 `nginx-reverse-emby`。用户已允许为该宿主新建 worktree；本方案把两仓视为同一交付，不在本仓伪造宿主实现。

## 失败行为

- 查询域名无法规范化、映射后缀非法或与已有规范化后缀冲突：拒绝写入，提示字段错误，不改已有映射。
- 未授权读写映射或直达管理页：明确拒绝，不出现空白页，响应与审计不含 Token。
- 解析命中但 Vault 材料缺失或失效：该次调用失败，操作者能看出是该域名的已配置 Token 不可用；不回退环境变量（命中后不得混用）。
- 未命中且环境变量无 Token：该次调用失败，操作者能看出该域名没有可用 Token；不静默使用其它后缀的 Token。
- 插件未安装或生产 handle 不可用：统一解析入口视为「无映射」，只走环境变量兜底；不得因此打开 DNS 记录管理面。
- 管理页与解析错误信息、审计记录只记后缀和动作（新增/轮换/删除/失败类别），不记 Token 内容。

## 删除面

- 本需求交付面删除「以 Cloudflare 区域记录增删改查为产品」：专门页和解析入口都不提供记录 CRUD；不以能管理记录为验收通过。现有 `List/Create/Update/Delete` 不接到新页面或 ACME/DDNS。
- 不增加其它 DNS 厂商字段或入口。
- 不增加按域名的区域 Token 字段。
- 不为该插件新增 `ui.schema.json` 来代替专门页。
- 不把 Token 明文写入插件静态配置或通用插件详情表单。
- 不删除环境变量全局 Token 与 `--cf-token`。

## 机械验收

- 配置 `example.com` → Token A 后，询问 `example.com` 与 `www.example.com` 得到 A；同时配置 `api.example.com` → Token B 后，询问 `api.example.com` 得到 B，询问 `www.example.com` 仍为 A；`other.test` 在环境变量为 Token C 时得到 C。
- 两个不同后缀可保存不同 Token，也可保存同一 Token；重复同一规范化后缀被拒绝且不覆盖其它映射。
- 管理页可新增、改后缀、轮换、删除；刷新或重启后仍是最后一次成功保存。未授权直达得到拒绝。保存后再打开，列表/详情/编辑框/错误/审计都没有 Token 明文。
- 为证书域名或 DDNS 域名配置映射后，对应签发/续期/DDNS 使用该映射 Token，而不是环境变量里的另一个 Token；删除或轮换后下一次操作使用新结果。
- 无映射且仅有环境变量 Token 时，ACME DNS-01 与 DDNS 与现网一致仍可用。无映射且无环境变量 Token 时失败，且提示可归因到该域名没有可用 Token。
- 管理页没有 DNS 记录 CRUD、没有其它厂商、没有区域 Token 字段。HTTP-01 与手动上传证书路径不被本需求改坏。

## 实施 Unknowns

- 宿主为插件发布类型化 handle、以及专门页具体侧栏位置（基础设施或插件分组）的最终信息架构，实现时按面板现有导航惯例选择，不改变本方案的 owner 划分。
- 同一 Token 材料被多条后缀共用时，Vault 是一条共享引用还是按映射复制，只要对外语义仍是「两域名可用同一 Token」且轮换/删除不泄露明文，就不阻塞本方案。
- 本 workflow 的 `implementation_base_ref` 仍为空；执行阶段再锁定基线。相邻宿主改动需要独立 worktree，不写入本仓 state。
