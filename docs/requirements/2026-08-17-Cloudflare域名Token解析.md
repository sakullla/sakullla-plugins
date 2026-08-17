# 需求：Cloudflare 域名 Token 解析

日期：2026-08-17

## 一屏摘要

- 目标：按域名提供 Cloudflare Token，让不同域名可以使用不同 Token，而不再只能依赖一份全局 Token。（R1）
- 使用者：配置多域名 Token 的管理员；申请证书或更新 DDNS 时按域名取 Token 的现有调用方。（R1、R4）
- 范围：解析器按域名返回 Token、专门管理页维护映射，以及 ACME DNS-01 与 DDNS 改走解析器。（R2、R3、R4）
- 关键规则：配置可以是二级域或更具体后缀，多条命中取最长后缀；未命中回退环境变量全局 Token；界面不回显已保存 Token。（R2、R5、R6）
- 成功标准：为某后缀配置的 Token 会被该域及其更具体未另配名称使用；未配置域名在仍有环境变量 Token 时继续可用。（R2、R4、R5）
- 不做事项：不把本插件做成 DNS 记录管理工具，不引入其它 DNS 厂商，本轮不删除环境变量全局 Token，也不按域名映射区域 Token。（R7、R8、R9、R10）

## 完整需求

### R1 按域名提供 Cloudflare Token

当前控制面用一份环境变量全局 Token 同时服务 ACME DNS-01 与 DDNS。管理员需要能为不同域名配置不同的 Cloudflare API Token，也可以让多个域名共用同一 Token。`cloudflare-dns` 作为这些调用方的解析入口：调用方提供域名，解析器根据已保存映射返回应使用的 Token。

验收：

- 管理员可以为两个不同域名保存两个不同 Token，调用方询问各域名时分别得到对应 Token。
- 管理员可以为两个不同域名保存同一 Token，两个域名的调用都使用该 Token。
- 本需求交付后，调用方不再把环境变量全局 Token 当作唯一来源。

### R2 按域名后缀解析 Token

管理员配置的名称可以是二级域（如 `example.com`）或更具体的后缀（如 `api.example.com`）。调用方给出完整域名后，解析器在已配置名称中选择能作为该域名后缀的映射；同时有多条后缀命中时，使用最长的那一条。解析结果只决定使用哪一个已保存 Token，不表示本插件去读写 Cloudflare DNS 记录。

验收：

- 仅配置 `example.com` 时，询问 `example.com`、`www.example.com` 都得到该映射的 Token。
- 同时配置 `example.com` 与 `api.example.com` 时，询问 `api.example.com` 得到更具体那条的 Token，询问 `www.example.com` 得到 `example.com` 那条的 Token。
- 配置名称不是所询域名的后缀时，该条映射不参与命中。

### R3 专门的映射管理界面

面板提供专门页面，供获授权管理员查看、新增、修改和删除「域名后缀 → Cloudflare Token」映射。创建或轮换时可以写入 Token；保存后任何列表、详情、错误或审计展示都不得回显 Token 明文，也不得提供导出已保存明文的操作。删除或修改前有明确对象提示；取消确认不产生变更。

验收：

- 获授权管理员可在该页面完成映射的新增、修改后缀、轮换 Token 和删除，刷新或重启后仍按最后一次成功保存生效。
- 未授权身份看不到写入入口，直接访问时得到明确拒绝而不是空白页。
- 已保存 Token 在任何读取界面中不可见；再次打开编辑时不会预填明文 Token。
- 重复配置同一后缀时被拒绝并提示，不覆盖其它后缀的映射。

### R4 现有调用方改走解析器

当前使用全局 Cloudflare Token 的 ACME DNS-01（含证书签发与续期）和 DDNS 更新，在需要 Token 时先向解析器提供本次涉及的域名，再使用返回结果访问 Cloudflare。调用方不得绕过解析器、只读环境变量来决定「这个域名用哪个 Token」。

验收：

- 为证书所涉域名配置了映射后，该证书的 DNS-01 签发或续期使用映射中的 Token，而不是环境变量中的另一个 Token。
- 为 DDNS 所涉域名配置了映射后，该域名的解析更新使用映射中的 Token。
- 映射被删除或 Token 被轮换后，后续签发、续期或 DDNS 更新使用新的解析结果，不继续使用已删除或已轮换前的映射。

### R5 未命中时回退环境变量全局 Token

当所询域名没有任何已配置后缀可以命中时，解析器返回现有环境变量全局 Token（按现网优先级：`CLOUDFLARE_DNS_API_TOKEN`、`CF_DNS_API_TOKEN`、`CF_TOKEN`、`CF_Token`）。映射命中时不得再混用环境变量 Token。环境变量也没有可用 Token 时，该次调用失败，并让操作者能看出是该域名没有可用 Token。

验收：

- 未配置任何映射、但环境变量仍有 Token 时，现有 ACME DNS-01 与 DDNS 行为与现在一致，仍然可用。
- 已为 `example.com` 配置 Token A、环境变量为 Token B 时，询问 `www.example.com` 得到 A，询问与 `example.com` 无关的域名得到 B。
- 无命中映射且环境变量为空或未设置时，调用失败，且不会静默使用其它域名的 Token。

### R6 已保存 Token 仅可写入不可回读

映射中的 Cloudflare Token 按写入型敏感信息处理。管理界面、解析结果展示、错误信息和审计元数据只允许出现域名后缀、是否已配置、最近更新时间一类非密钥信息，不得出现 Token 明文或可用于还原明文的材料。

验收：

- 保存成功后刷新页面，列表和详情都不显示 Token 明文。
- 解析失败或权限不足时的提示不包含 Token 明文。
- 审计或操作记录可以记下「哪个后缀被新增、轮换或删除」，但不记下 Token 内容。

## 不做事项

### R7 不管理 Cloudflare DNS 记录

本需求不把 `cloudflare-dns` 做成在 Cloudflare 上列出、创建、修改或删除 DNS 记录的工具。解析器只回答「这个域名用哪个 Token」。现有插件中面向区域记录管理的能力不作为本需求交付。

验收：

- 专门管理页和解析入口都不提供 DNS 记录的增删改查。
- 验收本需求时，不以「能在 Cloudflare 控制台外管理记录」为通过条件。

### R8 不引入其它 DNS 厂商

本需求只覆盖 Cloudflare API Token 的按域名供给。不增加其它 DNS 提供商的映射或解析。

验收：

- 管理页只接受 Cloudflare Token 映射。
- 现有非 Cloudflare 的证书方式（HTTP-01、手动上传）不受本需求改动。

### R9 本轮不删除环境变量全局 Token

现有环境变量、部署参数 `--cf-token` 以及它们对未命中域名的兜底继续保留。本需求不要求下线这些入口。

验收：

- 未配置映射时，仅设置现有环境变量仍能使 ACME DNS-01 与 DDNS 工作。
- 文档或界面若提到全局 Token，应说明它只在解析未命中时作为兜底。

### R10 不按域名映射 Cloudflare 区域 Token

可选的 `CLOUDFLARE_ZONE_API_TOKEN`（及别名）保持现有环境变量用法，不进入本需求的域名映射或专门管理页。

验收：

- 管理页没有「区域 Token」字段或按域名配置入口。
- 区域 Token 的现有环境变量行为不被本需求改为按域名解析。

## 来源

- `plugins/cloudflare-dns/README.md`、`plugins/cloudflare-dns/config.schema.json`：当前插件是单密钥引用的 DNS 工作流，用来界定 R7 的排除。
- `nginx-reverse-emby` 的 `panel/backend-go/internal/controlplane/config/config.go`：全局 Token 同时启用 ACME DNS-01 与 DDNS，支撑 R4、R5。
- `nginx-reverse-emby` 的 `docs-site/guides/certificates.md`、`docs-site/reference/environment-variables.md`：现有全局 Token 名称、启用条件和操作者预期，支撑 R1、R5、R9。
