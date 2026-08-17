---
# Runtime 只读取这一处文件头机器区；不要在正文重复机器字段。
format: exploration
# AI 在此填写非空摘要；详细内容写入下方预建章节。
summary: 本仓 cloudflare-dns 仍是单 secret_ref 的 DNS 记录工作流；需求所点的 ACME/DDNS 调用方在相邻宿主里直接读环境变量全局 Token，两边都还没有域名后缀解析或专门映射页。
---
# Exploration

<!-- 正文供 current owner 与下游 reader 阅读，不参与 Runtime stage machine validation。 -->

## 证据与直接消费者

- 本需求在本仓的实现入口是 `plugins/cloudflare-dns`：二进制 `plugins/cloudflare-dns/cmd/cloudflare-dns/main.go` 调用 `RunEntrypoint`；`plugins/cloudflare-dns/plugin.yaml` 声明 `id: cloudflare-dns`、`runtime: rpc-service`、`host_scope: control-plane`、`extension_points: [dns.provider]`、权限 `dns.manage`/`secret.use`/`event.emit`/`service.revocable-resource-handle`，以及 `config_schema: config.schema.json`。该清单未声明 `ui_schema`。
- 当前插件形态与 R1/R2 目标不一致：`plugins/cloudflare-dns/config.schema.json` 与 `plugins/cloudflare-dns/model.go` 的 `Configuration` 只接受 `generation`、`secret_ref`、`resource_group_ref`。`README.md` 与 `plugin.yaml` 描述的是单密钥 Cloudflare DNS 工作流（区域/记录操作），不是域名后缀 Token 解析器。`plugins/cloudflare-dns/service.go` 现有方法为 `TokenStatus`、`ListZones`、`ListRecords`、`Create`、`Update`、`Delete`、`EnrollToken`、`RotateToken`。在该插件内搜索 `Resolve`/`longest`/`HasSuffix` 未发现解析符号。
- 当前 Token 处理：材料只写入宿主 Vault。`EnrollToken`/`RotateToken` 接受 `[]byte` 后清除。`TokenStatus`/`UIProjection`/`AuditRecord`/`EventRecord` 暴露 `secret_ref`、version、zones、permissions、操作元数据，不暴露 Token 明文。生产 Activate 失败关闭：默认 admission 是 `unavailableAdmission`；无 `--nre-ci-rpc-handshake` 时 `RunEntrypoint` 返回 `ErrTypedHandlesUnavailable`（`controller.go`、`entrypoint.go`）。
- 需求点名的相邻控制面仍用一份进程环境变量 Token 同时服务 ACME DNS-01 与 DDNS：`nginx-reverse-emby/panel/backend-go/internal/controlplane/config/config.go` 的 `LoadFromEnv` 按 `CLOUDFLARE_DNS_API_TOKEN`、`CF_DNS_API_TOKEN`、`CF_TOKEN`、`CF_Token` 读取；`ACME_DNS_PROVIDER=cf` 且 Token 非空时打开 `ManagedDNSCertificatesEnabled`，并把同一 Token 写入 `DDNSRuntimeConfig`。ACME 签发器 `newMasterCFDNSManagedCertificateIssuer()` 再次读这些环境变量，并单独读 `CLOUDFLARE_ZONE_API_TOKEN`/`CF_ZONE_API_TOKEN`（空则回退 DNS Token）。`DDNSService.upsertRecords` 直接使用 `s.cfg.DDNS.Token`。文档 `docs-site/guides/certificates.md` 与 `docs-site/reference/environment-variables.md` 记录同一别名顺序、`--cf-token`/`CF_TOKEN` 部署路径和可选区域 Token。未发现这些调用方对本仓 `plugins/cloudflare-dns` 的调用。
- 本仓测试入口：`testing/integration/cloudflare-dns/cloudflare_test.go`（Token 状态、密钥脱敏、enroll/rotate CAS、区域范围 DNS CRUD、对账/exactly-once、撤销边界）与 `testing/integration/cloudflare-dns/rpc_test.go`（必需 grants、默认失败关闭 Activate、配置拒绝明文 `token` 字段、规范 CI handshake）。`newTestService`/`testConfiguration` 固定单个 `SecretRef` `vault/cloudflare`。打包/CI：`cmd/nre-ci/main_test.go` 的 `artifactRPCService` needle 为 `cloudflare-dns/cmd/cloudflare-dns`；`internal/pluginmanifest/manifest_test.go` 期望中文名「Cloudflare DNS」，并禁止该插件声明 `ui_schema`。`testing/corpus` 无 `cloudflare-dns` 树；插件目录旁无 `*_test.go`。
- 相邻调用方测试覆盖现有「只读环境变量」行为：`config_test.go` 的 `TestLoadFromEnvManagedDNSCertificatesEnabled`/`Disabled`；`cert_master_cf_dns_issuer_test.go` 的别名与区域 Token 回退；`ddns_test.go` 注入 `Token cf-token`。
- `docs/sakullla-workflow/2026-08-17-Cloudflare域名Token解析/00-state.yaml` 的 `requirement_ids` 为 R1–R10，exploration 待完成，`implementation_base_ref` 为空。

## 复用点

- RPC ABI `nre:rpc/v1` 与 plugin-sdk handshake/lifecycle（`go.mod` require `github.com/sakullla/nginx-reverse-emby/plugin-sdk v0.6.1`；Controller 的 Handshake/Prepare/Activate/Stop）。
- 宿主 grants：`requiredGrants` 为 `audit`、`authorizer`、`cloudflare-dns`、`dynamic-ui`、`log`、`vault-secret`。
- Vault 接口 `Verify`/`Enroll`/`Rotate`：不透明 `secret_ref` 与一次性材料；`TokenMetadata` 只有 `SecretRef`+`Version`。
- Authorizer 先 coarse 再 exact 的 `ActionContext`；bootstrap 用 `Vault:Enroll`，轮换用 `Vault:Rotate`。
- `UIProjection` 与 `AuditRecord` 已省略 Token 明文；`rpc_test` 拒绝配置字段 `token`。
- `plugin.yaml` 已声明 `dns.provider` 扩展点与 `dns.manage` 权限（当前含义是 DNS 工作流，不是 Token 解析）。
- 相邻仓已有环境变量别名合同和区域 Token 拆分：`config.go`、`certificates.md`、`environment-variables.md`、`cert_master_cf_dns_issuer.go`（R5/R9/R10 基线）。

## 风险

- 需求要把 `cloudflare-dns` 做成按域名的 Token 解析器并提供专门映射页；当前插件是单密钥 DNS 记录管理器，且 `manifest_test` 禁止该插件声明配置 UI schema。
- ACME/DDNS 调用方在相邻 `nginx-reverse-emby`，今天绕过本插件直接读环境变量；改它们不在本仓实现树内。
- 当前 `Service` 从不向任何调用方返回 Token 明文；R1/R4 要求调用方使用解析到的 Token。Vault handle 与明文返回之间与 R6 存在未落地的合同张力。
- 没有类型化宿主 handle 时生产 Activate 失败关闭，因此要服务线上 ACME/DDNS 的解析器不能沿用当前默认 admission 路径。
- 签发器在 `CLOUDFLARE_ZONE_API_TOKEN` 为空时把 DNS Token 复制为区域 Token；映射工作不得把区域 Token 并入域名映射（R10）。
- `plugin.yaml` 描述仍是「在指定 Cloudflare 区域管理 DNS 记录」，而 R7 明确排除该能力作为本需求交付。

## Unknowns

- `plugins/cloudflare-dns` 与 `testing/corpus` 中不存在域名后缀 Token 映射、Resolve API 或专门映射页；在本插件搜索 `Resolve`/`longest`/`HasSuffix` 无命中。
- 映射持久化落在插件配置、宿主/Vault 还是相邻面板存储，现有代码未给出证据。
- 相邻 ACME/DDNS 将如何调用本插件（RPC 方法、同进程或新的宿主 handle）尚未实现；当前路径是直接读环境变量。
- 解析器返回明文 Token 还是仅返回 Vault/handle 证明，现有代码未给出证据；当前 `Service` 从不返回 Token 字节。
- 专门管理页是插件 dynamic-ui、`ui.route` 还是宿主面板，现有代码未给出证据；本插件当前不得声明 `ui.schema.json`。
- workflow `00-state.yaml` 的 `implementation_base_ref` 为空；本 workflow 尚未锁定实现基线。

## 验证焦点

- R1/R2：两个域名可映射到不同或相同 Token；最长匹配后缀胜出；非后缀映射不命中。当前测试没有后缀解析覆盖。
- R3/R6：获授权的映射 CRUD 在重启后保持；未授权得到明确拒绝；列表/详情/编辑/错误/审计从不回显或导出 Token；重复后缀被拒绝。现有脱敏测试只覆盖单密钥 enroll/rotate/status 路径。
- R4：ACME 签发/续期和 DDNS upsert 必须按所涉域名从解析器取 Token，包括删除或轮换之后；当前测试断言的是环境变量 Token。
- R5/R9：未命中回退顺序为 `CLOUDFLARE_DNS_API_TOKEN` > `CF_DNS_API_TOKEN` > `CF_TOKEN` > `CF_Token`；命中后不得混用环境变量 Token；空未命中须可见失败；`--cf-token`/环境变量对未映射域名仍然有效。
- R7/R8/R10：不以 DNS 记录增删改查、其它厂商或区域 Token 字段作为本需求通过条件。
- 围绕任何新的映射/解析面，保留现有失败关闭、grant、拒绝明文配置、以及材料清除测试作为回归。
