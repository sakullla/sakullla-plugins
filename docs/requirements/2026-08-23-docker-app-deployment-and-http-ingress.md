# 需求：Docker App 部署体验与 HTTP 入口集成

日期：2026-08-23

## 实现状态（2026-08-23）

- R1 已实现：提交后立即显示部署中，部署成功与列表刷新分开提示，镜像观察改为限流后台任务。
- R2 已实现：表单支持 `.env`，必填变量在执行前校验；内容只瞬时传输，Agent 持久文件原子替换且不回显。
- R3 尚未实现：当前公共 `http.backend-provider` 契约只支持 Agent 托管、manifest 静态描述符，不能表达控制面插件运行时产生的“应用 × 端口”动态目录。不得在主应用按 `docker-app` ID 特判；需要先扩展公共 SDK 的动态 provider 目录契约。
- R4 部分实现：应用页创建已传递 operation key、保留 `http://`/`https://`，创建结果进入宿主全局规则；宿主侧修改/删除后的反向查询与页面对账仍缺公共 `http.rule` 查询契约。
- R5 部分实现：变量缺失及各操作阶段有安全、可操作提示，不再向页面只显示 `broker operation failed`；Docker CLI 具体失败原因的安全分类仍需补充标准化错误码。
- R6 已实现源代码：应用状态持久化，临时 generation 工作区会从状态重新物化；Agent 命令代理工作区按插件实例持久化且不随 generation 清理。该项依赖通用宿主变更合入。
- R7 已满足：不自动生成秘密、规则或更新镜像。
- 发布尚未完成：0.1.7 已可构建验证，但正式安装需要官方签名器。

## 一屏摘要

- 目标：Docker App 能可靠部署 Compose，并从应用页或全局规则页建立可验证的 HTTP 入口。（R1、R3、R4）
- 使用者：通过控制面管理 Agent 上 Docker 应用、变量和入口域名的管理员。（R1、R2）
- 范围：部署反馈、`.env`、后台镜像检查、规则提供商目录、应用侧挂载规则与持久性。（R1-R6）
- 关键规则：部署结果不受慢速 registry 检查阻塞；秘密只在目标 Agent 使用，不回显到控制面。（R1、R2、R5）
- 成功标准：长时间拉取可观察、变量 Compose 可部署、Docker 应用可选作后端、两处创建的规则一致生效。（R1-R4）
- 不做事项：不自动生成秘密，不因读取列表自动创建规则，不让更新检查决定部署成败。（R7）

## 完整需求

### R1 部署过程与结果必须及时可观察

管理员提交 Compose 后，页面必须立即进入明确的部署中状态，并在部署操作成功或失败时给出独立、可理解的最终结果。镜像拉取、容器创建和应用列表刷新属于可区分的阶段；部署已经成功时，后续镜像版本检查或页面刷新失败不得把结果表现为部署失败或让页面长期没有提示。应用列表和部署响应不得同步等待不受控的远端 registry 最新 digest 查询；更新信息可以稍后出现。

验收：

- 首次拉取一个耗时超过普通请求时长的镜像时，页面立即显示“正在部署”或等价状态，并保持可取消页面交互或继续观察状态。
- 容器成功启动后，页面显示部署成功；即使随后 registry 查询超时，也只显示独立的版本检查提示，不撤销部署成功结果。
- 部署失败时显示失败阶段和可操作原因；再次渲染应用列表不会无限阻塞部署请求。
- 重复刷新应用列表不会为每个应用串行等待远端 registry，且已部署应用始终可以立即显示。

### R2 Compose `.env` 输入与变量替换

部署和编辑表单必须提供独立的 `.env` 多行输入，支持 Docker Compose 标准变量形式，包括 `${VAR}`、`${VAR:-default}` 和 `${VAR:?message}`。`.env` 内容只传给目标 Agent 使用，不进入插件配置快照、应用列表响应、浏览器回显、普通日志或审计详情。首次提供时保存到对应应用的持久工作目录；更新时提供新内容表示替换，留空表示复用目标 Agent 上已有内容。

验收：

- 管理员粘贴包含 `${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}` 的 Compose，并在 `.env` 中提供该变量后，可以完成 Compose 解析和部署。
- 缺少 `:?` 必填变量时，错误指出变量名和 Compose 提供的提示，但不包含任何已提交变量值。
- 使用 `:-` 默认值且未在 `.env` 提供变量时，Docker Compose 使用声明的默认值。
- 编辑已部署应用并将 `.env` 输入留空时，原有 Agent 端 `.env` 继续生效；提交新内容时完整替换且不会产生半写入文件。
- 查看、列出或编辑应用时，API 和页面均不返回已保存的 `.env` 内容。

### R3 Docker 应用必须出现在全局 HTTP 后端选择中

全局“添加规则”弹窗选择目标 Agent 后，后端选择区域必须列出该 Agent 上由 Docker App 管理且具有发布端口的应用。每个候选项必须能识别应用、目标 Agent 和端口；多端口应用允许选择具体端口。没有发布端口、目标不匹配或当前不可用的应用不得被当作可用后端静默提交。

验收：

- 目标 Agent 上存在 `hubproxy` 且发布 `5000` 时，添加规则弹窗能看到名称和端口明确的 Docker 应用候选项。
- 切换目标 Agent 后，候选项随 Agent 更新，不混入其他节点的应用。
- 多个发布端口不会合并成含糊的单一选项；提交结果绑定管理员实际选择的端口。
- 应用离线或端口不可用时，界面显示不可用状态或不提供提交，不能创建指向错误节点的规则。

### R4 应用页“挂 HTTP”与全局规则必须一致生效

Docker App 应用卡片中的“挂 HTTP”必须以真实域名和选定发布端口创建宿主管理的 HTTP 规则。创建成功后，应用页显示域名、端口和生效状态；该规则同时出现在全局规则列表，并可按全局规则的正常流程查看、编辑或删除。应用页不得把占位符当成已输入域名，也不得在宿主拒绝规则时显示成功。

验收：

- 输入真实域名、选择 `hubproxy:5000` 并保存后，规则创建成功且通过该域名可访问对应 Agent 上的端口。
- 以 `{"domain":"https://hub.zouter.124536.xyz","port":5000}` 提交 `hubproxy` 的挂载请求时，系统接受完整 HTTPS URL、规范化域名并创建启用的 HTTPS 前端规则。
- 新规则在全局规则页可见，其目标 Agent、后端端口和启用状态与应用页一致。
- 域名为空、仍为占位文本、格式非法、端口未发布或规则冲突时，应用页显示明确错误且不追加本地成功记录。
- 从全局规则页修改或删除该规则后，Docker App 页面下次加载反映宿主真实状态，不继续显示过期成功状态。

### R5 错误提示与秘密边界

用户可见错误必须区分 Compose 校验、变量缺失、镜像拉取、Docker 执行、规则创建、部署后列表刷新和版本检查，不得只返回无上下文的 `broker operation failed`。错误响应、日志和审计不得包含 `.env` 值、认证材料或整份可能含秘密的 Compose 文档；允许返回非敏感的应用 ID、阶段、变量名、镜像引用和状态码。

验收：

- Docker 命令失败时，页面能识别失败阶段，并显示经过脱敏的 Docker/Compose 原因。
- `http.rule` 宿主操作失败时，页面显示规则创建阶段及可操作原因，不得只显示 `broker operation failed`。
- 部署已成功但列表刷新失败时，两种结果分别呈现，不合并为一个失败。
- 提交含密码的 `.env` 后，API 响应、控制面日志、Agent 日志和审计记录均搜索不到密码值。
- 错误不再把整份 Compose 作为引号中的错误参数返回。

### R6 Agent 重启与 generation 切换后的持久性

应用工作目录、Compose 文件、`.env`、相对目录映射和 Docker 持久数据不得因 Agent 进程重启、热更新或 docker-app generation 切换而被清理。临时执行端点可以随 generation 回收，但不得与应用数据目录共用清理生命周期。

验收：

- 部署包含 `./data` 相对目录映射的应用后重启 Agent，目录内容仍存在，应用可以按原 Compose 再次启停。
- docker-app generation 升级或回滚后，已有 Compose 和 `.env` 继续可用。
- Agent 重启本身不会执行 `docker compose down`，也不会删除 named volume、bind mount 数据或应用 workspace。

## 不做事项

### R7 不自动替用户决定秘密、规则或版本更新

本范围不自动生成数据库密码、JWT/TOTP 密钥等业务秘密；不因应用具有发布端口就自动创建公网规则；不因读取应用列表或发现新 digest 就自动替换镜像。秘密、入口域名和版本更新仍由管理员明确提交或确认。

验收：

- 未填写必填秘密时系统要求管理员提供，不生成隐式值。
- 仅部署带端口的应用不会自动出现新域名规则。
- registry 检查发现新 digest 时只提示，未获明确确认不会切换运行镜像。

## 来源

- `plugins/docker-app/README.md#Docker App plugin`：当前秘密材料、运行面与 HTTP 入口边界。
- `plugins/docker-app/assets/ui/index.html#create-form`：当前部署表单只有 Compose YAML，没有 `.env` 输入。
- `plugins/docker-app/assets/ui/app.js#createForm`：当前成功提示位于同步列表刷新之后。
- `plugins/docker-app/app_ui.go#appViewFor`：当前应用投影同步执行镜像观察，可能阻塞响应。
- `plugins/docker-app/plugin.yaml#extension_points`：当前未声明 `http.backend-provider`，因此不会进入全局提供商目录。
- `plugins/docker-app/http_offer.go#ProjectHTTPOffers`：已有 Docker 应用发布端口候选投影，但尚未接入全局提供商目录。
- `panel/frontend/src/components/RuleForm.vue#providerOptions`：全局规则表单只消费宿主 HTTP backend provider 目录。
- `panel/backend-go/internal/controlplane/service/plugin_host_resources.go#pluginHostHTTPRuleCreate`：应用页“挂 HTTP”创建标准宿主 HTTP 规则并指向 Agent 发布端口。
- 用户提供的“添加规则”与 Docker App 页面截图：确认全局提供商目录缺少 Docker 应用，以及应用页存在独立挂 HTTP 入口。
