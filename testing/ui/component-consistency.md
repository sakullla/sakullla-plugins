# 九页组件一致性审计

> 本文件由 `node testing/ui/component-consistency.mjs` 从当前页面实时生成；请勿手改。
> 检查对象为 R6 的九页：accelerator-sources、cloudflare-dns、docker-app、doh、ip-policy、reverse-l4、shadowsocks-server、waf、webdav。

- 主题：light；视口：1440×900；场景：各页主流程及必要子视图（如 mirrors、login、routing、files）；空状态优先使用页面自带的空数据场景。
- 夹具中隐藏的空数据容器（docker-app #app-empty、shadowsocks-server #app-empty、waf #event-empty）在测量时临时解除自身与祖先的 hidden，测量后立即恢复；元素列标注该测量方式。
- 结果：46 个存在的组件中 46 个通过，0 个未消除。

## 检查口径

| 组件 | kit 类名 | 检查的 `--ui-*` token |
| --- | --- | --- |
| 主按钮 | `.ui-btn`（不含 secondary、ghost、danger、icon） | 背景 `--ui-primary`、文字 `--ui-on-primary`、圆角与字号（`--sm`/`--lg` 取对应 kit token） |
| 输入 | `.ui-input` | 背景 `--ui-surface`、文字 `--ui-text`、边框 `--ui-border`、圆角 `--ui-radius-md`；字号 `--ui-text-sm`，转换器大输入允许 `--ui-control-height-lg`/`--ui-text-base` 变体 |
| 表格 | `.ui-table` | 字号 `--ui-text-sm`、表头背景 `--ui-sunken`、表头文字 `--ui-text-tertiary` |
| 徽章 | `.ui-badge` | 圆角 `--ui-radius-full`、字号 `--ui-text-xs`，背景/文字必须命中一套 kit 徽章 token |
| 对话框 | `dialog.ui-dialog` | 背景 `--ui-surface`、文字 `--ui-text`、边框 `--ui-border`、圆角 `--ui-radius-2xl` |
| 空状态 | `.ui-empty` | 背景 `--ui-surface`、边框 `--ui-border` 或状态面板的 `--ui-border-subtle`、圆角 `--ui-radius-2xl`、标题文字 `--ui-text`；夹具隐藏的空数据容器在测量时临时解除 hidden |

「已消除」表示组件使用 kit 类名、检查的 `--ui-*` token 全部命中；页面自身布局类（如栅格、宽度）不会改变组件 token，按布局类单独列出。临时解除 hidden 后仍不可见的空状态标为“未验证”，不计入已消除。

## 逐项清单

| 页面 | 场景 | 组件 | 元素 | kit 类名 | `--ui-*` token | 差异是否已消除 |
| --- | --- | --- | --- | --- | --- | --- |
| accelerator-sources | mirrors | 主按钮 | button.ui-btn | 是 | 是 | 已消除 |
| accelerator-sources | usage | 输入 | input#convert-input.ui-input | 是 | 是 | 已消除（大尺寸变体（--ui-control-height-lg、--ui-text-base）） |
| accelerator-sources | usage | 表格 | — | — | — | 不适用（页面主流程没有表格） |
| accelerator-sources | usage | 徽章 | span.ui-badge.ui-badge--plain（隐藏） | 是 | 是 | 已消除 |
| accelerator-sources | usage | 对话框 | — | — | — | 不适用（页面没有对话框） |
| accelerator-sources | mirrors | 空状态 | div.ui-empty | 是 | 是 | 已消除 |
| cloudflare-dns | mappings | 主按钮 | button#mapping-add.ui-btn | 是 | 是 | 已消除 |
| cloudflare-dns | mappings | 输入 | input#mapping-search.ui-input | 是 | 是 | 已消除 |
| cloudflare-dns | mappings | 表格 | table.ui-table | 是 | 是 | 已消除 |
| cloudflare-dns | mappings | 徽章 | span.ui-badge.ui-badge--success | 是 | 是 | 已消除 |
| cloudflare-dns | mappings | 对话框 | dialog#mapping-create.ui-dialog | 是 | 是 | 已消除 |
| cloudflare-dns | empty | 空状态 | div#mapping-empty.ui-empty | 是 | 是 | 已消除 |
| docker-app | apps | 主按钮 | button#deploy-toggle.ui-btn | 是 | 是 | 已消除 |
| docker-app | apps | 输入 | input#app-search.ui-input | 是 | 是 | 已消除 |
| docker-app | apps | 表格 | — | — | — | 不适用（页面主流程没有表格） |
| docker-app | apps | 徽章 | p.app-card-status.ui-badge | 是 | 是 | 已消除（布局类：app-card-status） |
| docker-app | files | 对话框 | dialog#files-mkdir-dialog.ui-dialog.files-dialog | 是 | 是 | 已消除（布局类：files-dialog） |
| docker-app | apps | 空状态 | div#app-empty.ui-empty（测量时临时解除 hidden） | 是 | 是 | 已消除 |
| doh | endpoint | 主按钮 | button#copy-doh-url.ui-btn.ui-btn--lg.doh-copy | 是 | 是 | 已消除（布局类：doh-copy） |
| doh | endpoint | 输入 | — | — | — | 不适用（页面主流程没有输入控件） |
| doh | endpoint | 表格 | — | — | — | 不适用（页面主流程没有表格） |
| doh | endpoint | 徽章 | span.ui-badge.ui-badge--info | 是 | 是 | 已消除 |
| doh | endpoint | 对话框 | — | — | — | 不适用（页面没有对话框） |
| doh | endpoint | 空状态 | — | — | — | 不适用（页面没有空状态） |
| ip-policy | global | 主按钮 | button.ui-btn.ip-rule-submit | 是 | 是 | 已消除（布局类：ip-rule-submit） |
| ip-policy | global | 输入 | input#rule-value.ui-input | 是 | 是 | 已消除 |
| ip-policy | global | 表格 | table.ui-table.ip-rule-table | 是 | 是 | 已消除（布局类：ip-rule-table） |
| ip-policy | global | 徽章 | span#rule-count.ui-badge.ui-badge--plain | 是 | 是 | 已消除 |
| ip-policy | global | 对话框 | dialog#source-dialog.ui-dialog | 是 | 是 | 已消除 |
| ip-policy | global | 空状态 | div#province-empty.ui-empty.ip-province-empty（隐藏） | 是 | 是 | 已消除（布局类：ip-province-empty） |
| reverse-l4 | mappings | 主按钮 | button#create-toggle.ui-btn | 是 | 是 | 已消除 |
| reverse-l4 | mappings | 输入 | input#map-name.ui-input | 是 | 是 | 已消除 |
| reverse-l4 | mappings | 表格 | — | — | — | 不适用（页面主流程没有表格） |
| reverse-l4 | mappings | 徽章 | p#map-count.ui-badge.ui-badge--plain | 是 | 是 | 已消除 |
| reverse-l4 | mappings | 对话框 | dialog#mapping-dialog.ui-dialog | 是 | 是 | 已消除 |
| reverse-l4 | empty | 空状态 | div#map-empty.ui-empty | 是 | 是 | 已消除 |
| shadowsocks-server | listens | 主按钮 | button#create-toggle.ui-btn | 是 | 是 | 已消除 |
| shadowsocks-server | listens | 输入 | input#share-host.ui-input | 是 | 是 | 已消除 |
| shadowsocks-server | routing | 表格 | table.ui-table.routing-table.routing-table--rules | 是 | 是 | 已消除（布局类：routing-table、routing-table--rules） |
| shadowsocks-server | listens | 徽章 | span.ui-badge.ui-badge--plain | 是 | 是 | 已消除 |
| shadowsocks-server | listens | 对话框 | dialog#listen-detail.ui-dialog | 是 | 是 | 已消除 |
| shadowsocks-server | listens | 空状态 | div#app-empty.ui-empty（测量时临时解除 hidden） | 是 | 是 | 已消除 |
| waf | overview | 主按钮 | button.ui-btn | 是 | 是 | 已消除 |
| waf | events | 输入 | input#event-query.ui-input | 是 | 是 | 已消除 |
| waf | events | 表格 | table.ui-table.waf-events-table | 是 | 是 | 已消除（布局类：waf-events-table） |
| waf | events | 徽章 | span#event-count.ui-badge.ui-badge--plain | 是 | 是 | 已消除 |
| waf | events | 对话框 | dialog#rule-dialog.ui-dialog | 是 | 是 | 已消除 |
| waf | events | 空状态 | div#event-empty.ui-empty（测量时临时解除 hidden） | 是 | 是 | 已消除 |
| webdav | login | 主按钮 | button.ui-btn.ui-btn--block | 是 | 是 | 已消除 |
| webdav | login | 输入 | input#login-username.ui-input | 是 | 是 | 已消除 |
| webdav | files | 表格 | table.ui-table.listing | 是 | 是 | 已消除（布局类：listing） |
| webdav | files | 徽章 | span.ui-badge.ui-badge--plain | 是 | 是 | 已消除 |
| webdav | files | 对话框 | dialog#mkdir-dialog.ui-dialog | 是 | 是 | 已消除 |
| webdav | empty | 空状态 | div#empty.ui-empty | 是 | 是 | 已消除 |

## 跨页差异

- 主按钮：9/9 页存在；类名与 token 检查全部通过；kit 变体：ui-btn--block、ui-btn--lg；页面布局类：doh-copy、ip-rule-submit。
- 输入：8/9 页存在；类名与 token 检查全部通过；token 变体：大尺寸变体（--ui-control-height-lg、--ui-text-base）；不适用：doh。
- 表格：5/9 页存在；类名与 token 检查全部通过；页面布局类：ip-rule-table、listing、routing-table、routing-table--rules、waf-events-table；不适用：accelerator-sources、docker-app、doh、reverse-l4。
- 徽章：9/9 页存在；类名与 token 检查全部通过；kit 变体：ui-badge--info、ui-badge--plain、ui-badge--success；页面布局类：app-card-status。
- 对话框：7/9 页存在；类名与 token 检查全部通过；页面布局类：files-dialog；不适用：accelerator-sources、doh。
- 空状态：8/9 页存在；类名与 token 检查全部通过；页面布局类：ip-province-empty；不适用：doh。

## 结论

九页主流程实际出现的组件均使用共享 kit 类名与 `--ui-*` token；夹具中隐藏的空数据状态按标注的临时解除 hidden 方式测量，尺寸与布局差异均落在 kit token 变体内，差异已消除。
