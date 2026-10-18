# 九页键盘检查

> 本文件由 `node testing/ui/keyboard-checks.mjs` 从当前页面实时生成；请勿手改。
> 检查对象为 R6 的九页：accelerator-sources、cloudflare-dns、docker-app、doh、ip-policy、reverse-l4、shadowsocks-server、waf、webdav。

- 主题：light；视口：1440×900；按键通过 CDP 真实派发 `Tab`、`Enter`、`Escape`。
- 焦点可见：`:focus-visible` 为真，且存在 outline 或 box-shadow；对话框页的 Esc 还必须把焦点还给触发元素。
- 无对话框页面不伪造“关闭”结果：记录 Esc 后无模态层、焦点保持。
- 每页只记录下表所列的一个主流程键盘路径；页面其它交互不在本证据覆盖范围内。

## 结果汇总

| 页面 | Tab 焦点可见 | Enter 触发 | Esc 实际效果 |
| --- | --- | --- | --- |
| accelerator-sources | 通过 | 通过 | 通过 |
| cloudflare-dns | 通过 | 通过 | 通过 |
| docker-app | 通过 | 通过 | 通过 |
| doh | 通过 | 通过 | 通过 |
| ip-policy | 通过 | 通过 | 通过 |
| reverse-l4 | 通过 | 通过 | 通过 |
| shadowsocks-server | 通过 | 通过 | 通过 |
| waf | 通过 | 通过 | 通过 |
| webdav | 通过 | 通过 | 通过 |

汇总：27/27 项通过，0 项失败。

## 页面覆盖范围

| 页面 | 本次覆盖的主流程操作 |
| --- | --- |
| accelerator-sources | 链接转换主流程：Tab 到 #convert-input，填入链接后 Enter 复制结果；Esc 清空输入并隐藏结果 |
| cloudflare-dns | 映射主流程：Tab 到 #mapping-add，Enter 打开新建映射对话框；Esc 关闭并还焦 |
| docker-app | 应用主流程：Tab 到 #deploy-toggle，Enter 打开创建抽屉；Esc 关闭并还焦 |
| doh | 复制主操作：Tab 到 #copy-doh-url，Enter 触发复制状态；Esc 无对话框且焦点保持 |
| ip-policy | 规则数据主流程：Tab 到 #add-source，Enter 打开来源对话框；Esc 关闭并还焦 |
| reverse-l4 | 映射主流程：Tab 到 #create-toggle，Enter 打开映射对话框；Esc 关闭并还焦 |
| shadowsocks-server | 监听主流程：Tab 到 #create-toggle，Enter 打开创建监听对话框；Esc 关闭并还焦 |
| waf | 事件主流程：Tab 到首条事件按钮，Enter 打开事件详情对话框；Esc 关闭并还焦 |
| webdav | 文件主流程：Tab 到 #mkdir-button，Enter 打开新建文件夹对话框；Esc 关闭并还焦 |

## 逐项记录

| 页面 | 场景 | 元素 | 操作 | 结果 |
| --- | --- | --- | --- | --- |
| accelerator-sources | usage | #convert-input | Tab | 通过：Tab ×3 → input#convert-input.ui-input（:focus-visible=真，box-shadow） |
| accelerator-sources | usage | #convert-input | Enter | 通过：Enter 提交链接转换：结果区可见，复制提示「已复制」（data-state=copied） |
| accelerator-sources | usage | #convert-input | Esc | 通过：页面无对话框；Esc 清空链接输入并隐藏转换结果，焦点仍在 input#convert-input.ui-input（:focus-visible=真，box-shadow） |
| cloudflare-dns | mappings | #mapping-add | Tab | 通过：Tab ×2 → button#mapping-add.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| cloudflare-dns | mappings | #mapping-add | Enter | 通过：打开 #mapping-create，焦点进入对话框（input.ui-input（:focus-visible=真，box-shadow）） |
| cloudflare-dns | mappings | #mapping-add | Esc | 通过：关闭 #mapping-create，焦点回到 button#mapping-add.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| docker-app | apps | #deploy-toggle | Tab | 通过：Tab ×4 → button#deploy-toggle.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| docker-app | apps | #deploy-toggle | Enter | 通过：打开 #app-create，焦点进入对话框（input.ui-input（:focus-visible=真，box-shadow）） |
| docker-app | apps | #deploy-toggle | Esc | 通过：关闭 #app-create，焦点回到 button#deploy-toggle.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| doh | endpoint | #copy-doh-url | Tab | 通过：Tab ×1 → button#copy-doh-url.ui-btn.ui-btn--lg.doh-copy（:focus-visible=真，outline 2px，box-shadow） |
| doh | endpoint | #copy-doh-url | Enter | 通过：复制状态已显示（成功或失败提示均已触发） |
| doh | endpoint | #copy-doh-url | Esc | 通过：页面无对话框；Esc 后未出现模态层，焦点仍在 button#copy-doh-url.ui-btn.ui-btn--lg.doh-copy（:focus-visible=真，outline 2px，box-shadow） |
| ip-policy | data | #add-source | Tab | 通过：Tab ×21 → button#add-source.ui-btn.ui-btn--secondary（:focus-visible=真，outline 2px，box-shadow） |
| ip-policy | data | #add-source | Enter | 通过：打开 #source-dialog，焦点进入对话框（button#source-close.ui-btn.ui-btn--icon.ui-btn--ghost（:focus-visible=真，outline 2px，box-shadow）） |
| ip-policy | data | #add-source | Esc | 通过：关闭 #source-dialog，焦点回到 button#add-source.ui-btn.ui-btn--secondary（:focus-visible=真，outline 2px，box-shadow） |
| reverse-l4 | mappings | #create-toggle | Tab | 通过：Tab ×1 → button#create-toggle.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| reverse-l4 | mappings | #create-toggle | Enter | 通过：打开 #mapping-dialog，焦点进入对话框（input#map-name.ui-input（:focus-visible=真，box-shadow）） |
| reverse-l4 | mappings | #create-toggle | Esc | 通过：关闭 #mapping-dialog，焦点回到 button#create-toggle.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| shadowsocks-server | listens | #create-toggle | Tab | 通过：Tab ×3 → button#create-toggle.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| shadowsocks-server | listens | #create-toggle | Enter | 通过：打开 #create-dialog，焦点进入对话框（input.ui-input（:focus-visible=真，box-shadow）） |
| shadowsocks-server | listens | #create-toggle | Esc | 通过：关闭 #create-dialog，焦点回到 button#create-toggle.ui-btn（:focus-visible=真，outline 2px，box-shadow） |
| waf | events | #event-list tr button | Tab | 通过：Tab ×7 → button.ui-btn.ui-btn--ghost.ui-btn--sm（:focus-visible=真，outline 2px，box-shadow） |
| waf | events | #event-list tr button | Enter | 通过：打开 #event-dialog，焦点进入对话框（button.ui-btn.ui-btn--icon.ui-btn--ghost（:focus-visible=真，outline 2px，box-shadow）） |
| waf | events | #event-list tr button | Esc | 通过：关闭 #event-dialog，焦点回到 button.ui-btn.ui-btn--ghost.ui-btn--sm（:focus-visible=真，outline 2px，box-shadow） |
| webdav | files | #mkdir-button | Tab | 通过：Tab ×4 → button#mkdir-button.ui-btn.ui-btn--secondary（:focus-visible=真，outline 2px，box-shadow） |
| webdav | files | #mkdir-button | Enter | 通过：打开 #mkdir-dialog，焦点进入对话框（input#mkdir-name.ui-input（:focus-visible=真，box-shadow）） |
| webdav | files | #mkdir-button | Esc | 通过：关闭 #mkdir-dialog，焦点回到 button#mkdir-button.ui-btn.ui-btn--secondary（:focus-visible=真，outline 2px，box-shadow） |

## 结论

以上 9 页共记录 27 项键盘操作，逐页覆盖范围见「页面覆盖范围」；未列出的交互路径不在本次键盘检查范围内。无对话框页面的 Esc 行为按实际观察记录，不伪造关闭结果。
