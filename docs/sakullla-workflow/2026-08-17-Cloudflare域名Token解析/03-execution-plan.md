---
# Runtime 只读取这一处文件头机器区；全部可执行 Recipe/DAG/验证字段都在这里填写。
format: execution_plan
tasks:
  - id: T-map-resolve
    goal: 插件按规范化域名后缀保存映射并用最长后缀解析，调用方按域名取 Token，未命中返回其提供的兜底 Token，且不回显明文
    depends_on: []
    covers: [R1, R2, R4, R5, R6]
    scope:
      - plugins/cloudflare-dns
      - testing/integration/cloudflare-dns
    outcomes:
      - 两个不同后缀可解析到不同 Token 引用，也可解析到同一 Token 引用
      - 仅配置 example.com 时 example.com 与 www.example.com 命中该映射；同时配置 api.example.com 时后者取更长后缀
      - 非后缀不命中；重复规范化后缀被拒绝
      - 调用方按所涉域名询问解析入口得到该域名应使用的 Token，而不是读取单一全局 secret_ref
      - 映射删除或 Token 轮换后，下一次按同一域名解析得到新结果
      - 未命中时返回本次调用提供的兜底 Token；命中后不得改用兜底 Token
      - 无命中且无兜底时失败，且可看出该域名没有可用 Token
      - 列表、状态、错误和审计只有后缀与元数据，没有 Token 明文
    verify:
      - go test ./plugins/cloudflare-dns ./testing/integration/cloudflare-dns ./internal/pluginmanifest
    test: extend
  - id: T-mapping-ui
    goal: 插件提供专门映射管理界面，获授权可完成 CRUD，未授权被明确拒绝且不回显 Token
    depends_on: [T-map-resolve]
    covers: [R3]
    scope:
      - plugins/cloudflare-dns
    outcomes:
      - 获授权管理员可新增、改后缀、轮换 Token、删除映射，刷新或重启后仍是最后一次成功保存
      - 未授权看不到写入入口，直达地址得到明确拒绝而不是空白页
      - 保存后再打开，列表、详情和编辑框都不预填 Token 明文
      - 删除或轮换需确认，取消不改状态
    verify:
      - go test ./plugins/cloudflare-dns
    test: new
delivery_verification:
  plugin-resolver:
    command: go test ./plugins/cloudflare-dns ./testing/integration/cloudflare-dns ./internal/pluginmanifest
  mapping-ui:
    command: go test ./plugins/cloudflare-dns
---
# Execution Plan

本仓 workflow 只能写入 `sakullla-plugins`。T-map-resolve 落地映射、按域名解析、调用方合同、未命中兜底和脱敏；T-mapping-ui 在本插件内提供专门管理界面。相邻宿主里把 ACME/DDNS 接到该解析入口、以及把管理界面挂进面板侧栏，超出本仓 scope，需在 `nginx-reverse-emby` 另开交付。R7–R10 靠方案排除面覆盖。
