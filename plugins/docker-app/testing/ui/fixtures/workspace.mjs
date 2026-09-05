// Deliberately synthetic data. These fixtures are never host acceptance evidence.
export const agents = [
  { id: "node-a", name: "节点 A", online: true },
  { id: "node-b", name: "节点 B", online: true },
  { id: "offline", name: "离线节点", online: false },
  { id: "missing", name: "缺少 Docker", online: true },
  { id: "unavailable", name: "执行不可用", online: true },
  { id: "denied", name: "无权限节点", online: true },
  { id: "failed", name: "检测失败节点", online: true },
];

export const makeApp = (id, agent = "node-a", overrides = {}) => ({
  id, agent_id: agent, name: id, status: "运行中", version: "nginx:1.27",
  compose: 'services:\n  web:\n    image: nginx:1.27\n    ports:\n      - "8080:80"\n',
  services: ["web"], ports: [8080], rules: [],
  actions: [{ id: "stop", label: "停止" }, { id: "restart", label: "重启" }, { id: "delete", label: "删除" }],
  ...overrides,
});

export const longApp = makeApp("long-application-" + "identity-".repeat(8), "node-a", {
  version: "registry.example.test/" + "namespace/".repeat(14) + "image:release-2026",
  services: ["web", "database", "cache"], ports: [8080, 8081, 9000, 9001, 9002, 9003],
});

export const engineFor = (id) => ({
  agent_id: id, state: id === "missing" ? "missing" : id === "unavailable" ? "report-offline" : id === "failed" ? "detection-failed" : "ready",
  online: !["unavailable", "failed"].includes(id), ready: !["missing", "unavailable", "failed"].includes(id),
  ...(!["missing", "unavailable", "failed"].includes(id) ? { version: "27.1.1" } : {}),
  ...(id === "missing" ? { command: { script: "curl -fsSL https://get.docker.com | sh" } } : {}),
});
