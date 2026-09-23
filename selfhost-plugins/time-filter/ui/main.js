// 任务时间筛选 — modal surface
// 经典脚本（无 import）：由 Multica 宿主以单文档形式托管，一切经宿主桥接。
const pending = new Map();
const port = globalThis.__multicaPluginBridgePortV2;
let sequence = 0;

if (!(port instanceof MessagePort)) throw new Error("Multica surface bridge is unavailable");
delete globalThis.__multicaPluginBridgePortV2;
port.onmessage = (message) => {
  const payload = message.data;
  if (payload?.kind === "theme") return applyTheme(payload.theme);
  const entry = pending.get(payload?.id);
  if (!entry) return;
  pending.delete(payload.id);
  if (payload.ok) entry.resolve(payload.data);
  else entry.reject(new Error(payload.error));
};
port.start();

function applyTheme(theme) {
  for (const [name, value] of Object.entries(theme ?? {})) {
    document.documentElement.style.setProperty(name, value);
  }
}

function call(method, path, body) {
  const id = `r${++sequence}`;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    port.postMessage({ id, kind: "action", method, path, body });
  });
}

function resize() {
  port.postMessage({ id: `resize${Date.now()}`, kind: "ui.resize", height: document.body.scrollHeight + 16 });
}

const RANGES = [
  ["today", "今天"],
  ["yesterday", "昨天"],
  ["this_week", "本周"],
  ["last_week", "上周"],
  ["this_month", "本月"],
];
const BASES = [
  ["created", "创建时间"],
  ["schedule", "排期"],
];

let basis = "created";
let busy = false;

function btn(label, active) {
  return `<button data-x style="padding:6px 12px; cursor:pointer; border:1px solid var(--border,#ddd); border-radius:var(--radius,6px); background:${active ? "var(--primary,#111)" : "var(--background,#fff)"}; color:${active ? "var(--primary-foreground,#fff)" : "var(--foreground,#111)"}">${label}</button>`;
}

function render() {
  const root = document.getElementById("root");
  root.innerHTML = `
    <div style="padding:14px 16px; display:grid; gap:12px; min-width:520px; font: 13px/1.5 system-ui, sans-serif; color:var(--foreground,#111)">
      <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap">
        <span style="color:var(--muted-foreground,#888)">基准</span>
        ${BASES.map(([k, l]) => btn(l, basis === k).replace("data-x", `data-basis="${k}"`)).join("")}
        <span style="width:16px"></span>
        <span style="color:var(--muted-foreground,#888)">范围</span>
        ${RANGES.map(([k, l]) => btn(l, false).replace("data-x", `data-range="${k}"`)).join("")}
      </div>
      <div id="status" style="color:var(--muted-foreground,#888); min-height:1.2em"></div>
      <div id="list" style="display:grid; gap:6px; max-height:420px; overflow:auto"></div>
    </div>`;
  root.querySelectorAll("[data-basis]").forEach((el) => {
    el.onclick = () => { basis = el.dataset.basis; render(); };
  });
  root.querySelectorAll("[data-range]").forEach((el) => {
    el.onclick = () => query(el.dataset.range);
  });
  resize();
}

async function query(range) {
  if (busy) return;
  busy = true;
  const status = document.getElementById("status");
  const list = document.getElementById("list");
  status.textContent = "查询中…";
  list.innerHTML = "";
  try {
    const resp = await call("POST", "/hooks/query", { range, basis });
    const payload = resp && resp.items ? resp : resp?.data?.items ? resp.data : resp;
    const items = payload?.items ?? [];
    const window = payload?.window ?? {};
    status.textContent = `${payload?.label ?? range}（${basis === "created" ? "创建时间" : "排期"} ${window.start ?? "?"} ~ ${window.end ?? "?"}）共 ${payload?.count ?? items.length} 条`;
    if (!items.length) {
      list.innerHTML = `<div style="color:var(--muted-foreground,#888)">没有符合条件的任务。</div>`;
    } else {
      list.innerHTML = items
        .map(
          (it) => `<div style="display:flex; gap:10px; padding:6px 8px; border:1px solid var(--border,#eee); border-radius:var(--radius,6px); align-items:baseline">
            <span style="font-weight:600; white-space:nowrap">${esc(it.identifier)}</span>
            <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">${esc(it.title)}</span>
            <span style="color:var(--muted-foreground,#888); white-space:nowrap">${esc(it.status)}</span>
            <span style="color:var(--muted-foreground,#888); white-space:nowrap">${esc(it.date)}</span>
          </div>`,
        )
        .join("");
    }
  } catch (error) {
    status.textContent = `查询失败：${error.message}`;
  }
  busy = false;
  resize();
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

document.body.innerHTML = `<div id="root"></div>`;
render();
