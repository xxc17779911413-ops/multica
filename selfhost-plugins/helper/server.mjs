// 任务时间筛选 — 插件 hook 转发服务
// 接收 Multica 宿主的 ui-trigger hook 调用，内部调用 multica CLI 完成时间筛选。
import { createServer as createHTTPServer } from "node:http";
import { createServer as createHTTPSServer } from "node:https";
import { readFileSync } from "node:fs";
import { execFile } from "node:child_process";

const PORT = Number(process.env.PORT ?? 9090);
const CLI = process.env.MULTICA_CLI ?? "/root/multica-node/bin/multica";
const TZ_OFFSET_MIN = 480; // Asia/Shanghai

const RANGE_LABELS = {
  today: "今天",
  yesterday: "昨天",
  this_week: "本周",
  last_week: "上周",
  this_month: "本月",
};

function shanghaiParts(d) {
  const t = new Date(d.getTime() + TZ_OFFSET_MIN * 60_000);
  return { y: t.getUTCFullYear(), m: t.getUTCMonth(), d: t.getUTCDate(), dow: t.getUTCDay() };
}

function localMidnight(parts) {
  return new Date(Date.UTC(parts.y, parts.m, parts.d) - TZ_OFFSET_MIN * 60_000);
}

function computeWindow(range, now = new Date()) {
  const p = shanghaiParts(now);
  const todayStart = localMidnight(p);
  const day = 86_400_000;
  switch (range) {
    case "today":
      return { start: todayStart, end: new Date(now.getTime() + 60_000), startDate: isoDate(todayStart), endDate: isoDate(now) };
    case "yesterday":
      return { start: new Date(todayStart - day), end: todayStart, startDate: isoDate(new Date(todayStart - day)), endDate: isoDate(new Date(todayStart - day)) };
    case "this_week": {
      const monday = new Date(todayStart - ((p.dow + 6) % 7) * day);
      return { start: monday, end: new Date(now.getTime() + 60_000), startDate: isoDate(monday), endDate: isoDate(now) };
    }
    case "last_week": {
      const monday = new Date(todayStart - ((p.dow + 6) % 7) * day);
      return { start: new Date(monday - 7 * day), end: monday, startDate: isoDate(new Date(monday - 7 * day)), endDate: isoDate(new Date(monday - day)) };
    }
    case "this_month": {
      const first = localMidnight({ y: p.y, m: p.m, d: 1 });
      return { start: first, end: new Date(now.getTime() + 60_000), startDate: isoDate(first), endDate: isoDate(now) };
    }
    default:
      throw new Error(`unknown range: ${range}`);
  }
}

function isoDate(d) {
  const t = new Date(d.getTime() + TZ_OFFSET_MIN * 60_000);
  return t.toISOString().slice(0, 10);
}

function runCLI(args) {
  return new Promise((resolve, reject) => {
    execFile(CLI, args, { maxBuffer: 32 * 1024 * 1024, timeout: 60_000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`CLI failed: ${err.message} ${String(stderr).slice(0, 300)}`));
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`CLI JSON parse failed: ${String(stdout).slice(0, 200)}`));
      }
    });
  });
}

async function fetchAll() {
  const FIELDS = "id,identifier,title,status,created_at,start_date,due_date";
  const out = [];
  for (let page = 0; page < 6; page++) {
    const data = await runCLI([
      "issue", "list", "--output", "json", "--limit", "100", "--offset", String(page * 100),
      "--fields", FIELDS, "--sort", "created_at", "--direction", "desc",
    ]);
    const issues = Array.isArray(data) ? data : data.issues ?? [];
    out.push(...issues);
    const hasMore = Array.isArray(data) ? issues.length === 100 : Boolean(data.has_more);
    if (!hasMore || issues.length < 100) break;
  }
  return out;
}

function filterItems(issues, basis, w) {
  const startMs = w.start.getTime();
  const endMs = w.end.getTime();
  const items = [];
  for (const it of issues) {
    if (basis === "schedule") {
      const d = (it.start_date ?? "").slice(0, 10);
      if (d && d >= w.startDate && d <= w.endDate) {
        items.push({ identifier: it.identifier, title: it.title, status: it.status, date: `排期 ${d}` });
      }
    } else {
      const t = Date.parse(it.created_at);
      if (Number.isFinite(t) && t >= startMs && t < endMs) {
        items.push({ identifier: it.identifier, title: it.title, status: it.status, date: `创建 ${isoDate(new Date(t))}` });
      }
    }
  }
  return items;
}

const tlsCert = process.env.MULTICA_HOOK_TLS_CERT;
const tlsKey = process.env.MULTICA_HOOK_TLS_KEY;
const createServer = tlsCert && tlsKey
  ? (handler) => createHTTPSServer({ cert: readFileSync(tlsCert), key: readFileSync(tlsKey) }, handler)
  : createHTTPServer;

const server = createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true }));
  }
  if (req.method !== "POST" || !req.url?.startsWith("/query")) {
    res.writeHead(404).end();
    return;
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      const input = body.input ?? {};
      const range = String(input.range ?? "today");
      const basis = input.basis === "schedule" ? "schedule" : "created";
      const w = computeWindow(range);
      const issues = await fetchAll();
      const items = filterItems(issues, basis, w);
      const payload = {
        range,
        basis,
        label: RANGE_LABELS[range] ?? range,
        window: { start: w.startDate, end: w.endDate },
        scanned: issues.length,
        count: items.length,
        items,
      };
      console.log(`[${new Date().toISOString()}] ${range}/${basis} -> ${items.length}/${issues.length}`);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    } catch (error) {
      console.error(error);
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(error.message ?? error) }));
    }
  });
});

server.listen(PORT, () => console.log(`time-filter helper listening on ${tlsCert ? "https" : "http"}://:${PORT}`));
