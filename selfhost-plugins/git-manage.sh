#!/bin/bash
set -e

# ---------- 1) multica 主仓库：本地补丁分支 ----------
cd /root/multica
git config user.name "xiaxuchen"
git config user.email "37445028+xiaxuchen@users.noreply.github.com"

# 忽略苹果元数据与备份文件
grep -q '^\._\*$' .gitignore 2>/dev/null || printf '\n._*\n*.bak*\n' >> .gitignore

git checkout -b xp/selfhost-local 2>/dev/null || git checkout xp/selfhost-local

# 提交 A：前端功能改动
git add packages/views/projects/components/project-detail.tsx
if ! git diff --cached --quiet; then
  git commit -m "feat(web): 项目页按创建时间筛选（全部/今天/昨天/本周/上周/本月）

ProjectIssues 看板上方新增创建时间筛选条，复用 IssueSurface 的 clientFilter
接缝做客户端过滤，不改服务端。" || echo "COMMIT-A-FAILED"
fi

# 提交 B：自托管部署编排
git add .gitignore docker-compose.selfhost.lan.yml docker-compose.plugin.yml
if ! git diff --cached --quiet; then
  git commit -m "chore(selfhost): 局域网覆盖与插件平台部署编排

- docker-compose.selfhost.lan.yml: 局域网暴露 + 公司 DNS + 时区（自 iMac 迁移）
- docker-compose.plugin.yml: 启用插件平台（FF_PLUGINS_V1）、插件 surface origin(:8082)、
  dev origin/host.docker.internal 与专用 CA；密钥经 .env 注入，本文件无密钥" || echo "COMMIT-B-FAILED"
fi

echo "== multica log =="
git log --oneline -5
git status --short | head -8

# ---------- 2) 插件与转发服务仓库 ----------
cd /root/multica-plugins
if [ ! -d .git ]; then
  git init -q
  git config user.name "xiaxuchen"
  git config user.email "37445028+xiaxuchen@users.noreply.github.com"
fi

cat > .gitignore <<'EOF'
key.pem
*.zip
*.log
._*
nohup.out
EOF

cat > README.md <<'EOF'
# 时间筛选插件（Multica 自托管扩展）

任务维度的时间筛选：插件包（modal 界面）+ hook 转发服务（调 multica CLI 过滤）。

## 目录
- `time-filter/` — 插件包：`multica.plugin.json` + `ui/main.js`（modal 界面）
- `helper/` — hook 转发服务（HTTPS :9090，systemd 单元见 `multica-time-filter-helper.service`）
- `*.sh` — 部署脚本：`deploy3.sh`（启服务/重建 backend）、`install4.sh`（发布+安装插件）、`e2e.sh`（全链路验证）

## 运行依赖
- backend 已启用插件平台：见 `/root/multica/docker-compose.plugin.yml`（FF_PLUGINS_V1=true + 密钥在 .env）
- helper 使用自签证书（`helper/cert.pem`，私钥不提交），backend 通过 MULTICA_PLUGIN_DEV_CA 信任
- helper 调 `/root/multica-node/bin/multica`（CLI 已登录）读取任务

## 部署顺序
1. `bash deploy3.sh`（helper 服务 + backend 配置）
2. `bash install4.sh`（发布插件包并安装到工作区）
3. `bash e2e.sh`（验证）
EOF

git add -A
if ! git diff --cached --quiet; then
  git commit -q -m "初始化：时间筛选插件（modal + ui hook + CLI 转发服务）"
fi
echo "== plugins log =="
git log --oneline | head -3
echo GIT-MANAGE-DONE
