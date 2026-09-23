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
