# 上游同步对比（2026-10-13）

本次同步核心代码与构建修复，保留本仓库的规则、配置模板及仓库/镜像发布地址。前端使用本仓库配套的 subweb 构建产物，服务地址迁移至 `miaoceo.com`。完整后端编译由 GitHub Actions 执行。

## 对比依据

- 本地起点：`d53ecae`，原 `main` / `origin/main`。
- 上游：`https://github.com/LM-Firefly/subconverter.git` 的 `main`，完整提交 `5f6e219` 以 `git rev-parse upstream/main` 为准。
- 共同祖先：`5b8d3af0d7b659e3ff6029560e4a6811538a9c21`。
- 上游有 12 个本地历史中不存在的非合并提交，但部分旧功能本地已经有等价实现。本次以两个分支的实际文件差异为准，未直接整仓库 merge。

## 已同步

| 范围 | 实际变化 |
| --- | --- |
| 协议模型、解析及导出 | 新增 GostRelay、OpenVPN、SSH、Tailscale、ZeroTier、ShadowQuic、EasyTier 类型；扩展已有 VLESS、VMess、TUIC、Hysteria2、WireGuard、AnyTLS 等参数。不同目标客户端支持的字段和协议仍不同。 |
| 订阅加载 | 新增 `agekey` 参数及 age X25519 解密实现，增加 OpenSSL 编译和链接依赖。原自定义 User-Agent 和 Emoji 处理逻辑仍在。 |
| Surge / Surfboard / 规则转换 | Surge 自动识别和默认版本更新；增加域名与非域名规则拆分；Surfboard 使用独立导出函数；调整部分规则类型和参数。 |
| JavaScript 绑定 | 随协议模型同步 QuickJS 字段读写。 |
| CMake | 更新静态依赖查找、Clang 警告选项、MinGW 链接配置和 QuickJS 兼容宏；加入 age 源文件与 OpenSSL。 |
| Alpine / macOS / Windows 构建脚本 | 同步构建目录隔离、依赖构建及安装、并发参数、严格错误处理和打包路径修复。第三方依赖仓库 URL 没有改换来源。 |
| 规则更新器 | `scripts/update_rules.py` 新增可选 `exclude` 过滤；现有 `rules_config.conf` 保持原样。 |
| Docker | 同步多阶段构建，同时改为 `COPY` 当前工作区源码，防止重新克隆上游或漏掉本地修改；版本使用已有 `VERSION` / `SHA` 构建参数；保留原 maintainer。新增 `.dockerignore` 排除 Git 元数据和构建临时目录。 |
| GitHub Actions | Docker 构建上下文改为仓库根目录，指定 `scripts/Dockerfile`；各架构先推送摘要，全部成功后合并发布；amd64 镜像运行 SS、VLESS、AnyTLS 转换到 Clash 和 sing-box 的检查。 |
| 配套前端 | 使用 `xuanranran/subweb` 的本地生产构建更新 `base/sub-web/`；API 与短链地址改为 `miaoceo.com`，没有引入上游的前端项目。 |

核心改动来自 16 个 `src` 文件（含 2 个新增 age 文件）以及 6 个构建/规则更新文件；另外新增 `.dockerignore` 和本文档。

## 保留未同步

| 路径 | 保留内容 / 原因 |
| --- | --- |
| `.github/workflows/submodule.yml` | 继续从 `xuanranran/subweb` 和 `xuanranran/Rules` 获取内容。 |
| `.github/workflows/docker.yml` 的发布地址 | 继续发布到 `lovinyarn/subconverter` 和 `ghcr.io/xuanranran/subconverter`；只调整构建上下文、摘要推送、所需权限和运行检查。 |
| `.github/` 其他文件 | 不带入上游工作流触发条件、清理任务、Action 版本和问题反馈地址变动。 |
| `.gitmodules` | 保留现状。其 Rules URL 本来就是 `LM-Firefly/Rules.git`；本次没有改写它。 |
| `scripts/rules_config.conf` | 保留 `xuanranran/Rules`、现有匹配范围和配置复制行为。 |
| `scripts/merge_manifest.py` | 保留 `lovinyarn/subconverter` 镜像地址。 |
| `base/rules/`、`base/config/`、`base/snippets/`、`base/base/`、`base/pref.example.toml` | 保留现有规则与模板，不覆盖成上游版本。 |
| 前端仓库来源 | 保留 `xuanranran/subweb`，`base/sub-web/` 使用该项目的生产构建更新。 |
| README、辅助启动脚本、对比工具 | 保留本地版本。 |

## 需要关注的行为变化

1. `target=surge` 未传 `ver` 或传入无效版本时，默认由 3 改为 5；自动识别也偏向新版 Surge。旧客户端需要明确指定版本并验证输出。
2. `classic` 在代码中改为 `use_domain_set`，同时传给 Clash 和 Surge 生成流程；Surge 调用处取反（`!ext.use_domain_set`）。这会影响远程规则拆分，不能仅凭参数名称理解为旧版行为完全相同。
3. 源码现在需要 OpenSSL 开发库。静态依赖选项默认由 OFF 改为 ON，macOS 构建脚本则明确关闭该选项。
4. 原来的 `ua`、`xudp`、WireGuard 单链接输出和 Emoji 处理实现仍在；当前源码与上游对应文件一致。
5. 上游提到的 VLESS、TUIC、WireGuard、Masque、Mieru、Sudoku、TrustTunnel、AnyTLS 等并非本次全部首次引入：本地此前已支持其中一些，本次补充参数、格式解析和导出实现。

## 验证

- `git diff --check` 通过。
- 三个平台的 Bash 构建脚本通过 `bash -n` 语法检查。
- Python 规则更新器通过语法检查和临时目录行为验证：排除文件、保留目录结构、扁平复制及未配置排除项时的复制行为。
- 核对 `src` 与上游文件一致，包括新增 age 源文件。
- 核对 `.gitmodules`、规则、配置模板、`rules_config.conf`、`merge_manifest.py` 相对原 HEAD 均无修改；工作流与前端仅包含上述部署调整。
- subweb 的 `npm ci` 与生产构建通过；新版前端已部署到 Debian，配置文件与首页资源通过内网验证，并保留备份。
- `sub.miaoceo.com` 与 `api.miaoceo.com` 均通过 SS、VLESS、AnyTLS 到 Clash 和 sing-box 的转换检查。
- `i.miaoceo.com` 通过短链创建、CORS、302 跳转及最终订阅内容的端到端检查（使用自建测试节点，不涉及真实订阅）。
- Debian 本地构建已通过 CMake 配置，但并行编译期间服务器出现内存压力及 SSH/HTTP 超时；后端镜像未切换。完整镜像构建和新版后端检查转交 GitHub Actions，不将配置检查或旧版后端检查视为新版编译成功。
