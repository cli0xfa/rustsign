# RustSign

基于 Tauri 2 + Rust + React 的 Windows PE 文件数字签名桌面工具。支持 Authenticode 签名、验证、时间戳、证书管理及本地 TSA 服务。

## 功能

### 数字签名

- 对 `.exe`、`.dll`、`.sys`、`.ocx`、`.cab` 等 PE 文件进行 Authenticode 签名
- 支持**应用模式**（普通软件签名）和**驱动模式**（内核驱动签名，自动下载交叉证书）
- 支持 SHA-1、SHA-256、SHA-384、SHA-512 四种摘要算法
- 支持**追加签名**：在已有签名基础上叠加多个签名，Windows 资源管理器可全部识别
- 签名后可调整签名顺序、删除指定签名
- 内置 RFC 3161 时间戳支持，可配置远程 TSA 服务器地址

### 证书管理

- 支持导入 PEM（可含私钥）、PFX/P12（含密码保护）及 CRT/CER 公钥证书
- 支持导出证书为 PEM、PFX 或 PVK+SPC 格式
- 本地 JSON 数据库存储，数据目录通过系统标准用户数据目录解析（Windows 为 `%LOCALAPPDATA%/rustsign/`）
- 支持生成**自签名测试证书**（根证书 + 签名证书），可用于开发测试
- 支持基于已有 CA 证书**签发从属证书**

### 本地时间戳服务 (TSA)

- 内置 RFC 3161 兼容的本地时间戳授权服务器
- 可绑定自定义地址和端口
- 使用自签名 TSA 证书签发时间戳令牌
- 适用于离线环境或无外网 TSA 的场景

### 签名验证

- 解析 PE 文件的证书表，验证 Authenticode 签名有效性
- 展示签名者、颁发者、摘要算法、是否有时间戳等详细信息
- 支持识别嵌套签名（追加签名场景）

### 签名规则

- 保存默认签名配置：签名模式、摘要算法、时间戳 URL、交叉证书路径
- 自动应用预设规则，减少重复配置

## 界面预览

应用采用三个一级工作区；生成证书位于证书库内：

| 页面 | 功能 |
|------|------|
| 文件工作台 | 围绕同一个文件进行签名、验证与签名管理；跨页保留草稿 |
| 证书库 | 搜索、状态筛选、排序、导入导出、删除及详情抽屉 |
| 证书库 → 生成测试证书 | 生成根 CA 与签名证书，或通过已有 CA 签发子证书；显示实际输出路径 |
| 本地时间戳服务 | 配置、启停、服务状态及本地时区的自定义时间 |

文件操作默认修改原文件，替换已有签名及删除操作会显示确认。验证结果仅代表 CMS 签名与 Authenticode 摘要检查，不代表 Windows 信任链或驱动加载策略通过。主题和语言设置位于顶部「视图」菜单。

应用使用自定义标题栏、应用菜单与窗口菜单，支持 Windows 11 最大化按钮悬停分屏。主窗口在主题与界面外壳就绪后显示；数据在页内加载。启动失败时提供原生重试／退出提示。最小窗口为 500×480，窄窗口自动折叠菜单和导航。执行中的任务会阻止退出；本地 TSA 运行时，确认后停止服务再退出。

常用快捷键：`Ctrl+O` 打开文件，`Ctrl+Shift+I` 导入证书，`Ctrl+1/2/3` 切换工作区，`Alt+Space` 打开窗口菜单，`F1` 查看快捷键，`Alt+F4` 退出。

## 技术栈

| 层 | 技术 |
|----|------|
| 桌面框架 | Tauri 2 |
| 后端 | Rust (signing, crypto, PE parsing, CMS/PKCS#7) |
| 前端 | React 19 + TypeScript + Tailwind CSS 3 |
| UI 组件 | Lucide React 图标 + Sonner 通知 |
| 构建 | Vite 6 |

### 核心依赖

- `authenticode` — Authenticode 摘要计算
- `cms` — CMS/PKCS#7 签名结构构建
- `goblin` — PE 文件解析与证书表读写
- `x509-cert` + `der` — X.509 证书解析与 DER 编解码
- `rsa` + `sha2` — RSA 签名与哈希
- `reqwest` — HTTP 客户端（远程时间戳）
- `tiny_http` — 本地 TSA 服务器

## 开发

### 环境要求

- Rust stable（项目使用 edition 2024）
- Node.js 22+
- Windows 10/11、macOS 或 Linux；桌面构建需安装各平台的 [Tauri 系统依赖](https://v2.tauri.app/start/prerequisites/)

### 跨平台支持与边界

签名、验证、证书导入导出、证书生成、远程时间戳和本地 TSA 均使用跨平台 Rust 实现。时间戳模块不调用 Win32 API；HTTP/HTTPS 使用 `reqwest` + `rustls`，沿用系统信任根与代理设置，无需系统 OpenSSL 作为 HTTP TLS 后端。

| 范围 | 实现与限制 |
|------|------------|
| PE 签名与验证 | 直接解析 PE/CMS 数据，可在不同宿主系统上处理 Windows PE 文件；不调用 Windows 信任链或驱动加载策略 API |
| RFC 3161 时间戳 | Rust 构造请求、HTTP 传输、ASN.1 解析和令牌嵌入；保留 TSA 令牌原始 DER 与 Authenticode 时间戳属性，兼容 Windows 文件格式 |
| 本地 TSA | `tiny_http` + Rust 加密实现，支持系统时间或固定 UTC 时间；界面将本地时间转换为 Unix 时间戳 |
| 本地数据 | Windows：`%LOCALAPPDATA%/rustsign/`；macOS：`~/Library/Application Support/rustsign/`；Linux：`$XDG_DATA_HOME/rustsign/`，未设置时为 `~/.local/share/rustsign/` |
| 原生窗口 | Win32/WebView2 代码仅在 Windows 编译，用于 Snap、命中测试和首帧显示；其他平台使用 Tauri 窗口 API |
| 测试 | `npm run test:rust` 通过 Node.js 创建隔离目录，Windows/macOS/Linux 通用；原生冒烟、窗口按钮和录屏 PowerShell 脚本仅适用于 Windows |
| 安装包 | 当前发布配置和 Release 仍生成 Windows NSIS 安装包；其他平台可用 `cargo tauri build --no-bundle` 构建可执行程序，未配置对应安装包 |

交叉证书缓存同样位于上述数据目录的 `cross-certs/` 中，遵循调试构建的 `RUSTSIGN_DATA_DIR` 隔离设置。证书导入记录引用本机原始文件路径；迁移到另一台机器或另一操作系统时需重新导入证书。

### 安装 Tauri CLI

```powershell
cargo install tauri-cli --version "^2"
```

### 启动开发模式

```powershell
npm install
cargo tauri dev
```

### 编译检查

```powershell
cargo check              # Rust 编译检查
cargo clippy --package rustsign # 代码检查
npx tsc --noEmit               # TypeScript 类型检查
npm test                      # Vitest + React Testing Library
npm run test:e2e               # 构建并运行 Playwright（首次需 npx playwright install chromium）
npm run test:rust              # 完整 Rust 回归，自动隔离证书数据库与配置
npm run test:native            # Windows WebView2 / Tauri IPC 原生冒烟，使用临时文件副本
powershell -File scripts/test-window-chrome.ps1 # 原生按钮消息与窗口菜单，报告物理鼠标验收是否可用
powershell -File scripts/capture-startup.ps1 -Output artifacts/startup-after.mp4 # 60fps 可见启动录屏
powershell -File scripts/test-startup-failure.ps1 # 在 test:native 生成的测试构建上验证启动超时提示
```

自动测试的浏览器截图位于 `artifacts/`，Windows 原生冒烟报告位于 `artifacts/native-smoke.json`。`desktop-smoke` Cargo feature 仅用于原生测试，默认构建不包含测试命令。调试构建可通过 `RUSTSIGN_DATA_DIR` 指定隔离数据目录，发布构建始终使用对应系统的本地数据位置。

完整 Rust 测试请通过 `npm run test:rust` 运行，以免测试操作个人证书数据库。根 CA 模式会输出可用于签发子证书的 `test_root_ca.pfx`，其密码与本次生成配置一致；旧版自签名测试证书生成库接口继续保留。

时间戳回归使用本机临时端口上的 TSA，覆盖四种摘要算法、固定时间、带空格与中文的文件路径、PE 签名与摘要验证以及时间戳消息摘要匹配，无需访问公网。ASN.1 测试另覆盖令牌 DER 保留、异常长度和时间戳属性替换。

历史商业驱动证书的两项回归需要可选的 `test_data/1.pfx`，或通过 `RUSTSIGN_TEST_DRIVER_PFX` 指定该证书路径；未提供时会跳过。它们不再引用开发者机器的盘符或个人缓存。CMS 结构断言在所有平台执行，调用 `Get-AuthenticodeSignature` 的原生检查仅在 Windows 执行。

### 发布构建

```powershell
cargo tauri build         # 生成 NSIS 安装包
```

Windows 安装包位于 `target/release/bundle/nsis/`。

## 项目结构

```
├── src/                    # React 前端
│   ├── components/         # UI 组件
│   ├── lib/                # Tauri 命令封装
│   ├── types/              # TypeScript 类型定义
│   └── i18n/               # 国际化文本
├── src-tauri/              # Rust 后端
│   ├── src/                # 源码
│   │   ├── lib.rs          # 签名编排入口
│   │   ├── signer.rs       # CMS/PKCS#7 签名创建
│   │   ├── verify.rs       # 签名验证与解析
│   │   ├── pe.rs           # PE 文件证书表读写
│   │   ├── crypto.rs       # 证书/私钥加载
│   │   ├── cert_manager.rs # 证书数据库 CRUD
│   │   ├── cert_gen.rs     # 测试证书生成
│   │   ├── cross_cert.rs   # 交叉证书下载
│   │   ├── timestamp.rs    # RFC 3161 时间戳
│   │   ├── local_tsa.rs    # 本地 TSA 服务器
│   │   └── rules.rs        # 默认签名规则
│   └── tests/              # 集成测试
├── test_data/              # 测试用证书与 PE 文件
└── Cargo.toml              # Rust 工作区配置
```

## CI/CD

- **CI**：每次 push/PR 在 Windows、Ubuntu 和 macOS 上运行 TypeScript 类型检查、ESLint、Prettier 格式检查、前端与浏览器测试、Rust 测试、Clippy、rustfmt；新增平台的实际通过情况以 CI 运行结果为准
- **Release**：推送与 `src-tauri/tauri.conf.json`、`src-tauri/Cargo.toml` 版本一致的 `v*` 标签；CI 全部通过后自动编译 NSIS 安装包及可执行文件，并生成 GitHub Release 和发布说明

发布新版本时，先同步更新 `src-tauri/tauri.conf.json` 与 `src-tauri/Cargo.toml` 中的版本号，再创建并推送对应标签，例如 `v0.3.1`。版本号必须与标签完全一致。

## 更新日志

### v0.3.1

- 时间戳及交叉证书的 HTTPS 客户端改用 rustls，保留系统信任根与代理设置，减少对平台原生 TLS 后端的依赖
- 加固时间戳响应 DER 长度解析，保留 TSA 原始令牌编码及 Windows Authenticode 兼容性
- 补充本地 TSA 四种摘要算法、固定时间、中文与空格路径的签名回归
- Rust 测试改为跨平台 Node.js 入口，交叉证书缓存遵循统一数据目录与测试隔离设置
- 为非 Windows 平台补齐窗口操作，移除历史测试中的个人 Windows 路径
- CI 扩展到 Windows、Ubuntu 和 macOS，并更新跨平台支持说明

### v0.2.0

- 重构 `signer.rs`：用 `with_signer!` 宏 + `digest_oid_for` 收敛四路摘要算法的重复 `match` 分支
- 清理死代码：移除 `build_signed_data` 的 `_is_nested` 参数及未使用的 `_is_nested()` 函数
- 抽取 `main.rs` 的 `build_file_dialog` 辅助函数，消除 open/save/open_directory 三个对话框命令的重复
- 修复 `random_serial` 在首字节恰好为 0（约 1/128 概率）时触发 `expect` panic 的问题
- 重构 `App.tsx` 跨页面拖拽通信：由渲染期消费 ref 改为 state 驱动，符合 React 单向数据流
- 新增前端 ESLint + Prettier 配置并接入 CI，统一代码风格
- 新增 `rustfmt.toml` 显式锁定 Rust 格式化配置
- 清理前端未使用的导入、死状态与空接口定义

### v0.1.0

- 首个公开版本：Authenticode 签名、验证、时间戳、证书管理及本地 TSA 服务

## 许可证

MIT
