# IPA Analyzer

IPA Analyzer 是一款用于查看和分析 IPA 文件的 macOS 桌面工具。所有分析均在本机完成，应用只读取 IPA 内容，不会运行其中的程序、动态库或脚本。

## 主要功能

- 查看应用名称、版本、Bundle ID、图标和文件大小
- 查看签名类型、证书、描述文件和 Entitlements
- 查看支持的设备架构、最低系统版本、SDK 和动态库
- 汇总隐私权限、URL Scheme 和 Associated Domains
- 查看 Framework、Extension、Watch App 和 App Clip
- 浏览 IPA 完整文件结构、大小与哈希信息
- 提供摘要与原始数据视图、搜索、复制和文件预览

## 从源码运行

适合希望查看源码、参与开发或使用命令行分析的用户。

开发环境要求：

- macOS 13 或更高版本
- Python 3.11 或更高版本
- macOS 系统工具：`security`、`codesign`、`file`、`lipo`、`otool`、`openssl`

克隆项目并安装依赖：

```bash
git clone https://github.com/zhangshuaidongya2/IPAAnalyzer.git
cd IPAAnalyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

启动 GUI：

```bash
python main.py --gui
```

也可以在启动时直接打开一个 IPA：

```bash
python main.py /path/to/Test.ipa --gui
```

使用命令行分析：

```bash
python main.py /path/to/Test.ipa
```

同时输出完整 JSON 报告：

```bash
python main.py /path/to/Test.ipa --json report.json
```

运行测试：

```bash
python -m unittest discover -v
```

源码运行不需要 Developer ID 证书。完成首次安装后，后续只需激活 `.venv` 即可运行。

## 下载与安装

需要 macOS 13 或更高版本。请从 GitHub Releases 按 Mac 芯片下载对应安装包：

- Apple Silicon（M1、M2、M3、M4 等）：`IPA-Analyzer-*-macOS-arm64.dmg`
- Intel Mac：`IPA-Analyzer-*-macOS-x86_64.dmg`

打开下载的 DMG，将 `IPA Analyzer.app` 拖入“应用程序”文件夹，然后双击启动。Release 安装包已使用 Apple Developer ID 签名并经过 Apple 公证。

## 使用方法

1. 启动 `IPA Analyzer`。
2. 点击 `Open IPA` 选择文件，或直接把 `.ipa` 文件拖入窗口。
3. 在摘要页面查看主要信息，在其他页面查看签名、权限、组件、文件和原始数据。
4. 需要分析其他文件时，重新打开或拖入新的 IPA 即可。

也可以在 Finder 中右键 `.ipa` 文件，选择“打开方式”中的 `IPA Analyzer`。

## 安全与隐私

- IPA 分析完全在本机进行，不会上传文件或分析结果。
- 不会执行 IPA 中的二进制、动态库或脚本。
- 临时解压内容会在分析结束后自动清理。
- 不提供解密、修改、重签名或安装 IPA 的功能。
- 对损坏、加密或包含危险路径的压缩包会拒绝或限制处理。

## 反馈

遇到问题或有功能建议，可以通过 GitHub Issues 提交，并附上 macOS 版本、应用版本和问题现象。请不要上传包含敏感信息或未公开应用数据的 IPA 文件。
