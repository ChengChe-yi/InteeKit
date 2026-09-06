# InteeKit

> 统一管理游戏内拾取与交互提示框的轻量插件

<div align="center">

![Version](https://img.shields.io/github/v/tag/ChengChe-yi/InteeKit?style=flat-square&label=version&color=blue&sort=semver)
![Platform](https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square&logo=windows)
![Status](https://img.shields.io/badge/status-beta-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

一款统一管理 Intee 交互面板的插件:白/黑名单过滤拾取与交互条目,支持热重载。

<img src="docs/preview.jpg" width="720" alt="屏蔽效果预览"/>

*怪物掉落物不再弹出拾取提示框,正常交互(烹饪)不受影响*

</div>

---

## ⚠️ 免责通知

> **本插件仍处于测试阶段**,强烈不建议在正式服或主要账号上使用。
>
> 使用本插件产生的任何后果(包括但不限于封号、数据异常等)均由使用者自行承担。


## 📦 安装

支持主流启动器的插件安装

安装完成后将以下文件部署到DLL同级目录:

```
目录/
├── InteeKit.dll             # 插件主 DLL
├── Config.ini               # 主配置文件
├── Whitelist.ini            # 白名单配置文件
└── Blacklist.ini            # 黑名单配置文件
```

---

## 🚀 使用方法

### 配置项 (`Config.ini`)

```ini
[PickupFilter]
Name  = 屏蔽怪物掉落物
Type  = bool
Value = 1   ; 1 = 开启,0 = 关闭,默认屏蔽怪物掉落物

[Whitelist]
Name  = 白名单启用
Type  = bool
Value = 1   ; 1 = 启用白名单,0 = 关闭

[Blacklist]
Name  = 黑名单启用
Type  = bool
Value = 1   ; 1 = 启用黑名单,0 = 关闭

[Log]
Name  = 日志开关
Type  = bool
Value = 1   ; 1 = 输出日志,0 = 静默
```

### 白名单 / 黑名单 (`Whitelist.ini` / `Blacklist.ini`)

名单文件各分两个区: `[Text]` 按名称精确匹配, `[Icon]` 按完整图标名精确匹配:

```ini
[Text]
史莱姆凝液

[Icon]
UI_ItemIcon_100012
```
#### 判定顺序为 黑名单 > 白名单 > 默认。
---

使用 [MinHook](https://github.com/TsudaKageyu/minhook),完整授权声明见 `src/MinHook` 源码文件头

---
## 🤝 反馈与贡献

- 🐛 提交 Issue:遇到崩溃、漏拦、误拦等情况
- 💡 提出建议:功能优化或新特性想法
- 🔧 提交 PR:欢迎改进代码与文档

---

<div align="center">

**❤️ by [ChengChe-yi](https://github.com/ChengChe-yi)**

</div>
