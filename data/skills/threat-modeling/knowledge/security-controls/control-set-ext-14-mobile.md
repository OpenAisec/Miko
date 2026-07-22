<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Control Set 15: Mobile Security (MOBILE)

**Domain**: MOBILE - 移动端安全
**Version**: 1.0
**Last Updated**: 2025-12-30

---

## Overview

移动端安全控制集，适用于iOS/Android原生和跨平台应用。当检测到以下触发条件时按需加载：
- iOS项目 (*.xcodeproj, Podfile)
- Android项目 (build.gradle, AndroidManifest.xml)
- React Native (react-native.config.js)
- Flutter (pubspec.yaml)

---

## Core Controls

### MOBILE-01: Secure Local Storage
**控制要求**: 本地存储必须加密保护

- 使用平台安全存储 (Keychain/Keystore)
- 敏感数据加密存储
- 禁止明文存储凭证
- 应用卸载时清理数据

### MOBILE-02: Transport Security
**控制要求**: 网络传输必须安全

- 强制HTTPS通信
- 证书固定 (Certificate Pinning)
- 禁止不安全的TLS配置
- 检测代理/中间人攻击

### MOBILE-03: Code Protection
**控制要求**: 应用代码必须保护

- 代码混淆 (ProGuard/R8/SwiftShield)
- 防止反编译和调试
- 资源文件加密
- 敏感逻辑服务端实现

### MOBILE-04: Runtime Protection
**控制要求**: 运行时环境必须安全

- 检测越狱/Root设备
- 防止动态注入
- 完整性校验
- 调试检测和阻断

### MOBILE-05: Authentication Security
**控制要求**: 移动端认证必须安全

- 生物识别集成 (Face ID/Touch ID)
- 安全的会话管理
- 设备绑定和注册
- 离线认证策略

### MOBILE-06: Data Leakage Prevention
**控制要求**: 防止数据泄露

- 禁止敏感数据剪贴板
- 截屏保护
- 日志脱敏
- 第三方SDK审核

---

## L4 References

详细实践指南参考 `references/` 目录：
- reference-set-15-mobile-security.md
- reference-set-15-certificate-pinning.md

---

## STRIDE Mapping

| STRIDE | Applicable Controls |
|--------|---------------------|
| S | MOBILE-04, MOBILE-05 |
| T | MOBILE-03, MOBILE-04 |
| R | MOBILE-05 |
| I | MOBILE-01, MOBILE-02, MOBILE-06 |
| D | MOBILE-04 |
| E | MOBILE-04, MOBILE-05 |
