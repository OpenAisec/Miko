<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Control Set 13: Supply Chain Security (SUPPLY)

**Domain**: SUPPLY - 供应链安全
**Version**: 1.0
**Last Updated**: 2025-12-30

---

## Overview

供应链安全控制集，适用于依赖管理和构建流水线。当检测到以下触发条件时按需加载：
- package.json / package-lock.json
- requirements.txt / Pipfile
- pom.xml / build.gradle
- go.mod / go.sum
- Cargo.toml

---

## Core Controls

### SUPPLY-01: Dependency Vulnerability Scanning
**控制要求**: 所有依赖必须进行漏洞扫描

- 集成到CI/CD流水线 (npm audit/pip-audit/snyk)
- 阻断高危漏洞的构建
- 定期扫描已部署应用
- 漏洞修复SLA (Critical: 24h, High: 7d)

### SUPPLY-02: Dependency Pinning
**控制要求**: 依赖版本必须锁定

- 使用锁文件 (package-lock.json, Pipfile.lock)
- 禁止使用范围版本 (`^`, `~`, `*`)
- 定期审核和更新依赖
- 记录依赖更新原因

### SUPPLY-03: SBOM Generation
**控制要求**: 必须生成和维护软件物料清单

- 每次构建生成SBOM (CycloneDX/SPDX)
- SBOM存储和版本管理
- 支持漏洞追溯查询
- 合规性报告生成

### SUPPLY-04: Source Verification
**控制要求**: 依赖来源必须可验证

- 使用官方/可信仓库
- 校验包完整性 (checksum/signature)
- 私有仓库访问控制
- 禁止直接从Git安装未发布包

### SUPPLY-05: CI/CD Pipeline Security
**控制要求**: 构建流水线必须安全配置

- 流水线配置版本控制
- 密钥不硬编码在流水线中
- 最小权限执行
- 构建产物签名

### SUPPLY-06: License Compliance
**控制要求**: 依赖许可证必须合规

- 许可证扫描和审核
- 禁止不兼容许可证
- 维护许可证白名单
- 法律合规文档

---

## L4 References

详细实践指南参考 `references/` 目录：
- reference-set-13-dependency-management.md
- reference-set-13-supply-chain-security.md
- reference-set-13-npm-security.md
- reference-set-13-cicd-security.md

---

## STRIDE Mapping

| STRIDE | Applicable Controls |
|--------|---------------------|
| S | SUPPLY-04 |
| T | SUPPLY-01, SUPPLY-02, SUPPLY-05 |
| I | SUPPLY-03 |
| E | SUPPLY-05 |
