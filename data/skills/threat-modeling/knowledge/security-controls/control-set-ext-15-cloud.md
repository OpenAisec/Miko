<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Control Set 16: Cloud Security (CLOUD)

**Domain**: CLOUD - 云服务安全
**Version**: 1.0
**Last Updated**: 2025-12-30

---

## Overview

云服务安全控制集，适用于AWS/Azure/GCP/阿里云等云平台。当检测到以下触发条件时按需加载：
- terraform/*.tf
- AWS SDK调用 (boto3, aws-sdk)
- Azure SDK调用 (azure-*)
- GCP SDK调用 (google-cloud-*)
- serverless.yml

---

## Core Controls

### CLOUD-01: IAM Least Privilege
**控制要求**: IAM权限必须遵循最小权限原则

- 禁止使用通配符权限 (`*`)
- 定期权限审查和清理
- 使用角色而非长期凭证
- 条件策略限制访问范围

### CLOUD-02: Resource Access Policy
**控制要求**: 资源访问策略必须明确限制

- S3/Blob存储禁止公开访问
- 数据库不暴露公网
- API网关认证授权
- 资源标签和分类

### CLOUD-03: Security Group Configuration
**控制要求**: 安全组必须最小化开放

- 禁止0.0.0.0/0入站规则 (除必要端口)
- 仅开放必需端口
- 使用安全组引用而非IP
- 定期审核安全组规则

### CLOUD-04: Logging and Monitoring
**控制要求**: 必须启用全面的日志和监控

- CloudTrail/Activity Log启用
- VPC Flow Logs启用
- 安全事件告警配置
- 日志集中存储和保留

### CLOUD-05: Encryption Configuration
**控制要求**: 数据必须加密存储和传输

- 存储加密 (EBS/S3/RDS加密)
- 传输加密 (TLS强制)
- 密钥管理 (KMS/Key Vault)
- 客户管理密钥 (CMK)

### CLOUD-06: Network Architecture
**控制要求**: 网络架构必须安全设计

- VPC/VNet隔离
- 私有子网部署应用
- NAT网关出站
- PrivateLink服务访问

---

## L4 References

详细实践指南参考 `references/` 目录：
- reference-set-16-cloud-architecture.md
- reference-set-16-serverless-security.md

---

## STRIDE Mapping

| STRIDE | Applicable Controls |
|--------|---------------------|
| S | CLOUD-01 |
| T | CLOUD-02, CLOUD-05 |
| R | CLOUD-04 |
| I | CLOUD-02, CLOUD-03, CLOUD-05 |
| D | CLOUD-03, CLOUD-06 |
| E | CLOUD-01, CLOUD-02 |
