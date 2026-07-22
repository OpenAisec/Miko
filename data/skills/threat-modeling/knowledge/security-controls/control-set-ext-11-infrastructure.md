<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Control Set 12: Infrastructure Security (INFRA)

**Domain**: INFRA - 基础设施安全
**Version**: 1.0
**Last Updated**: 2025-12-30

---

## Overview

基础设施安全控制集，适用于容器化、编排和IaC环境。当检测到以下触发条件时按需加载：
- Dockerfile
- docker-compose.yml
- kubernetes/*.yaml
- helm chart
- terraform/*.tf

---

## Core Controls

### INFRA-01: Container Image Security
**控制要求**: 容器镜像必须经过安全扫描和签名验证

- 使用最小化基础镜像 (distroless/alpine)
- 镜像扫描集成到CI/CD流水线
- 禁止使用 `latest` 标签
- 实施镜像签名验证 (cosign/notary)

### INFRA-02: Container Runtime Security
**控制要求**: 容器运行时必须遵循最小权限原则

- 禁止特权容器 (`privileged: false`)
- 禁止root用户运行 (`runAsNonRoot: true`)
- 只读根文件系统 (`readOnlyRootFilesystem: true`)
- 限制capabilities (`drop: ALL`)

### INFRA-03: Resource Limits
**控制要求**: 所有容器必须配置资源限制

- CPU限制 (`resources.limits.cpu`)
- 内存限制 (`resources.limits.memory`)
- 存储配额限制
- PID限制防止fork炸弹

### INFRA-04: Network Segmentation
**控制要求**: 网络必须分段隔离

- NetworkPolicy限制Pod间通信
- 服务网格mTLS (Istio/Linkerd)
- Ingress/Egress流量控制
- 敏感服务不暴露公网

### INFRA-05: Secrets Management
**控制要求**: 敏感信息不得硬编码在配置中

- 使用外部密钥管理 (Vault/AWS Secrets Manager)
- Kubernetes Secrets加密存储
- 禁止环境变量存储敏感数据
- 密钥自动轮换机制

### INFRA-06: Infrastructure as Code Security
**控制要求**: IaC模板必须经过安全扫描

- 静态扫描 (checkov/tfsec/terrascan)
- 敏感数据不提交到版本控制
- 变更需经过审批流程
- 漂移检测和修复

---

## L4 References

详细实践指南参考 `references/` 目录：
- reference-set-12-docker-security.md
- reference-set-12-kubernetes-security.md
- reference-set-12-iac-security.md

---

## STRIDE Mapping

| STRIDE | Applicable Controls |
|--------|---------------------|
| S | INFRA-02, INFRA-05 |
| T | INFRA-01, INFRA-06 |
| I | INFRA-04, INFRA-05 |
| D | INFRA-03 |
| E | INFRA-02, INFRA-04 |
