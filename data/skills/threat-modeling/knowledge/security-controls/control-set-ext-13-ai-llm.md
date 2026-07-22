<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Control Set 14: AI/LLM Security (AI)

**Domain**: AI - AI/LLM安全
**Version**: 1.0
**Last Updated**: 2025-12-30

---

## Overview

AI/LLM安全控制集，适用于大语言模型和AI Agent应用。当检测到以下触发条件时按需加载：
- openai API调用
- anthropic API调用
- langchain/llamaindex导入
- 本地模型加载 (transformers/llama.cpp)

---

## Core Controls

### AI-01: Prompt Injection Prevention
**控制要求**: 必须防护提示词注入攻击

- 用户输入与系统提示词隔离
- 输入净化和转义
- 使用结构化提示词模板
- 检测和阻断注入尝试

### AI-02: Output Validation
**控制要求**: LLM输出必须验证后使用

- 输出格式验证 (JSON Schema)
- 敏感信息过滤
- 代码执行前沙箱验证
- 幻觉检测和标记

### AI-03: Model Access Control
**控制要求**: 模型访问必须受控

- API密钥安全存储和轮换
- 速率限制防滥用
- 用户级别访问控制
- 审计日志记录所有调用

### AI-04: Data Isolation
**控制要求**: 敏感数据不得泄露给模型

- PII脱敏后再发送
- 上下文窗口敏感数据检测
- 禁止训练数据包含敏感信息
- 数据分类和标记

### AI-05: Agent Action Control
**控制要求**: AI Agent执行动作必须受限

- 动作白名单机制
- 高风险操作人工确认
- 资源访问范围限制
- 回滚和撤销能力

### AI-06: Model Security
**控制要求**: 模型本身必须安全

- 模型文件完整性校验
- 防止模型窃取/提取
- 对抗样本防护
- 模型版本管理

---

## L4 References

详细实践指南参考 `references/` 目录：
- reference-set-14-ai-agent-security.md
- reference-set-14-prompt-injection-prevention.md

内部参考：
- llm-threats.yaml

---

## STRIDE Mapping

| STRIDE | Applicable Controls |
|--------|---------------------|
| S | AI-03 |
| T | AI-01, AI-05 |
| R | AI-03 |
| I | AI-02, AI-04, AI-06 |
| D | AI-03 |
| E | AI-05 |
