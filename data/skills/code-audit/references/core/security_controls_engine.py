#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Controls Detection Engine
安全控制检测引擎

基于安全控制矩阵和语言适配器，检测代码中缺失的安全控制。

核心理念:
  - 不搜索"危险代码"，而是验证"安全控制是否存在"
  - 从"应该是什么"出发，而非"存在什么"
  - 与语言/框架无关的通用框架

使用方法:
  python security_controls_engine.py --path /path/to/project --language php

版本: 1.0.0
"""

import os
import re
import sys
import yaml
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict
import json

# ============================================================================
# 数据结构定义
# ============================================================================

@dataclass
class SecurityControl:
    """安全控制定义"""
    id: str
    name: str
    name_zh: str
    description: str
    severity: str
    cwe: str
    patterns: List[str] = field(default_factory=list)


@dataclass
class SensitiveOperation:
    """敏感操作定义"""
    name: str
    name_zh: str
    patterns: List[str]
    required_controls: List[str]
    risk_level: str
    description: str


@dataclass
class Finding:
    """检测发现"""
    file_path: str
    line_number: int
    operation_name: str
    operation_pattern: str
    missing_control: str
    control_name_zh: str
    severity: str
    cwe: str
    code_snippet: str
    method_name: str = ""


@dataclass
class OperationContext:
    """操作上下文"""
    file_path: str
    line_number: int
    method_name: str
    operation_type: str
    matched_pattern: str
    context_lines: List[str]  # 上下文代码行
    context_start: int  # 上下文起始行号


# ============================================================================
# 配置加载器
# ============================================================================

class ConfigLoader:
    """加载安全控制矩阵和语言适配器"""

    def __init__(self, config_dir: str):
        self.config_dir = Path(config_dir)
        self.matrix = None
        self.adapters = {}

    def load_matrix(self) -> Dict:
        """加载安全控制矩阵"""
        matrix_path = self.config_dir / "core" / "security_controls_matrix.yaml"
        if not matrix_path.exists():
            raise FileNotFoundError(f"Security controls matrix not found: {matrix_path}")

        with open(matrix_path, 'r', encoding='utf-8') as f:
            self.matrix = yaml.safe_load(f)
        return self.matrix

    def load_adapter(self, language: str) -> Dict:
        """加载语言适配器"""
        adapter_path = self.config_dir / "adapters" / f"{language}.yaml"
        if not adapter_path.exists():
            raise FileNotFoundError(f"Adapter not found for language: {language}")

        with open(adapter_path, 'r', encoding='utf-8') as f:
            adapter = yaml.safe_load(f)
            self.adapters[language] = adapter
        return adapter

    def get_security_controls(self) -> Dict[str, SecurityControl]:
        """获取所有安全控制定义"""
        controls = {}
        for ctrl_id, ctrl_data in self.matrix.get('security_controls', {}).items():
            controls[ctrl_id] = SecurityControl(
                id=ctrl_data.get('id', ctrl_id.upper()),
                name=ctrl_data.get('name', ctrl_id),
                name_zh=ctrl_data.get('name_zh', ctrl_id),
                description=ctrl_data.get('description', ''),
                severity=ctrl_data.get('severity', 'MEDIUM'),
                cwe=ctrl_data.get('cwe', 'CWE-000')
            )
        return controls

    def get_sensitive_operations(self) -> Dict[str, SensitiveOperation]:
        """获取所有敏感操作定义"""
        operations = {}
        for op_name, op_data in self.matrix.get('sensitive_operations', {}).items():
            operations[op_name] = SensitiveOperation(
                name=op_data.get('name', op_name),
                name_zh=op_data.get('name_zh', op_name),
                patterns=op_data.get('patterns', []),
                required_controls=op_data.get('required_controls', []),
                risk_level=op_data.get('risk_level', 'MEDIUM'),
                description=op_data.get('description', '')
            )
        return operations


# ============================================================================
# 代码扫描器
# ============================================================================

class CodeScanner:
    """代码扫描器 - 识别敏感操作"""

    def __init__(self, adapter: Dict, operations: Dict[str, SensitiveOperation]):
        self.adapter = adapter
        self.operations = operations
        self.file_extensions = adapter.get('file_extensions', [])

    def scan_directory(self, path: str) -> List[OperationContext]:
        """扫描目录，找出所有敏感操作"""
        results = []
        path = Path(path)

        for file_path in path.rglob('*'):
            if not file_path.is_file():
                continue

            # 检查文件扩展名
            if not any(str(file_path).endswith(ext) for ext in self.file_extensions):
                continue

            # 跳过常见的非代码目录
            skip_dirs = ['vendor', 'node_modules', '.git', 'dist', 'build', 'test', 'tests', '__pycache__']
            if any(skip_dir in str(file_path) for skip_dir in skip_dirs):
                continue

            try:
                operations = self.scan_file(str(file_path))
                results.extend(operations)
            except Exception as e:
                print(f"Warning: Error scanning {file_path}: {e}", file=sys.stderr)

        return results

    def scan_file(self, file_path: str) -> List[OperationContext]:
        """扫描单个文件"""
        results = []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            content = ''.join(lines)

        # 获取操作模式
        op_patterns = self.adapter.get('operation_patterns', {})
        method_patterns = op_patterns.get('method_patterns', {})
        route_patterns = op_patterns.get('route_patterns', {})

        # 合并所有模式
        all_patterns = {}
        for op_type, patterns in method_patterns.items():
            all_patterns[op_type] = patterns
        for op_type, patterns in route_patterns.items():
            if op_type in all_patterns:
                all_patterns[op_type].extend(patterns)
            else:
                all_patterns[op_type] = patterns

        # 搜索敏感操作
        for line_num, line in enumerate(lines, 1):
            for op_type, patterns in all_patterns.items():
                for pattern in patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            # 提取方法名
                            method_name = self._extract_method_name(line)

                            # 获取上下文
                            context_start = max(0, line_num - 30)
                            context_end = min(len(lines), line_num + 30)
                            context_lines = lines[context_start:context_end]

                            results.append(OperationContext(
                                file_path=file_path,
                                line_number=line_num,
                                method_name=method_name,
                                operation_type=op_type,
                                matched_pattern=pattern,
                                context_lines=context_lines,
                                context_start=context_start + 1
                            ))
                            break  # 每行只匹配一次
                    except re.error:
                        continue

        return results

    def _extract_method_name(self, line: str) -> str:
        """从代码行提取方法名"""
        # PHP: function delete($id)
        match = re.search(r'function\s+(\w+)', line)
        if match:
            return match.group(1)

        # Java: public void deleteUser(int id)
        match = re.search(r'(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', line)
        if match:
            return match.group(1)

        # Python: def delete(self, id):
        match = re.search(r'def\s+(\w+)', line)
        if match:
            return match.group(1)

        # JavaScript: async delete(id) or function delete(id)
        match = re.search(r'(?:async\s+)?(?:function\s+)?(\w+)\s*[\(=]', line)
        if match:
            return match.group(1)

        # Go: func (c *Controller) Delete(id int)
        match = re.search(r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(', line)
        if match:
            return match.group(1)

        return "unknown"


# ============================================================================
# 安全控制检测器
# ============================================================================

class ControlDetector:
    """检测安全控制是否存在"""

    def __init__(self, adapter: Dict, controls: Dict[str, SecurityControl]):
        self.adapter = adapter
        self.controls = controls
        self.control_patterns = adapter.get('control_patterns', {})

    def check_controls(self, context: OperationContext, required_controls: List[str]) -> List[str]:
        """检查上下文中是否存在必需的安全控制，返回缺失的控制列表"""
        missing = []
        context_text = ''.join(context.context_lines)

        for control_name in required_controls:
            if not self._has_control(context_text, control_name):
                missing.append(control_name)

        return missing

    def _has_control(self, context_text: str, control_name: str) -> bool:
        """检查上下文中是否存在指定的安全控制"""
        patterns = self._get_control_patterns(control_name)

        for pattern in patterns:
            try:
                if re.search(pattern, context_text, re.IGNORECASE | re.MULTILINE):
                    return True
            except re.error:
                continue

        return False

    def _get_control_patterns(self, control_name: str) -> List[str]:
        """获取安全控制的所有检测模式"""
        patterns = []

        control_data = self.control_patterns.get(control_name, {})

        if isinstance(control_data, dict):
            # 嵌套结构 (按框架分类)
            for framework, framework_patterns in control_data.items():
                if isinstance(framework_patterns, list):
                    patterns.extend(framework_patterns)
        elif isinstance(control_data, list):
            # 直接列表
            patterns.extend(control_data)

        # 如果有 patterns 子键
        if isinstance(control_data, dict) and 'patterns' in control_data:
            patterns.extend(control_data['patterns'])

        return patterns


# ============================================================================
# 报告生成器
# ============================================================================

class ReportGenerator:
    """生成检测报告"""

    def __init__(self, controls: Dict[str, SecurityControl]):
        self.controls = controls

    def generate_report(self, findings: List[Finding], output_format: str = 'text') -> str:
        """生成报告"""
        if output_format == 'json':
            return self._generate_json_report(findings)
        elif output_format == 'markdown':
            return self._generate_markdown_report(findings)
        else:
            return self._generate_text_report(findings)

    def _generate_text_report(self, findings: List[Finding]) -> str:
        """生成文本报告"""
        lines = []
        lines.append("=" * 80)
        lines.append("安全控制审计报告 (Security Controls Audit Report)")
        lines.append("=" * 80)
        lines.append("")

        # 统计
        by_severity = defaultdict(list)
        for f in findings:
            by_severity[f.severity].append(f)

        lines.append("概览:")
        lines.append(f"  总发现数: {len(findings)}")
        lines.append(f"  CRITICAL: {len(by_severity['CRITICAL'])}")
        lines.append(f"  HIGH: {len(by_severity['HIGH'])}")
        lines.append(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
        lines.append(f"  LOW: {len(by_severity.get('LOW', []))}")
        lines.append("")

        # 详细发现
        lines.append("-" * 80)
        lines.append("详细发现:")
        lines.append("-" * 80)

        for i, f in enumerate(findings, 1):
            lines.append("")
            lines.append(f"[{i}] {f.severity} - {f.control_name_zh}缺失")
            lines.append(f"    文件: {f.file_path}:{f.line_number}")
            lines.append(f"    操作: {f.method_name} ({f.operation_name})")
            lines.append(f"    CWE: {f.cwe}")
            lines.append(f"    代码:")
            for line in f.code_snippet.split('\n')[:5]:
                lines.append(f"      {line}")

        return '\n'.join(lines)

    def _generate_markdown_report(self, findings: List[Finding]) -> str:
        """生成Markdown报告"""
        lines = []
        lines.append("# 安全控制审计报告")
        lines.append("")

        # 统计
        by_severity = defaultdict(list)
        by_control = defaultdict(list)
        for f in findings:
            by_severity[f.severity].append(f)
            by_control[f.missing_control].append(f)

        lines.append("## 概览")
        lines.append("")
        lines.append(f"- **总发现数**: {len(findings)}")
        lines.append(f"- **CRITICAL**: {len(by_severity['CRITICAL'])}")
        lines.append(f"- **HIGH**: {len(by_severity['HIGH'])}")
        lines.append(f"- **MEDIUM**: {len(by_severity['MEDIUM'])}")
        lines.append("")

        # 按控制类型统计
        lines.append("## 按控制类型统计")
        lines.append("")
        lines.append("| 控制类型 | 缺失数量 |")
        lines.append("|----------|----------|")
        for control, findings_list in sorted(by_control.items(), key=lambda x: -len(x[1])):
            control_zh = self.controls.get(control, SecurityControl(control, control, control, '', '', '')).name_zh
            lines.append(f"| {control_zh} | {len(findings_list)} |")
        lines.append("")

        # 详细发现
        lines.append("## 详细发现")
        lines.append("")

        for i, f in enumerate(findings, 1):
            lines.append(f"### [{i}] {f.severity} - {f.control_name_zh}缺失")
            lines.append("")
            lines.append(f"- **位置**: `{f.file_path}:{f.line_number}`")
            lines.append(f"- **操作**: `{f.method_name}` ({f.operation_name})")
            lines.append(f"- **CWE**: [{f.cwe}](https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html)")
            lines.append("")
            lines.append("```")
            lines.append(f.code_snippet[:500])
            lines.append("```")
            lines.append("")

        return '\n'.join(lines)

    def _generate_json_report(self, findings: List[Finding]) -> str:
        """生成JSON报告"""
        data = {
            "summary": {
                "total": len(findings),
                "by_severity": {},
                "by_control": {}
            },
            "findings": []
        }

        for f in findings:
            data["summary"]["by_severity"][f.severity] = data["summary"]["by_severity"].get(f.severity, 0) + 1
            data["summary"]["by_control"][f.missing_control] = data["summary"]["by_control"].get(f.missing_control, 0) + 1

            data["findings"].append({
                "file_path": f.file_path,
                "line_number": f.line_number,
                "method_name": f.method_name,
                "operation_name": f.operation_name,
                "missing_control": f.missing_control,
                "control_name_zh": f.control_name_zh,
                "severity": f.severity,
                "cwe": f.cwe,
                "code_snippet": f.code_snippet[:500]
            })

        return json.dumps(data, indent=2, ensure_ascii=False)


# ============================================================================
# 主引擎
# ============================================================================

class SecurityControlsEngine:
    """安全控制检测引擎"""

    def __init__(self, config_dir: str):
        self.config_loader = ConfigLoader(config_dir)
        self.config_loader.load_matrix()

    def audit(self, project_path: str, language: str) -> List[Finding]:
        """执行审计"""
        # 加载配置
        adapter = self.config_loader.load_adapter(language)
        controls = self.config_loader.get_security_controls()
        operations = self.config_loader.get_sensitive_operations()

        # 扫描代码
        scanner = CodeScanner(adapter, operations)
        detected_operations = scanner.scan_directory(project_path)

        print(f"发现 {len(detected_operations)} 个敏感操作", file=sys.stderr)

        # 检测缺失的控制
        detector = ControlDetector(adapter, controls)
        findings = []

        for op_context in detected_operations:
            # 获取操作类型对应的必需控制
            op_type = op_context.operation_type
            if op_type in operations:
                required = operations[op_type].required_controls
            else:
                # 尝试匹配
                required = []
                for op_name, op_def in operations.items():
                    if op_type in op_name or any(op_type in p for p in op_def.patterns):
                        required = op_def.required_controls
                        break

            if not required:
                continue

            # 检查缺失的控制
            missing = detector.check_controls(op_context, required)

            for control_name in missing:
                control = controls.get(control_name, SecurityControl(
                    control_name, control_name, control_name, '', 'MEDIUM', 'CWE-000'
                ))

                # 提取代码片段
                snippet_lines = op_context.context_lines[
                    max(0, op_context.line_number - op_context.context_start - 3):
                    op_context.line_number - op_context.context_start + 3
                ]
                snippet = ''.join(snippet_lines)

                findings.append(Finding(
                    file_path=op_context.file_path,
                    line_number=op_context.line_number,
                    operation_name=op_context.operation_type,
                    operation_pattern=op_context.matched_pattern,
                    missing_control=control_name,
                    control_name_zh=control.name_zh,
                    severity=control.severity,
                    cwe=control.cwe,
                    code_snippet=snippet,
                    method_name=op_context.method_name
                ))

        # 按严重程度排序
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda f: severity_order.get(f.severity, 4))

        return findings


# ============================================================================
# 命令行接口
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='安全控制检测引擎 - 检测代码中缺失的安全控制',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s --path /path/to/project --language php
  %(prog)s --path /path/to/project --language java --format markdown
  %(prog)s --path /path/to/project --language python --output report.json --format json

支持的语言: php, java, python, go, javascript
        '''
    )

    parser.add_argument('--path', '-p', required=True, help='项目路径')
    parser.add_argument('--language', '-l', required=True,
                        choices=['php', 'java', 'python', 'go', 'javascript'],
                        help='项目语言')
    parser.add_argument('--format', '-f', default='text',
                        choices=['text', 'markdown', 'json'],
                        help='输出格式 (默认: text)')
    parser.add_argument('--output', '-o', help='输出文件 (默认: stdout)')
    parser.add_argument('--config', '-c',
                        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        help='配置目录路径')

    args = parser.parse_args()

    try:
        # 初始化引擎
        engine = SecurityControlsEngine(args.config)

        # 执行审计
        findings = engine.audit(args.path, args.language)

        # 生成报告
        controls = engine.config_loader.get_security_controls()
        reporter = ReportGenerator(controls)
        report = reporter.generate_report(findings, args.format)

        # 输出
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"报告已保存到: {args.output}", file=sys.stderr)
        else:
            print(report)

        # 退出码
        sys.exit(1 if findings else 0)

    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
