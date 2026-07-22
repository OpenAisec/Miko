#!/bin/bash
# Security Controls Audit Script
# 安全控制审计脚本
#
# 使用方法:
#   ./audit.sh <project_path> <language> [format]
#
# 示例:
#   ./audit.sh /path/to/php/project php
#   ./audit.sh /path/to/java/project java markdown
#   ./audit.sh /path/to/python/project python json

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$SCRIPT_DIR/security_controls_engine.py"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 帮助信息
show_help() {
    echo "安全控制审计脚本 (Security Controls Audit)"
    echo ""
    echo "使用方法:"
    echo "  $0 <project_path> <language> [format] [output_file]"
    echo ""
    echo "参数:"
    echo "  project_path  - 项目路径"
    echo "  language      - 语言 (php, java, python, go, javascript)"
    echo "  format        - 输出格式 (text, markdown, json) [默认: text]"
    echo "  output_file   - 输出文件 [可选]"
    echo ""
    echo "示例:"
    echo "  $0 /path/to/project php"
    echo "  $0 /path/to/project java markdown"
    echo "  $0 /path/to/project python json report.json"
    echo ""
}

# 检查参数
if [ $# -lt 2 ]; then
    show_help
    exit 1
fi

PROJECT_PATH="$1"
LANGUAGE="$2"
FORMAT="${3:-text}"
OUTPUT="$4"

# 验证项目路径
if [ ! -d "$PROJECT_PATH" ]; then
    echo -e "${RED}错误: 项目路径不存在: $PROJECT_PATH${NC}"
    exit 1
fi

# 验证语言
VALID_LANGUAGES="php java python go javascript"
if [[ ! " $VALID_LANGUAGES " =~ " $LANGUAGE " ]]; then
    echo -e "${RED}错误: 不支持的语言: $LANGUAGE${NC}"
    echo "支持的语言: $VALID_LANGUAGES"
    exit 1
fi

# 验证格式
VALID_FORMATS="text markdown json"
if [[ ! " $VALID_FORMATS " =~ " $FORMAT " ]]; then
    echo -e "${RED}错误: 不支持的格式: $FORMAT${NC}"
    echo "支持的格式: $VALID_FORMATS"
    exit 1
fi

# 检查 Python
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo -e "${RED}错误: 未找到 Python${NC}"
        exit 1
    fi
    PYTHON="python"
else
    PYTHON="python3"
fi

# 检查依赖
$PYTHON -c "import yaml" 2>/dev/null || {
    echo -e "${YELLOW}安装依赖: pyyaml${NC}"
    $PYTHON -m pip install pyyaml -q
}

# 运行审计
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}          Security Controls Audit - 安全控制审计                ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "项目路径: ${GREEN}$PROJECT_PATH${NC}"
echo -e "语言:     ${GREEN}$LANGUAGE${NC}"
echo -e "格式:     ${GREEN}$FORMAT${NC}"
echo ""

if [ -n "$OUTPUT" ]; then
    $PYTHON "$ENGINE" \
        --path "$PROJECT_PATH" \
        --language "$LANGUAGE" \
        --format "$FORMAT" \
        --output "$OUTPUT" \
        --config "$SCRIPT_DIR/.."

    echo -e "${GREEN}报告已保存到: $OUTPUT${NC}"
else
    $PYTHON "$ENGINE" \
        --path "$PROJECT_PATH" \
        --language "$LANGUAGE" \
        --format "$FORMAT" \
        --config "$SCRIPT_DIR/.."
fi
