#!/usr/bin/env python3
# Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

"""
Module Discovery Script for STRIDE Threat Modeling (P1 Phase).

Implements Three-Layer Discovery Strategy:
  - Layer 1: Deterministic Discovery (95%+ confidence)
    - Static code patterns: @app.route, @router.get, etc.
    - Config file parsing: openapi.yaml, routes.yaml, serverless.yml
    - Framework-specific: Django URLconf, Spring @RequestMapping

  - Layer 2: Heuristic Discovery (70-90% confidence)
    - Directory/file patterns: routes/, handlers/, api/, controllers/
    - Code pattern matching: request/response handling functions
    - Import analysis: flask, fastapi, express, etc.

  - Layer 3: Potential Discovery (30-60% confidence - Dynamic Routes)
    - Conditional registration: if config.ENABLE_* + add_route
    - Plugin systems: plugin.register, loader.load_module
    - Reflection calls: getattr, eval, exec

Enhanced Detection (when available):
  - Semgrep: Framework-native route detection
  - OWASP Noir: LLM-enhanced endpoint discovery
  - CodeQL: Deep dataflow analysis

Usage:
    # Basic file listing
    python module_discovery.py /path/to/project

    # Full P1 discovery with three-layer analysis
    python module_discovery.py /path/to/project --p1-discovery

    # Detect dynamic route indicators
    python module_discovery.py /path/to/project --detect-dynamic

    # Output P1_static_discovery.yaml format
    python module_discovery.py /path/to/project --p1-discovery --output-yaml

Output: JSON/YAML format for integration with threat modeling workflow.
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# Common patterns to exclude
DEFAULT_EXCLUDES = {
    # Version control
    ".git", ".svn", ".hg",
    # Dependencies
    "node_modules", "vendor", "venv", ".venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    # Build outputs
    "dist", "build", "out", "target", ".next", ".nuxt",
    # IDE
    ".idea", ".vscode", ".vs",
    # Misc
    ".DS_Store", "Thumbs.db", "*.pyc", "*.pyo",
}

# Documentation categories for Phase 1.1 Doc-Guided Discovery
DOC_CATEGORIES = {
    "readme": {
        "patterns": ["README*", "readme*"],
        "extensions": [".md", ".rst", ".txt", ""],
        "priority": 1,
    },
    "architecture": {
        "patterns": ["ARCHITECTURE*", "architecture*", "DESIGN*", "design*"],
        "extensions": [".md", ".rst", ".txt"],
        "priority": 2,
    },
    "api_docs": {
        "patterns": ["api*", "API*", "swagger*", "openapi*"],
        "extensions": [".md", ".yaml", ".yml", ".json"],
        "priority": 3,
    },
    "docs_directory": {
        "patterns": ["docs", "doc", "documentation"],
        "is_directory": True,
        "priority": 4,
    },
    "contributing": {
        "patterns": ["CONTRIBUTING*", "contributing*"],
        "extensions": [".md", ".rst", ".txt", ""],
        "priority": 5,
    },
    "changelog": {
        "patterns": ["CHANGELOG*", "changelog*", "HISTORY*", "history*", "NEWS*"],
        "extensions": [".md", ".rst", ".txt", ""],
        "priority": 6,
    },
}

# File categories for project understanding
FILE_CATEGORIES = {
    "entry_points": {
        "patterns": ["main.py", "app.py", "index.js", "index.ts", "main.go", "Main.java"],
        "description": "Application entry points",
    },
    "api_routes": {
        "patterns": ["routes", "api", "endpoints", "handlers", "controllers"],
        "extensions": [".py", ".js", ".ts", ".go", ".java"],
        "description": "API route definitions",
    },
    "config": {
        "patterns": ["config", "settings", ".env", "*.yaml", "*.yml", "*.toml", "*.json"],
        "description": "Configuration files",
    },
    "models": {
        "patterns": ["models", "schemas", "entities", "types"],
        "description": "Data models and schemas",
    },
    "auth": {
        "patterns": ["auth", "authentication", "authorization", "security", "jwt", "oauth"],
        "description": "Authentication/Authorization",
    },
    "database": {
        "patterns": ["db", "database", "migrations", "repositories", "dal"],
        "description": "Database layer",
    },
    "tests": {
        "patterns": ["test", "tests", "spec", "__tests__", "*_test.py", "*_test.go"],
        "description": "Test files",
    },
    "deploy": {
        "patterns": ["deploy", "k8s", "kubernetes", "docker", "terraform", "pulumi", "cdk"],
        "extensions": [".yaml", ".yml", ".tf", ".hcl"],
        "description": "Deployment configuration",
    },
    "docs": {
        "patterns": ["docs", "documentation", "*.md", "*.rst"],
        "description": "Documentation",
    },
}

# =============================================================================
# Three-Layer Discovery Patterns
# =============================================================================

# Layer 1: Deterministic Discovery (95%+ confidence)
LAYER1_ROUTE_PATTERNS = {
    "python_flask": {
        "patterns": [
            r'@app\.route\s*\(\s*["\']([^"\']+)["\']',
            r'@blueprint\.route\s*\(\s*["\']([^"\']+)["\']',
            r'@bp\.route\s*\(\s*["\']([^"\']+)["\']',
        ],
        "confidence": 0.95,
        "framework": "Flask",
    },
    "python_fastapi": {
        "patterns": [
            r'@app\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
        ],
        "confidence": 0.95,
        "framework": "FastAPI",
    },
    "python_django": {
        "patterns": [
            r'path\s*\(\s*["\']([^"\']+)["\']',
            r're_path\s*\(\s*["\']([^"\']+)["\']',
            r'url\s*\(\s*r?["\']([^"\']+)["\']',
        ],
        "confidence": 0.95,
        "framework": "Django",
    },
    "javascript_express": {
        "patterns": [
            r'app\.(get|post|put|delete|patch|all|use)\s*\(\s*["\']([^"\']+)["\']',
            r'router\.(get|post|put|delete|patch|all|use)\s*\(\s*["\']([^"\']+)["\']',
        ],
        "confidence": 0.95,
        "framework": "Express",
    },
    "java_spring": {
        "patterns": [
            r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
            r'@GetMapping\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'@PostMapping\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'@PutMapping\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'@DeleteMapping\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
        ],
        "confidence": 0.95,
        "framework": "Spring",
    },
    "go_gin": {
        "patterns": [
            r'\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']+)["\']',
        ],
        "confidence": 0.95,
        "framework": "Gin",
    },
    # === Additional Entry Point Types (P1-GAP-01 fix) ===
    "python_graphql": {
        "patterns": [
            r'@strawberry\.type',
            r'@strawberry\.mutation',
            r'@strawberry\.subscription',
            r'class\s+\w+\s*\(\s*graphene\.ObjectType\s*\)',
            r'@Query\s*\(',
            r'@Mutation\s*\(',
            r'type\s+Query\s*\{',
            r'type\s+Mutation\s*\{',
        ],
        "confidence": 0.92,
        "framework": "GraphQL",
        "entry_type": "graphql",
    },
    "python_websocket": {
        "patterns": [
            r'@socketio\.on\s*\(\s*["\']([^"\']+)["\']',
            r'@sio\.on\s*\(\s*["\']([^"\']+)["\']',
            r'@websocket\s*\(',
            r'async\s+def\s+websocket\s*\(',
            r'WebSocketEndpoint',
            r'websocket_route\s*\(',
        ],
        "confidence": 0.90,
        "framework": "WebSocket",
        "entry_type": "websocket",
    },
    "python_celery": {
        "patterns": [
            r'@celery\.task\s*\(',
            r'@app\.task\s*\(',
            r'@shared_task\s*\(',
            r'@task\s*\(\s*bind\s*=',
            r'celery_app\.task\s*\(',
        ],
        "confidence": 0.92,
        "framework": "Celery",
        "entry_type": "message_queue",
    },
    "python_scheduler": {
        "patterns": [
            r'@scheduler\.scheduled_job\s*\(',
            r'@scheduler\.task\s*\(',
            r'schedule\.every\s*\(',
            r'crontab\s*\(',
            r'@periodic_task\s*\(',
            r'CronTrigger\s*\(',
        ],
        "confidence": 0.88,
        "framework": "Scheduler",
        "entry_type": "cron_jobs",
    },
    "python_file_upload": {
        "patterns": [
            r'UploadFile',
            r'FileUpload',
            r'request\.files',
            r'multipart/form-data',
            r'@upload_file',
            r'FormData\s*\(',
        ],
        "confidence": 0.85,
        "framework": "FileUpload",
        "entry_type": "file_upload",
    },
    "debug_endpoints": {
        "patterns": [
            r'@app\.route\s*\(\s*["\'][^"\']*debug[^"\']*["\']',
            r'@app\.route\s*\(\s*["\'][^"\']*admin[^"\']*["\']',
            r'/debug/',
            r'/admin/',
            r'@debug_only',
            r'if\s+DEBUG\s*:.*route',
            r'@require_debug',
        ],
        "confidence": 0.90,
        "framework": "Debug",
        "entry_type": "debug_endpoints",
    },
    "health_endpoints": {
        "patterns": [
            r'@app\.route\s*\(\s*["\'][^"\']*health[^"\']*["\']',
            r'@app\.route\s*\(\s*["\'][^"\']*ready[^"\']*["\']',
            r'@app\.route\s*\(\s*["\'][^"\']*live[^"\']*["\']',
            r'/health',
            r'/healthz',
            r'/readiness',
            r'/liveness',
        ],
        "confidence": 0.95,
        "framework": "Health",
        "entry_type": "health_endpoints",
    },
    "grpc_service": {
        "patterns": [
            r'\.proto\b',
            r'grpc\.server\s*\(',
            r'add_\w+Servicer_to_server',
            r'class\s+\w+Servicer\s*\(',
            r'@grpc_method',
        ],
        "confidence": 0.90,
        "framework": "gRPC",
        "entry_type": "internal_api",
    },
}

# Layer 1: Configuration file patterns
LAYER1_CONFIG_PATTERNS = {
    "openapi": {
        "files": ["openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"],
        "confidence": 0.98,
        "type": "api_spec",
    },
    "routes_config": {
        "files": ["routes.yaml", "routes.yml", "routes.json", "api.yaml", "endpoints.yaml"],
        "confidence": 0.90,
        "type": "routes",
    },
    "serverless": {
        "files": ["serverless.yml", "serverless.yaml", "sam.yaml", "template.yaml"],
        "confidence": 0.92,
        "type": "serverless",
    },
    "api_gateway": {
        "files": ["kong.yml", "kong.yaml", "apisix.yaml", "envoy.yaml"],
        "confidence": 0.90,
        "type": "gateway",
    },
}

# Layer 2: Heuristic Discovery (70-90% confidence)
LAYER2_DIRECTORY_PATTERNS = {
    "route_directories": {
        "patterns": ["routes", "routers", "api", "apis", "endpoints", "handlers", "controllers", "views"],
        "confidence": 0.80,
    },
    "middleware_directories": {
        "patterns": ["middleware", "middlewares", "interceptors", "filters"],
        "confidence": 0.75,
    },
    "service_directories": {
        "patterns": ["services", "service", "providers", "modules"],
        "confidence": 0.70,
    },
}

LAYER2_IMPORT_PATTERNS = {
    "flask": {
        "patterns": [r"from flask import", r"import flask"],
        "confidence": 0.85,
        "framework": "Flask",
    },
    "fastapi": {
        "patterns": [r"from fastapi import", r"import fastapi"],
        "confidence": 0.85,
        "framework": "FastAPI",
    },
    "django": {
        "patterns": [r"from django", r"import django"],
        "confidence": 0.85,
        "framework": "Django",
    },
    "express": {
        "patterns": [r"require\(['\"]express['\"]\)", r"from ['\"]express['\"]"],
        "confidence": 0.85,
        "framework": "Express",
    },
    "spring": {
        "patterns": [r"import org\.springframework", r"@SpringBootApplication"],
        "confidence": 0.85,
        "framework": "Spring",
    },
}

# Layer 3: Dynamic Route Indicators (30-60% confidence)
LAYER3_DYNAMIC_PATTERNS = {
    "conditional_registration": {
        "patterns": [
            r"if\s+(?:config|settings|env|os\.environ)\..*?(?:add_route|add_url_rule|include_router|mount)",
            r"if\s+.*?ENABLE.*?:\s*\n\s*.*?(?:route|router|app\.)",
            r"if\s+.*?(?:DEBUG|DEVELOPMENT|ADMIN).*?:\s*\n\s*.*?(?:route|app\.)",
        ],
        "confidence": 0.50,
        "risk": "HIGH",
        "description": "Route registration depends on configuration flags",
    },
    "plugin_system": {
        "patterns": [
            r"(?:plugin|extension|addon)\.(?:register|load|install)",
            r"(?:load|import)_(?:plugin|module|extension)s?\s*\(",
            r"(?:plugin|extension)_manager\.(?:register|add)",
            r"for\s+\w+\s+in\s+(?:plugins|extensions|modules):",
        ],
        "confidence": 0.45,
        "risk": "MEDIUM",
        "description": "Routes may be registered by plugin system",
    },
    "reflection_calls": {
        "patterns": [
            r"getattr\s*\([^)]+,\s*['\"](?:route|handler|view)['\"]",
            r"eval\s*\([^)]+(?:route|path|endpoint)",
            r"exec\s*\([^)]+(?:route|path|endpoint)",
            r"__import__\s*\([^)]+(?:route|handler|api)",
        ],
        "confidence": 0.40,
        "risk": "HIGH",
        "description": "Routes may be generated via reflection/metaprogramming",
    },
    "dynamic_url_construction": {
        "patterns": [
            r"add_url_rule\s*\(\s*[^'\"]+\+",  # String concatenation in URL
            r"add_route\s*\(\s*f['\"]",  # f-string in route
            r"\.route\s*\(\s*[^'\"]+\+",  # String concatenation
            r"url\s*=\s*[^'\"]+\+\s*['\"]",
        ],
        "confidence": 0.55,
        "risk": "MEDIUM",
        "description": "URL paths constructed dynamically",
    },
    "runtime_registration": {
        "patterns": [
            r"def\s+\w+\([^)]*\):\s*\n[^}]*?(?:app|router)\.(?:add_route|add_url_rule|register)",
            r"(?:register|add)_(?:route|endpoint|handler)\s*\(\s*\w+\s*,",  # Function to add routes
        ],
        "confidence": 0.50,
        "risk": "MEDIUM",
        "description": "Routes registered at runtime via function calls",
    },
}

# Enhanced tool detection
# NOTE: Script only DETECTS and SUGGESTS. LLM DECIDES and CALLS.
ENHANCED_TOOLS = {
    "semgrep": {
        "command": "semgrep",
        "check_args": ["--version"],
        "description": "Framework-native route detection with Semgrep",
        "confidence_boost": 0.10,
        # LLM will decide whether to run these commands based on suggested_action
        "recommended_commands": [
            {
                "purpose": "route_discovery",
                "command": "semgrep --config auto --json --output semgrep_routes.json {project_path}",
                "description": "Discover framework routes and API endpoints",
            },
            {
                "purpose": "security_patterns",
                "command": "semgrep --config p/security-audit --json --output semgrep_security.json {project_path}",
                "description": "Detect security-relevant code patterns",
            },
        ],
    },
    "noir": {
        "command": "noir",
        "check_args": ["--version"],
        "description": "OWASP Noir LLM-enhanced endpoint discovery",
        "confidence_boost": 0.15,
        "recommended_commands": [
            {
                "purpose": "endpoint_discovery",
                "command": "noir -b {project_path} -f json -o noir_endpoints.json",
                "description": "Discover API endpoints with LLM-enhanced analysis",
            },
        ],
    },
    "codeql": {
        "command": "codeql",
        "check_args": ["version"],
        "description": "CodeQL deep dataflow analysis",
        "confidence_boost": 0.12,
        "recommended_commands": [
            {
                "purpose": "database_creation",
                "command": "codeql database create codeql_db --language={language} --source-root={project_path}",
                "description": "Create CodeQL database for analysis",
            },
            {
                "purpose": "dataflow_analysis",
                "command": "codeql database analyze codeql_db --format=json --output=codeql_results.json",
                "description": "Run dataflow analysis queries",
            },
        ],
    },
}


def should_exclude(path: Path, excludes: Set[str]) -> bool:
    """Check if path should be excluded."""
    name = path.name
    for exclude in excludes:
        if exclude.startswith("*"):
            if name.endswith(exclude[1:]):
                return True
        elif name == exclude:
            return True
    return False


def get_file_info(path: Path, root: Path) -> Dict:
    """Get file information."""
    rel_path = path.relative_to(root)
    stat = path.stat()

    return {
        "path": str(rel_path),
        "name": path.name,
        "extension": path.suffix.lower() if path.suffix else None,
        "size": stat.st_size,
        "is_hidden": path.name.startswith("."),
    }


def list_files(
    root: Path,
    extensions: Optional[Set[str]] = None,
    max_depth: Optional[int] = None,
    excludes: Optional[Set[str]] = None,
) -> Dict:
    """List files in directory with metadata."""
    if excludes is None:
        excludes = DEFAULT_EXCLUDES

    root = root.resolve()  # S2 fix: Canonicalize to prevent path traversal

    files = []
    directories = []
    total_size = 0
    extension_counts: Dict[str, int] = {}

    def walk(current: Path, depth: int):
        nonlocal total_size

        if max_depth is not None and depth > max_depth:
            return

        try:
            entries = sorted(current.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        except PermissionError:
            return

        for entry in entries:
            if should_exclude(entry, excludes):
                continue

            # S1 fix: Symlink boundary check — prevent escape from project root
            if entry.is_symlink():
                try:
                    resolved = entry.resolve()
                    if not str(resolved).startswith(str(root.resolve())):
                        continue  # Skip symlinks pointing outside project
                except (OSError, ValueError):
                    continue

            if entry.is_dir():
                rel_path = entry.relative_to(root)
                directories.append(str(rel_path))
                walk(entry, depth + 1)
            elif entry.is_file():
                ext = entry.suffix.lower() if entry.suffix else "(no extension)"

                # Filter by extension if specified
                if extensions and ext.lstrip(".") not in extensions and ext not in extensions:
                    continue

                file_info = get_file_info(entry, root)
                files.append(file_info)
                total_size += file_info["size"]
                extension_counts[ext] = extension_counts.get(ext, 0) + 1

    walk(root, 0)

    return {
        "root": str(root.absolute()),
        "total_files": len(files),
        "total_directories": len(directories),
        "total_size_bytes": total_size,
        "extension_summary": dict(sorted(extension_counts.items(), key=lambda x: -x[1])),
        "directories": directories,
        "files": files,
    }


def categorize_files(files: List[Dict]) -> Dict:
    """Categorize files by their likely purpose."""
    categorized = {cat: [] for cat in FILE_CATEGORIES}
    categorized["other"] = []

    for file_info in files:
        path = file_info["path"].lower()
        name = file_info["name"].lower()
        ext = file_info["extension"] or ""

        matched = False
        for cat_name, cat_config in FILE_CATEGORIES.items():
            patterns = cat_config.get("patterns", [])
            cat_extensions = cat_config.get("extensions", [])

            for pattern in patterns:
                if pattern.startswith("*"):
                    if name.endswith(pattern[1:]):
                        categorized[cat_name].append(file_info["path"])
                        matched = True
                        break
                elif pattern in path.split(os.sep) or pattern == name:
                    if not cat_extensions or ext in cat_extensions:
                        categorized[cat_name].append(file_info["path"])
                        matched = True
                        break
            if matched:
                break

        if not matched:
            categorized["other"].append(file_info["path"])

    # Remove empty categories and add counts
    result = {}
    for cat_name, files_list in categorized.items():
        if files_list:
            result[cat_name] = {
                "count": len(files_list),
                "description": FILE_CATEGORIES.get(cat_name, {}).get("description", "Other files"),
                "files": files_list[:20],  # Limit for readability
                "truncated": len(files_list) > 20,
            }

    return result


def detect_project_type(result: Dict) -> Dict:
    """Detect project type from file patterns."""
    extensions = result.get("extension_summary", {})
    files = [f["name"].lower() for f in result.get("files", [])]

    indicators = {
        "python": {
            "extensions": [".py"],
            "files": ["setup.py", "pyproject.toml", "requirements.txt", "Pipfile"],
        },
        "javascript": {
            "extensions": [".js", ".jsx"],
            "files": ["package.json", "webpack.config.js"],
        },
        "typescript": {
            "extensions": [".ts", ".tsx"],
            "files": ["tsconfig.json", "package.json"],
        },
        "go": {
            "extensions": [".go"],
            "files": ["go.mod", "go.sum"],
        },
        "java": {
            "extensions": [".java"],
            "files": ["pom.xml", "build.gradle"],
        },
        "rust": {
            "extensions": [".rs"],
            "files": ["Cargo.toml"],
        },
        "docker": {
            "files": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
        },
        "kubernetes": {
            "files": ["k8s", "kubernetes", "helm"],
        },
        "terraform": {
            "extensions": [".tf", ".hcl"],
            "files": ["main.tf", "terraform.tfvars"],
        },
    }

    detected = []
    for proj_type, config in indicators.items():
        score = 0

        # Check extensions
        for ext in config.get("extensions", []):
            if ext in extensions:
                score += extensions[ext]

        # Check specific files
        for fname in config.get("files", []):
            if fname.lower() in files:
                score += 10

        if score > 0:
            detected.append({"type": proj_type, "confidence_score": score})

    return {
        "detected_types": sorted(detected, key=lambda x: -x["confidence_score"]),
        "primary_type": detected[0]["type"] if detected else "unknown",
    }


def match_doc_pattern(name: str, pattern: str) -> bool:
    """Match a filename against a documentation pattern using glob-style matching."""
    # Handle patterns with wildcards
    if "*" in pattern:
        return fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.lower(), pattern.lower())
    # Exact match (case-insensitive)
    return name.lower() == pattern.lower()


def classify_documentation(
    project_root: Path,
    files: List[Dict],
    directories: List[str],
) -> Dict[str, Any]:
    """
    Classify documentation files by category and build prioritized list.

    Args:
        project_root: Root path of the project
        files: List of file info dicts from list_files()
        directories: List of directory paths

    Returns:
        Dict containing categorized documentation files
    """
    categorized: Dict[str, List[Dict]] = {cat: [] for cat in DOC_CATEGORIES}
    all_doc_files: List[Dict] = []

    # First, identify docs directories
    docs_dirs: Set[str] = set()
    for dir_path in directories:
        dir_name = Path(dir_path).name.lower()
        for pattern in DOC_CATEGORIES["docs_directory"]["patterns"]:
            if dir_name == pattern.lower():
                docs_dirs.add(dir_path)
                categorized["docs_directory"].append({
                    "path": dir_path + "/",
                    "category": "docs_directory",
                    "is_directory": True,
                })
                break

    # Classify each file
    for file_info in files:
        file_path = file_info["path"]
        file_name = file_info["name"]
        file_ext = file_info.get("extension", "") or ""
        file_size = file_info.get("size", 0)

        # Check if file is in a docs directory
        in_docs_dir = any(file_path.startswith(docs_dir + os.sep) or file_path.startswith(docs_dir + "/")
                         for docs_dir in docs_dirs)

        matched_category = None
        match_priority = 999

        # Check against each category
        for cat_name, cat_config in DOC_CATEGORIES.items():
            if cat_config.get("is_directory"):
                continue

            patterns = cat_config.get("patterns", [])
            allowed_extensions = cat_config.get("extensions", [".md", ".rst", ".txt", ""])
            priority = cat_config.get("priority", 99)

            # Check extension compatibility
            ext_match = file_ext.lower() in [e.lower() for e in allowed_extensions]
            if not ext_match and file_ext != "":
                continue

            # Check pattern match
            for pattern in patterns:
                if match_doc_pattern(file_name, pattern):
                    if priority < match_priority:
                        matched_category = cat_name
                        match_priority = priority
                    break

        # If matched or in docs directory with doc extension
        if matched_category:
            doc_entry = {
                "path": file_path,
                "name": file_name,
                "category": matched_category,
                "size": file_size,
                "in_docs_dir": in_docs_dir,
                "priority": match_priority,
            }
            categorized[matched_category].append(doc_entry)
            all_doc_files.append(doc_entry)
        elif in_docs_dir and file_ext.lower() in [".md", ".rst", ".txt"]:
            # Files in docs directory that don't match specific patterns
            doc_entry = {
                "path": file_path,
                "name": file_name,
                "category": "docs_directory",
                "size": file_size,
                "in_docs_dir": True,
                "priority": DOC_CATEGORIES["docs_directory"]["priority"],
            }
            all_doc_files.append(doc_entry)

    # Build simplified output for each category
    doc_files_by_category: Dict[str, List[str]] = {}
    for cat_name, entries in categorized.items():
        if entries:
            doc_files_by_category[cat_name] = [e["path"] for e in entries]

    # Sort all docs by priority then by size (larger = more content = higher priority)
    all_doc_files.sort(key=lambda x: (x["priority"], -x["size"]))

    # Build priority order list
    doc_priority_order = [
        {"path": doc["path"], "category": doc["category"], "size": doc["size"]}
        for doc in all_doc_files
    ]

    return {
        "files": doc_files_by_category,
        "doc_priority_order": doc_priority_order,
        "docs_directories": list(docs_dirs),
    }


def calculate_doc_quality_score(
    project_root: Path,
    doc_classification: Dict[str, Any],
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Calculate documentation quality score.

    Scoring:
    - base_score (0-40):
      - has_readme: 20
      - has_architecture_doc: 10
      - has_api_doc: 10

    - depth_score (0-30):
      - readme_size_>_5kb: 10
      - has_docs_directory: 10
      - docs_file_count_>_5: 10

    - completeness_score (0-30):
      - has_contributing: 5
      - has_changelog: 5
      - has_openapi_spec: 10
      - has_code_comments_ratio_>_10%: 10

    Grade mapping:
      - high: >= 70
      - medium: 40-69
      - low: 10-39
      - none: < 10

    Args:
        project_root: Root path of the project
        doc_classification: Output from classify_documentation()
        files: List of all file info dicts

    Returns:
        Dict with total_score, grade, breakdown
    """
    doc_files = doc_classification.get("files", {})
    priority_order = doc_classification.get("doc_priority_order", [])
    docs_dirs = doc_classification.get("docs_directories", [])

    # Initialize scores
    base_score = 0
    depth_score = 0
    completeness_score = 0

    # Base score calculations
    has_readme = bool(doc_files.get("readme"))
    has_architecture = bool(doc_files.get("architecture"))
    has_api_docs = bool(doc_files.get("api_docs"))

    if has_readme:
        base_score += 20
    if has_architecture:
        base_score += 10
    if has_api_docs:
        base_score += 10

    # Depth score calculations
    # Check readme size
    readme_size = 0
    for doc in priority_order:
        if doc["category"] == "readme":
            readme_size = max(readme_size, doc["size"])
    if readme_size > 5000:  # > 5KB
        depth_score += 10

    # Check for docs directory
    has_docs_directory = bool(docs_dirs)
    if has_docs_directory:
        depth_score += 10

    # Count docs files
    total_doc_files = len(priority_order)
    if total_doc_files > 5:
        depth_score += 10

    # Completeness score calculations
    has_contributing = bool(doc_files.get("contributing"))
    has_changelog = bool(doc_files.get("changelog"))

    if has_contributing:
        completeness_score += 5
    if has_changelog:
        completeness_score += 5

    # Check for OpenAPI spec
    has_openapi_spec = False
    for doc in priority_order:
        if doc["category"] == "api_docs":
            doc_name = Path(doc["path"]).name.lower()
            if any(kw in doc_name for kw in ["openapi", "swagger"]) and \
               doc_name.endswith((".yaml", ".yml", ".json")):
                has_openapi_spec = True
                break
    if has_openapi_spec:
        completeness_score += 10

    # Check code comment ratio (estimate from file sizes)
    # This is a heuristic: count files that might have significant comments
    # For accurate measurement, we'd need to parse files, but that's expensive
    # Instead, we check if there are inline documentation patterns
    code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp"}
    code_files = [f for f in files if (f.get("extension") or "").lower() in code_extensions]

    # Simple heuristic: if there are docstring/jsdoc patterns in the project
    # we'll check by looking for common doc file patterns
    # For now, give partial credit if there's any API documentation
    if has_api_docs and code_files:
        # Assume documented API implies some code documentation
        completeness_score += 5

    # Additional check: look for code documentation indicators
    for f in files:
        fname = f["name"].lower()
        if fname in ["api.md", "api.rst", "reference.md", "reference.rst"]:
            completeness_score = min(30, completeness_score + 5)
            break

    # Calculate total and grade
    total_score = base_score + depth_score + completeness_score

    if total_score >= 70:
        grade = "high"
    elif total_score >= 40:
        grade = "medium"
    elif total_score >= 10:
        grade = "low"
    else:
        grade = "none"

    return {
        "total_score": total_score,
        "grade": grade,
        "breakdown": {
            "base_score": base_score,
            "depth_score": depth_score,
            "completeness_score": completeness_score,
        },
        "details": {
            "has_readme": has_readme,
            "has_architecture_doc": has_architecture,
            "has_api_doc": has_api_docs,
            "readme_size_bytes": readme_size,
            "has_docs_directory": has_docs_directory,
            "total_doc_files": total_doc_files,
            "has_contributing": has_contributing,
            "has_changelog": has_changelog,
            "has_openapi_spec": has_openapi_spec,
        },
    }


def analyze_documentation(
    project_root: Path,
    files: List[Dict],
    directories: List[str],
) -> Dict[str, Any]:
    """
    Perform comprehensive documentation analysis for Phase 1.1.

    Args:
        project_root: Root path of the project
        files: List of file info dicts from list_files()
        directories: List of directory paths

    Returns:
        Dict containing complete documentation analysis
    """
    # Classify documentation
    doc_classification = classify_documentation(project_root, files, directories)

    # Calculate quality score
    quality_score = calculate_doc_quality_score(project_root, doc_classification, files)

    # Determine if project has meaningful documentation
    has_documentation = quality_score["total_score"] >= 10

    return {
        "has_documentation": has_documentation,
        "quality_grade": quality_score["grade"],
        "quality_score": quality_score["total_score"],
        "score_breakdown": quality_score["breakdown"],
        "score_details": quality_score["details"],
        "files": doc_classification["files"],
        "doc_priority_order": doc_classification["doc_priority_order"],
        "docs_directories": doc_classification["docs_directories"],
    }


# =============================================================================
# Enhanced Tool Detection
# =============================================================================

def check_enhanced_tools() -> Dict[str, Any]:
    """
    Check availability of enhanced detection tools (Semgrep, OWASP Noir, CodeQL).

    This function ONLY detects and suggests. It does NOT call tools directly.
    The LLM should decide whether to run the recommended commands based on
    the suggested_action field.

    Returns:
        Dict with tool availability, version, and suggested actions for LLM
    """
    tools_status = {}

    for tool_name, tool_config in ENHANCED_TOOLS.items():
        tool_info = {
            "available": False,
            "version": None,
            "description": tool_config["description"],
            "confidence_boost": tool_config["confidence_boost"],
            "suggested_action": "SKIP",  # Default: tool not available
            "recommended_commands": [],
        }

        try:
            cmd = [tool_config["command"]] + tool_config["check_args"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                tool_info["available"] = True
                # Extract version from output
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', result.stdout + result.stderr)
                if version_match:
                    tool_info["version"] = version_match.group(1)
                # Tool available: suggest LLM to run it for enhanced discovery
                tool_info["suggested_action"] = "RUN_FOR_ENHANCED_DISCOVERY"
                tool_info["recommended_commands"] = tool_config.get("recommended_commands", [])
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

        tools_status[tool_name] = tool_info

    # Add summary for LLM decision making
    available_tools = [name for name, info in tools_status.items() if info["available"]]
    tools_status["_summary"] = {
        "available_count": len(available_tools),
        "available_tools": available_tools,
        "llm_action_required": len(available_tools) > 0,
        "instruction": (
            "Enhanced tools detected. LLM should execute recommended_commands "
            "for tools with suggested_action='RUN_FOR_ENHANCED_DISCOVERY' "
            "and merge results into discovery output."
            if available_tools else
            "No enhanced tools available. Proceed with standard three-layer discovery."
        ),
    }

    return tools_status


# =============================================================================
# Layer 1: Deterministic Discovery
# =============================================================================

def discover_layer1_routes(
    project_root: Path,
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Layer 1: Deterministic discovery of routes from code patterns.

    Scans for standard route decorators and patterns with 95%+ confidence.

    Args:
        project_root: Project root directory
        files: List of file info dicts

    Returns:
        Dict with discovered routes and confidence metrics
    """
    discoveries = []
    frameworks_detected = set()

    # File extension to language mapping
    ext_to_lang = {
        ".py": ["python_flask", "python_fastapi", "python_django",
                "python_graphql", "python_websocket", "python_celery",
                "python_scheduler", "python_file_upload",
                "debug_endpoints", "health_endpoints", "grpc_service"],
        ".js": ["javascript_express"],
        ".ts": ["javascript_express"],
        ".java": ["java_spring"],
        ".go": ["go_gin"],
    }

    for file_info in files:
        ext = (file_info.get("extension") or "").lower()
        if ext not in ext_to_lang:
            continue

        file_path = project_root / file_info["path"]
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (IOError, OSError):
            continue

        # Check patterns for this file type
        for pattern_group in ext_to_lang[ext]:
            if pattern_group not in LAYER1_ROUTE_PATTERNS:
                continue

            pattern_config = LAYER1_ROUTE_PATTERNS[pattern_group]
            for pattern in pattern_config["patterns"]:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    # Extract route path (last group is usually the path)
                    groups = match.groups()
                    route_path = groups[-1] if groups else match.group(0)

                    discoveries.append({
                        "path": route_path,
                        "file": file_info["path"],
                        "line": content[:match.start()].count('\n') + 1,
                        "pattern_type": pattern_group,
                        "framework": pattern_config["framework"],
                        "confidence": pattern_config["confidence"],
                        "layer": 1,
                    })
                    frameworks_detected.add(pattern_config["framework"])

    return {
        "discoveries": discoveries,
        "count": len(discoveries),
        "frameworks": list(frameworks_detected),
        "confidence": 0.95 if discoveries else 0.0,
    }


def discover_layer1_configs(
    project_root: Path,
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Layer 1: Discover API specs and route configuration files.

    Args:
        project_root: Project root directory
        files: List of file info dicts

    Returns:
        Dict with discovered config files
    """
    discoveries = []
    file_names = {f["name"].lower(): f for f in files}

    for config_type, config_info in LAYER1_CONFIG_PATTERNS.items():
        for config_file in config_info["files"]:
            if config_file.lower() in file_names:
                file_info = file_names[config_file.lower()]
                discoveries.append({
                    "file": file_info["path"],
                    "type": config_info["type"],
                    "config_type": config_type,
                    "confidence": config_info["confidence"],
                    "layer": 1,
                })

    return {
        "discoveries": discoveries,
        "count": len(discoveries),
        "has_openapi": any(d["config_type"] == "openapi" for d in discoveries),
        "confidence": max([d["confidence"] for d in discoveries], default=0.0),
    }


# =============================================================================
# Layer 2: Heuristic Discovery
# =============================================================================

def discover_layer2_directories(
    directories: List[str],
) -> Dict[str, Any]:
    """
    Layer 2: Heuristic discovery based on directory patterns.

    Args:
        directories: List of directory paths

    Returns:
        Dict with probable route directories
    """
    discoveries = []
    dir_names = {Path(d).name.lower(): d for d in directories}

    for pattern_type, pattern_config in LAYER2_DIRECTORY_PATTERNS.items():
        for pattern in pattern_config["patterns"]:
            if pattern.lower() in dir_names:
                discoveries.append({
                    "directory": dir_names[pattern.lower()],
                    "pattern_type": pattern_type,
                    "matched_pattern": pattern,
                    "confidence": pattern_config["confidence"],
                    "layer": 2,
                })

    return {
        "discoveries": discoveries,
        "count": len(discoveries),
        "confidence": max([d["confidence"] for d in discoveries], default=0.0),
    }


def discover_layer2_imports(
    project_root: Path,
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Layer 2: Detect web frameworks from import statements.

    Args:
        project_root: Project root directory
        files: List of file info dicts

    Returns:
        Dict with detected frameworks
    """
    discoveries = []
    frameworks_detected = {}

    code_extensions = {".py", ".js", ".ts", ".java", ".go"}

    for file_info in files:
        ext = (file_info.get("extension") or "").lower()
        if ext not in code_extensions:
            continue

        file_path = project_root / file_info["path"]
        if not file_path.exists():
            continue

        try:
            # Only read first 100 lines for imports
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= 100:
                        break
                    lines.append(line)
                content = "".join(lines)
        except (IOError, OSError):
            continue

        for framework_key, framework_config in LAYER2_IMPORT_PATTERNS.items():
            for pattern in framework_config["patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    framework = framework_config["framework"]
                    if framework not in frameworks_detected:
                        frameworks_detected[framework] = {
                            "framework": framework,
                            "confidence": framework_config["confidence"],
                            "files": [],
                            "layer": 2,
                        }
                    frameworks_detected[framework]["files"].append(file_info["path"])
                    break

    return {
        "discoveries": list(frameworks_detected.values()),
        "count": len(frameworks_detected),
        "frameworks": list(frameworks_detected.keys()),
        "confidence": max([d["confidence"] for d in frameworks_detected.values()], default=0.0),
    }


# =============================================================================
# Layer 3: Dynamic Route Detection
# =============================================================================

def discover_layer3_dynamic(
    project_root: Path,
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Layer 3: Detect dynamic route indicators (uncertainty sources).

    Args:
        project_root: Project root directory
        files: List of file info dicts

    Returns:
        Dict with dynamic route indicators
    """
    indicators = []
    code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rb"}

    for file_info in files:
        ext = (file_info.get("extension") or "").lower()
        if ext not in code_extensions:
            continue

        file_path = project_root / file_info["path"]
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (IOError, OSError):
            continue

        for indicator_type, indicator_config in LAYER3_DYNAMIC_PATTERNS.items():
            for pattern in indicator_config["patterns"]:
                matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
                if matches:
                    for match in matches[:5]:  # Limit to 5 matches per pattern per file
                        line_num = content[:match.start()].count('\n') + 1
                        # Extract context (the matching line)
                        lines = content.split('\n')
                        context = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                        indicators.append({
                            "type": indicator_type,
                            "file": file_info["path"],
                            "line": line_num,
                            "pattern_matched": pattern[:50] + "..." if len(pattern) > 50 else pattern,
                            "context": context[:100] if len(context) > 100 else context,
                            "confidence": indicator_config["confidence"],
                            "risk": indicator_config["risk"],
                            "description": indicator_config["description"],
                            "layer": 3,
                        })

    # Assign Finding IDs to HIGH risk indicators (P1-GAP-06 fix)
    finding_seq = 1
    architecture_findings = []
    for ind in indicators:
        if ind["risk"] == "HIGH":
            finding_id = f"F-P1-{finding_seq:03d}"
            ind["finding_id"] = finding_id
            architecture_findings.append({
                "id": finding_id,
                "type": "dynamic_route",
                "title": f"Dynamic Route Indicator: {ind['type']}",
                "description": ind["description"],
                "severity": "HIGH" if ind["risk"] == "HIGH" else "MEDIUM",
                "category": "dynamic_route",
                "location": {
                    "file": ind["file"],
                    "line": ind["line"],
                },
                "security_relevance": "Routes may be registered dynamically, potentially bypassing security controls",
                "recommended_action": "Verify all dynamic routes are properly secured in later phases",
            })
            finding_seq += 1

    # Group by type for summary
    by_type = {}
    for ind in indicators:
        t = ind["type"]
        if t not in by_type:
            by_type[t] = {
                "type": t,
                "count": 0,
                "risk": ind["risk"],
                "description": ind["description"],
                "locations": [],
            }
        by_type[t]["count"] += 1
        by_type[t]["locations"].append({
            "file": ind["file"],
            "line": ind["line"],
            "finding_id": ind.get("finding_id"),
        })

    return {
        "indicators": indicators,
        "architecture_findings": architecture_findings,  # P1-GAP-06: Pre-generated findings
        "summary": list(by_type.values()),
        "total_count": len(indicators),
        "has_dynamic_routes": len(indicators) > 0,
        "high_risk_count": sum(1 for i in indicators if i["risk"] == "HIGH"),
        "medium_risk_count": sum(1 for i in indicators if i["risk"] == "MEDIUM"),
        "findings_generated": len(architecture_findings),
    }


# =============================================================================
# Module ID Generation and Security Level Suggestion (P1-GAP-02, P1-GAP-03 fix)
# =============================================================================

# Security level heuristics based on directory/module naming patterns
SECURITY_LEVEL_HEURISTICS = {
    "HIGH": {
        "patterns": [
            "auth", "authentication", "authorization", "security", "oauth",
            "jwt", "token", "session", "credential", "password", "secret",
            "crypto", "encrypt", "decrypt", "key", "cert", "ssl", "tls",
            "payment", "billing", "checkout", "transaction", "finance",
            "admin", "superuser", "privileged", "rbac", "permission", "acl",
            "api", "gateway", "proxy", "webhook", "callback",
        ],
        "description": "Authentication, authorization, payment, or security-critical components",
    },
    "MEDIUM": {
        "patterns": [
            "user", "account", "profile", "settings", "preference",
            "data", "database", "db", "model", "entity", "repository",
            "service", "business", "logic", "domain", "core",
            "upload", "file", "storage", "media", "asset",
            "email", "notification", "message", "queue", "worker",
            "integration", "external", "third-party", "plugin",
        ],
        "description": "User data, business logic, or integration components",
    },
    "LOW": {
        "patterns": [
            "util", "utils", "helper", "common", "shared", "lib",
            "test", "tests", "spec", "mock", "fixture",
            "doc", "docs", "documentation", "example", "sample",
            "static", "public", "asset", "css", "js", "image",
            "log", "logging", "metric", "monitor", "health",
            "config", "setting", "constant", "enum",
        ],
        "description": "Utilities, tests, documentation, or static assets",
    },
}


def suggest_security_level(path: str, name: str) -> Tuple[str, str, float]:
    """
    Suggest security level for a module based on path and name patterns.

    Args:
        path: Module directory path
        name: Module name

    Returns:
        Tuple of (security_level, reason, confidence)
    """
    path_lower = path.lower()
    name_lower = name.lower()
    combined = f"{path_lower}/{name_lower}"

    # Check HIGH patterns first (most specific)
    for pattern in SECURITY_LEVEL_HEURISTICS["HIGH"]["patterns"]:
        if pattern in combined:
            return (
                "HIGH",
                f"Contains security-sensitive pattern: '{pattern}'",
                0.85,
            )

    # Check MEDIUM patterns
    for pattern in SECURITY_LEVEL_HEURISTICS["MEDIUM"]["patterns"]:
        if pattern in combined:
            return (
                "MEDIUM",
                f"Contains data/business pattern: '{pattern}'",
                0.75,
            )

    # Check LOW patterns
    for pattern in SECURITY_LEVEL_HEURISTICS["LOW"]["patterns"]:
        if pattern in combined:
            return (
                "LOW",
                f"Contains utility/test pattern: '{pattern}'",
                0.80,
            )

    # Default to MEDIUM with low confidence
    return (
        "MEDIUM",
        "No specific pattern matched, defaulting to MEDIUM",
        0.50,
    )


def generate_module_id(path: str, index: int, prefix: str = "M") -> str:
    """
    Generate a module ID from path.

    Format: M-{abbreviated_name} or M-{index:03d} if name is too complex

    Args:
        path: Module directory path
        index: Sequential index for fallback
        prefix: ID prefix (default: "M")

    Returns:
        Module ID string
    """
    # Extract meaningful name from path
    parts = path.replace("\\", "/").split("/")
    # Filter out common non-meaningful parts
    skip_parts = {"src", "lib", "app", "main", ".", ""}
    meaningful_parts = [p for p in parts if p.lower() not in skip_parts]

    if meaningful_parts:
        # Use last meaningful part as base name
        base_name = meaningful_parts[-1]
        # Clean and abbreviate
        clean_name = re.sub(r'[^a-zA-Z0-9]', '', base_name)
        if len(clean_name) > 10:
            # Abbreviate long names
            clean_name = clean_name[:8]
        if clean_name:
            return f"{prefix}-{clean_name.lower()}"

    # Fallback to index-based ID
    return f"{prefix}-{index:03d}"


def generate_module_inventory_suggestions(
    directories: List[str],
    layer2_dirs: Dict,
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Generate module inventory suggestions with IDs and security levels.

    Args:
        directories: List of all directory paths
        layer2_dirs: Layer 2 heuristic directory discoveries
        files: List of file info dicts

    Returns:
        Dict with suggested module inventory
    """
    # Identify candidate module directories
    # Priority: Layer 2 discoveries > top-level directories with code
    module_candidates = []
    used_ids = set()

    # First, add Layer 2 discovered directories (probable route/handler dirs)
    layer2_discoveries = layer2_dirs.get("discoveries", [])
    for disc in layer2_discoveries:
        dir_path = disc.get("directory", "")
        if dir_path:
            module_candidates.append({
                "path": dir_path,
                "source": "layer2_heuristic",
                "confidence": disc.get("confidence", 0.80),
            })

    # Then, add top-level directories that contain code files
    code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".php"}
    dir_file_counts = {}
    for f in files:
        f_path = f.get("path", "")
        f_ext = f.get("extension", "")
        if f_ext and f_ext.lower() in code_extensions:
            # Get top-level directory
            parts = f_path.replace("\\", "/").split("/")
            if len(parts) > 1:
                top_dir = parts[0]
                if top_dir not in dir_file_counts:
                    dir_file_counts[top_dir] = 0
                dir_file_counts[top_dir] += 1

    for dir_name, file_count in dir_file_counts.items():
        if file_count >= 3:  # At least 3 code files to be considered a module
            # Check if not already in candidates
            if not any(c["path"] == dir_name for c in module_candidates):
                module_candidates.append({
                    "path": dir_name,
                    "source": "code_directory",
                    "confidence": 0.70,
                    "file_count": file_count,
                })

    # Generate module suggestions
    modules = []
    for idx, candidate in enumerate(module_candidates):
        path = candidate["path"]
        name = Path(path).name or path

        # Generate unique ID
        base_id = generate_module_id(path, idx + 1)
        module_id = base_id
        counter = 1
        while module_id in used_ids:
            module_id = f"{base_id}-{counter}"
            counter += 1
        used_ids.add(module_id)

        # Suggest security level
        security_level, reason, level_confidence = suggest_security_level(path, name)

        # Count files in this module
        module_files = [f for f in files if f.get("path", "").startswith(path)]
        total_loc = sum(f.get("size", 0) for f in module_files)  # Approximate LOC

        modules.append({
            "id": module_id,
            "name": name.replace("_", " ").replace("-", " ").title(),
            "path": path,
            "type": "Suggested",  # Claude should refine this
            "security_level": security_level,
            "security_level_reason": reason,
            "security_level_confidence": level_confidence,
            "files": len(module_files),
            "loc_estimate": total_loc // 50,  # Rough LOC estimate (50 bytes per line)
            "source": candidate.get("source", "unknown"),
            "discovery_confidence": candidate.get("confidence", 0.50),
        })

    return {
        "modules": modules,
        "total_modules": len(modules),
        "generation_notes": [
            "Module IDs are suggestions - Claude should verify and adjust",
            "Security levels are heuristic-based - review for accuracy",
            "Module types are placeholder 'Suggested' - Claude should assign actual types",
        ],
    }


# =============================================================================
# Confidence Calculation
# =============================================================================

def calculate_coverage_confidence(
    layer1_routes: Dict,
    layer1_configs: Dict,
    layer2_dirs: Dict,
    layer2_imports: Dict,
    layer3_dynamic: Dict,
    enhanced_tools: Dict,
) -> Dict[str, Any]:
    """
    Calculate overall coverage confidence based on three-layer discovery.

    Formula:
      base_confidence = weighted_avg(layer1, layer2)
      uncertainty_penalty = layer3_dynamic_count * 0.02 (max 0.20)
      tool_boost = sum(available_tools.confidence_boost)
      final = base_confidence - uncertainty_penalty + tool_boost

    Args:
        layer1_routes: Layer 1 route discovery results
        layer1_configs: Layer 1 config discovery results
        layer2_dirs: Layer 2 directory discovery results
        layer2_imports: Layer 2 import discovery results
        layer3_dynamic: Layer 3 dynamic indicator results
        enhanced_tools: Enhanced tool availability

    Returns:
        Dict with confidence metrics
    """
    # Base confidence from Layer 1 (weight: 0.6)
    l1_route_conf = layer1_routes.get("confidence", 0.0)
    l1_config_conf = layer1_configs.get("confidence", 0.0)
    l1_confidence = max(l1_route_conf, l1_config_conf) * 0.6

    # Layer 2 contribution (weight: 0.3)
    l2_dir_conf = layer2_dirs.get("confidence", 0.0)
    l2_import_conf = layer2_imports.get("confidence", 0.0)
    l2_confidence = max(l2_dir_conf, l2_import_conf) * 0.3

    # Base confidence (max contribution from L1+L2 = 0.9)
    base_confidence = min(0.95, l1_confidence + l2_confidence + 0.05)  # +0.05 baseline

    # Uncertainty penalty from Layer 3 (max penalty: 0.20)
    dynamic_count = layer3_dynamic.get("total_count", 0)
    high_risk_count = layer3_dynamic.get("high_risk_count", 0)
    uncertainty_penalty = min(0.20, dynamic_count * 0.02 + high_risk_count * 0.03)

    # Tool boost (if enhanced tools available)
    tool_boost = 0.0
    for tool_name, tool_info in enhanced_tools.items():
        if tool_info.get("available", False):
            tool_boost += tool_info.get("confidence_boost", 0.0)
    tool_boost = min(0.15, tool_boost)  # Cap tool boost at 0.15

    # Final confidence
    final_confidence = max(0.0, min(1.0, base_confidence - uncertainty_penalty + tool_boost))

    # Determine uncertainty sources
    uncertainty_sources = []
    if layer3_dynamic.get("has_dynamic_routes", False):
        for summary in layer3_dynamic.get("summary", []):
            uncertainty_sources.append({
                "type": summary["type"],
                "impact": summary["risk"],
                "count": summary["count"],
                "description": summary["description"],
            })

    if not layer1_configs.get("has_openapi", False):
        uncertainty_sources.append({
            "type": "no_openapi_spec",
            "impact": "LOW",
            "count": 1,
            "description": "No OpenAPI specification found for validation",
        })

    return {
        "overall_confidence": round(final_confidence, 3),
        "confidence_breakdown": {
            "layer1_contribution": round(l1_confidence, 3),
            "layer2_contribution": round(l2_confidence, 3),
            "base_confidence": round(base_confidence, 3),
            "uncertainty_penalty": round(uncertainty_penalty, 3),
            "tool_boost": round(tool_boost, 3),
        },
        "uncertainty_sources": uncertainty_sources,
        "has_uncertainty": len(uncertainty_sources) > 0,
        "recommendation": (
            "HIGH_CONFIDENCE" if final_confidence >= 0.85
            else "MEDIUM_CONFIDENCE" if final_confidence >= 0.70
            else "LOW_CONFIDENCE_REVIEW_REQUIRED"
        ),
    }


# =============================================================================
# Full P1 Discovery
# =============================================================================

def run_p1_discovery(
    project_root: Path,
    files: List[Dict],
    directories: List[str],
) -> Dict[str, Any]:
    """
    Run full three-layer P1 discovery.

    Args:
        project_root: Project root directory
        files: List of file info dicts
        directories: List of directory paths

    Returns:
        Complete P1 discovery results
    """
    # Check enhanced tools
    enhanced_tools = check_enhanced_tools()

    # Layer 1: Deterministic Discovery
    layer1_routes = discover_layer1_routes(project_root, files)
    layer1_configs = discover_layer1_configs(project_root, files)

    # Layer 2: Heuristic Discovery
    layer2_dirs = discover_layer2_directories(directories)
    layer2_imports = discover_layer2_imports(project_root, files)

    # Layer 3: Dynamic Route Detection
    layer3_dynamic = discover_layer3_dynamic(project_root, files)

    # Calculate confidence
    coverage_confidence = calculate_coverage_confidence(
        layer1_routes,
        layer1_configs,
        layer2_dirs,
        layer2_imports,
        layer3_dynamic,
        enhanced_tools,
    )

    # Generate module inventory suggestions (P1-GAP-02, P1-GAP-03)
    module_suggestions = generate_module_inventory_suggestions(
        directories,
        layer2_dirs,
        files,
    )

    # Build summary
    all_frameworks = set()
    all_frameworks.update(layer1_routes.get("frameworks", []))
    all_frameworks.update(layer2_imports.get("frameworks", []))

    # Collect entry types discovered
    entry_types_discovered = set()
    for route in layer1_routes.get("discoveries", []):
        entry_type = LAYER1_ROUTE_PATTERNS.get(route.get("pattern_type", ""), {}).get("entry_type")
        if entry_type:
            entry_types_discovered.add(entry_type)
        else:
            entry_types_discovered.add("rest_api")  # Default for standard routes

    return {
        "schema_version": "3.2.0",
        "discovery_timestamp": datetime.now().isoformat(),
        "enhanced_tools": enhanced_tools,
        "layer1_deterministic": {
            "routes": layer1_routes,
            "configs": layer1_configs,
        },
        "layer2_heuristic": {
            "directories": layer2_dirs,
            "frameworks": layer2_imports,
        },
        "layer3_dynamic_indicators": layer3_dynamic,
        "module_suggestions": module_suggestions,  # NEW: Module ID + security_level suggestions
        "coverage_confidence": coverage_confidence,
        "summary": {
            "total_routes_discovered": layer1_routes.get("count", 0),
            "config_files_found": layer1_configs.get("count", 0),
            "probable_route_dirs": layer2_dirs.get("count", 0),
            "frameworks_detected": list(all_frameworks),
            "dynamic_indicators_found": layer3_dynamic.get("total_count", 0),
            "overall_confidence": coverage_confidence["overall_confidence"],
            "has_openapi": layer1_configs.get("has_openapi", False),
            "suggested_modules_count": module_suggestions.get("total_modules", 0),
            "entry_types_discovered": list(entry_types_discovered),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Module Discovery Script for STRIDE threat modeling (P1 Phase)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # List all files in a project
    python module_discovery.py /path/to/project

    # Filter by extensions
    python module_discovery.py /path/to/project --extensions py,js,ts

    # Limit directory depth
    python module_discovery.py /path/to/project --max-depth 3

    # Categorize files by purpose
    python module_discovery.py /path/to/project --categorize

    # Detect project type
    python module_discovery.py /path/to/project --detect-type

    # Analyze documentation (Phase 1.1 Doc-Guided Discovery)
    python module_discovery.py /path/to/project --doc-analysis

    # Combined analysis for threat modeling
    python module_discovery.py /path/to/project --categorize --detect-type --doc-analysis

    # === P1 Three-Layer Discovery ===

    # Full P1 discovery with three-layer analysis
    python module_discovery.py /path/to/project --p1-discovery

    # Detect dynamic route indicators only
    python module_discovery.py /path/to/project --detect-dynamic

    # Output P1 discovery in YAML format
    python module_discovery.py /path/to/project --p1-discovery --output-yaml

    # P1 discovery with summary only (for CI/CD integration)
    python module_discovery.py /path/to/project --p1-discovery --summary-only --output-yaml
        """
    )

    parser.add_argument(
        "path",
        help="Project directory path"
    )

    parser.add_argument(
        "--extensions", "-e",
        help="Filter by file extensions (comma-separated, e.g., py,js,ts)"
    )

    parser.add_argument(
        "--max-depth", "-d",
        type=int,
        help="Maximum directory depth to traverse"
    )

    parser.add_argument(
        "--categorize", "-c",
        action="store_true",
        help="Categorize files by purpose (entry points, API, config, etc.)"
    )

    parser.add_argument(
        "--detect-type", "-t",
        action="store_true",
        help="Detect project type from file patterns"
    )

    parser.add_argument(
        "--doc-analysis", "-D",
        action="store_true",
        help="Analyze documentation files for Phase 1.1 Doc-Guided Discovery"
    )

    parser.add_argument(
        "--summary-only", "-s",
        action="store_true",
        help="Output summary only (no file list)"
    )

    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty-print JSON output"
    )

    # P1 Three-Layer Discovery arguments
    parser.add_argument(
        "--p1-discovery",
        action="store_true",
        help="Run full three-layer P1 discovery (deterministic + heuristic + dynamic)"
    )

    parser.add_argument(
        "--detect-dynamic",
        action="store_true",
        help="Detect dynamic route indicators only (Layer 3)"
    )

    parser.add_argument(
        "--output-yaml",
        action="store_true",
        help="Output in YAML format (requires PyYAML)"
    )

    args = parser.parse_args()

    # Validate path
    root = Path(args.path)
    if not root.exists():
        print(json.dumps({"error": f"Path does not exist: {args.path}"}))
        sys.exit(1)
    if not root.is_dir():
        print(json.dumps({"error": f"Path is not a directory: {args.path}"}))
        sys.exit(1)

    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = set(ext.strip().lstrip(".") for ext in args.extensions.split(","))

    # List files
    result = list_files(root, extensions, args.max_depth)

    # P1 Three-Layer Discovery mode
    if args.p1_discovery:
        p1_result = run_p1_discovery(root, result["files"], result["directories"])
        # Merge P1 discovery into result
        result["p1_discovery"] = p1_result
        result["coverage_confidence"] = p1_result["coverage_confidence"]
        # Also include categorization and type detection
        result["categories"] = categorize_files(result["files"])
        result["project_type"] = detect_project_type(result)
        result["documentation"] = analyze_documentation(
            root,
            result["files"],
            result["directories"],
        )

    # Dynamic route detection only (Layer 3)
    elif args.detect_dynamic:
        dynamic_result = discover_layer3_dynamic(root, result["files"])
        result["dynamic_indicators"] = dynamic_result

    # Add categorization if requested
    if args.categorize:
        result["categories"] = categorize_files(result["files"])

    # Add project type detection if requested
    if args.detect_type:
        result["project_type"] = detect_project_type(result)

    # Add documentation analysis if requested (Phase 1.1 Doc-Guided Discovery)
    if args.doc_analysis:
        result["documentation"] = analyze_documentation(
            root,
            result["files"],
            result["directories"],
        )

    # Remove file list if summary only
    if args.summary_only:
        del result["files"]
        del result["directories"]

    # Output format selection
    if args.output_yaml:
        if not YAML_AVAILABLE:
            print(json.dumps({"error": "PyYAML not installed. Run: pip install pyyaml"}))
            sys.exit(1)
        print(yaml.dump(result, default_flow_style=False, allow_unicode=True, sort_keys=False))
    elif args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
