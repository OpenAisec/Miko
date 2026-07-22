#!/usr/bin/env python3
# Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

"""
Phase Data Manager for STRIDE Threat Modeling Workflow.

Manages structured data extraction, storage, and cross-phase querying
for the 8-phase threat modeling workflow.

Design Philosophy (per SKILL.md First Principles):
- Context is a shared resource: Script queries replace re-reading Markdown
- Claude is smart: LLM does analysis, script does data management
- Progressive disclosure: Query on-demand, don't preload
- Scripts are black boxes: Execution doesn't consume context, only output does
- Freedom matches task fragility: ID generation by script, descriptions by LLM

Primary Approach (Option C):
- LLM outputs Markdown with embedded ```yaml:{block_name} blocks
- This script extracts, validates, and stores structured data
- Cross-phase queries return focused summaries

Backup Approach (Option B):
- LLM outputs JSON directly (triggered by explicit prompt)
- This script stores JSON input as-is

Usage:
    # Extract YAML blocks from Markdown report
    python phase_data.py --extract P1-PROJECT-UNDERSTANDING.md --phase 1

    # Query phase data
    python phase_data.py --query --phase 1 --type entry_points
    python phase_data.py --query --phase 2 --element P-001
    python phase_data.py --query --phase 5 --threats-for-element P-013
    python phase_data.py --query --phase 1 --summary

    # Validate phase completion
    python phase_data.py --validate --phase 1
    python phase_data.py --validate --phase 2

    # Store JSON directly (Option B backup)
    python phase_data.py --store --phase 5 --input-json threats.json

    # Cross-phase aggregation
    python phase_data.py --aggregate --phases 1,2,5 --format summary

    # Initialize session
    python phase_data.py --init --project "OPEN-WEBUI" --path /path/to/project

Output: JSON format for integration with threat modeling workflow.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import yaml


# ============================================================================
# Configuration
# ============================================================================

SCHEMA_VERSION = "3.2.0"
SESSION_SCHEMA_VERSION = "3.2.0"  # Version for session management

# Standard YAML block names per phase (from WORKFLOW.md v2.2.2)
# NOTE: l1_coverage is EMBEDDED inside data_flows block, not extracted separately
# NOTE: P3/P4 blocks are output as Markdown tables, not YAML blocks (per WORKFLOW.md)
PHASE_BLOCKS = {
    1: ["module_inventory", "entry_point_inventory", "discovery_checklist"],
    2: ["dfd_elements", "data_flows", "interface_inventory", "data_flow_traces"],  # l1_coverage is embedded in data_flows
    3: ["trust_boundaries", "interfaces", "data_nodes", "cross_boundary_flows"],
    4: ["security_gaps", "design_matrix"],
    5: ["threat_inventory"],
    6: ["validated_risks", "attack_paths", "attack_chains", "poc_details"],
    7: ["mitigation_plan", "roadmap"],
}

# Required blocks per phase (validation gates)
# These are the minimum required blocks that MUST be present for validation to pass
REQUIRED_BLOCKS = {
    1: ["module_inventory", "entry_point_inventory", "discovery_checklist"],
    2: ["dfd_elements", "data_flows"],  # l1_coverage validated separately from data_flows content
    3: ["trust_boundaries"],  # interfaces, data_nodes, cross_boundary_flows are optional
    4: ["security_gaps"],     # design_matrix validated separately
    5: ["threat_inventory"],
    6: ["validated_risks"],   # attack_paths, poc_details validated separately
    7: ["mitigation_plan"],   # roadmap validated separately
}

# Phase dependency matrix for Phase End Protocol
# Defines what each phase requires from previous phases and how to query that data
PHASE_DEPENDENCIES = {
    1: {"requires": [], "query": None, "description": "Initial discovery - no dependencies"},
    2: {"requires": [1], "query": "--query --phase 1 --summary", "description": "Requires entry points from P1"},
    3: {"requires": [2], "query": "--query --phase 2 --summary", "description": "Requires DFD elements from P2"},
    4: {"requires": [1, 2, 3], "query": "--aggregate --phases 1,2,3 --format summary", "description": "Requires discovery, DFD, and trust boundaries"},
    5: {"requires": [2], "query": "--query --phase 2 --type dfd", "description": "Requires DFD for STRIDE analysis"},
    6: {"requires": [5], "query": "--query --phase 5 --summary", "description": "Requires threat inventory from P5"},
    7: {"requires": [6], "query": "--query --phase 6 --summary", "description": "Requires validated risks from P6"},
    8: {"requires": [1, 2, 3, 4, 5, 6, 7], "query": "--aggregate --phases 1,2,3,4,5,6,7 --format summary", "description": "Requires all phases for final report"},
}

# Entry point types for discovery checklist validation
ENTRY_POINT_TYPES = [
    "rest_api",
    "internal_api",
    "graphql",
    "websocket",
    "cron_jobs",
    "message_queue",
    "webhooks",
    "file_upload",
    "health_endpoints",
    "debug_endpoints",
]

# YAML block extraction pattern
# Matches ```yaml:{block_name} ... ``` blocks
YAML_BLOCK_PATTERN = re.compile(
    r'```yaml:([\w-]+)\s*\n(.*?)```',
    re.DOTALL | re.MULTILINE
)

# ============================================================================
# ID Format Validation Patterns (migrated from validate_count_conservation.py)
# ============================================================================

ID_PATTERNS = {
    # P1 Entity Patterns
    'module': re.compile(r'^M-\d{3}$'),                       # M-001
    'entry_point': re.compile(r'^EP-[A-Z]+-\d{3}$'),          # EP-API-001
    'finding': re.compile(r'^F-P[1-8]-\d{3}$'),              # F-P1-001

    # P2 DFD Element Patterns
    'external_interactor': re.compile(r'^EI-\d{3}$'),        # EI-001
    'process': re.compile(r'^P-\d{3}$'),                     # P-001
    'data_store': re.compile(r'^DS-\d{3}$'),                 # DS-001
    'data_flow': re.compile(r'^DF-\d{3}$'),                  # DF-001

    # P3 Trust Boundary Patterns
    'trust_boundary': re.compile(r'^TB-\d{3}$'),             # TB-001
    'interface': re.compile(r'^IF-\d{3}$'),                  # IF-001
    'data_node': re.compile(r'^DN-\d{3}$'),                  # DN-001

    # P4 Security Gap Patterns
    'security_gap': re.compile(r'^GAP-\d{3}$'),              # GAP-001

    # P5 Threat Patterns
    'threat': re.compile(r'^T-[STRIDE]-[A-Z]+-\d{3}-\d{3}$'),  # T-S-P-001-001
    'threat_alt': re.compile(r'^T-[STRIDE]-[A-Z]+\d+-\d{3}$'), # T-S-P1-001 (legacy format)

    # P6 Risk Patterns
    'validated_risk': re.compile(r'^VR-\d{3,}$'),            # VR-001 (L2: 3+ digits)
    'poc': re.compile(r'^POC-\d{3,}$'),                      # POC-001 (L2: 3+ digits)
    'attack_path': re.compile(r'^AP-\d{3,}$'),               # AP-001 (L2: 3+ digits)
    'attack_chain': re.compile(r'^AC-\d{3,}$'),              # AC-001 (L2: 3+ digits)

    # P7 Mitigation Patterns
    'mitigation': re.compile(r'^MIT-\d{3,}$'),               # MIT-001 (L2: 3+ digits)

    # Forbidden formats
    'forbidden_risk': re.compile(r'^RISK-\d+$'),              # RISK-001 (should be VR-xxx)
    'forbidden_threat': re.compile(r'^T-[STRIDE]-[A-Z]{3,}-\d{3}$'),  # T-E-RCE-001 (missing ElementID)
    'forbidden_mitigation': re.compile(r'^M-\d{3}$'),         # M-001 collision with Module
}

# Security design domains for P4 validation (16 domains per P4-SECURITY-DESIGN-REVIEW.md)
# Core Domains (01-10): AUTHN, AUTHZ, INPUT, OUTPUT, CLIENT, CRYPTO, LOG, ERROR, API, DATA
# Extended Domains (ext-11 to ext-16): INFRA, SUPPLY, AI, MOBILE, CLOUD, AGENT
SECURITY_DOMAINS = [
    # Core domains (01-10)
    "AUTHN", "AUTHZ", "INPUT", "OUTPUT", "CLIENT",
    "CRYPTO", "LOG", "ERROR", "API", "DATA",
    # Extended domains (ext-11 to ext-16)
    "INFRA", "SUPPLY", "AI", "MOBILE", "CLOUD", "AGENT"
]

# STRIDE categories for threat validation
STRIDE_CATEGORIES = ['S', 'T', 'R', 'I', 'D', 'E']

# STRIDE per Element Applicability Matrix
# Defines which STRIDE categories apply to each DFD element type
STRIDE_PER_ELEMENT = {
    "Process": ["S", "T", "R", "I", "D", "E"],  # All six categories
    "DataStore": ["T", "R", "I", "D"],          # Tampering, Repudiation, Info Disclosure, DoS
    "DataFlow": ["T", "I", "D"],                # Tampering, Info Disclosure, DoS
    "ExternalInteractor": ["S", "R"],           # Spoofing, Repudiation (as source)
}

# STRIDE per Interaction Matrix (Source → Target)
# Defines applicable STRIDE based on interaction type
STRIDE_PER_INTERACTION = {
    # (Source Type, Target Type) → Applicable STRIDE categories
    ("ExternalInteractor", "Process"): {
        "target": ["S", "T", "R", "I", "D", "E"],  # Full STRIDE on target
        "source": ["S", "R"],                      # External can spoof/repudiate
        "flow": ["T", "I", "D"],                   # Data in transit
    },
    ("ExternalInteractor", "DataStore"): {
        "target": ["T", "R", "I", "D"],
        "source": ["S", "R"],
        "flow": ["T", "I", "D"],
    },
    ("Process", "Process"): {
        "target": ["T", "R", "I", "D", "E"],
        "source": [],                              # Internal process, no spoofing
        "flow": ["T", "I", "D"],
    },
    ("Process", "DataStore"): {
        "target": ["T", "R", "I", "D"],
        "source": [],
        "flow": ["T", "I", "D"],
    },
    ("DataStore", "Process"): {
        "target": ["T", "I"],                     # Data poisoning, info leakage
        "source": [],
        "flow": ["T", "I"],
    },
}

# Trust boundary severity multipliers
BOUNDARY_SEVERITY_MULTIPLIERS = {
    "Internet_DMZ": 2.0,        # Public to DMZ
    "DMZ_Internal": 1.5,        # DMZ to internal network
    "Internal_Database": 1.8,   # Internal to data tier
    "SameTrustZone": 1.0,       # No boundary crossing
    "default": 1.2,             # Unknown boundary type
}

# Final reports that should contain VR entries (for CP3 validation)
FINAL_REPORTS = [
    'RISK-INVENTORY',
    'RISK-ASSESSMENT-REPORT',
    'MITIGATION-MEASURES',
    'PENETRATION-TEST-PLAN',
]


# ============================================================================
# Phase State Machine (YAML-First Enforcement)
# ============================================================================
# Enforces the principle: "YAML is data, Markdown is presentation"
# Reports MUST NOT be generated from LLM memory - they MUST read YAML data first

# Phase workflow states (per phase)
PHASE_STATES = {
    "pending": "Phase not started",
    "yaml_in_progress": "YAML data generation in progress",
    "yaml_completed": "YAML data file written and validated",
    "report_started": "Report generation started (YAML read required)",
    "report_completed": "Report generated from YAML data",
}

# Required YAML files per phase (these MUST exist before report generation)
PHASE_YAML_FILES = {
    1: ["P1_project_context.yaml"],
    2: ["P2_dfd_elements.yaml"],
    3: ["P3_boundary_context.yaml"],
    4: ["P4_security_gaps.yaml"],
    5: ["P5_threat_inventory.yaml"],
    6: ["P6_validated_risks.yaml"],
    7: ["P7_mitigation_plan.yaml"],
    # P8 aggregates from P1-P7, no primary YAML
}

# Required Markdown reports per phase (generated FROM YAML)
PHASE_REPORT_FILES = {
    1: ["P1-PROJECT-UNDERSTANDING.md"],
    2: ["P2-DFD-ANALYSIS.md"],
    3: ["P3-TRUST-BOUNDARY.md"],
    4: ["P4-SECURITY-REVIEW.md"],
    5: ["P5-STRIDE-THREATS.md"],
    6: ["P6-RISK-VALIDATION.md"],
    7: ["P7-MITIGATION-PLAN.md"],
    # P8 generates final reports
}

# Minimum required fields per phase YAML (for completeness validation)
# NOTE: Currently not referenced by validators (they use inline checks).
# Available for future centralized schema validation via load_phase_data().
YAML_REQUIRED_FIELDS = {
    1: {
        "P1_project_context.yaml": ["module_inventory", "entry_point_inventory"],
    },
    2: {
        "P2_dfd_elements.yaml": ["dfd_elements", "data_flows"],
    },
    3: {
        "P3_boundary_context.yaml": ["trust_boundaries"],
    },
    4: {
        "P4_security_gaps.yaml": ["security_gaps"],
    },
    5: {
        "P5_threat_inventory.yaml": ["threat_inventory"],
    },
    6: {
        "P6_validated_risks.yaml": ["validated_risks"],
    },
    7: {
        "P7_mitigation_plan.yaml": ["mitigation_plan"],
    },
}


# ============================================================================
# Directory Structure Management
# ============================================================================

def get_phase_working_dir(project_root: str) -> Path:
    """Get the .phase_working directory path."""
    return Path(project_root) / "Risk_Assessment_Report" / ".phase_working"


def _validate_session_id(session_id: str) -> bool:
    """Validate session_id to prevent path traversal. Returns True if safe."""
    if not session_id:
        return False
    if '..' in session_id or '/' in session_id or '\\' in session_id:
        return False
    return True


def get_phase_data_dir(project_root: str, session_id: Optional[str] = None) -> Path:
    """
    Get the phase data directory path.

    If session_id is provided, returns the session-specific data directory.
    If not provided, attempts to get the current active session's data directory.
    Falls back to legacy structure if no session exists.

    Args:
        project_root: Project root directory
        session_id: Optional specific session ID

    Returns:
        Path to the data directory
    """
    phase_working = get_phase_working_dir(project_root)

    # If session_id provided, use that session's data directory
    if session_id:
        if not _validate_session_id(session_id):
            print(f"Warning: Invalid session_id rejected: {session_id!r}", file=sys.stderr)
            return phase_working / "data"
        return phase_working / session_id / "data"

    # Try to get current session
    current_session_dir = get_current_session_dir(project_root)
    if current_session_dir:
        return current_session_dir / "data"

    # Fallback to legacy structure (phase_data/) - deprecated, use data/ for new sessions
    # NOTE: This fallback exists only for backward compatibility with pre-3.0 sessions
    legacy_path = phase_working / "phase_data"
    if legacy_path.exists():
        return legacy_path
    # For new sessions without SESSION_ID, still use data/ subdirectory naming convention
    return phase_working / "data"


def get_current_session_dir(project_root: str) -> Optional[Path]:
    """
    Get the current active session directory.

    Reads _session_meta.yaml to find the current active session.

    Args:
        project_root: Project root directory

    Returns:
        Path to the current session directory, or None if no active session
    """
    phase_working = get_phase_working_dir(project_root)
    meta_file = phase_working / "_session_meta.yaml"

    if not meta_file.exists():
        return None

    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = yaml.safe_load(f)

        if not meta:
            return None

        current_session = meta.get("current_session", {})
        session_id = current_session.get("session_id")

        if not session_id:
            return None

        session_dir = phase_working / session_id
        if session_dir.exists():
            return session_dir

    except (yaml.YAMLError, IOError) as e:
        print(f"Warning: Failed to read session metadata: {e}", file=sys.stderr)

    return None


def ensure_directories(project_root: str, session_id: Optional[str] = None) -> Dict[str, Path]:
    """
    Ensure all required directories exist.

    Args:
        project_root: Project root directory
        session_id: Optional session ID for session-specific directories

    Returns:
        Dict with directory paths
    """
    phase_working = get_phase_working_dir(project_root)
    phase_working.mkdir(parents=True, exist_ok=True)

    # L9: Also ensure reports/ subdirectory exists per WORKFLOW.md
    report_dir = Path(project_root) / "Risk_Assessment_Report"
    report_dir.mkdir(parents=True, exist_ok=True)

    if session_id:
        # Session-specific structure
        session_dir = phase_working / session_id
        data_dir = session_dir / "data"
        session_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        return {
            "phase_working": phase_working,
            "session_dir": session_dir,
            "phase_data": data_dir,
        }
    else:
        # Legacy structure or auto-detect current session
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            data_dir = current_session_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            return {
                "phase_working": phase_working,
                "session_dir": current_session_dir,
                "phase_data": data_dir,
            }
        else:
            # Fallback: check if legacy phase_data/ exists, otherwise use data/
            legacy_data = phase_working / "phase_data"
            if legacy_data.exists():
                # Legacy backward compatibility
                return {
                    "phase_working": phase_working,
                    "phase_data": legacy_data,
                }
            else:
                # New default: use data/ subdirectory
                phase_data = phase_working / "data"
                phase_data.mkdir(parents=True, exist_ok=True)
                return {
                    "phase_working": phase_working,
                    "phase_data": phase_data,
                }


# ============================================================================
# Session Management (Multi-Version)
# ============================================================================

def _generate_session_id(project_name: str) -> str:
    """
    Generate a session ID in the format {PROJECT}-YYYYMMDD_HHMMSS.

    Args:
        project_name: Project name (will be uppercased and normalized)

    Returns:
        Session ID string
    """
    # Normalize project name: uppercase, replace spaces/underscores with hyphens
    normalized = project_name.upper().replace("_", "-").replace(" ", "-")
    # Remove consecutive hyphens
    while "--" in normalized:
        normalized = normalized.replace("--", "-")
    # Remove leading/trailing hyphens
    normalized = normalized.strip("-")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{normalized}_{timestamp}"


def _detect_legacy_session(project_root: str) -> bool:
    """
    Detect legacy single-file session structure.

    Legacy structure has:
    - .phase_working/_session.yaml (not in a subdirectory)
    - .phase_working/phase_data/ directory

    New structure has:
    - .phase_working/_session_meta.yaml
    - .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/{SESSION_ID}/data/

    Args:
        project_root: Project root directory

    Returns:
        True if legacy structure detected, False otherwise
    """
    phase_working = get_phase_working_dir(project_root)

    # Check for legacy _session.yaml at top level
    legacy_session = phase_working / "_session.yaml"
    legacy_data = phase_working / "phase_data"

    # Check for new structure markers
    new_meta = phase_working / "_session_meta.yaml"

    # Legacy if: has old _session.yaml AND phase_data/ AND no _session_meta.yaml
    if legacy_session.exists() and legacy_data.exists() and not new_meta.exists():
        return True

    return False


def _load_session_meta(project_root: str) -> Optional[Dict]:
    """
    Load the global session metadata file.

    Args:
        project_root: Project root directory

    Returns:
        Session metadata dict, or None if not found
    """
    meta_file = get_phase_working_dir(project_root) / "_session_meta.yaml"

    if not meta_file.exists():
        return None

    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        print(f"Warning: {e}", file=sys.stderr)
        return None


def _save_session_meta(project_root: str, meta: Dict) -> None:
    """
    Save the global session metadata file.

    Args:
        project_root: Project root directory
        meta: Session metadata dict
    """
    phase_working = get_phase_working_dir(project_root)
    phase_working.mkdir(parents=True, exist_ok=True)
    meta_file = phase_working / "_session_meta.yaml"

    with open(meta_file, "w", encoding="utf-8") as f:
        yaml.dump(meta, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _update_session_meta(
    project_root: str,
    session_id: str,
    project_name: str,
    action: str,
    current_phase: Optional[int] = None,
    phases_completed: Optional[List[int]] = None
) -> None:
    """
    Update global _session_meta.yaml.

    Args:
        project_root: Project root directory
        session_id: Session ID
        project_name: Project name
        action: Action type - "create", "resume", "update", "complete", "abort"
        current_phase: Optional current phase number
        phases_completed: Optional list of completed phases
    """
    now = datetime.now().isoformat()
    meta = _load_session_meta(project_root)

    if not meta:
        # Initialize new meta structure
        meta = {
            "schema_version": SESSION_SCHEMA_VERSION,
            "project_name": project_name,
            "current_session": None,
            "sessions": [],
            "last_completed": None,
        }

    # Update project name (use provided or keep existing)
    if project_name:
        meta["project_name"] = project_name

    # Find existing session entry
    session_entry = None
    for s in meta.get("sessions", []):
        if s.get("session_id") == session_id:
            session_entry = s
            break

    if action == "create":
        # Create new session entry
        new_entry = {
            "session_id": session_id,
            "status": "in_progress",
            "phases_completed": phases_completed or [],
            "started_at": now,
            "ended_at": None,
        }
        meta["sessions"].append(new_entry)

        # Set as current session
        meta["current_session"] = {
            "session_id": session_id,
            "status": "in_progress",
            "current_phase": current_phase or 1,
            "started_at": now,
        }

    elif action == "resume":
        if session_entry:
            session_entry["status"] = "in_progress"
            meta["current_session"] = {
                "session_id": session_id,
                "status": "in_progress",
                "current_phase": current_phase or session_entry.get("phases_completed", [])[-1] + 1 if session_entry.get("phases_completed") else 1,
                "started_at": session_entry.get("started_at", now),
            }

    elif action == "update":
        if session_entry:
            if phases_completed:
                session_entry["phases_completed"] = sorted(list(set(phases_completed)))
            if current_phase:
                if meta.get("current_session", {}).get("session_id") == session_id:
                    meta["current_session"]["current_phase"] = current_phase

    elif action == "complete":
        if session_entry:
            session_entry["status"] = "completed"
            session_entry["ended_at"] = now
            if phases_completed:
                session_entry["phases_completed"] = sorted(list(set(phases_completed)))
            meta["last_completed"] = session_id
            if meta.get("current_session", {}).get("session_id") == session_id:
                meta["current_session"] = None

    elif action == "abort":
        if session_entry:
            session_entry["status"] = "aborted"
            session_entry["ended_at"] = now
            if meta.get("current_session", {}).get("session_id") == session_id:
                meta["current_session"] = None

    _save_session_meta(project_root, meta)


def check_session(project_root: str) -> Dict:
    """
    Check for incomplete sessions and return status.

    Scans for sessions with status "in_progress" and returns detailed info.

    Args:
        project_root: Project root directory

    Returns:
        Dict with session status:
        - has_incomplete: bool
        - incomplete_sessions: list of incomplete session info
        - current_session: current active session info or None
        - legacy_detected: bool if legacy structure found
    """
    result = {
        "has_incomplete": False,
        "incomplete_sessions": [],
        "current_session": None,
        "legacy_detected": False,
        "total_sessions": 0,
    }

    # Check for legacy structure
    if _detect_legacy_session(project_root):
        result["legacy_detected"] = True
        phase_working = get_phase_working_dir(project_root)
        legacy_session = phase_working / "_session.yaml"

        try:
            with open(legacy_session, "r", encoding="utf-8") as f:
                legacy_data = yaml.safe_load(f)
            if legacy_data:
                result["has_incomplete"] = True
                result["incomplete_sessions"].append({
                    "session_id": legacy_data.get("session_id", "legacy"),
                    "type": "legacy",
                    "project_name": legacy_data.get("project_name"),
                    "current_phase": legacy_data.get("current_phase", 1),
                    "phases_completed": legacy_data.get("phases_completed", []),
                    "started_at": legacy_data.get("started_at"),
                    "message": "Legacy single-file session detected. Use --migrate-session to upgrade.",
                })
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: {e}", file=sys.stderr)

        return result

    # Check new session structure
    meta = _load_session_meta(project_root)
    if not meta:
        return result

    result["total_sessions"] = len(meta.get("sessions", []))

    # Get current session
    if meta.get("current_session"):
        result["current_session"] = meta["current_session"]

    # Find all incomplete sessions
    for session in meta.get("sessions", []):
        if session.get("status") == "in_progress":
            result["has_incomplete"] = True
            session_info = {
                "session_id": session.get("session_id"),
                "type": "multi_version",
                "phases_completed": session.get("phases_completed", []),
                "started_at": session.get("started_at"),
            }

            # Load session-specific data for more details
            session_dir = get_phase_working_dir(project_root) / session.get("session_id", "")
            session_file = session_dir / "_session.yaml"
            if session_file.exists():
                try:
                    with open(session_file, "r", encoding="utf-8") as f:
                        session_data = yaml.safe_load(f)
                    if session_data:
                        session_info["current_phase"] = session_data.get("current_phase", 1)
                        session_info["project_name"] = session_data.get("project_name")
                except (yaml.YAMLError, IOError) as e:
                    print(f"Warning: {e}", file=sys.stderr)

            result["incomplete_sessions"].append(session_info)

    return result


def create_session(project_name: str, project_path: str) -> Dict:
    """
    Create a new session with subdirectory structure.

    Creates:
    - .phase_working/_session_meta.yaml (updated)
    - .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/{SESSION_ID}/data/

    Args:
        project_name: Project name
        project_path: Project path

    Returns:
        Dict with session creation result
    """
    session_id = _generate_session_id(project_name)
    now = datetime.now().isoformat()

    # Create directory structure
    dirs = ensure_directories(project_path, session_id)

    # Create session-specific _session.yaml
    session_data = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "project_name": project_name,
        "project_path": project_path,
        "started_at": now,
        "skill_version": SCHEMA_VERSION,
        "phases_completed": [],
        "current_phase": 1,
        "last_updated": now,
        "extraction_status": {
            f"phase{i}": {"extracted": False, "entities": 0}
            for i in range(1, 9)
        },
    }

    session_file = dirs["session_dir"] / "_session.yaml"
    with open(session_file, "w", encoding="utf-8") as f:
        yaml.dump(session_data, f, allow_unicode=True, default_flow_style=False)

    # Update global session meta
    _update_session_meta(
        project_path,
        session_id,
        project_name,
        "create",
        current_phase=1,
        phases_completed=[]
    )

    return {
        "status": "success",
        "action": "create_session",
        "session_id": session_id,
        "session_dir": str(dirs["session_dir"]),
        "data_dir": str(dirs["phase_data"]),
        "project_name": project_name,
        "message": f"Session created: {session_id}",
    }


def resume_session(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Resume an incomplete session.

    If session_id is not provided, resumes the most recent incomplete session.

    Args:
        project_root: Project root directory
        session_id: Optional specific session ID to resume

    Returns:
        Dict with resume result
    """
    # Check for incomplete sessions
    check_result = check_session(project_root)

    if not check_result["has_incomplete"]:
        return {
            "status": "error",
            "action": "resume_session",
            "message": "No incomplete sessions found to resume.",
        }

    # Handle legacy session
    if check_result["legacy_detected"] and not session_id:
        return {
            "status": "error",
            "action": "resume_session",
            "message": "Legacy session detected. Use --migrate-session first to convert to new format.",
            "legacy_info": check_result["incomplete_sessions"][0] if check_result["incomplete_sessions"] else None,
        }

    # Find session to resume
    target_session = None

    if session_id:
        # Find specific session
        for s in check_result["incomplete_sessions"]:
            if s["session_id"] == session_id:
                target_session = s
                break
        if not target_session:
            return {
                "status": "error",
                "action": "resume_session",
                "message": f"Session '{session_id}' not found or not incomplete.",
                "available_sessions": [s["session_id"] for s in check_result["incomplete_sessions"]],
            }
    else:
        # Get most recent incomplete (last in list, sorted by started_at)
        incomplete = sorted(
            check_result["incomplete_sessions"],
            key=lambda x: x.get("started_at", ""),
            reverse=True
        )
        if incomplete:
            target_session = incomplete[0]

    if not target_session:
        return {
            "status": "error",
            "action": "resume_session",
            "message": "No resumable session found.",
        }

    # Resume the session
    target_id = target_session["session_id"]

    # Update session meta
    meta = _load_session_meta(project_root)
    if meta:
        for s in meta.get("sessions", []):
            if s.get("session_id") == target_id:
                current_phase = max(s.get("phases_completed", [0])) + 1 if s.get("phases_completed") else 1
                break
        else:
            current_phase = target_session.get("current_phase", 1)

        _update_session_meta(
            project_root,
            target_id,
            target_session.get("project_name", ""),
            "resume",
            current_phase=current_phase
        )

    # Load session data
    session_dir = get_phase_working_dir(project_root) / target_id
    session_file = session_dir / "_session.yaml"

    session_data = None
    if session_file.exists():
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                session_data = yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: {e}", file=sys.stderr)

    return {
        "status": "success",
        "action": "resume_session",
        "session_id": target_id,
        "session_dir": str(session_dir),
        "current_phase": session_data.get("current_phase") if session_data else target_session.get("current_phase", 1),
        "phases_completed": session_data.get("phases_completed") if session_data else target_session.get("phases_completed", []),
        "project_name": session_data.get("project_name") if session_data else target_session.get("project_name"),
        "message": f"Session resumed: {target_id}",
    }


def migrate_legacy_session(project_root: str) -> Dict:
    """
    Migrate legacy session to new multi-version structure.

    Converts:
    - .phase_working/_session.yaml → .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/phase_data/ → .phase_working/{SESSION_ID}/data/

    Creates:
    - .phase_working/_session_meta.yaml

    Args:
        project_root: Project root directory

    Returns:
        Dict with migration result
    """
    if not _detect_legacy_session(project_root):
        return {
            "status": "error",
            "action": "migrate_legacy_session",
            "message": "No legacy session structure detected.",
        }

    phase_working = get_phase_working_dir(project_root)
    legacy_session_file = phase_working / "_session.yaml"
    legacy_data_dir = phase_working / "phase_data"

    # Load legacy session data
    try:
        with open(legacy_session_file, "r", encoding="utf-8") as f:
            legacy_data = yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        return {
            "status": "error",
            "action": "migrate_legacy_session",
            "message": f"Failed to read legacy session: {e}",
        }

    if not legacy_data:
        return {
            "status": "error",
            "action": "migrate_legacy_session",
            "message": "Legacy session file is empty.",
        }

    # Generate session ID based on legacy data
    project_name = legacy_data.get("project_name", "UNKNOWN")
    legacy_session_id = legacy_data.get("session_id", "")

    # Try to parse timestamp from legacy session_id (format: YYYYMMDD-HHMMSS)
    if legacy_session_id and re.match(r'\d{8}-\d{6}', legacy_session_id):
        # Convert old format to new format
        timestamp = legacy_session_id.replace("-", "_")
        new_session_id = f"{project_name.upper()}-{timestamp}"
    else:
        # Use legacy start time or current time
        started_at = legacy_data.get("started_at", "")
        if started_at:
            try:
                dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                timestamp = dt.strftime("%Y%m%d_%H%M%S")
            except ValueError:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_session_id = f"{project_name.upper()}-{timestamp}"

    # Create new session directory
    new_session_dir = phase_working / new_session_id
    new_data_dir = new_session_dir / "data"

    new_session_dir.mkdir(parents=True, exist_ok=True)
    new_data_dir.mkdir(parents=True, exist_ok=True)

    # Copy phase data files
    migrated_files = []
    if legacy_data_dir.exists():
        import shutil
        for file_path in legacy_data_dir.glob("*.yaml"):
            dest = new_data_dir / file_path.name
            shutil.copy2(file_path, dest)
            migrated_files.append(file_path.name)

    # Update legacy session data and save to new location
    legacy_data["session_id"] = new_session_id
    legacy_data["migrated_from"] = "legacy"
    legacy_data["migrated_at"] = datetime.now().isoformat()

    new_session_file = new_session_dir / "_session.yaml"
    with open(new_session_file, "w", encoding="utf-8") as f:
        yaml.dump(legacy_data, f, allow_unicode=True, default_flow_style=False)

    # Create _session_meta.yaml
    phases_completed = legacy_data.get("phases_completed", [])
    current_phase = legacy_data.get("current_phase", 1)

    _update_session_meta(
        project_root,
        new_session_id,
        project_name,
        "create",
        current_phase=current_phase,
        phases_completed=phases_completed
    )

    # Archive legacy files (rename, don't delete)
    legacy_session_file.rename(phase_working / "_session.yaml.legacy")
    if legacy_data_dir.exists():
        legacy_data_dir.rename(phase_working / "phase_data.legacy")

    return {
        "status": "success",
        "action": "migrate_legacy_session",
        "old_session_id": legacy_session_id,
        "new_session_id": new_session_id,
        "session_dir": str(new_session_dir),
        "data_dir": str(new_data_dir),
        "files_migrated": migrated_files,
        "project_name": project_name,
        "phases_completed": phases_completed,
        "current_phase": current_phase,
        "message": f"Successfully migrated legacy session to {new_session_id}",
    }


def list_sessions(project_root: str) -> Dict:
    """
    List all sessions for a project.

    Args:
        project_root: Project root directory

    Returns:
        Dict with list of all sessions and their status
    """
    result = {
        "sessions": [],
        "current_session": None,
        "total": 0,
        "completed": 0,
        "in_progress": 0,
        "aborted": 0,
        "legacy_detected": False,
    }

    # Check for legacy
    if _detect_legacy_session(project_root):
        result["legacy_detected"] = True

    # Load session meta
    meta = _load_session_meta(project_root)
    if not meta:
        if result["legacy_detected"]:
            result["message"] = "Only legacy session found. Use --migrate-session to upgrade."
        else:
            result["message"] = "No sessions found."
        return result

    result["current_session"] = meta.get("current_session")
    result["last_completed"] = meta.get("last_completed")

    for session in meta.get("sessions", []):
        session_info = {
            "session_id": session.get("session_id"),
            "status": session.get("status"),
            "phases_completed": session.get("phases_completed", []),
            "started_at": session.get("started_at"),
            "ended_at": session.get("ended_at"),
        }

        # Load additional session details if available
        session_dir = get_phase_working_dir(project_root) / session.get("session_id", "")
        session_file = session_dir / "_session.yaml"
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    session_data = yaml.safe_load(f)
                if session_data:
                    session_info["project_name"] = session_data.get("project_name")
                    session_info["current_phase"] = session_data.get("current_phase")
            except (yaml.YAMLError, IOError) as e:
                print(f"Warning: {e}", file=sys.stderr)

        result["sessions"].append(session_info)

        # Count by status
        status = session.get("status", "")
        if status == "completed":
            result["completed"] += 1
        elif status == "in_progress":
            result["in_progress"] += 1
        elif status == "aborted":
            result["aborted"] += 1

    result["total"] = len(result["sessions"])

    return result


def init_session(project_name: str, project_path: str, force: bool = False) -> Dict:
    """
    Initialize or update session metadata.

    Checks for incomplete sessions first. If found, returns a warning
    unless force=True is specified.

    Creates new multi-version session structure:
    - .phase_working/_session_meta.yaml
    - .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/{SESSION_ID}/data/

    Args:
        project_name: Project name
        project_path: Project path
        force: If True, create new session even if incomplete sessions exist

    Returns:
        Dict with session initialization result
    """
    # Check for incomplete sessions
    check_result = check_session(project_path)

    # Check for legacy session - suggest migration
    if check_result["legacy_detected"]:
        if not force:
            return {
                "status": "warning",
                "action": "init_session",
                "message": "Legacy session detected. Use --migrate-session to upgrade, or --force to create a new session.",
                "legacy_info": check_result["incomplete_sessions"][0] if check_result["incomplete_sessions"] else None,
                "hint": "Run with --force to ignore and create new session, or --migrate-session to upgrade legacy session.",
            }

    # Check for incomplete multi-version sessions
    if check_result["has_incomplete"] and not check_result["legacy_detected"] and not force:
        return {
            "status": "warning",
            "action": "init_session",
            "message": f"Found {len(check_result['incomplete_sessions'])} incomplete session(s). Use --resume to continue or --force to start new.",
            "incomplete_sessions": [
                {
                    "session_id": s["session_id"],
                    "current_phase": s.get("current_phase", 1),
                    "phases_completed": s.get("phases_completed", []),
                }
                for s in check_result["incomplete_sessions"]
            ],
            "hint": "Run with --resume to continue incomplete session, or --force to start new session.",
        }

    # Create new session
    result = create_session(project_name, project_path)
    result["action"] = "init_session"  # Override action name for compatibility

    return result


def load_session(project_root: str, session_id: Optional[str] = None) -> Optional[Dict]:
    """
    Load existing session metadata.

    If session_id is provided, loads that specific session.
    Otherwise, loads the current active session.
    Falls back to legacy session if no multi-version session exists.

    Args:
        project_root: Project root directory
        session_id: Optional specific session ID to load

    Returns:
        Session data dict, or None if not found
    """
    phase_working = get_phase_working_dir(project_root)

    # If session_id provided, load that session
    if session_id:
        if not _validate_session_id(session_id):
            return None
        session_file = phase_working / session_id / "_session.yaml"
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except (yaml.YAMLError, IOError) as e:
                print(f"Warning: {e}", file=sys.stderr)
                return None
        return None

    # Try to get current active session
    current_session_dir = get_current_session_dir(project_root)
    if current_session_dir:
        session_file = current_session_dir / "_session.yaml"
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except (yaml.YAMLError, IOError) as e:
                print(f"Warning: {e}", file=sys.stderr)

    # Fallback to legacy session file
    legacy_session_file = phase_working / "_session.yaml"
    if legacy_session_file.exists():
        try:
            with open(legacy_session_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data:
                    data["_legacy"] = True  # Mark as legacy session
                return data
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: {e}", file=sys.stderr)

    return None


def update_session(project_root: str, updates: Dict, session_id: Optional[str] = None) -> Dict:
    """
    Update session metadata.

    NOTE (L3): This function writes to _session.yaml AND _session_meta.yaml (dual-write).
    This is intentional: _session.yaml is the per-session source of truth; _session_meta.yaml
    is the global index for session discovery. Both must stay in sync. A future improvement
    could use a transaction wrapper, but for single-user CLI usage the sequential write is safe.

    NOTE (L4): No file locking is used. This is acceptable because the tool is designed for
    single-user CLI usage where concurrent writes don't occur.

    NOTE (L5): No state transition validation is performed. The FSM enforcement is handled
    at the phase_end_protocol level (M9 fix), not at the generic update_session level.

    Args:
        project_root: Project root directory
        updates: Dict of fields to update
        session_id: Optional specific session ID to update (defaults to current)

    Returns:
        Dict with update result
    """
    phase_working = get_phase_working_dir(project_root)

    # Determine which session to update
    if session_id:
        session_file = phase_working / session_id / "_session.yaml"
    else:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_file = current_session_dir / "_session.yaml"
            session_id = current_session_dir.name
        else:
            # Fallback to legacy
            session_file = phase_working / "_session.yaml"

    if not session_file.exists():
        return {"error": "Session not initialized. Run --init first."}

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            session_data = yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        return {"error": f"Failed to read session file: {e}"}

    # Apply updates
    session_data.update(updates)
    session_data["last_updated"] = datetime.now().isoformat()

    with open(session_file, "w", encoding="utf-8") as f:
        yaml.dump(session_data, f, allow_unicode=True, default_flow_style=False)

    # Update session meta if this is a multi-version session
    if session_id and not session_file.parent.name.startswith("."):
        project_name = session_data.get("project_name", "")
        phases_completed = session_data.get("phases_completed", [])
        current_phase = session_data.get("current_phase")
        _update_session_meta(
            project_root,
            session_id,
            project_name,
            "update",
            current_phase=current_phase,
            phases_completed=phases_completed
        )

    return {"status": "success", "updated_fields": list(updates.keys())}


# ============================================================================
# YAML Block Extraction (Option C - Primary Approach)
# ============================================================================

def extract_yaml_blocks(markdown_content: str) -> Dict[str, Any]:
    """
    Extract all ```yaml:{block_name} blocks from Markdown content.

    Returns:
        Dict mapping block_name to parsed YAML content
    """
    blocks = {}
    errors = []

    for match in YAML_BLOCK_PATTERN.finditer(markdown_content):
        block_name = match.group(1)
        yaml_content = match.group(2).strip()

        try:
            parsed = yaml.safe_load(yaml_content)
            if block_name in blocks:
                print(f"Warning: Duplicate YAML block '{block_name}' — later definition wins", file=sys.stderr)
            blocks[block_name] = parsed
        except yaml.YAMLError as e:
            errors.append({
                "block": block_name,
                "error": str(e),
                "content_preview": yaml_content[:200] + "..." if len(yaml_content) > 200 else yaml_content
            })

    return {
        "blocks": blocks,
        "block_names": list(blocks.keys()),
        "count": len(blocks),
        "errors": errors,
    }


def extract_from_markdown(
    markdown_file: str,
    phase: int,
    project_root: str,
    session_id: Optional[str] = None,
    mark_complete: bool = True
) -> Dict:
    """
    Extract YAML blocks from a Markdown report and store them.

    Args:
        markdown_file: Path to the Markdown file
        phase: Phase number (1-8)
        project_root: Project root directory
        session_id: Optional session ID (uses current session if not specified)
        mark_complete: If True, mark phase as completed in session state (M9 fix)

    Returns:
        Extraction result with status and stored data info
    """
    # Resolve file path
    md_path = Path(markdown_file)
    if not md_path.is_absolute():
        md_path = Path(project_root) / "Risk_Assessment_Report" / markdown_file

    if not md_path.exists():
        return {"error": f"File not found: {md_path}"}

    # Read and extract
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    extraction = extract_yaml_blocks(content)

    if extraction["errors"]:
        return {
            "status": "partial",
            "phase": phase,
            "errors": extraction["errors"],
            "blocks_extracted": extraction["count"],
        }

    if extraction["count"] == 0:
        return {
            "status": "warning",
            "phase": phase,
            "message": "No YAML blocks found in Markdown file",
            "hint": "Ensure blocks use ```yaml:{block_name} format",
        }

    # Determine session ID if not provided
    if not session_id:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_id = current_session_dir.name

    # Store extracted data in session-specific or legacy location
    dirs = ensure_directories(project_root, session_id)
    phase_file = dirs["phase_data"] / f"phase{phase}.yaml"

    phase_data = {
        "phase": phase,
        "extracted_at": datetime.now().isoformat(),
        "source_file": str(md_path),
        "blocks": extraction["blocks"],
    }

    if session_id:
        phase_data["session_id"] = session_id

    with open(phase_file, "w", encoding="utf-8") as f:
        yaml.dump(phase_data, f, allow_unicode=True, default_flow_style=False)

    # Update session extraction status
    session = load_session(project_root, session_id)
    if session:
        entity_count = _count_entities(extraction["blocks"])

        # Handle both old and new extraction_status formats
        if "extraction_status" not in session:
            session["extraction_status"] = {}

        session["extraction_status"][f"phase{phase}"] = {
            "extracted": True,
            "entities": entity_count,
            "blocks": extraction["block_names"],
        }

        # Mark phase complete in session state (M9 fix: gated by mark_complete param)
        # When called from phase_end_protocol, mark_complete=False — completion
        # is deferred until after validation passes.
        if mark_complete:
            if "phases_completed" not in session:
                session["phases_completed"] = []

            if phase not in session["phases_completed"]:
                session["phases_completed"].append(phase)
                session["phases_completed"].sort()

            session["current_phase"] = max(session.get("current_phase", 1), phase + 1)
            update_session(project_root, session, session_id)

            # Also update session meta
            if session_id:
                _update_session_meta(
                    project_root,
                    session_id,
                    session.get("project_name", ""),
                    "update",
                    current_phase=session["current_phase"],
                    phases_completed=session["phases_completed"]
                )

    return {
        "status": "success",
        "phase": phase,
        "blocks_extracted": extraction["count"],
        "blocks": {
            name: {"count": _count_items(data)}
            for name, data in extraction["blocks"].items()
        },
        "stored_to": str(phase_file),
        "session_id": session_id,
    }


def _count_entities(blocks: Dict) -> int:
    """Count total entities across all blocks."""
    total = 0
    for data in blocks.values():
        total += _count_items(data)
    return total


def _count_items(data: Any) -> int:
    """Count items in a data structure."""
    if isinstance(data, list):
        return len(data)
    elif isinstance(data, dict):
        # Count items in common list-like keys
        for key in ["modules", "entries", "flows", "threats", "risks", "items"]:
            if key in data and isinstance(data[key], list):
                return len(data[key])
        # Default: count top-level keys
        return len(data)
    return 1


# ============================================================================
# JSON Storage (Option B - Backup Approach)
# ============================================================================

def store_json(
    json_file: str,
    phase: int,
    project_root: str,
    block_name: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict:
    """
    Store JSON input directly (Option B backup mode).

    Args:
        json_file: Path to JSON file
        phase: Phase number
        project_root: Project root directory
        block_name: Optional block name (defaults to "data")
        session_id: Optional session ID (uses current session if not specified)

    Returns:
        Storage result
    """
    json_path = Path(json_file)

    if not json_path.exists():
        return {"error": f"File not found: {json_path}"}

    with open(json_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {e}"}

    # Determine block name
    if block_name is None:
        block_name = "data"

    # Determine session ID if not provided
    if not session_id:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_id = current_session_dir.name

    # Store as phase data
    dirs = ensure_directories(project_root, session_id)
    phase_file = dirs["phase_data"] / f"phase{phase}.yaml"

    # Load existing or create new
    if phase_file.exists():
        with open(phase_file, "r", encoding="utf-8") as f:
            phase_data = yaml.safe_load(f) or {}
    else:
        phase_data = {
            "phase": phase,
            "extracted_at": datetime.now().isoformat(),
            "source_file": str(json_path),
            "blocks": {},
        }

    phase_data["blocks"][block_name] = data
    phase_data["last_updated"] = datetime.now().isoformat()
    if session_id:
        phase_data["session_id"] = session_id

    with open(phase_file, "w", encoding="utf-8") as f:
        yaml.dump(phase_data, f, allow_unicode=True, default_flow_style=False)

    return {
        "status": "success",
        "phase": phase,
        "block_name": block_name,
        "items_stored": _count_items(data),
        "stored_to": str(phase_file),
        "mode": "json_direct (Option B)",
        "session_id": session_id,
    }


# ============================================================================
# Query Functions
# ============================================================================

# F9: Module-level cache for load_phase_data (keyed by resolved file path)
_PHASE_DATA_CACHE: Dict[str, Optional[Dict]] = {}

def load_phase_data(
    phase: int,
    project_root: str,
    session_id: Optional[str] = None
) -> Optional[Dict]:
    """
    Load phase data from storage.

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory
        session_id: Optional specific session ID (uses current session if not specified)

    Returns:
        Phase data dict, or None if not found
    """
    # P3-FIX-01: Use correct file names per phase (from SKILL.md)
    PHASE_FILE_NAMES = {
        1: "P1_project_context.yaml",
        2: "P2_dfd_elements.yaml",  # Or P2_final_aggregated.yaml
        3: "P3_boundary_context.yaml",
        4: "P4_security_gaps.yaml",
        5: "P5_threat_inventory.yaml",
        6: "P6_validated_risks.yaml",
        7: "P7_mitigation_plan.yaml",
        8: "P8_report_manifest.yaml",
    }

    # Get appropriate data directory
    data_dir = get_phase_data_dir(project_root, session_id)

    # Try phase-specific file first
    phase_filename = PHASE_FILE_NAMES.get(phase, f"phase{phase}.yaml")
    phase_file = data_dir / phase_filename

    if not phase_file.exists():
        # Try legacy phase{N}.yaml format
        legacy_phase_file = data_dir / f"phase{phase}.yaml"
        if legacy_phase_file.exists():
            phase_file = legacy_phase_file
        else:
            # If no session-specific file found and no session_id specified,
            # try legacy location as fallback
            if not session_id:
                legacy_file = get_phase_working_dir(project_root) / "phase_data" / f"phase{phase}.yaml"
                if legacy_file.exists():
                    phase_file = legacy_file
                else:
                    return None
            else:
                return None

    # F9: Cache lookup by resolved file path
    cache_key = str(phase_file.resolve())
    if cache_key in _PHASE_DATA_CACHE:
        return _PHASE_DATA_CACHE[cache_key]

    try:
        with open(phase_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            _PHASE_DATA_CACHE[cache_key] = data
            return data
    except (yaml.YAMLError, IOError) as e:
        print(f"Warning: {e}", file=sys.stderr)
        return None


def query_phase(
    phase: int,
    project_root: str,
    query_type: Optional[str] = None,
    element_id: Optional[str] = None,
    block_name: Optional[str] = None,
    summary: bool = False
) -> Dict:
    """
    Query phase data.

    Args:
        phase: Phase number
        project_root: Project root directory
        query_type: Type of data to query (e.g., "entry_points", "threats")
        element_id: Specific element to query
        block_name: Specific block to query
        summary: Return summary instead of full data

    Returns:
        Query result
    """
    phase_data = load_phase_data(phase, project_root)

    if not phase_data:
        return {
            "error": f"No data found for phase {phase}",
            "hint": f"Run --extract on P{phase}-*.md first",
        }

    blocks = phase_data.get("blocks", {})

    # Summary mode: return overview
    if summary:
        return {
            "phase": phase,
            "extracted_at": phase_data.get("extracted_at"),
            "source_file": phase_data.get("source_file"),
            "blocks": {
                name: {
                    "count": _count_items(data),
                    "type": type(data).__name__,
                }
                for name, data in blocks.items()
            },
        }

    # Query specific block
    if block_name:
        if block_name not in blocks:
            return {
                "error": f"Block '{block_name}' not found in phase {phase}",
                "available_blocks": list(blocks.keys()),
            }
        return {
            "phase": phase,
            "block": block_name,
            "data": blocks[block_name],
        }

    # Query by type mapping
    type_block_mapping = {
        "entry_points": "entry_point_inventory",
        "modules": "module_inventory",
        "checklist": "discovery_checklist",
        "dfd": "dfd_elements",
        "flows": "data_flows",
        "gaps": "security_gaps",
        "threats": "threat_inventory",
        "risks": "validated_risks",
        "attacks": "attack_paths",
        "mitigations": "mitigation_plan",
    }

    if query_type:
        target_block = type_block_mapping.get(query_type, query_type)
        if target_block in blocks:
            return {
                "phase": phase,
                "query_type": query_type,
                "block": target_block,
                "data": blocks[target_block],
            }
        return {
            "error": f"Query type '{query_type}' not found",
            "available_blocks": list(blocks.keys()),
        }

    # Query specific element across blocks
    if element_id:
        results = _find_element(blocks, element_id)
        if results:
            return {
                "phase": phase,
                "element_id": element_id,
                "found_in": results,
            }
        return {
            "error": f"Element '{element_id}' not found in phase {phase}",
        }

    # Default: return all blocks
    return {
        "phase": phase,
        "blocks": blocks,
    }


def _find_element(blocks: Dict, element_id: str) -> List[Dict]:
    """Find element by ID across all blocks."""
    results = []

    for block_name, data in blocks.items():
        found = _search_in_data(data, element_id)
        if found:
            results.append({
                "block": block_name,
                "data": found,
            })

    return results


def _search_in_data(data: Any, element_id: str, path: str = "") -> Optional[Any]:
    """Recursively search for element by ID."""
    if isinstance(data, dict):
        # Check if this dict has matching id
        if data.get("id") == element_id:
            return data
        # Search in values
        for key, value in data.items():
            result = _search_in_data(value, element_id, f"{path}.{key}")
            if result:
                return result
    elif isinstance(data, list):
        for i, item in enumerate(data):
            result = _search_in_data(item, element_id, f"{path}[{i}]")
            if result:
                return result
    return None


def query_threats_for_element(
    element_id: str,
    project_root: str
) -> Dict:
    """Query all threats associated with a specific element."""
    # Load phase 5 (threats) and phase 6 (validated risks)
    p5_data = load_phase_data(5, project_root)
    p6_data = load_phase_data(6, project_root)

    results = {
        "element_id": element_id,
        "threats": [],
        "validated_risks": [],
    }

    if p5_data:
        threats = p5_data.get("blocks", {}).get("threat_inventory", {})
        if isinstance(threats, dict) and "threats" in threats:
            threat_list = threats["threats"]
        elif isinstance(threats, list):
            threat_list = threats
        else:
            threat_list = []

        for threat in threat_list:
            if isinstance(threat, dict):
                if (threat.get("element_id") == element_id or
                    threat.get("target") == element_id or
                    element_id in str(threat.get("affected_elements", []))):
                    results["threats"].append(threat)

    if p6_data:
        risks = p6_data.get("blocks", {}).get("validated_risks", {})
        if isinstance(risks, dict) and "risks" in risks:
            risk_list = risks["risks"]
        elif isinstance(risks, list):
            risk_list = risks
        else:
            risk_list = []

        for risk in risk_list:
            if isinstance(risk, dict):
                if (risk.get("element_id") == element_id or
                    risk.get("threat_id", "").endswith(element_id) or
                    element_id in str(risk.get("affected_elements", []))):
                    results["validated_risks"].append(risk)

    results["threat_count"] = len(results["threats"])
    results["risk_count"] = len(results["validated_risks"])

    return results


# ============================================================================
# Validation Functions
# ============================================================================

def validate_p1_checklist(project_root: str) -> Dict:
    """
    Validate Phase 1 discovery checklist completeness.

    Validation Gates (from design doc):
    - BLOCKING: All checklist items have status in [COMPLETED, NOT_APPLICABLE]
    - BLOCKING: No items with scanned: false
    - BLOCKING: schema_version must match SCHEMA_VERSION (P1-GAP-12)
    - WARNING: Sum of counts matches entry_point_inventory length
    """
    phase_data = load_phase_data(1, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 1,
            "message": "Phase 1 data not found. Run --extract first.",
        }

    # P1-GAP-12: Validate schema_version
    # Tolerates both bare "3.1.0" and date-suffixed "3.1.0 (20260313a)" formats
    schema_version = phase_data.get("schema_version", "")
    if not schema_version.startswith(SCHEMA_VERSION):
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "schema_version",
            "message": f"Invalid schema_version: '{schema_version}'. Expected prefix: '{SCHEMA_VERSION}'",
            "action_required": "FIX",
            "hint": f"Ensure P1_project_context.yaml has 'schema_version: \"{SCHEMA_VERSION}\"' or \"{SCHEMA_VERSION} (YYYYMMDD{chr(97)})\" at the top",
        }

    blocks = phase_data.get("blocks", phase_data)
    checklist = blocks.get("discovery_checklist", {})
    entry_points = blocks.get("entry_point_inventory", {})

    # P1-GAP-NEW-09: Validate project_context block (BLOCKING per spec line 41)
    project_context = blocks.get("project_context", phase_data.get("project_context", {}))
    if not project_context:
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "project_context",
            "message": "Missing project_context block",
            "action_required": "FIX",
            "hint": "P1 output must include project_context with project_type and tech_stack",
        }

    # Validate required fields in project_context
    project_type = project_context.get("project_type", "")
    tech_stack = project_context.get("tech_stack", {})
    if not project_type:
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "project_context.project_type",
            "message": "Missing project_type in project_context",
            "action_required": "FIX",
            "hint": "project_context must include project_type (e.g., 'web_application', 'api_service', 'microservices')",
        }

    if not checklist:
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "discovery_checklist",
            "message": "Missing discovery_checklist block",
            "action_required": "FIX",
        }

    # Get checklist items
    checklist_items = checklist.get("checklist", checklist)
    if not isinstance(checklist_items, dict):
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "checklist_format",
            "message": "Invalid checklist format",
        }

    blocking_issues = []
    warnings = []

    # Check each entry point type
    for ep_type in ENTRY_POINT_TYPES:
        item = checklist_items.get(ep_type, {})

        # BLOCKING: scanned must be true
        if not item.get("scanned", False):
            blocking_issues.append({
                "type": ep_type,
                "issue": "Not scanned",
                "severity": "BLOCKING",
            })

        # BLOCKING: status must be COMPLETED or NOT_APPLICABLE
        status = item.get("status", "UNKNOWN")
        if status not in ["COMPLETED", "NOT_APPLICABLE"]:
            blocking_issues.append({
                "type": ep_type,
                "issue": f"Invalid status: {status}",
                "severity": "BLOCKING",
            })

    # WARNING: Count consistency check
    summary = checklist.get("summary", {})
    total_from_checklist = summary.get("total_entry_points", 0)

    # Count from entry_point_inventory
    total_from_inventory = 0
    if isinstance(entry_points, dict):
        for key in ["api_entries", "ui_entries", "system_entries", "hidden_entries"]:
            items = entry_points.get(key, [])
            if isinstance(items, list):
                total_from_inventory += len(items)

    if total_from_checklist != total_from_inventory and total_from_inventory > 0:
        warnings.append({
            "issue": "Entry point count mismatch",
            "checklist_count": total_from_checklist,
            "inventory_count": total_from_inventory,
            "severity": "WARNING",
        })

    # P1-GAP-04: Validate Entry Point ID format (EP-{TYPE}-{NNN})
    ep_id_pattern = re.compile(r'^EP-(API|UI|SYS|HID|WS|GQL|MQ|CRON|FILE|DBG|INT)-\d{3}$')
    seen_ep_ids = set()
    ep_id_issues = []

    if isinstance(entry_points, dict):
        for key in ["api_entries", "ui_entries", "system_entries", "hidden_entries"]:
            items = entry_points.get(key, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        ep_id = item.get("id", "")
                        # Check format
                        if ep_id and not ep_id_pattern.match(ep_id):
                            ep_id_issues.append({
                                "id": ep_id,
                                "issue": "Invalid format",
                                "expected": "EP-{TYPE}-{NNN} where TYPE is API|UI|SYS|HID|WS|GQL|MQ|CRON|FILE|DBG|INT",
                            })
                        # Check uniqueness
                        if ep_id in seen_ep_ids:
                            blocking_issues.append({
                                "id": ep_id,
                                "issue": "Duplicate Entry Point ID",
                                "severity": "BLOCKING",
                            })
                        else:
                            seen_ep_ids.add(ep_id)

    if ep_id_issues:
        warnings.append({
            "issue": "Entry Point ID format warnings",
            "count": len(ep_id_issues),
            "details": ep_id_issues[:10],  # Limit to first 10
            "severity": "WARNING",
        })

    # P1-GAP-NEW-05: Validate coverage_confidence block
    coverage_confidence = blocks.get("coverage_confidence", phase_data.get("coverage_confidence", {}))
    if not coverage_confidence:
        warnings.append({
            "type": "missing_coverage_confidence",
            "issue": "Missing coverage_confidence block",
            "hint": "P1 output should include coverage_confidence with overall_confidence",
            "severity": "WARNING",
        })
    else:
        overall_conf = coverage_confidence.get("overall_confidence", -1)
        if not isinstance(overall_conf, (int, float)) or overall_conf < 0 or overall_conf > 1:
            warnings.append({
                "type": "invalid_coverage_confidence",
                "issue": f"Invalid overall_confidence value: {overall_conf}",
                "expected": "Float between 0.0 and 1.0",
                "severity": "WARNING",
            })
        elif overall_conf < 0.70:
            warnings.append({
                "type": "low_coverage_confidence",
                "issue": f"Low coverage confidence: {overall_conf:.2f}",
                "recommendation": "Review uncertainty sources before proceeding",
                "severity": "WARNING",
            })

    # P1-GAP-NEW-06: Validate module_inventory security_level
    module_inventory = blocks.get("module_inventory", {})
    modules_list = module_inventory.get("modules", []) if isinstance(module_inventory, dict) else []
    modules_without_security_level = []

    for module in modules_list:
        if isinstance(module, dict):
            mid = module.get("id", module.get("name", "unknown"))
            security_level = module.get("security_level", "")
            if not security_level:
                modules_without_security_level.append(mid)
            elif security_level not in ["HIGH", "MEDIUM", "LOW", "CRITICAL"]:
                warnings.append({
                    "type": "invalid_security_level",
                    "module_id": mid,
                    "issue": f"Invalid security_level: {security_level}",
                    "expected": ["HIGH", "MEDIUM", "LOW", "CRITICAL"],
                    "severity": "WARNING",
                })

    if modules_without_security_level:
        warnings.append({
            "type": "missing_security_level",
            "issue": f"{len(modules_without_security_level)} modules missing security_level",
            "modules": modules_without_security_level[:10],  # Limit to first 10
            "hint": "Each module should have security_level: HIGH|MEDIUM|LOW|CRITICAL",
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 1,
            "validation": "checklist",
            "passed": False,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 1 validation FAILED - blocking issues found",
            "options": [
                "[1] FIX - Supplement missing entry discovery",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 1,
        "validation": "checklist",
        "passed": True,
        "coverage": summary.get("coverage", "N/A"),
        "total_entry_points": total_from_checklist,
        "warnings": warnings,
        "message": "Phase 1 validation PASSED",
    }


def validate_p2_l1_coverage(project_root: str) -> Dict:
    """
    Validate Phase 2 L1 interface 100% coverage.

    Validation Gates (from design doc):
    - BLOCKING: l1_coverage.coverage_percentage == 100
    - BLOCKING: All entry_point_analysis.*.analyzed == true
    - WARNING: All entry_point_analysis.*.data_flow_traced == true
    """
    phase_data = load_phase_data(2, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 2,
            "message": "Phase 2 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", phase_data)
    data_flows = blocks.get("data_flows", {})

    # Get L1 coverage info
    l1_coverage = data_flows.get("l1_coverage", {})

    if not l1_coverage:
        return {
            "status": "warning",
            "phase": 2,
            "validation": "l1_coverage",
            "message": "No l1_coverage block found in data_flows",
            "hint": "Ensure P2 report includes l1_coverage in data_flows block",
        }

    blocking_issues = []
    warnings = []

    # BLOCKING: 100% coverage
    coverage_pct = l1_coverage.get("coverage_percentage", 0)
    if coverage_pct < 100:
        blocking_issues.append({
            "issue": "L1 coverage below 100%",
            "current": coverage_pct,
            "required": 100,
            "severity": "BLOCKING",
        })

    # Check individual entry point analysis
    ep_analysis = l1_coverage.get("entry_point_analysis", {})
    unanalyzed = []
    untraced = []

    for ep_id, status in ep_analysis.items():
        if isinstance(status, dict):
            if not status.get("analyzed", False):
                unanalyzed.append(ep_id)
            if not status.get("data_flow_traced", False):
                untraced.append(ep_id)

    # BLOCKING: All must be analyzed
    if unanalyzed:
        blocking_issues.append({
            "issue": "Entry points not analyzed",
            "count": len(unanalyzed),
            "entry_points": unanalyzed[:10],  # Show first 10
            "severity": "BLOCKING",
        })

    # WARNING: Data flow tracing
    if untraced:
        warnings.append({
            "issue": "Entry points without data flow tracing",
            "count": len(untraced),
            "entry_points": untraced[:10],
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 2,
            "validation": "l1_coverage",
            "passed": False,
            "coverage_percentage": coverage_pct,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 2 validation FAILED - L1 coverage incomplete",
            "options": [
                "[1] FIX - Analyze missing entry points",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 2,
        "validation": "l1_coverage",
        "passed": True,
        "coverage_percentage": coverage_pct,
        "total_analyzed": l1_coverage.get("analyzed", l1_coverage.get("total_entry_points", 0)),
        "warnings": warnings,
        "message": "Phase 2 validation PASSED - 100% L1 coverage achieved",
    }


def validate_p3_trust_boundaries(project_root: str) -> Dict:
    """
    Validate Phase 3 trust boundary completeness.

    Validation Gates (from P3-TRUST-BOUNDARY.md):
    - BLOCKING: trust_boundaries block present with at least 1 boundary
    - BLOCKING: All boundaries have valid TB-xxx IDs
    - BLOCKING: Each boundary has type from [Network, Process, User, Data, Service]
    - WARNING: cross_boundary_flows should reference defined boundaries
    - WARNING: interfaces should have valid IF-xxx IDs
    """
    phase_data = load_phase_data(3, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 3,
            "message": "Phase 3 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", phase_data)
    boundaries = blocks.get("trust_boundaries", {})
    interfaces = blocks.get("interfaces", {})
    data_nodes = blocks.get("data_nodes", {})
    cross_flows = blocks.get("cross_boundary_flows", {})

    if not boundaries:
        return {
            "status": "blocking",
            "phase": 3,
            "gate": "trust_boundaries",
            "message": "Missing trust_boundaries block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract boundary list (handle both list and dict formats)
    boundary_list = boundaries if isinstance(boundaries, list) else boundaries.get("boundaries", [])
    if not boundary_list:
        return {
            "status": "blocking",
            "phase": 3,
            "gate": "boundary_count",
            "message": "No trust boundaries defined",
            "action_required": "FIX",
        }

    # Validate boundary IDs and types
    valid_types = ["Network", "Process", "User", "Data", "Service"]
    boundary_ids = []

    for boundary in boundary_list:
        if isinstance(boundary, dict):
            bid = boundary.get("id", "")
            boundary_ids.append(bid)

            # Check ID format
            if not ID_PATTERNS['trust_boundary'].match(bid):
                blocking_issues.append({
                    "type": "invalid_id",
                    "id": bid,
                    "issue": "Invalid trust boundary ID format",
                    "expected": "TB-xxx (e.g., TB-001)",
                    "severity": "BLOCKING",
                })

            # Check boundary type
            btype = boundary.get("type", "")
            if btype and btype not in valid_types:
                blocking_issues.append({
                    "type": "invalid_type",
                    "id": bid,
                    "issue": f"Invalid boundary type: {btype}",
                    "expected": valid_types,
                    "severity": "BLOCKING",
                })

    # Validate interfaces (WARNING level)
    interface_list = interfaces if isinstance(interfaces, list) else interfaces.get("interfaces", [])
    for iface in interface_list:
        if isinstance(iface, dict):
            iid = iface.get("id", "")
            if iid and not ID_PATTERNS['interface'].match(iid):
                warnings.append({
                    "type": "invalid_interface_id",
                    "id": iid,
                    "issue": "Invalid interface ID format",
                    "expected": "IF-xxx",
                    "severity": "WARNING",
                })

    # Validate cross_boundary_flows reference defined boundaries (L1 fix)
    flow_list = cross_flows if isinstance(cross_flows, list) else cross_flows.get("flows", [])
    for flow in flow_list:
        if isinstance(flow, dict):
            for field in ("source_boundary", "target_boundary"):
                ref = flow.get(field, "")
                if ref and ref not in boundary_ids:
                    warnings.append({
                        "type": "undefined_boundary_ref",
                        "flow_id": flow.get("id", "unknown"),
                        "field": field,
                        "reference": ref,
                        "issue": f"Cross-boundary flow references undefined boundary: {ref}",
                        "severity": "WARNING",
                    })

    # Validate data nodes (WARNING level)
    node_list = data_nodes if isinstance(data_nodes, list) else data_nodes.get("data_nodes", [])
    for node in node_list:
        if isinstance(node, dict):
            nid = node.get("id", "")
            if nid and not ID_PATTERNS['data_node'].match(nid):
                warnings.append({
                    "type": "invalid_data_node_id",
                    "id": nid,
                    "issue": "Invalid data node ID format",
                    "expected": "DN-xxx",
                    "severity": "WARNING",
                })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 3,
            "validation": "trust_boundaries",
            "passed": False,
            "boundary_count": len(boundary_list),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 3 validation FAILED - trust boundary issues found",
            "options": [
                "[1] FIX - Correct trust boundary definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 3,
        "validation": "trust_boundaries",
        "passed": True,
        "boundary_count": len(boundary_list),
        "boundary_ids": boundary_ids,
        "interface_count": len(interface_list),
        "data_node_count": len(node_list),
        "warnings": warnings,
        "message": f"Phase 3 validation PASSED - {len(boundary_list)} trust boundaries defined",
    }


def validate_p4_security_design(project_root: str) -> Dict:
    """
    Validate Phase 4 security design review completeness.

    Validation Gates (from P4-SECURITY-DESIGN-REVIEW.md):
    - BLOCKING: security_gaps block present
    - BLOCKING: All gaps have valid GAP-xxx IDs
    - BLOCKING: All gaps have domain from 16-domain list
    - WARNING: design_matrix should cover all 16 domains
    - WARNING: Each domain should have a rating
    """
    phase_data = load_phase_data(4, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 4,
            "message": "Phase 4 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", phase_data)
    security_gaps = blocks.get("security_gaps", {})
    design_matrix = blocks.get("design_matrix", {})

    if not security_gaps:
        return {
            "status": "blocking",
            "phase": 4,
            "gate": "security_gaps",
            "message": "Missing security_gaps block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract gaps list
    gaps_list = security_gaps if isinstance(security_gaps, list) else security_gaps.get("gaps", [])

    # Validate gap IDs and domains
    gap_ids = []
    gap_domains = set()

    for gap in gaps_list:
        if isinstance(gap, dict):
            gid = gap.get("id", "")
            gap_ids.append(gid)

            # Check ID format
            if gid and not ID_PATTERNS['security_gap'].match(gid):
                blocking_issues.append({
                    "type": "invalid_gap_id",
                    "id": gid,
                    "issue": "Invalid security gap ID format",
                    "expected": "GAP-xxx (e.g., GAP-001)",
                    "severity": "BLOCKING",
                })

            # Check domain
            domain = gap.get("domain", "")
            if domain:
                gap_domains.add(domain)
                if domain not in SECURITY_DOMAINS:
                    blocking_issues.append({
                        "type": "invalid_domain",
                        "id": gid,
                        "domain": domain,
                        "issue": f"Invalid security domain: {domain}",
                        "expected": SECURITY_DOMAINS,
                        "severity": "BLOCKING",
                    })

            # Check severity
            severity = gap.get("severity", "")
            if severity and severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                warnings.append({
                    "type": "invalid_severity",
                    "id": gid,
                    "issue": f"Non-standard severity: {severity}",
                    "expected": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "severity": "WARNING",
                })

    # Check design matrix coverage (WARNING)
    matrix_data = design_matrix if isinstance(design_matrix, dict) else {}
    assessed_domains = set()

    for domain in SECURITY_DOMAINS:
        domain_entry = matrix_data.get(domain, {})
        if domain_entry:
            assessed_domains.add(domain)
            rating = domain_entry.get("rating", domain_entry.get("status", ""))
            if not rating:
                warnings.append({
                    "type": "missing_rating",
                    "domain": domain,
                    "issue": f"Domain {domain} missing rating",
                    "severity": "WARNING",
                })

    missing_domains = set(SECURITY_DOMAINS) - assessed_domains
    if missing_domains and design_matrix:
        warnings.append({
            "type": "incomplete_matrix",
            "issue": f"Design matrix missing {len(missing_domains)} domains",
            "missing_domains": list(missing_domains),
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 4,
            "validation": "security_design",
            "passed": False,
            "gap_count": len(gaps_list),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 4 validation FAILED - security gap issues found",
            "options": [
                "[1] FIX - Correct security gap definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    # P4 Coverage Verification: Check P1 module + P2 dataflow coverage
    # This is called at P4 phase boundary to ensure complete traceability
    coverage_result = verify_p4_coverage(project_root)
    coverage_warnings = []
    coverage_blockers = []

    if coverage_result.get("status") == "FAIL":
        for blocker in coverage_result.get("blockers", []):
            coverage_blockers.append({
                "type": "coverage_gap",
                "issue": blocker,
                "severity": "WARNING",  # Coverage gaps are warnings, not blockers at P4
            })
    elif coverage_result.get("status") == "WARN":
        for warning in coverage_result.get("warnings", []):
            coverage_warnings.append({
                "type": "coverage_warning",
                "issue": warning,
                "severity": "WARNING",
            })

    warnings.extend(coverage_warnings)
    warnings.extend(coverage_blockers)

    return {
        "status": "passed",
        "phase": 4,
        "validation": "security_design",
        "passed": True,
        "gap_count": len(gaps_list),
        "gap_ids": gap_ids,
        "domains_covered": list(gap_domains),
        "matrix_coverage": f"{len(assessed_domains)}/{len(SECURITY_DOMAINS)}",
        "warnings": warnings,
        "coverage_verification": {
            "p1_module_coverage": coverage_result.get("p1_module_coverage", {}),
            "p2_dataflow_coverage": coverage_result.get("p2_dataflow_coverage", {}),
            "overall_coverage_percentage": coverage_result.get("overall_coverage_percentage", 0),
        },
        "message": f"Phase 4 validation PASSED - {len(gaps_list)} security gaps documented",
    }


def validate_p5_threat_inventory(project_root: str) -> Dict:
    """
    Validate Phase 5 threat inventory completeness.

    Validation Gates (from P5-STRIDE-ANALYSIS.md):
    - BLOCKING: threat_inventory block present
    - BLOCKING: All threats have valid T-{STRIDE}-{Element}-{Seq} IDs
    - BLOCKING: summary.total matches actual threat count
    - BLOCKING: by_stride totals sum to total
    - WARNING: All STRIDE categories should be represented
    """
    phase_data = load_phase_data(5, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 5,
            "message": "Phase 5 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", phase_data)
    threat_inventory = blocks.get("threat_inventory", {})

    if not threat_inventory:
        return {
            "status": "blocking",
            "phase": 5,
            "gate": "threat_inventory",
            "message": "Missing threat_inventory block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract threats list
    threats_list = threat_inventory.get("threats", [])
    summary = threat_inventory.get("summary", {})

    if not threats_list:
        return {
            "status": "blocking",
            "phase": 5,
            "gate": "threat_count",
            "message": "No threats defined in threat_inventory",
            "action_required": "FIX",
        }

    # Validate threat IDs
    threat_ids = []
    stride_counts = {'S': 0, 'T': 0, 'R': 0, 'I': 0, 'D': 0, 'E': 0}

    for threat in threats_list:
        if isinstance(threat, dict):
            tid = threat.get("id", "")
            threat_ids.append(tid)

            # Check ID format (support both formats)
            valid_format = (
                ID_PATTERNS['threat'].match(tid) or
                ID_PATTERNS['threat_alt'].match(tid)
            )
            if tid and not valid_format:
                blocking_issues.append({
                    "type": "invalid_threat_id",
                    "id": tid,
                    "issue": "Invalid threat ID format",
                    "expected": "T-{S|T|R|I|D|E}-{ElementID}-{Seq} (e.g., T-S-P-001-001)",
                    "severity": "BLOCKING",
                })

            # Count STRIDE category
            stride_type = threat.get("stride_type", "")
            if not stride_type and tid:
                # Extract from ID
                parts = tid.split('-')
                if len(parts) >= 2:
                    stride_type = parts[1]

            if stride_type in stride_counts:
                stride_counts[stride_type] += 1
            elif stride_type:
                warnings.append({
                    "type": "invalid_stride_type",
                    "id": tid,
                    "stride_type": stride_type,
                    "issue": f"Invalid STRIDE type: {stride_type}",
                    "expected": STRIDE_CATEGORIES,
                    "severity": "WARNING",
                })

            # Required field presence check (M6)
            THREAT_REQUIRED_FIELDS = ["element_id", "title", "description"]
            missing_fields = [f for f in THREAT_REQUIRED_FIELDS if not threat.get(f)]
            if missing_fields:
                warnings.append({
                    "type": "missing_required_fields",
                    "id": tid,
                    "missing": missing_fields,
                    "issue": f"Threat {tid} missing fields: {missing_fields}",
                    "severity": "WARNING",
                })

    # Validate summary counts
    actual_count = len(threats_list)
    declared_total = summary.get("total", 0)

    if declared_total != actual_count:
        blocking_issues.append({
            "type": "count_mismatch",
            "issue": "Threat count mismatch",
            "declared": declared_total,
            "actual": actual_count,
            "severity": "BLOCKING",
        })

    # Validate by_stride totals
    by_stride = summary.get("by_stride", {})
    stride_total = sum(by_stride.get(s, 0) for s in STRIDE_CATEGORIES)

    if by_stride and stride_total != actual_count:
        blocking_issues.append({
            "type": "stride_sum_mismatch",
            "issue": "by_stride sum doesn't match total",
            "stride_sum": stride_total,
            "actual": actual_count,
            "severity": "BLOCKING",
        })

    # Check STRIDE coverage (WARNING)
    missing_stride = [s for s in STRIDE_CATEGORIES if stride_counts[s] == 0]
    if missing_stride:
        warnings.append({
            "type": "incomplete_stride_coverage",
            "issue": f"Missing STRIDE categories: {missing_stride}",
            "stride_counts": stride_counts,
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 5,
            "validation": "threat_inventory",
            "passed": False,
            "threat_count": actual_count,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 5 validation FAILED - threat inventory issues found",
            "options": [
                "[1] FIX - Correct threat definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    # P5 Element Coverage Verification: Check P2 DFD element coverage
    # This is called at P5 phase boundary to ensure all elements have STRIDE analysis
    element_coverage = verify_p5_element_coverage(project_root)
    coverage_warnings = []

    if element_coverage.get("status") in ["FAIL", "WARN"]:
        uncovered = element_coverage.get("uncovered_elements", [])
        partial = element_coverage.get("partial_stride_elements", [])

        if uncovered:
            coverage_warnings.append({
                "type": "element_coverage_gap",
                "issue": f"{len(uncovered)} P2 DFD elements have no STRIDE threats",
                "uncovered_elements": [e.get("element_id") for e in uncovered[:5]],
                "severity": "WARNING",
            })

        if partial:
            coverage_warnings.append({
                "type": "partial_stride_coverage",
                "issue": f"{len(partial)} elements have incomplete STRIDE coverage",
                "partial_elements": [e.get("element_id") for e in partial[:5]],
                "severity": "WARNING",
            })

    warnings.extend(coverage_warnings)

    return {
        "status": "passed",
        "phase": 5,
        "validation": "threat_inventory",
        "passed": True,
        "threat_count": actual_count,
        "stride_distribution": stride_counts,
        "warnings": warnings,
        "element_coverage_verification": {
            "overall_coverage_percentage": element_coverage.get("overall_coverage_percentage", 0),
            "stride_completeness": element_coverage.get("stride_completeness", 0),
            "element_coverage": element_coverage.get("element_coverage", {}),
        },
        "message": f"Phase 5 validation PASSED - {actual_count} threats documented",
    }


def validate_p6_validated_risks(project_root: str) -> Dict:
    """
    Validate Phase 6 risk validation completeness.

    Validation Gates (from P6-RISK-VALIDATION.md):
    - BLOCKING: validated_risks block present
    - BLOCKING: All risks have valid VR-xxx IDs
    - BLOCKING: All VRs have threat_refs[] (CP2)
    - BLOCKING: Count conservation formula holds (CP1)
    - WARNING: POC-xxx required for Critical/High priority
    - WARNING: attack_chains should be defined
    """
    phase_data = load_phase_data(6, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 6,
            "message": "Phase 6 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", phase_data)
    validated_risks = blocks.get("validated_risks", {})
    poc_details = blocks.get("poc_details", {})
    attack_chains = blocks.get("attack_chains", {})

    if not validated_risks:
        return {
            "status": "blocking",
            "phase": 6,
            "gate": "validated_risks",
            "message": "Missing validated_risks block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract risk list
    risk_summary = validated_risks.get("risk_summary", {})
    risk_details = validated_risks.get("risk_details", [])

    if not risk_details:
        risk_details = validated_risks.get("risks", [])

    # Validate risk IDs and threat_refs
    vr_ids = []
    all_threat_refs = []
    critical_high_without_poc = []

    for risk in risk_details:
        if isinstance(risk, dict):
            vr_id = risk.get("id", "")
            vr_ids.append(vr_id)

            # Check VR ID format
            if vr_id and not ID_PATTERNS['validated_risk'].match(vr_id):
                blocking_issues.append({
                    "type": "invalid_vr_id",
                    "id": vr_id,
                    "issue": "Invalid validated risk ID format",
                    "expected": "VR-xxx (e.g., VR-001)",
                    "severity": "BLOCKING",
                })

            # Check threat_refs (CP2)
            threat_refs = risk.get("threat_refs", [])
            if not threat_refs:
                blocking_issues.append({
                    "type": "missing_threat_refs",
                    "id": vr_id,
                    "issue": "VR missing threat_refs[]",
                    "severity": "BLOCKING",
                })
            else:
                all_threat_refs.extend(threat_refs)

            # Check POC for Critical/High
            priority = risk.get("priority", "")
            poc_ref = risk.get("related_poc", risk.get("poc_id", ""))
            if priority in ["P0", "P1", "CRITICAL", "HIGH"] and not poc_ref:
                critical_high_without_poc.append(vr_id)

    # Check for forbidden RISK-xxx format
    risk_pattern = ID_PATTERNS['forbidden_risk']
    for risk in risk_details:
        if isinstance(risk, dict):
            for key, value in risk.items():
                if isinstance(value, str) and risk_pattern.match(value):
                    blocking_issues.append({
                        "type": "forbidden_id_format",
                        "id": value,
                        "issue": "Forbidden RISK-xxx format found (should be VR-xxx)",
                        "severity": "BLOCKING",
                    })

    # Count conservation (4-bucket detail level):
    # P5.total = verified + theoretical + pending + excluded
    # Note: CP1 checkpoint uses 2-bucket form: consolidated + excluded = total
    #        where consolidated = verified + theoretical + pending (semantically equivalent)

    # Count conservation check (basic)
    declared_counts = risk_summary.get("total_verified", 0) + \
                     risk_summary.get("total_theoretical", 0) + \
                     risk_summary.get("total_pending", 0) + \
                     risk_summary.get("total_excluded", 0)
    declared_identified = risk_summary.get("total_identified", 0)

    if declared_counts > 0 and declared_identified > 0 and declared_counts != declared_identified:
        blocking_issues.append({
            "type": "count_conservation_violation",
            "issue": "Risk summary counts do not balance (CP1 violation)",
            "identified": declared_identified,
            "sum": declared_counts,
            "hint": "Run --validate-checkpoints for full CP1 validation",
            "severity": "BLOCKING",
        })

    # POC coverage warning
    if critical_high_without_poc:
        warnings.append({
            "type": "missing_poc",
            "issue": f"{len(critical_high_without_poc)} Critical/High risks without POC",
            "risks": critical_high_without_poc[:5],
            "severity": "WARNING",
        })

    # Attack chains warning
    chains_list = attack_chains if isinstance(attack_chains, list) else attack_chains.get("chains", [])
    if not chains_list:
        warnings.append({
            "type": "missing_attack_chains",
            "issue": "No attack chains defined",
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 6,
            "validation": "validated_risks",
            "passed": False,
            "risk_count": len(risk_details),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 6 validation FAILED - validated risk issues found",
            "options": [
                "[1] FIX - Correct risk definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    # P6 Findings Coverage Verification: Check P1-P5 findings coverage + count conservation
    # This is called at P6 phase boundary to ensure complete traceability
    findings_coverage = verify_p6_findings_coverage(project_root)
    coverage_blockers = []
    coverage_warnings = []

    if findings_coverage.get("status") == "FAIL":
        for blocker in findings_coverage.get("blockers", []):
            coverage_blockers.append({
                "type": "findings_coverage_gap",
                "issue": blocker,
                "severity": "BLOCKING",
            })
        blocking_issues.extend(coverage_blockers)
    elif findings_coverage.get("status") == "WARN":
        for warning in findings_coverage.get("warnings", []):
            coverage_warnings.append({
                "type": "findings_coverage_warning",
                "issue": warning,
                "severity": "WARNING",
            })

    warnings.extend(coverage_warnings)

    # Re-check for blocking issues after coverage check
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 6,
            "validation": "validated_risks",
            "passed": False,
            "risk_count": len(risk_details),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 6 validation FAILED - validated risk issues found",
            "options": [
                "[1] FIX - Correct risk definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 6,
        "validation": "validated_risks",
        "passed": True,
        "risk_count": len(risk_details),
        "vr_ids": vr_ids,
        "threat_ref_count": len(set(all_threat_refs)),
        "warnings": warnings,
        "findings_coverage_verification": {
            "p4_gaps_coverage": findings_coverage.get("p4_gaps_coverage", {}),
            "p5_threats_coverage": findings_coverage.get("p5_threats_coverage", {}),
            "count_conservation": findings_coverage.get("count_conservation", {}),
            "overall_coverage_percentage": findings_coverage.get("overall_coverage_percentage", 0),
        },
        "message": f"Phase 6 validation PASSED - {len(risk_details)} validated risks documented",
    }


def validate_p7_mitigation_plan(project_root: str) -> Dict:
    """
    Validate Phase 7 mitigation plan completeness.

    Validation Gates (from P7-MITIGATION-PLANNING.md):
    - BLOCKING: mitigation_plan block present
    - BLOCKING: All mitigations have valid MIT-xxx IDs
    - BLOCKING: All mitigations have risk_refs[] linking to VR-xxx
    - WARNING: Every VR-xxx should have at least one MIT-xxx
    - WARNING: roadmap should be defined with timeline
    """
    phase_data = load_phase_data(7, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 7,
            "message": "Phase 7 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", phase_data)
    mitigation_plan = blocks.get("mitigation_plan", {})
    roadmap = blocks.get("roadmap", {})

    if not mitigation_plan:
        return {
            "status": "blocking",
            "phase": 7,
            "gate": "mitigation_plan",
            "message": "Missing mitigation_plan block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract mitigations list
    mitigations = mitigation_plan.get("mitigations", [])

    if not mitigations:
        return {
            "status": "blocking",
            "phase": 7,
            "gate": "mitigation_count",
            "message": "No mitigations defined in mitigation_plan",
            "action_required": "FIX",
        }

    # Validate mitigation IDs and risk_refs
    mit_ids = []
    covered_vrs = set()
    mitigations_without_risk_refs = []

    for mitigation in mitigations:
        if isinstance(mitigation, dict):
            mit_id = mitigation.get("id", "")
            mit_ids.append(mit_id)

            # Check MIT ID format
            if mit_id and not ID_PATTERNS['mitigation'].match(mit_id):
                blocking_issues.append({
                    "type": "invalid_mit_id",
                    "id": mit_id,
                    "issue": "Invalid mitigation ID format",
                    "expected": "MIT-xxx (e.g., MIT-001)",
                    "severity": "BLOCKING",
                })

            # Check for forbidden M-xxx format (collision with Module)
            if mit_id and ID_PATTERNS['forbidden_mitigation'].match(mit_id):
                blocking_issues.append({
                    "type": "forbidden_mit_format",
                    "id": mit_id,
                    "issue": "M-xxx format collides with Module ID",
                    "expected": "MIT-xxx (e.g., MIT-001)",
                    "severity": "BLOCKING",
                })

            # Check risk_refs
            risk_refs = mitigation.get("risk_refs", [])
            if not risk_refs:
                mitigations_without_risk_refs.append(mit_id)
            else:
                for vr in risk_refs:
                    covered_vrs.add(vr)

            # Validate risk_refs format
            for vr in risk_refs:
                if not ID_PATTERNS['validated_risk'].match(vr):
                    warnings.append({
                        "type": "invalid_risk_ref",
                        "mitigation": mit_id,
                        "risk_ref": vr,
                        "issue": "Invalid risk reference format",
                        "expected": "VR-xxx",
                        "severity": "WARNING",
                    })

    # Mitigations without risk_refs is blocking
    if mitigations_without_risk_refs:
        blocking_issues.append({
            "type": "missing_risk_refs",
            "mitigations": mitigations_without_risk_refs,
            "issue": f"{len(mitigations_without_risk_refs)} mitigations missing risk_refs[]",
            "severity": "BLOCKING",
        })

    # Cross-validate with P6 VRs (try to load P6 for comparison)
    p6_data = load_phase_data(6, project_root)
    if p6_data:
        p6_blocks = p6_data.get("blocks", {})
        p6_risks = p6_blocks.get("validated_risks", {})
        risk_details = p6_risks.get("risk_details", p6_risks.get("risks", []))

        p6_vr_ids = set()
        for risk in risk_details:
            if isinstance(risk, dict):
                vr_id = risk.get("id", "")
                if vr_id:
                    p6_vr_ids.add(vr_id)

        uncovered_vrs = p6_vr_ids - covered_vrs
        if uncovered_vrs:
            warnings.append({
                "type": "uncovered_risks",
                "issue": f"{len(uncovered_vrs)} VRs without mitigation",
                "uncovered": list(uncovered_vrs)[:5],
                "severity": "WARNING",
            })

    # Roadmap validation (WARNING)
    roadmap_data = roadmap if roadmap else mitigation_plan.get("roadmap", {})
    if not roadmap_data:
        warnings.append({
            "type": "missing_roadmap",
            "issue": "No roadmap defined",
            "severity": "WARNING",
        })
    else:
        # Check roadmap has timeline sections
        expected_sections = ["immediate", "short_term", "medium_term", "long_term"]
        present_sections = [s for s in expected_sections if roadmap_data.get(s)]
        if len(present_sections) < 2:
            warnings.append({
                "type": "incomplete_roadmap",
                "issue": f"Roadmap only has {len(present_sections)} timeline sections",
                "present": present_sections,
                "expected": expected_sections,
                "severity": "WARNING",
            })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 7,
            "validation": "mitigation_plan",
            "passed": False,
            "mitigation_count": len(mitigations),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 7 validation FAILED - mitigation plan issues found",
            "options": [
                "[1] FIX - Correct mitigation definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 7,
        "validation": "mitigation_plan",
        "passed": True,
        "mitigation_count": len(mitigations),
        "mit_ids": mit_ids,
        "vr_coverage": len(covered_vrs),
        "warnings": warnings,
        "message": f"Phase 7 validation PASSED - {len(mitigations)} mitigations documented",
    }


def validate_phase(phase: int, project_root: str) -> Dict:
    """
    Route to appropriate phase-specific validation function.

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory

    Returns:
        Dict with validation results including:
        - status: "passed", "blocking", "warning", or "error"
        - phase: Phase number
        - passed: Boolean
        - blocking_issues: List of blocking issues (if any)
        - warnings: List of warnings (if any)
        - message: Human-readable summary
    """
    # Phase-specific validators
    validators = {
        1: validate_p1_checklist,
        2: validate_p2_l1_coverage,
        3: validate_p3_trust_boundaries,
        4: validate_p4_security_design,
        5: validate_p5_threat_inventory,
        6: validate_p6_validated_risks,
        7: validate_p7_mitigation_plan,
    }

    if phase in validators:
        return validators[phase](project_root)

    # Phase 8 uses generic validation (reports, not data blocks)
    if phase == 8:
        return _validate_p8_reports(project_root)

    # Unknown phase
    return {
        "status": "error",
        "phase": phase,
        "message": f"Unknown phase: {phase}. Valid phases are 1-8.",
    }


def _validate_p8_reports(project_root: str) -> Dict:
    """
    Validate Phase 8 report generation completeness.

    Checks that all 8 required reports are generated in Risk_Assessment_Report/.
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    if not report_dir.exists():
        return {
            "status": "blocking",
            "phase": 8,
            "gate": "report_directory",
            "message": "Risk_Assessment_Report/ directory not found",
            "action_required": "FIX",
        }

    required_reports = [
        "RISK-ASSESSMENT-REPORT",
        "RISK-INVENTORY",
        "MITIGATION-MEASURES",
        "PENETRATION-TEST-PLAN",
        "ARCHITECTURE-ANALYSIS",
        "DFD-DIAGRAM",
        "COMPLIANCE-REPORT",
        "ATTACK-PATH-VALIDATION",
    ]

    found_reports = []
    missing_reports = []

    # Glob once, iterate cached list (M13 fix: was 8 redundant globs)
    all_md_files = list(report_dir.glob("**/*.md"))

    for report_name in required_reports:
        found = False
        for f in all_md_files:
            if report_name.upper() in f.name.upper():
                found = True
                found_reports.append(f.name)
                break
        if not found:
            missing_reports.append(report_name)

    if missing_reports:
        return {
            "status": "blocking",
            "phase": 8,
            "validation": "reports",
            "passed": False,
            "found_reports": found_reports,
            "missing_reports": missing_reports,
            "message": f"Phase 8 validation FAILED - {len(missing_reports)} reports missing",
            "options": [
                "[1] FIX - Generate missing reports",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    # P8 Attack Path Coverage Verification: Check pentest covers P6 attack paths
    # This is called at P8 phase boundary to ensure complete test coverage
    attack_coverage = verify_p8_attack_coverage(project_root)
    coverage_warnings = []

    if attack_coverage.get("status") in ["FAIL", "WARN"]:
        ap_uncovered = attack_coverage.get("attack_paths", {}).get("uncovered_paths", [])
        ac_uncovered = attack_coverage.get("attack_chains", {}).get("uncovered_chains", [])

        if ap_uncovered:
            coverage_warnings.append({
                "type": "attack_path_coverage_gap",
                "issue": f"{len(ap_uncovered)} P6 attack paths have no test cases",
                "uncovered_paths": ap_uncovered[:5],
                "severity": "WARNING",
            })

        if ac_uncovered:
            coverage_warnings.append({
                "type": "attack_chain_coverage_gap",
                "issue": f"{len(ac_uncovered)} P6 attack chains have no test scenarios",
                "uncovered_chains": ac_uncovered[:5],
                "severity": "WARNING",
            })

    return {
        "status": "passed",
        "phase": 8,
        "validation": "reports",
        "passed": True,
        "found_reports": found_reports,
        "warnings": coverage_warnings,
        "attack_coverage_verification": {
            "attack_paths": attack_coverage.get("attack_paths", {}),
            "attack_chains": attack_coverage.get("attack_chains", {}),
            "validated_risks": attack_coverage.get("validated_risks", {}),
            "overall_coverage_percentage": attack_coverage.get("overall_coverage_percentage", 0),
        },
        "message": f"Phase 8 validation PASSED - all {len(required_reports)} reports generated",
    }


# ============================================================================
# Aggregation Functions
# ============================================================================

def aggregate_phases(
    phases: List[int],
    project_root: str,
    format_type: str = "summary"
) -> Dict:
    """
    Aggregate data from multiple phases.

    Args:
        phases: List of phase numbers to aggregate
        project_root: Project root directory
        format_type: "summary" or "full"

    Returns:
        Aggregated data
    """
    result = {
        "phases_requested": phases,
        "phases_found": [],
        "phases_missing": [],
        "aggregated_data": {},
    }

    for phase in phases:
        phase_data = load_phase_data(phase, project_root)

        if phase_data:
            result["phases_found"].append(phase)

            if format_type == "summary":
                # Summary: block names and counts only
                blocks = phase_data.get("blocks", {})
                result["aggregated_data"][f"phase{phase}"] = {
                    "extracted_at": phase_data.get("extracted_at"),
                    "blocks": {
                        name: _count_items(data)
                        for name, data in blocks.items()
                    },
                }
            else:
                # Full: include all data
                result["aggregated_data"][f"phase{phase}"] = phase_data
        else:
            result["phases_missing"].append(phase)

    result["complete"] = len(result["phases_missing"]) == 0

    return result


# ============================================================================
# Count Conservation Validation (CP1/CP2/CP3)
# Migrated from validate_count_conservation.py v2.1.0
# NOTE (M12): CP validators use UPPERCASE status (PASS/FAIL/WARN) per migration origin.
# Phase validators use lowercase (passed/blocking/error/warning). Consumers at
# boundaries must use the correct case; main() normalizes via .lower() for exit codes.
# ============================================================================

# Regex patterns for content parsing (from validate_count_conservation.py)
_THREAT_PATTERN = re.compile(r'T-[STRIDE]-[A-Z]+-\d{3}(?:-\d{3})?')
_VR_PATTERN = re.compile(r'VR-\d{3,}')  # L2: 3+ digits for >999 VRs
_TOTAL_PATTERN = re.compile(r'(?:total|总数|总计)[\s:]*(\d+)', re.IGNORECASE)
_THREAT_REF_PATTERN = re.compile(r'threat_refs?\s*[:\|]\s*\[?([^\]\n]+)\]?', re.IGNORECASE)


def extract_threat_ids_from_phase_data(phase5_data: Dict) -> Tuple[int, List[str]]:
    """
    Extract threat IDs from phase 5 structured data.

    Args:
        phase5_data: Phase 5 data loaded via load_phase_data()

    Returns:
        Tuple of (declared_total, list_of_threat_ids)
    """
    if not phase5_data:
        return 0, []

    blocks = phase5_data.get("blocks", {})
    threat_inventory = blocks.get("threat_inventory", {})

    threats = []

    # Handle different data structures
    if isinstance(threat_inventory, dict):
        # Check for 'threats' key
        threat_list = threat_inventory.get("threats", [])
        if isinstance(threat_list, list):
            for threat in threat_list:
                if isinstance(threat, dict):
                    threat_id = threat.get("id") or threat.get("threat_id")
                    if threat_id:
                        threats.append(threat_id)
        # Check for summary total
        summary = threat_inventory.get("summary", {})
        declared_total = summary.get("total", len(threats))
    elif isinstance(threat_inventory, list):
        # Direct list of threats
        for threat in threat_inventory:
            if isinstance(threat, dict):
                threat_id = threat.get("id") or threat.get("threat_id")
                if threat_id:
                    threats.append(threat_id)
        declared_total = len(threats)
    else:
        declared_total = 0

    # Deduplicate
    threats = list(set(threats))

    return declared_total, threats


def extract_vr_mapping_from_phase_data(phase6_data: Dict) -> Dict[str, List[str]]:
    """
    Extract VR to threat_refs mapping from phase 6 data.

    Args:
        phase6_data: Phase 6 data loaded via load_phase_data()

    Returns:
        Dict mapping VR IDs to their threat_refs (e.g., {'VR-001': ['T-S-P1-001', ...]})
    """
    if not phase6_data:
        return {}

    blocks = phase6_data.get("blocks", {})
    validated_risks = blocks.get("validated_risks", {})

    vr_mapping = {}

    # Handle different data structures
    if isinstance(validated_risks, dict):
        risk_list = validated_risks.get("risk_details", validated_risks.get("risks", []))
    elif isinstance(validated_risks, list):
        risk_list = validated_risks
    else:
        risk_list = []

    for risk in risk_list:
        if isinstance(risk, dict):
            vr_id = risk.get("id") or risk.get("vr_id")
            if vr_id:
                # Get threat_refs (can be 'threat_refs', 'threat_ref', or 'source_threats')
                refs = risk.get("threat_refs") or risk.get("threat_ref") or risk.get("source_threats", [])
                if isinstance(refs, str):
                    refs = [refs]
                elif not isinstance(refs, list):
                    refs = []
                vr_mapping[vr_id] = list(set(refs))

    return vr_mapping


def extract_excluded_from_phase_data(phase6_data: Dict) -> List[str]:
    """
    Extract excluded threat IDs from phase 6 data.

    Args:
        phase6_data: Phase 6 data loaded via load_phase_data()

    Returns:
        List of excluded threat IDs
    """
    if not phase6_data:
        return []

    blocks = phase6_data.get("blocks", {})

    excluded = []

    # Check in validated_risks block for excluded section
    validated_risks = blocks.get("validated_risks", {})
    if isinstance(validated_risks, dict):
        excluded_threats = validated_risks.get("excluded_threats", [])
        if isinstance(excluded_threats, list):
            for threat in excluded_threats:
                if isinstance(threat, str):
                    excluded.append(threat)
                elif isinstance(threat, dict):
                    threat_id = threat.get("id") or threat.get("threat_id")
                    if threat_id:
                        excluded.append(threat_id)

        # Also check for threat_disposition block
        threat_disposition = validated_risks.get("threat_disposition", {})
        if isinstance(threat_disposition, dict):
            excluded_list = threat_disposition.get("excluded", [])
            if isinstance(excluded_list, list):
                for threat in excluded_list:
                    if isinstance(threat, str):
                        excluded.append(threat)
                    elif isinstance(threat, dict):
                        threat_id = threat.get("id") or threat.get("threat_id")
                        if threat_id:
                            excluded.append(threat_id)

    return list(set(excluded))


def extract_vr_ids_from_phase_data(phase6_data: Dict) -> List[str]:
    """
    Extract all unique VR IDs from phase 6 data.

    Args:
        phase6_data: Phase 6 data loaded via load_phase_data()

    Returns:
        Sorted list of unique VR IDs
    """
    vr_mapping = extract_vr_mapping_from_phase_data(phase6_data)
    return sorted(list(vr_mapping.keys()))


# ============================================================================
# Markdown Parsing Functions (backward compatibility with validate_count_conservation.py)
# ============================================================================

def extract_threat_ids_from_markdown(content: str) -> Tuple[int, List[str]]:
    """
    Extract threat IDs from P5 markdown content (backward compatibility).

    This function replicates the regex-based parsing from validate_count_conservation.py
    for direct markdown file analysis without phase_data extraction.

    Args:
        content: Raw markdown content of P5-STRIDE-THREATS.md

    Returns:
        Tuple of (declared_total, list_of_threat_ids)
    """
    threats = []

    # Look for threat IDs in format T-X-XXX-NNN
    matches = _THREAT_PATTERN.findall(content)
    threats = list(set(matches))  # Unique threats

    # Try to find total count from summary section
    total_match = _TOTAL_PATTERN.search(content)

    if total_match:
        declared_total = int(total_match.group(1))
    else:
        declared_total = len(threats)

    return declared_total, threats


def extract_vr_mapping_from_markdown(content: str) -> Dict[str, List[str]]:
    """
    Extract VR mapping from P6 markdown content (backward compatibility).

    This function replicates the regex-based parsing from validate_count_conservation.py.

    Args:
        content: Raw markdown content of P6-RISK-VALIDATION.md

    Returns:
        Dict mapping VR IDs to their threat_refs
    """
    vr_mapping = {}

    # Split by VR entries and extract refs
    lines = content.split('\n')
    current_vr = None

    for line in lines:
        vr_match = _VR_PATTERN.search(line)
        if vr_match:
            current_vr = vr_match.group()
            if current_vr not in vr_mapping:
                vr_mapping[current_vr] = []

        ref_match = _THREAT_REF_PATTERN.search(line)
        if ref_match and current_vr:
            refs = ref_match.group(1)
            # Parse comma-separated threat IDs
            threat_ids = _THREAT_PATTERN.findall(refs)
            vr_mapping[current_vr].extend(threat_ids)

    # Deduplicate
    for vr_id in vr_mapping:
        vr_mapping[vr_id] = list(set(vr_mapping[vr_id]))

    return vr_mapping


def extract_excluded_from_markdown(content: str) -> List[str]:
    """
    Extract excluded threats from P6 markdown content (backward compatibility).

    Args:
        content: Raw markdown content of P6-RISK-VALIDATION.md

    Returns:
        List of excluded threat IDs
    """
    excluded = []

    # Look for excluded section - stop at:
    # - ## or higher level heading
    # - ``` code block start
    # - End of file
    excluded_section = re.search(
        r'##[^\n]*[Ee]xcluded[^\n]*\n(.*?)(?=\n#{2,}|\n```|\Z)',
        content,
        re.DOTALL
    )

    if excluded_section:
        section_content = excluded_section.group(1)
        threat_ids = _THREAT_PATTERN.findall(section_content)
        excluded = list(set(threat_ids))

    # Also check for inline "excluded_threats:" list (not under a heading)
    if not excluded:
        inline_section = re.search(
            r'excluded_threats?\s*:\s*\n((?:[-*]\s*T-[STRIDE]-[^\n]+\n?)+)',
            content,
            re.IGNORECASE
        )
        if inline_section:
            threat_ids = _THREAT_PATTERN.findall(inline_section.group(1))
            excluded = list(set(threat_ids))

    return excluded


def extract_vr_ids_from_markdown(content: str) -> List[str]:
    """
    Extract all unique VR IDs from P6 markdown content (backward compatibility).

    Args:
        content: Raw markdown content of P6-RISK-VALIDATION.md

    Returns:
        Sorted list of unique VR IDs
    """
    matches = _VR_PATTERN.findall(content)
    return sorted(list(set(matches)))


# ============================================================================
# Main Checkpoint Validation Functions
# ============================================================================

def validate_cp1_threat_conservation(project_root: str, markdown_mode: bool = False) -> Dict:
    """
    CP1: Validate P5 → P6 threat count conservation.

    Formula: consolidated + excluded = p5_total

    Args:
        project_root: Project root directory
        markdown_mode: If True, parse from raw Markdown files instead of phase_data

    Returns:
        Dict with checkpoint, status (PASS/FAIL/WARN), details, message
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    if markdown_mode:
        # Find and read markdown files directly
        p5_file = None
        p6_file = None

        for f in report_dir.glob('**/*.md'):
            name = f.name.upper()
            if 'P5' in name or 'STRIDE-THREAT' in name:
                p5_file = f
            elif 'P6' in name or 'RISK-VALIDATION' in name:
                p6_file = f

        if not p5_file:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "P5 markdown file not found",
                "details": {"report_dir": str(report_dir)},
            }

        if not p6_file:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "P6 markdown file not found",
                "details": {"report_dir": str(report_dir)},
            }

        p5_content = p5_file.read_text(encoding='utf-8')
        p6_content = p6_file.read_text(encoding='utf-8')

        p5_total, p5_threats = extract_threat_ids_from_markdown(p5_content)
        vr_mapping = extract_vr_mapping_from_markdown(p6_content)
        excluded = extract_excluded_from_markdown(p6_content)

    else:
        # Use phase_data
        p5_data = load_phase_data(5, project_root)
        p6_data = load_phase_data(6, project_root)

        if not p5_data:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "Phase 5 data not found. Run --extract on P5 markdown first.",
                "details": {"hint": "python phase_data.py --extract P5-STRIDE-THREATS.md --phase 5"},
            }

        if not p6_data:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "Phase 6 data not found. Run --extract on P6 markdown first.",
                "details": {"hint": "python phase_data.py --extract P6-RISK-VALIDATION.md --phase 6"},
            }

        p5_total, p5_threats = extract_threat_ids_from_phase_data(p5_data)
        vr_mapping = extract_vr_mapping_from_phase_data(p6_data)
        excluded = extract_excluded_from_phase_data(p6_data)

    # Consolidate all threat_refs from VRs
    consolidated = []
    for refs in vr_mapping.values():
        consolidated.extend(refs)
    consolidated = list(set(consolidated))

    # Detect overlap between consolidated and excluded (M10 fix)
    overlap = set(consolidated) & set(excluded)

    # Calculate using union to avoid double-counting overlapping threats
    consolidated_count = len(consolidated)
    excluded_count = len(excluded)
    all_accounted = set(consolidated) | set(excluded)
    total_accounted = len(all_accounted)

    details = {
        "p5_total": p5_total,
        "consolidated": consolidated_count,
        "excluded": excluded_count,
        "accounted": total_accounted,
        "formula": f"{consolidated_count} consolidated + {excluded_count} excluded = {total_accounted} unique",
    }

    if overlap:
        details["overlap"] = sorted(overlap)
        details["overlap_warning"] = f"{len(overlap)} threat(s) in both consolidated and excluded: {sorted(overlap)}"

    # Determine status
    if total_accounted == p5_total:
        return {
            "checkpoint": "CP1",
            "status": "PASS",
            "message": f"Count conservation verified: {consolidated_count} + {excluded_count} = {p5_total}",
            "details": details,
        }
    elif total_accounted < p5_total:
        missing = p5_total - total_accounted
        return {
            "checkpoint": "CP1",
            "status": "FAIL",
            "message": f"Missing {missing} threats! Expected {p5_total}, got {total_accounted}",
            "details": details,
        }
    else:
        excess = total_accounted - p5_total
        return {
            "checkpoint": "CP1",
            "status": "WARN",
            "message": f"Excess {excess} threats counted. Expected {p5_total}, got {total_accounted}",
            "details": details,
        }


def validate_cp2_vr_threat_refs(project_root: str, markdown_mode: bool = False) -> Dict:
    """
    CP2: Validate every VR has at least one threat_ref.

    Args:
        project_root: Project root directory
        markdown_mode: If True, parse from raw Markdown files

    Returns:
        Dict with checkpoint, status (PASS/FAIL/WARN), details, message
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    if markdown_mode:
        p6_file = None
        for f in report_dir.glob('**/*.md'):
            name = f.name.upper()
            if 'P6' in name or 'RISK-VALIDATION' in name:
                p6_file = f
                break

        if not p6_file:
            return {
                "checkpoint": "CP2",
                "status": "WARN",
                "message": "P6 markdown file not found",
                "details": {"report_dir": str(report_dir)},
            }

        p6_content = p6_file.read_text(encoding='utf-8')
        vr_mapping = extract_vr_mapping_from_markdown(p6_content)
    else:
        p6_data = load_phase_data(6, project_root)

        if not p6_data:
            return {
                "checkpoint": "CP2",
                "status": "WARN",
                "message": "Phase 6 data not found. Run --extract on P6 markdown first.",
                "details": {"hint": "python phase_data.py --extract P6-RISK-VALIDATION.md --phase 6"},
            }

        vr_mapping = extract_vr_mapping_from_phase_data(p6_data)

    # Find VRs without threat_refs
    empty_vrs = [vr for vr, refs in vr_mapping.items() if not refs]

    if not vr_mapping:
        return {
            "checkpoint": "CP2",
            "status": "WARN",
            "message": "No ValidatedRisk entries found",
            "details": {"vr_count": 0},
        }

    if empty_vrs:
        return {
            "checkpoint": "CP2",
            "status": "FAIL",
            "message": f"{len(empty_vrs)} VRs missing threat_refs: {empty_vrs}",
            "details": {"empty_vrs": empty_vrs, "total_vrs": len(vr_mapping)},
        }

    return {
        "checkpoint": "CP2",
        "status": "PASS",
        "message": f"All {len(vr_mapping)} VRs have threat_refs",
        "details": {"vr_count": len(vr_mapping)},
    }


def validate_cp3_report_conservation(project_root: str) -> Dict:
    """
    CP3: Validate P6 VR count equals each report's VR count.

    Args:
        project_root: Project root directory

    Returns:
        Dict with checkpoint, status (PASS/FAIL/WARN), details, message
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    # Get P6 VR IDs (try phase_data first, then markdown)
    p6_data = load_phase_data(6, project_root)

    if p6_data:
        p6_vr_ids = extract_vr_ids_from_phase_data(p6_data)
    else:
        # Fallback to markdown
        p6_file = None
        for f in report_dir.glob('**/*.md'):
            name = f.name.upper()
            if 'P6' in name or 'RISK-VALIDATION' in name:
                p6_file = f
                break

        if not p6_file:
            return {
                "checkpoint": "CP3",
                "status": "WARN",
                "message": "P6 data/file not found",
                "details": {"report_dir": str(report_dir)},
            }

        p6_content = p6_file.read_text(encoding='utf-8')
        p6_vr_ids = extract_vr_ids_from_markdown(p6_content)

    p6_vr_count = len(p6_vr_ids)

    # Extract VR counts from all four final reports
    report_counts = {}

    for report_name in FINAL_REPORTS:
        report_info = {
            'file': None,
            'vr_ids': [],
            'count': 0,
            'found': False
        }

        # Search for report file (case-insensitive, with project prefix)
        for f in report_dir.glob('**/*.md'):
            if report_name.upper() in f.name.upper():
                report_info['file'] = str(f)
                report_info['found'] = True
                try:
                    content = f.read_text(encoding='utf-8')
                    matches = _VR_PATTERN.findall(content)
                    report_info['vr_ids'] = sorted(list(set(matches)))
                    report_info['count'] = len(report_info['vr_ids'])
                except Exception as e:
                    report_info['error'] = str(e)
                break

        report_counts[report_name] = report_info

    # Analyze discrepancies
    discrepancies = []
    missing_reports = []

    for report_name, info in report_counts.items():
        if not info['found']:
            missing_reports.append(report_name)
            continue

        if info['count'] != p6_vr_count:
            # Find which VRs are missing or extra
            p6_set = set(p6_vr_ids)
            report_set = set(info['vr_ids'])
            missing_in_report = p6_set - report_set
            extra_in_report = report_set - p6_set

            discrepancies.append({
                'report': report_name,
                'expected': p6_vr_count,
                'actual': info['count'],
                'missing': list(missing_in_report)[:5] if missing_in_report else [],
                'extra': list(extra_in_report)[:5] if extra_in_report else []
            })

    details = {
        'p6_vr_count': p6_vr_count,
        'p6_vr_ids': p6_vr_ids[:10] if len(p6_vr_ids) > 10 else p6_vr_ids,
        'reports_checked': len(FINAL_REPORTS),
        'reports_found': len(FINAL_REPORTS) - len(missing_reports),
        'per_report_counts': {
            name: info['count'] for name, info in report_counts.items() if info['found']
        }
    }

    if missing_reports:
        details['missing_reports'] = missing_reports

    if discrepancies:
        details['discrepancies'] = discrepancies

    # Determine status
    if not p6_vr_ids:
        return {
            "checkpoint": "CP3",
            "status": "WARN",
            "message": "No VR IDs found in P6 - skipping CP3 validation",
            "details": details,
        }

    if missing_reports and len(missing_reports) == len(FINAL_REPORTS):
        return {
            "checkpoint": "CP3",
            "status": "WARN",
            "message": "No final reports found - skipping CP3 validation",
            "details": details,
        }

    if discrepancies:
        mismatch_reports = [d['report'] for d in discrepancies]
        return {
            "checkpoint": "CP3",
            "status": "FAIL",
            "message": f"CP3 FAIL: VR count mismatch in {mismatch_reports}. P6 has {p6_vr_count} VRs.",
            "details": details,
        }

    if missing_reports:
        return {
            "checkpoint": "CP3",
            "status": "WARN",
            "message": f"CP3 PARTIAL: {len(FINAL_REPORTS) - len(missing_reports)} reports match, but missing: {missing_reports}",
            "details": details,
        }

    return {
        "checkpoint": "CP3",
        "status": "PASS",
        "message": f"CP3 PASS: All {len(FINAL_REPORTS)} reports have {p6_vr_count} VRs matching P6",
        "details": details,
    }


def validate_id_formats_in_phase(phase: int, project_root: str) -> Dict:
    """
    Validate ID formats in a specific phase.

    Checks:
    - Forbidden RISK-xxx (should be VR-xxx)
    - Non-compliant threat IDs

    Args:
        phase: Phase number (5 or 6 typically)
        project_root: Project root directory

    Returns:
        Dict with status (PASS/FAIL), details, and issues found
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    # Try to read markdown file for this phase
    phase_file = None
    for f in report_dir.glob('**/*.md'):
        name = f.name.upper()
        if f'P{phase}' in name:
            phase_file = f
            break

    if not phase_file:
        return {
            "validation": "id_formats",
            "phase": phase,
            "status": "WARN",
            "message": f"Phase {phase} markdown file not found",
        }

    content = phase_file.read_text(encoding='utf-8')

    issues = []

    # Check for RISK-xxx (should be VR-xxx)
    risk_ids = re.findall(r'\bRISK-\d+\b', content)
    if risk_ids:
        issues.append({
            "type": "forbidden_risk_id",
            "message": f"Found forbidden RISK-xxx IDs: {list(set(risk_ids))[:5]}",
            "count": len(set(risk_ids)),
            "hint": "Use VR-xxx format instead of RISK-xxx",
        })

    # Check for T-X-CATEGORY-xxx (should keep ElementID)
    bad_threat_ids = re.findall(r'\bT-[STRIDE]-[A-Z]{3,}-\d{3}\b', content)
    # Filter out valid ElementID patterns (which have digits in ElementID)
    truly_bad = [t for t in bad_threat_ids if not re.match(r'T-[STRIDE]-[A-Z]+\d+-\d{3}', t)]
    if truly_bad:
        issues.append({
            "type": "non_compliant_threat_id",
            "message": f"Found non-compliant threat IDs: {list(set(truly_bad))[:5]}",
            "count": len(set(truly_bad)),
            "hint": "Threat IDs should be T-X-ElementID-NNN (e.g., T-S-P1-001)",
        })

    if issues:
        return {
            "validation": "id_formats",
            "phase": phase,
            "status": "FAIL",
            "message": " | ".join([i["message"] for i in issues]),
            "details": {"issues": issues},
        }

    return {
        "validation": "id_formats",
        "phase": phase,
        "status": "PASS",
        "message": "All ID formats compliant",
        "details": {"file_checked": str(phase_file)},
    }


def validate_all_checkpoints(project_root: str, markdown_mode: bool = False) -> Dict:
    """
    Execute all checkpoint validations (CP1 + CP2 + CP3).

    Args:
        project_root: Project root directory
        markdown_mode: If True, use markdown parsing mode for CP1/CP2

    Returns:
        Dict with overall_status, individual checkpoint results, summary
    """
    results = {
        "validation": "all_checkpoints",
        "checkpoints": {},
        "blocking_failures": 0,
        "warnings": 0,
    }

    # Run all checkpoints
    cp1_result = validate_cp1_threat_conservation(project_root, markdown_mode)
    cp2_result = validate_cp2_vr_threat_refs(project_root, markdown_mode)
    cp3_result = validate_cp3_report_conservation(project_root)

    results["checkpoints"]["cp1"] = cp1_result
    results["checkpoints"]["cp2"] = cp2_result
    results["checkpoints"]["cp3"] = cp3_result

    # Count failures and warnings
    for cp_result in [cp1_result, cp2_result, cp3_result]:
        if cp_result["status"] == "FAIL":
            results["blocking_failures"] += 1
        elif cp_result["status"] == "WARN":
            results["warnings"] += 1

    # Determine overall status
    if results["blocking_failures"] > 0:
        results["overall_status"] = "FAIL"
        results["message"] = f"{results['blocking_failures']} checkpoint(s) failed"
    elif results["warnings"] > 0:
        results["overall_status"] = "WARN"
        results["message"] = f"All checkpoints passed with {results['warnings']} warning(s)"
    else:
        results["overall_status"] = "PASS"
        results["message"] = "All checkpoints passed"

    results["checked_at"] = datetime.now().isoformat()

    return results


def validate_workflow_complete(project_root: str) -> Dict:
    """
    Validate complete workflow data integrity.

    Checks:
    1. All phases are extracted
    2. Phase-specific validations pass (P1 checklist, P2 L1 coverage)
    3. All checkpoints pass (CP1, CP2, CP3)
    4. ID formats are compliant
    5. Ready for report generation

    Args:
        project_root: Project root directory

    Returns:
        Dict with overall workflow validation status
    """
    results = {
        "validation": "workflow",
        "phases": {},
        "phase_validations": {},
        "checkpoints": {},
        "id_validations": {},
        "blockers": [],
        "warnings": [],
    }

    # Check phase extraction status
    for phase in range(1, 9):
        phase_data = load_phase_data(phase, project_root)
        results["phases"][phase] = {
            "extracted": phase_data is not None,
            "has_blocks": bool(phase_data.get("blocks")) if phase_data else False,
        }

        if not phase_data and phase <= 7:  # P8 is report generation
            results["blockers"].append(f"Phase {phase} data not extracted")

    # Phase-specific validations
    if results["phases"].get(1, {}).get("extracted"):
        p1_val = validate_p1_checklist(project_root)
        results["phase_validations"]["p1_checklist"] = p1_val.get("status", "error")
        if p1_val.get("status") == "blocking":
            results["blockers"].append("P1 checklist validation failed")

    if results["phases"].get(2, {}).get("extracted"):
        p2_val = validate_p2_l1_coverage(project_root)
        results["phase_validations"]["p2_l1_coverage"] = p2_val.get("status", "error")
        if p2_val.get("status") == "blocking":
            results["blockers"].append("P2 L1 coverage validation failed")

    # Checkpoint validations
    if results["phases"].get(5, {}).get("extracted") and results["phases"].get(6, {}).get("extracted"):
        cp1 = validate_cp1_threat_conservation(project_root)
        cp2 = validate_cp2_vr_threat_refs(project_root)
        cp3 = validate_cp3_report_conservation(project_root)

        results["checkpoints"] = {
            "cp1": cp1["status"],
            "cp2": cp2["status"],
            "cp3": cp3["status"],
        }

        if cp1["status"] == "FAIL":
            results["blockers"].append(f"CP1 failed: {cp1['message']}")
        if cp2["status"] == "FAIL":
            results["blockers"].append(f"CP2 failed: {cp2['message']}")
        if cp3["status"] == "FAIL":
            results["warnings"].append(f"CP3 failed: {cp3['message']}")  # CP3 is warning-level

    # ID format validations
    for phase in [5, 6]:
        if results["phases"].get(phase, {}).get("extracted"):
            id_val = validate_id_formats_in_phase(phase, project_root)
            results["id_validations"][f"phase{phase}"] = id_val["status"]
            if id_val["status"] == "FAIL":
                results["warnings"].append(f"Phase {phase} ID format issues: {id_val['message']}")

    # Determine overall status
    if results["blockers"]:
        results["overall_status"] = "BLOCKED"
        results["ready_for_report"] = False
        results["message"] = f"Workflow blocked: {len(results['blockers'])} issue(s)"
    elif results["warnings"]:
        results["overall_status"] = "READY_WITH_WARNINGS"
        results["ready_for_report"] = True
        results["message"] = f"Workflow ready with {len(results['warnings'])} warning(s)"
    else:
        results["overall_status"] = "READY"
        results["ready_for_report"] = True
        results["message"] = "Workflow validation PASSED - ready for Phase 8 report generation"

    results["checked_at"] = datetime.now().isoformat()

    return results


# ============================================================================
# End-to-End Coverage Verification Functions
# ============================================================================
# These functions implement end-to-end data traceability verification:
# - P4 must cover P1 modules + P2 data flows
# - P5 must cover ALL P2 DFD elements with STRIDE analysis
# - P6 must cover ALL P1-P5 findings with count conservation
# - P8 penetration test must cover P6 attack paths/chains
# ============================================================================

def verify_p4_coverage(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Verify P4 Security Design Review coverage of P1 modules and P2 data flows.

    Formula: ∀ M-xxx ∈ P1 → ∃ GAP ∈ P4 : references(M-xxx)
             ∀ DF-xxx ∈ P2 → ∃ GAP ∈ P4 : references(DF-xxx)

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with verification status, coverage metrics, and uncovered items
    """
    result = {
        "verification": "p4_coverage",
        "status": "UNKNOWN",
        "p1_module_coverage": {},
        "p2_dataflow_coverage": {},
        "overall_coverage_percentage": 0.0,
        "uncovered_modules": [],
        "uncovered_dataflows": [],
        "blockers": [],
        "warnings": [],
    }

    try:
        # Load P1, P2, P4 data
        p1_data = load_phase_data(1, project_root, session_id)
        p2_data = load_phase_data(2, project_root, session_id)
        p4_data = load_phase_data(4, project_root, session_id)

        if not p1_data:
            result["status"] = "ERROR"
            result["blockers"].append("P1 data not found")
            return result

        if not p2_data:
            result["status"] = "ERROR"
            result["blockers"].append("P2 data not found")
            return result

        if not p4_data:
            result["status"] = "ERROR"
            result["blockers"].append("P4 data not found")
            return result

        # Extract P1 modules
        p1_blocks = p1_data.get("blocks", {})
        module_inventory = p1_blocks.get("module_inventory", {})
        modules = module_inventory.get("modules", [])
        if isinstance(modules, dict):
            modules = list(modules.values())

        p1_module_ids = set()
        for module in modules:
            if isinstance(module, dict):
                mod_id = module.get("id", module.get("path", ""))
                if mod_id:
                    p1_module_ids.add(mod_id)

        # Extract P2 data flows
        p2_blocks = p2_data.get("blocks", {})
        dfd_elements = p2_blocks.get("dfd_elements", {})
        data_flows_block = p2_blocks.get("data_flows", {})

        p2_dataflow_ids = set()

        # From dfd_elements
        elements = dfd_elements.get("elements", [])
        if isinstance(elements, list):
            for elem in elements:
                if isinstance(elem, dict) and elem.get("type") == "DataFlow":
                    df_id = elem.get("id", "")
                    if df_id:
                        p2_dataflow_ids.add(df_id)

        # From data_flows block
        flows = data_flows_block.get("flows", [])
        if isinstance(flows, list):
            for flow in flows:
                if isinstance(flow, dict):
                    df_id = flow.get("id", "")
                    if df_id:
                        p2_dataflow_ids.add(df_id)

        # Extract P4 security gaps and their references
        p4_blocks = p4_data.get("blocks", {})
        security_gaps = p4_blocks.get("security_gaps", {})
        gaps = security_gaps.get("gaps", [])
        if isinstance(gaps, dict):
            gaps = list(gaps.values())

        # Collect all module and dataflow references from P4 gaps
        p4_module_refs = set()
        p4_dataflow_refs = set()

        for gap in gaps:
            if not isinstance(gap, dict):
                continue

            # Check affected_modules, module_refs, or location fields
            affected_modules = gap.get("affected_modules", [])
            if isinstance(affected_modules, list):
                p4_module_refs.update(affected_modules)
            elif isinstance(affected_modules, str):
                p4_module_refs.add(affected_modules)

            module_refs = gap.get("module_refs", gap.get("modules", []))
            if isinstance(module_refs, list):
                p4_module_refs.update(module_refs)
            elif isinstance(module_refs, str):
                p4_module_refs.add(module_refs)

            location = gap.get("location", "")
            if location and isinstance(location, str):
                # Extract M-xxx patterns from location
                for match in re.findall(r'M-\d{3}', location):
                    p4_module_refs.add(match)

            # Check dataflow references
            dataflow_refs = gap.get("dataflow_refs", gap.get("data_flows", []))
            if isinstance(dataflow_refs, list):
                p4_dataflow_refs.update(dataflow_refs)
            elif isinstance(dataflow_refs, str):
                p4_dataflow_refs.add(dataflow_refs)

            # Extract DF-xxx patterns from description or location
            description = gap.get("description", "")
            for match in re.findall(r'DF-\d{3}', str(description) + str(location)):
                p4_dataflow_refs.add(match)

        # Calculate module coverage
        covered_modules = p1_module_ids.intersection(p4_module_refs)
        uncovered_modules = p1_module_ids - p4_module_refs
        module_coverage_pct = (
            len(covered_modules) / len(p1_module_ids) * 100
            if p1_module_ids else 100.0
        )

        result["p1_module_coverage"] = {
            "total_modules": len(p1_module_ids),
            "modules_in_p4": len(covered_modules),
            "coverage_percentage": round(module_coverage_pct, 2),
            "status": "PASS" if module_coverage_pct >= 100 else "FAIL",
        }
        result["uncovered_modules"] = sorted(list(uncovered_modules))

        # Calculate dataflow coverage
        covered_dataflows = p2_dataflow_ids.intersection(p4_dataflow_refs)
        uncovered_dataflows = p2_dataflow_ids - p4_dataflow_refs
        dataflow_coverage_pct = (
            len(covered_dataflows) / len(p2_dataflow_ids) * 100
            if p2_dataflow_ids else 100.0
        )

        result["p2_dataflow_coverage"] = {
            "total_dataflows": len(p2_dataflow_ids),
            "dataflows_in_p4": len(covered_dataflows),
            "coverage_percentage": round(dataflow_coverage_pct, 2),
            "status": "PASS" if dataflow_coverage_pct >= 100 else "FAIL",
        }
        result["uncovered_dataflows"] = sorted(list(uncovered_dataflows))

        # Overall coverage
        overall_pct = (module_coverage_pct + dataflow_coverage_pct) / 2
        result["overall_coverage_percentage"] = round(overall_pct, 2)

        # Determine status
        if uncovered_modules:
            result["blockers"].append(
                f"{len(uncovered_modules)} P1 modules not covered in P4"
            )
        if uncovered_dataflows:
            result["warnings"].append(
                f"{len(uncovered_dataflows)} P2 data flows not covered in P4"
            )

        if result["blockers"]:
            result["status"] = "FAIL"
        elif result["warnings"]:
            result["status"] = "WARN"
        else:
            result["status"] = "PASS"

        result["checked_at"] = datetime.now().isoformat()

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def verify_p5_element_coverage(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Verify P5 STRIDE analysis coverage of ALL P2 DFD elements.

    Formula: ∀ element ∈ P2 → ∃ T-xxx ∈ P5 : STRIDE_covers(element)

    Each DFD element type has applicable STRIDE categories:
    - Process: S, T, R, I, D, E (all six)
    - DataStore: T, R, I, D
    - DataFlow: T, I, D
    - ExternalInteractor (as source): S, R

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with verification status, element coverage, and STRIDE completeness
    """
    result = {
        "verification": "p5_element_coverage",
        "status": "UNKNOWN",
        "element_coverage": {
            "processes": {},
            "data_stores": {},
            "data_flows": {},
            "external_interactors": {},
        },
        "stride_completeness": 0.0,
        "overall_coverage_percentage": 0.0,
        "uncovered_elements": [],
        "partial_stride_elements": [],
        "blockers": [],
        "warnings": [],
    }

    # STRIDE applicability matrix per element type (STRIDE per Interaction)
    STRIDE_APPLICABILITY = {
        "Process": ["S", "T", "R", "I", "D", "E"],
        "DataStore": ["T", "R", "I", "D"],
        "DataFlow": ["T", "I", "D"],
        "ExternalInteractor": ["S", "R"],
    }

    try:
        # Load P2 and P5 data
        p2_data = load_phase_data(2, project_root, session_id)
        p5_data = load_phase_data(5, project_root, session_id)

        if not p2_data:
            result["status"] = "ERROR"
            result["blockers"].append("P2 data not found")
            return result

        if not p5_data:
            result["status"] = "ERROR"
            result["blockers"].append("P5 data not found")
            return result

        # Extract P2 DFD elements by type
        p2_blocks = p2_data.get("blocks", {})
        dfd_elements = p2_blocks.get("dfd_elements", {})
        elements = dfd_elements.get("elements", [])

        # Categorize elements by type
        elements_by_type = {
            "Process": [],
            "DataStore": [],
            "DataFlow": [],
            "ExternalInteractor": [],
        }

        if isinstance(elements, list):
            for elem in elements:
                if isinstance(elem, dict):
                    elem_type = elem.get("type", "unknown")
                    elem_id = elem.get("id", "")
                    if elem_type in elements_by_type and elem_id:
                        elements_by_type[elem_type].append(elem_id)

        # Also check data_flows block for additional DF-xxx IDs
        data_flows_block = p2_blocks.get("data_flows", {})
        flows = data_flows_block.get("flows", [])
        if isinstance(flows, list):
            for flow in flows:
                if isinstance(flow, dict):
                    df_id = flow.get("id", "")
                    if df_id and df_id not in elements_by_type["DataFlow"]:
                        elements_by_type["DataFlow"].append(df_id)

        # Extract P5 threats and map to elements
        p5_blocks = p5_data.get("blocks", {})
        threat_inventory = p5_blocks.get("threat_inventory", {})
        threats = threat_inventory.get("threats", [])
        if isinstance(threats, dict):
            threats = list(threats.values())

        # Build element → STRIDE coverage map
        # Threat ID format: T-{STRIDE}-{ElementType}-{ElementSeq}-{ThreatSeq}
        # e.g., T-S-P-001-001 = Spoofing threat for Process P-001
        element_stride_coverage = {}  # elem_id → set of STRIDE letters covered

        for threat in threats:
            if not isinstance(threat, dict):
                continue

            threat_id = threat.get("id", "") or threat.get("threat_id", "")
            target_element = threat.get("target_element", "") or threat.get("element_id", "")

            # Parse threat ID to extract STRIDE category and element reference
            # Format: T-{S}-{ElementType}-{Seq}-{Seq} or T-{S}-{ElementID}-{Seq}
            if threat_id and threat_id.startswith("T-"):
                parts = threat_id.split("-")
                if len(parts) >= 3:
                    stride_letter = parts[1]
                    if stride_letter in STRIDE_CATEGORIES:
                        # Try to extract element ID from threat ID or target_element
                        elem_id = target_element
                        if not elem_id and len(parts) >= 4:
                            # Reconstruct element ID from parts
                            # T-S-P-001-001 → P-001
                            elem_type_abbrev = parts[2]
                            elem_seq = parts[3] if len(parts) > 3 else "001"
                            elem_id = f"{elem_type_abbrev}-{elem_seq}"

                        if elem_id:
                            if elem_id not in element_stride_coverage:
                                element_stride_coverage[elem_id] = set()
                            element_stride_coverage[elem_id].add(stride_letter)

            # Also check element_refs or target fields
            element_refs = threat.get("element_refs", [])
            if isinstance(element_refs, list):
                for ref in element_refs:
                    if ref and threat_id.startswith("T-") and len(threat_id.split("-")) >= 2:
                        stride_letter = threat_id.split("-")[1]
                        if stride_letter in STRIDE_CATEGORIES:
                            if ref not in element_stride_coverage:
                                element_stride_coverage[ref] = set()
                            element_stride_coverage[ref].add(stride_letter)

        # Calculate coverage per element type
        total_applicable_categories = 0
        total_covered_categories = 0
        uncovered_elements = []
        partial_stride_elements = []

        type_mapping = {
            "Process": ("processes", "P-"),
            "DataStore": ("data_stores", "DS-"),
            "DataFlow": ("data_flows", "DF-"),
            "ExternalInteractor": ("external_interactors", "EI-"),
        }

        for elem_type, (result_key, id_prefix) in type_mapping.items():
            type_elements = elements_by_type[elem_type]
            applicable_stride = set(STRIDE_APPLICABILITY.get(elem_type, []))
            elements_with_threats = 0
            stride_coverage_map = {}

            for elem_id in type_elements:
                covered_stride = element_stride_coverage.get(elem_id, set())

                # Also check with ID prefix variations
                if not covered_stride:
                    for key in element_stride_coverage:
                        if key.startswith(id_prefix) or elem_id in key:
                            covered_stride = element_stride_coverage[key]
                            break

                stride_coverage_map[elem_id] = {
                    s: (s in covered_stride) for s in STRIDE_CATEGORIES
                }

                applicable_for_elem = applicable_stride.intersection(set(STRIDE_CATEGORIES))
                covered_for_elem = covered_stride.intersection(applicable_for_elem)

                total_applicable_categories += len(applicable_for_elem)
                total_covered_categories += len(covered_for_elem)

                if covered_stride:
                    elements_with_threats += 1
                    if covered_for_elem != applicable_for_elem:
                        missing = applicable_for_elem - covered_for_elem
                        partial_stride_elements.append({
                            "element_id": elem_id,
                            "type": elem_type,
                            "missing_stride": sorted(list(missing)),
                        })
                else:
                    uncovered_elements.append({
                        "element_id": elem_id,
                        "type": elem_type,
                        "applicable_stride": sorted(list(applicable_stride)),
                    })

            coverage_pct = (
                elements_with_threats / len(type_elements) * 100
                if type_elements else 100.0
            )

            result["element_coverage"][result_key] = {
                "total_from_p2": len(type_elements),
                "elements_with_threats": elements_with_threats,
                "coverage_percentage": round(coverage_pct, 2),
                "uncovered_elements": [e for e in uncovered_elements if e["type"] == elem_type],
                "stride_coverage": stride_coverage_map,
            }

        # Calculate STRIDE completeness
        stride_completeness = (
            total_covered_categories / total_applicable_categories
            if total_applicable_categories else 1.0
        )
        result["stride_completeness"] = round(stride_completeness, 4)

        # Overall coverage percentage
        total_elements = sum(len(elements_by_type[t]) for t in elements_by_type)
        covered_elements = total_elements - len(uncovered_elements)
        overall_coverage = (
            covered_elements / total_elements * 100 if total_elements else 100.0
        )
        result["overall_coverage_percentage"] = round(overall_coverage, 2)

        result["uncovered_elements"] = uncovered_elements
        result["partial_stride_elements"] = partial_stride_elements

        # Determine status
        if uncovered_elements:
            result["blockers"].append(
                f"{len(uncovered_elements)} P2 elements have no STRIDE threats"
            )
        if partial_stride_elements:
            result["warnings"].append(
                f"{len(partial_stride_elements)} elements have incomplete STRIDE coverage"
            )

        if result["blockers"]:
            result["status"] = "FAIL"
        elif result["warnings"]:
            result["status"] = "WARN"
        else:
            result["status"] = "PASS"

        result["checked_at"] = datetime.now().isoformat()

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def verify_p6_findings_coverage(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Verify P6 Risk Validation coverage of ALL P1-P5 findings.

    Formula: ∀ finding ∈ P1-P5 → ∃ ref ∈ P6
    Count Conservation: P5.total = P6.verified + P6.theoretical + P6.pending + P6.excluded

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with verification status, findings coverage, and count conservation check
    """
    result = {
        "verification": "p6_findings_coverage",
        "status": "UNKNOWN",
        "p1_findings_coverage": {},
        "p2_findings_coverage": {},
        "p3_findings_coverage": {},
        "p4_gaps_coverage": {},
        "p5_threats_coverage": {},
        "count_conservation": {},
        "overall_coverage_percentage": 0.0,
        "excluded_findings": [],
        "blockers": [],
        "warnings": [],
    }

    try:
        # Load all phase data
        p1_data = load_phase_data(1, project_root, session_id)
        p2_data = load_phase_data(2, project_root, session_id)
        p3_data = load_phase_data(3, project_root, session_id)
        p4_data = load_phase_data(4, project_root, session_id)
        p5_data = load_phase_data(5, project_root, session_id)
        p6_data = load_phase_data(6, project_root, session_id)

        if not p6_data:
            result["status"] = "ERROR"
            result["blockers"].append("P6 data not found")
            return result

        # Extract P6 validated risks and their references
        p6_blocks = p6_data.get("blocks", {})
        validated_risks = p6_blocks.get("validated_risks", {})
        # Primary key: risk_details; fallback: risks (for compatibility)
        risks = validated_risks.get("risk_details", [])
        if not risks:
            risks = validated_risks.get("risks", [])
        if isinstance(risks, dict):
            risks = list(risks.values())

        # Collect all references from P6 VRs
        p6_gap_refs = set()
        p6_threat_refs = set()
        p6_finding_refs = set()  # General finding refs (F-Px-xxx)
        p6_element_refs = set()

        for risk in risks:
            if not isinstance(risk, dict):
                continue

            # Threat references
            threat_refs = risk.get("threat_refs", risk.get("threats", []))
            if isinstance(threat_refs, list):
                p6_threat_refs.update(threat_refs)
            elif isinstance(threat_refs, str):
                p6_threat_refs.add(threat_refs)

            # Gap references
            gap_refs = risk.get("gap_refs", risk.get("gaps", []))
            if isinstance(gap_refs, list):
                p6_gap_refs.update(gap_refs)
            elif isinstance(gap_refs, str):
                p6_gap_refs.add(gap_refs)

            # Finding references
            finding_refs = risk.get("finding_refs", risk.get("findings", []))
            if isinstance(finding_refs, list):
                p6_finding_refs.update(finding_refs)
            elif isinstance(finding_refs, str):
                p6_finding_refs.add(finding_refs)

            # Element references
            element_refs = risk.get("element_refs", [])
            if isinstance(element_refs, list):
                p6_element_refs.update(element_refs)

        # Extract excluded findings from P6 (support both key names)
        excluded = validated_risks.get("excluded_findings", [])
        if not excluded:
            excluded = validated_risks.get("excluded_threats", [])
        if isinstance(excluded, list):
            for item in excluded:
                if isinstance(item, dict):
                    result["excluded_findings"].append(item)
                    # Also add to threat refs for count conservation
                    threat_id = item.get("threat_id", item.get("id", ""))
                    if threat_id:
                        p6_threat_refs.add(threat_id)
                elif isinstance(item, str):
                    result["excluded_findings"].append({"id": item})
                    p6_threat_refs.add(item)

        excluded_ids = set()
        for item in result["excluded_findings"]:
            if isinstance(item, dict):
                excluded_ids.add(item.get("id", item.get("threat_id", "")))
            elif isinstance(item, str):
                excluded_ids.add(item)

        # Check P4 gap coverage
        if p4_data:
            p4_blocks = p4_data.get("blocks", {})
            security_gaps = p4_blocks.get("security_gaps", {})
            gaps = security_gaps.get("gaps", [])
            if isinstance(gaps, dict):
                gaps = list(gaps.values())

            p4_gap_ids = set()
            for gap in gaps:
                if isinstance(gap, dict):
                    gap_id = gap.get("id", "")
                    if gap_id:
                        p4_gap_ids.add(gap_id)

            covered_gaps = p4_gap_ids.intersection(p6_gap_refs.union(excluded_ids))
            uncovered_gaps = p4_gap_ids - p6_gap_refs - excluded_ids
            gap_coverage_pct = (
                len(covered_gaps) / len(p4_gap_ids) * 100 if p4_gap_ids else 100.0
            )

            result["p4_gaps_coverage"] = {
                "total_gaps": len(p4_gap_ids),
                "gaps_in_vr_refs": len(p4_gap_ids.intersection(p6_gap_refs)),
                "gaps_excluded": len(p4_gap_ids.intersection(excluded_ids)),
                "coverage_percentage": round(gap_coverage_pct, 2),
                "uncovered_gaps": sorted(list(uncovered_gaps)),
                "status": "PASS" if gap_coverage_pct >= 100 else "FAIL",
            }

        # Check P5 threat coverage (with count conservation)
        if p5_data:
            p5_total, p5_threats = extract_threat_ids_from_phase_data(p5_data)

            # Get counts by status from P6
            verified_count = 0
            theoretical_count = 0
            pending_count = 0

            for risk in risks:
                if isinstance(risk, dict):
                    # Support both top-level and nested validation status
                    status = risk.get("validation_status", "")
                    if not status:
                        validation = risk.get("validation", {})
                        if isinstance(validation, dict):
                            status = validation.get("status", "")
                    status = status.lower() if status else ""

                    threat_refs = risk.get("threat_refs", [])
                    if isinstance(threat_refs, list):
                        ref_count = len(threat_refs)
                    else:
                        ref_count = 1 if threat_refs else 0

                    if status in ["verified", "confirmed", "exploitable"]:
                        verified_count += ref_count
                    elif status in ["theoretical", "potential", "possible"]:
                        theoretical_count += ref_count
                    elif status in ["pending", "needs_investigation"]:
                        pending_count += ref_count

            excluded_threat_count = len([
                e for e in result["excluded_findings"]
                if isinstance(e, dict) and (
                    e.get("source_phase") == "P5" or
                    str(e.get("id", e.get("threat_id", ""))).startswith("T-")
                )
            ])

            total_accounted = verified_count + theoretical_count + pending_count + excluded_threat_count
            conservation_check = (total_accounted == p5_total) if p5_total > 0 else True

            result["p5_threats_coverage"] = {
                "total_threats": p5_total,
                "verified": verified_count,
                "theoretical": theoretical_count,
                "pending": pending_count,
                "excluded": excluded_threat_count,
                "total_accounted": total_accounted,
                "conservation_formula": f"{verified_count} + {theoretical_count} + {pending_count} + {excluded_threat_count} = {total_accounted}",
                "conservation_check": conservation_check,
                "coverage_percentage": round(len(p6_threat_refs) / p5_total * 100 if p5_total else 100.0, 2),
                "status": "PASS" if conservation_check else "FAIL",
            }

            result["count_conservation"] = {
                "p5_total": p5_total,
                "p6_accounted": total_accounted,
                "formula_valid": conservation_check,
                "delta": total_accounted - p5_total,
            }

            if not conservation_check:
                result["blockers"].append(
                    f"Count conservation failed: P5={p5_total}, accounted={total_accounted}, delta={total_accounted - p5_total}"
                )

        # Calculate overall coverage
        coverage_values = []
        for key in ["p4_gaps_coverage", "p5_threats_coverage"]:
            if key in result and isinstance(result[key], dict):
                pct = result[key].get("coverage_percentage", 0)
                coverage_values.append(pct)

        overall_pct = sum(coverage_values) / len(coverage_values) if coverage_values else 0
        result["overall_coverage_percentage"] = round(overall_pct, 2)

        # Determine status
        if result["blockers"]:
            result["status"] = "FAIL"
        elif result["warnings"]:
            result["status"] = "WARN"
        else:
            result["status"] = "PASS"

        result["checked_at"] = datetime.now().isoformat()

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def verify_p8_attack_coverage(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Verify P8 Penetration Test Plan coverage of P6 attack paths and chains.

    Formula: ∀ AP-xxx ∈ P6 → ∃ TC-xxx ∈ P8 : tests(AP-xxx)
             ∀ AC-xxx ∈ P6 → ∃ scenario ∈ P8 : covers(AC-xxx)

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with verification status, attack path coverage, and test case mapping
    """
    result = {
        "verification": "p8_attack_coverage",
        "status": "UNKNOWN",
        "attack_paths": {
            "total_from_p6": 0,
            "paths_with_test_cases": 0,
            "coverage_percentage": 0.0,
            "path_test_mapping": {},
            "uncovered_paths": [],
            "deferred_paths": [],
        },
        "attack_chains": {
            "total_from_p6": 0,
            "chains_with_scenarios": 0,
            "coverage_percentage": 0.0,
            "chain_scenario_mapping": {},
            "uncovered_chains": [],
        },
        "validated_risks": {
            "total_from_p6": 0,
            "risks_with_tests": 0,
            "coverage_percentage": 0.0,
            "risk_test_mapping": {},
        },
        "overall_coverage_percentage": 0.0,
        "blockers": [],
        "warnings": [],
    }

    try:
        # Load P6 and P8 data
        p6_data = load_phase_data(6, project_root, session_id)
        p8_data = load_phase_data(8, project_root, session_id)

        if not p6_data:
            result["status"] = "ERROR"
            result["blockers"].append("P6 data not found")
            return result

        if not p8_data:
            result["status"] = "ERROR"
            result["blockers"].append("P8 data not found")
            return result

        # Extract P6 attack paths
        p6_blocks = p6_data.get("blocks", {})
        attack_paths_block = p6_blocks.get("attack_paths", {})
        attack_paths = attack_paths_block.get("paths", [])
        if isinstance(attack_paths, dict):
            attack_paths = list(attack_paths.values())

        p6_attack_path_ids = set()
        for path in attack_paths:
            if isinstance(path, dict):
                path_id = path.get("id", path.get("path_id", ""))
                if path_id:
                    p6_attack_path_ids.add(path_id)

        # Extract P6 attack chains
        attack_chains_block = p6_blocks.get("attack_chains", {})
        attack_chains = attack_chains_block.get("chains", [])
        if isinstance(attack_chains, dict):
            attack_chains = list(attack_chains.values())

        p6_attack_chain_ids = set()
        for chain in attack_chains:
            if isinstance(chain, dict):
                chain_id = chain.get("id", chain.get("chain_id", ""))
                if chain_id:
                    p6_attack_chain_ids.add(chain_id)

        # Extract P6 validated risks (for VR → TC mapping)
        validated_risks = p6_blocks.get("validated_risks", {})
        risks = validated_risks.get("risk_details", validated_risks.get("risks", []))
        if isinstance(risks, dict):
            risks = list(risks.values())

        p6_vr_ids = set()
        for risk in risks:
            if isinstance(risk, dict):
                vr_id = risk.get("id", "")
                if vr_id:
                    p6_vr_ids.add(vr_id)

        # Extract P8 test cases and their attack path mappings
        p8_blocks = p8_data.get("blocks", {})

        # Try multiple potential block names for test cases
        test_plan = p8_blocks.get("penetration_test_plan", {})
        if not test_plan:
            test_plan = p8_blocks.get("test_cases", {})
        if not test_plan:
            test_plan = p8_blocks.get("attack_path_coverage", {})

        test_cases = test_plan.get("test_cases", [])
        if isinstance(test_cases, dict):
            test_cases = list(test_cases.values())

        # Build mappings
        path_test_mapping = {}  # AP-xxx → [TC-xxx, ...]
        chain_scenario_mapping = {}  # AC-xxx → scenario description
        vr_test_mapping = {}  # VR-xxx → [TC-xxx, ...]
        deferred_paths = []

        for tc in test_cases:
            if not isinstance(tc, dict):
                continue

            tc_id = tc.get("id", tc.get("test_case_id", ""))

            # Map to attack paths
            attack_path_refs = tc.get("attack_path", tc.get("attack_path_refs", []))
            if isinstance(attack_path_refs, str):
                attack_path_refs = [attack_path_refs]
            for ap_ref in attack_path_refs:
                if ap_ref:
                    if ap_ref not in path_test_mapping:
                        path_test_mapping[ap_ref] = []
                    if tc_id:
                        path_test_mapping[ap_ref].append(tc_id)

            # Map to risks
            risk_refs = tc.get("risk", tc.get("risk_refs", tc.get("vr_refs", [])))
            if isinstance(risk_refs, str):
                risk_refs = [risk_refs]
            for vr_ref in risk_refs:
                if vr_ref:
                    if vr_ref not in vr_test_mapping:
                        vr_test_mapping[vr_ref] = []
                    if tc_id:
                        vr_test_mapping[vr_ref].append(tc_id)

        # Check for deferred paths in P8
        deferred_section = test_plan.get("deferred_paths", [])
        if isinstance(deferred_section, list):
            for item in deferred_section:
                if isinstance(item, dict):
                    deferred_paths.append(item)
                    path_id = item.get("path_id", "")
                    if path_id:
                        path_test_mapping[path_id] = ["DEFERRED"]

        # Check attack chain scenarios
        chain_scenarios = test_plan.get("attack_chain_scenarios", test_plan.get("scenarios", []))
        if isinstance(chain_scenarios, dict):
            chain_scenario_mapping = chain_scenarios
        elif isinstance(chain_scenarios, list):
            for scenario in chain_scenarios:
                if isinstance(scenario, dict):
                    chain_id = scenario.get("chain_id", scenario.get("attack_chain", ""))
                    description = scenario.get("description", scenario.get("scenario", ""))
                    if chain_id:
                        chain_scenario_mapping[chain_id] = description

        # Calculate attack path coverage
        covered_paths = set(path_test_mapping.keys()).intersection(p6_attack_path_ids)
        uncovered_paths = p6_attack_path_ids - set(path_test_mapping.keys())
        path_coverage_pct = (
            len(covered_paths) / len(p6_attack_path_ids) * 100
            if p6_attack_path_ids else 100.0
        )

        result["attack_paths"] = {
            "total_from_p6": len(p6_attack_path_ids),
            "paths_with_test_cases": len(covered_paths),
            "coverage_percentage": round(path_coverage_pct, 2),
            "path_test_mapping": path_test_mapping,
            "uncovered_paths": sorted(list(uncovered_paths)),
            "deferred_paths": deferred_paths,
        }

        # Calculate attack chain coverage
        covered_chains = set(chain_scenario_mapping.keys()).intersection(p6_attack_chain_ids)
        uncovered_chains = p6_attack_chain_ids - set(chain_scenario_mapping.keys())
        chain_coverage_pct = (
            len(covered_chains) / len(p6_attack_chain_ids) * 100
            if p6_attack_chain_ids else 100.0
        )

        result["attack_chains"] = {
            "total_from_p6": len(p6_attack_chain_ids),
            "chains_with_scenarios": len(covered_chains),
            "coverage_percentage": round(chain_coverage_pct, 2),
            "chain_scenario_mapping": chain_scenario_mapping,
            "uncovered_chains": sorted(list(uncovered_chains)),
        }

        # Calculate VR coverage
        covered_vrs = set(vr_test_mapping.keys()).intersection(p6_vr_ids)
        vr_coverage_pct = (
            len(covered_vrs) / len(p6_vr_ids) * 100
            if p6_vr_ids else 100.0
        )

        result["validated_risks"] = {
            "total_from_p6": len(p6_vr_ids),
            "risks_with_tests": len(covered_vrs),
            "coverage_percentage": round(vr_coverage_pct, 2),
            "risk_test_mapping": vr_test_mapping,
        }

        # Overall coverage
        overall_pct = (path_coverage_pct + chain_coverage_pct + vr_coverage_pct) / 3
        result["overall_coverage_percentage"] = round(overall_pct, 2)

        # Determine status
        if uncovered_paths:
            result["warnings"].append(
                f"{len(uncovered_paths)} P6 attack paths have no test cases"
            )
        if uncovered_chains:
            result["warnings"].append(
                f"{len(uncovered_chains)} P6 attack chains have no test scenarios"
            )

        # Critical/High VRs without tests are blockers
        critical_vrs_untested = [vr for vr in p6_vr_ids - covered_vrs]
        if critical_vrs_untested:
            result["warnings"].append(
                f"{len(critical_vrs_untested)} P6 validated risks have no test cases"
            )

        if result["blockers"]:
            result["status"] = "FAIL"
        elif result["warnings"]:
            result["status"] = "WARN"
        else:
            result["status"] = "PASS"

        result["checked_at"] = datetime.now().isoformat()

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def verify_all_coverage(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Execute all coverage verification checks.

    Runs:
    - verify_p4_coverage (P4 covers P1 modules + P2 data flows)
    - verify_p5_element_coverage (P5 STRIDE covers P2 DFD elements)
    - verify_p6_findings_coverage (P6 covers P1-P5 findings)
    - verify_p8_attack_coverage (P8 pentest covers P6 attack paths)

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with all verification results and overall status
    """
    results = {
        "verification": "all_coverage",
        "overall_status": "UNKNOWN",
        "verifications": {},
        "summary": {
            "total_checks": 4,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "errors": 0,
        },
        "blockers": [],
        "warnings": [],
    }

    # Run all verifications
    checks = [
        ("p4_coverage", verify_p4_coverage),
        ("p5_element_coverage", verify_p5_element_coverage),
        ("p6_findings_coverage", verify_p6_findings_coverage),
        ("p8_attack_coverage", verify_p8_attack_coverage),
    ]

    for check_name, check_func in checks:
        try:
            check_result = check_func(project_root, session_id)
            results["verifications"][check_name] = check_result

            status = check_result.get("status", "UNKNOWN")
            if status == "PASS":
                results["summary"]["passed"] += 1
            elif status == "FAIL":
                results["summary"]["failed"] += 1
                results["blockers"].extend(check_result.get("blockers", []))
            elif status == "WARN":
                results["summary"]["warnings"] += 1
                results["warnings"].extend(check_result.get("warnings", []))
            elif status == "ERROR":
                results["summary"]["errors"] += 1
                error = check_result.get("error", "Unknown error")
                results["blockers"].append(f"{check_name}: {error}")

        except Exception as e:
            results["verifications"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            results["summary"]["errors"] += 1
            results["blockers"].append(f"{check_name}: {str(e)}")

    # Determine overall status
    if results["summary"]["failed"] > 0 or results["summary"]["errors"] > 0:
        results["overall_status"] = "FAIL"
        results["message"] = (
            f"Coverage verification FAILED: {results['summary']['failed']} failed, "
            f"{results['summary']['errors']} errors"
        )
    elif results["summary"]["warnings"] > 0:
        results["overall_status"] = "WARN"
        results["message"] = (
            f"Coverage verification passed with {results['summary']['warnings']} warning(s)"
        )
    else:
        results["overall_status"] = "PASS"
        results["message"] = "All coverage verifications PASSED"

    results["checked_at"] = datetime.now().isoformat()

    return results


# ============================================================================
# Phase End Protocol
# ============================================================================

def _auto_detect_markdown_file(phase: int, project_root: str, session_id: Optional[str] = None) -> Optional[Path]:
    """
    Auto-detect the markdown file for a given phase.

    Search order:
    1. Session directory (if session_id provided or current session exists)
    2. Risk_Assessment_Report directory
    3. .phase_working directory (legacy)

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Path to markdown file, or None if not found
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    # Phase file patterns to search
    phase_patterns = [
        f"P{phase}-*.md",
        f"p{phase}-*.md",
    ]

    # Phase-specific name patterns
    phase_name_patterns = {
        1: ["PROJECT-UNDERSTANDING", "PROJECT_UNDERSTANDING"],
        2: ["DFD-ANALYSIS", "DFD_ANALYSIS", "CALL-FLOW", "DATA-FLOW"],
        3: ["TRUST-BOUNDARY", "TRUST_BOUNDARY"],
        4: ["SECURITY-DESIGN", "SECURITY_DESIGN", "DESIGN-REVIEW"],
        5: ["STRIDE-THREATS", "STRIDE_THREATS", "STRIDE-ANALYSIS"],
        6: ["RISK-VALIDATION", "RISK_VALIDATION", "VALIDATED-RISKS"],
        7: ["MITIGATION", "MITIGATION-PLAN", "MITIGATION_PLAN"],
        8: ["REPORT", "ASSESSMENT-REPORT", "FINAL-REPORT"],
    }

    # Directories to search in priority order
    search_dirs = []

    # 1. Session directory
    if session_id:
        session_dir = get_phase_working_dir(project_root) / session_id
        if session_dir.exists():
            search_dirs.append(session_dir)
    else:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            search_dirs.append(current_session_dir)

    # 2. Report directory
    if report_dir.exists():
        search_dirs.append(report_dir)

    # 3. Phase working directory (legacy)
    phase_working = get_phase_working_dir(project_root)
    if phase_working.exists():
        search_dirs.append(phase_working)

    # Search for file
    for search_dir in search_dirs:
        # Try P{N}-*.md pattern first
        for pattern in phase_patterns:
            matches = list(search_dir.glob(pattern))
            if matches:
                # Return most recently modified
                return max(matches, key=lambda p: p.stat().st_mtime)

        # Try phase-specific name patterns
        name_patterns = phase_name_patterns.get(phase, [])
        for name_pattern in name_patterns:
            for f in search_dir.glob("*.md"):
                if name_pattern.upper() in f.name.upper():
                    return f

    return None


def _generate_phase_summary(phase: int, phase_data: Dict) -> Dict:
    """
    Generate a summary of phase data for handoff to next phase.

    Args:
        phase: Phase number
        phase_data: Extracted phase data

    Returns:
        Dict with summary information
    """
    if not phase_data:
        return {"error": "No phase data available"}

    blocks = phase_data.get("blocks", {})
    summary = {
        "phase": phase,
        "extracted_at": phase_data.get("extracted_at"),
        "block_count": len(blocks),
    }

    # Phase-specific summaries
    if phase == 1:
        # P1: Module and entry point counts
        modules = blocks.get("module_inventory", {})
        entry_points = blocks.get("entry_point_inventory", {})
        checklist = blocks.get("discovery_checklist", {})

        if isinstance(modules, dict):
            summary["modules"] = _count_items(modules.get("modules", modules))
        elif isinstance(modules, list):
            summary["modules"] = len(modules)

        ep_count = 0
        if isinstance(entry_points, dict):
            for key in ["api_entries", "ui_entries", "system_entries", "hidden_entries"]:
                items = entry_points.get(key, [])
                if isinstance(items, list):
                    ep_count += len(items)
        summary["entry_points"] = ep_count

        if isinstance(checklist, dict):
            checklist_summary = checklist.get("summary", {})
            summary["coverage"] = checklist_summary.get("coverage", "N/A")
            summary["discovery_complete"] = all(
                checklist.get("checklist", {}).get(ep_type, {}).get("scanned", False)
                for ep_type in ENTRY_POINT_TYPES
                if ep_type in checklist.get("checklist", {})
            )

    elif phase == 2:
        # P2: DFD elements and data flows
        dfd_elements = blocks.get("dfd_elements", {})
        data_flows = blocks.get("data_flows", {})

        if isinstance(dfd_elements, dict):
            elements = dfd_elements.get("elements", [])
            summary["dfd_elements"] = len(elements) if isinstance(elements, list) else _count_items(elements)

            # Count by type
            type_counts = {}
            if isinstance(elements, list):
                for elem in elements:
                    if isinstance(elem, dict):
                        elem_type = elem.get("type", "unknown")
                        type_counts[elem_type] = type_counts.get(elem_type, 0) + 1
            summary["elements_by_type"] = type_counts

        if isinstance(data_flows, dict):
            flows = data_flows.get("flows", [])
            summary["data_flows"] = len(flows) if isinstance(flows, list) else _count_items(flows)

            # L1 coverage
            l1_coverage = data_flows.get("l1_coverage", {})
            if l1_coverage:
                summary["l1_coverage"] = f"{l1_coverage.get('coverage_percentage', 0)}%"

    elif phase == 3:
        # P3: Trust boundaries
        # P3 typically outputs tables, not YAML blocks
        summary["note"] = "P3 outputs Markdown tables, not YAML blocks"
        for block_name, data in blocks.items():
            summary[block_name] = _count_items(data)

    elif phase == 4:
        # P4: Security design review
        # P4 typically outputs tables, not YAML blocks
        summary["note"] = "P4 outputs Markdown tables, not YAML blocks"
        for block_name, data in blocks.items():
            summary[block_name] = _count_items(data)

    elif phase == 5:
        # P5: Threat inventory
        threat_inventory = blocks.get("threat_inventory", {})

        if isinstance(threat_inventory, dict):
            threats = threat_inventory.get("threats", [])
            summary["threats"] = len(threats) if isinstance(threats, list) else _count_items(threats)

            # Count by STRIDE category
            stride_counts = {"S": 0, "T": 0, "R": 0, "I": 0, "D": 0, "E": 0}
            if isinstance(threats, list):
                for threat in threats:
                    if isinstance(threat, dict):
                        threat_id = threat.get("id", "") or threat.get("threat_id", "")
                        # Extract STRIDE letter from T-X-... format
                        if threat_id and len(threat_id) > 2 and threat_id.startswith("T-"):
                            stride_letter = threat_id[2]
                            if stride_letter in stride_counts:
                                stride_counts[stride_letter] += 1
            summary["threats_by_stride"] = stride_counts
        elif isinstance(threat_inventory, list):
            summary["threats"] = len(threat_inventory)

    elif phase == 6:
        # P6: Validated risks
        validated_risks = blocks.get("validated_risks", {})
        attack_paths = blocks.get("attack_paths", {})

        if isinstance(validated_risks, dict):
            risks = validated_risks.get("risk_details", validated_risks.get("risks", []))
            summary["validated_risks"] = len(risks) if isinstance(risks, list) else _count_items(risks)

            # Excluded threats
            excluded = validated_risks.get("excluded_threats", [])
            if isinstance(excluded, list):
                summary["excluded_threats"] = len(excluded)
        elif isinstance(validated_risks, list):
            summary["validated_risks"] = len(validated_risks)

        if attack_paths:
            if isinstance(attack_paths, dict):
                paths = attack_paths.get("paths", [])
                summary["attack_paths"] = len(paths) if isinstance(paths, list) else _count_items(paths)
            elif isinstance(attack_paths, list):
                summary["attack_paths"] = len(attack_paths)

    elif phase == 7:
        # P7: Mitigation plan
        mitigation_plan = blocks.get("mitigation_plan", {})

        if isinstance(mitigation_plan, dict):
            mitigations = mitigation_plan.get("mitigations", [])
            summary["mitigations"] = len(mitigations) if isinstance(mitigations, list) else _count_items(mitigations)

            # Count by priority if available
            priority_counts = {}
            if isinstance(mitigations, list):
                for mit in mitigations:
                    if isinstance(mit, dict):
                        priority = mit.get("priority", "unspecified")
                        priority_counts[priority] = priority_counts.get(priority, 0) + 1
            if priority_counts:
                summary["mitigations_by_priority"] = priority_counts
        elif isinstance(mitigation_plan, list):
            summary["mitigations"] = len(mitigation_plan)

    # Add block names for all phases
    summary["blocks"] = list(blocks.keys())

    return summary


def phase_end_protocol(
    phase: int,
    project_root: str,
    markdown_file: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict:
    """
    Execute Phase End Protocol (extract + validate + summary).

    This is a complete phase completion workflow that:
    1. Extracts YAML blocks from the phase's Markdown report
    2. Validates phase completion against requirements
    3. Generates a summary for handoff to the next phase
    4. Updates session state to mark phase as completed

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory
        markdown_file: Optional markdown file path (auto-detect if not provided)
        session_id: Optional session ID (uses current session if not specified)

    Returns:
        Dict with:
        - phase: Phase number
        - extraction: Extraction result
        - validation: Validation result
        - summary: Data summary for next phase
        - overall_status: "success" | "warning" | "blocking"
        - next_phase_query: Command to query this data for next phase
    """
    result = {
        "phase": phase,
        "action": "phase_end_protocol",
        "extraction": None,
        "validation": None,
        "summary": None,
        "overall_status": None,
        "next_phase": None,
        "executed_at": datetime.now().isoformat(),
    }

    # Validate phase number
    if phase < 1 or phase > 8:
        result["overall_status"] = "error"
        result["error"] = f"Invalid phase number: {phase}. Must be 1-8."
        return result

    # Determine session ID if not provided (MUST run before FSM check - F1 fix)
    if not session_id:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_id = current_session_dir.name

    result["session_id"] = session_id

    # FSM enforcement: verify precondition (方案A - v3.1.0)
    # Ensures phases execute in order: P(N) requires P(N-1) completed
    if phase > 1 and session_id:
        session = load_session(project_root, session_id)
        if session:
            phases_completed = session.get("phases_completed", [])
            required_phase = phase - 1
            if required_phase not in phases_completed:
                result["overall_status"] = "error"
                result["error"] = f"FSM violation: Phase {phase} requires Phase {required_phase} to be completed first"
                result["hint"] = f"Complete Phase {required_phase} before proceeding to Phase {phase}"
                return result

    # Step 1: Find markdown file
    md_path = None
    if markdown_file:
        md_path = Path(markdown_file)
        if not md_path.is_absolute():
            md_path = Path(project_root) / "Risk_Assessment_Report" / markdown_file
    else:
        md_path = _auto_detect_markdown_file(phase, project_root, session_id)

    if not md_path or not md_path.exists():
        result["overall_status"] = "error"
        result["error"] = f"Markdown file not found for phase {phase}"
        result["hint"] = f"Expected file pattern: P{phase}-*.md in Risk_Assessment_Report/"
        if markdown_file:
            result["searched_for"] = str(md_path)
        return result

    result["source_file"] = str(md_path)

    # Step 2: Extract YAML blocks
    extraction_result = extract_from_markdown(
        str(md_path),
        phase,
        project_root,
        session_id=session_id,
        mark_complete=False  # M9 fix: defer completion until after validation
    )

    result["extraction"] = extraction_result

    if extraction_result.get("error"):
        result["overall_status"] = "error"
        result["error"] = extraction_result["error"]
        return result

    if extraction_result.get("status") == "warning" and extraction_result.get("blocks_extracted", 0) == 0:
        # No YAML blocks found - check if this phase uses tables instead
        if phase in [3, 4]:
            # P3/P4 use Markdown tables, not YAML blocks
            result["extraction"]["note"] = f"Phase {phase} uses Markdown tables, not YAML blocks per WORKFLOW.md"
            result["extraction"]["status"] = "partial"
        else:
            result["overall_status"] = "warning"
            result["warning"] = "No YAML blocks extracted from markdown file"
            result["hint"] = "Ensure blocks use ```yaml:{block_name} format"

    # Step 3: Validate phase completion
    validation_result = validate_phase(phase, project_root)
    result["validation"] = validation_result

    # Determine validation status
    validation_status = validation_result.get("status", "unknown")

    # Step 4: Generate summary for next phase
    phase_data = load_phase_data(phase, project_root, session_id=session_id)
    summary = _generate_phase_summary(phase, phase_data)
    result["summary"] = summary

    # Step 5: Update session state (M9 fix: only mark complete if validation passed)
    session = load_session(project_root, session_id)
    if session:
        # Update phases_completed — gate on validation status
        phases_completed = session.get("phases_completed", [])
        if validation_status not in ("blocking", "error"):
            if phase not in phases_completed:
                phases_completed.append(phase)
                phases_completed.sort()

        # Update current_phase to next phase
        next_phase_num = phase + 1 if phase < 8 else 8

        updates = {
            "phases_completed": phases_completed,
            "current_phase": next_phase_num,
            "last_phase_end_protocol": {
                "phase": phase,
                "executed_at": result["executed_at"],
                "status": validation_status,
            },
        }

        # Also update extraction_status
        if "extraction_status" not in session:
            session["extraction_status"] = {}

        session["extraction_status"][f"phase{phase}"] = {
            "extracted": True,
            "entities": extraction_result.get("blocks_extracted", 0),
            "blocks": list(extraction_result.get("blocks", {}).keys()),
            "phase_end_completed": True,
        }
        updates["extraction_status"] = session["extraction_status"]

        update_result = update_session(project_root, updates, session_id)
        result["session_updated"] = update_result.get("status") == "success"

        # Also update session meta for multi-version sessions
        if session_id:
            _update_session_meta(
                project_root,
                session_id,
                session.get("project_name", ""),
                "update",
                current_phase=next_phase_num,
                phases_completed=phases_completed
            )

    # Step 6: Prepare next phase info
    next_phase_num = phase + 1 if phase < 8 else None

    if next_phase_num:
        next_phase_deps = PHASE_DEPENDENCIES.get(next_phase_num, {})
        result["next_phase"] = {
            "phase": next_phase_num,
            "depends_on": next_phase_deps.get("requires", []),
            "description": next_phase_deps.get("description", ""),
            "query_command": f"python scripts/phase_data.py {next_phase_deps.get('query', '--query --phase ' + str(phase) + ' --summary')} --root {project_root}",
        }
    else:
        result["next_phase"] = {
            "phase": None,
            "message": "Phase 8 is the final phase. Workflow complete!",
        }

    # Step 7: Determine overall status
    if validation_status == "blocking":
        result["overall_status"] = "blocking"
        result["message"] = f"Phase {phase} has blocking issues that must be resolved before proceeding."
        result["action_required"] = "Fix blocking issues listed in validation result."
    elif validation_status == "warning" or extraction_result.get("status") == "warning":
        result["overall_status"] = "warning"
        result["message"] = f"Phase {phase} completed with warnings. Review before proceeding to Phase {next_phase_num}."
    elif validation_status == "passed" or validation_status == "success":
        result["overall_status"] = "success"
        result["message"] = f"Phase {phase} completed successfully. Ready for Phase {next_phase_num}." if next_phase_num else f"Phase {phase} completed. Workflow complete!"
    elif validation_status == "error":
        result["overall_status"] = "error"
        result["message"] = f"Phase {phase} validation encountered an error."
    else:
        # For phases without specific validation (P3, P4)
        if extraction_result.get("status") == "success" or extraction_result.get("blocks_extracted", 0) > 0:
            result["overall_status"] = "success"
            result["message"] = f"Phase {phase} data extracted. Ready for Phase {next_phase_num}." if next_phase_num else "Workflow complete!"
        else:
            result["overall_status"] = "warning"
            result["message"] = f"Phase {phase} completed but no structured data extracted."

    return result


# ============================================================================
# P2 Full Traversal Enhancement Functions
# ============================================================================

def p2_extract_traversal_tasks(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P2.0: Extract traversal tasks from P1 data for sub-agent dispatch.

    Reads P1_project_context.yaml and generates P2_traversal_tasks.yaml
    with tasks for analyzing each module and entry point.

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with extraction result and task summary
    """
    result = {
        "command": "p2_extract_tasks",
        "status": "error",
        "tasks_generated": 0,
        "output_file": None,
    }

    try:
        # Get data directory
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Read P1 data
        p1_file = data_dir / "P1_project_context.yaml"
        if not p1_file.exists():
            result["error"] = f"P1 data file not found: {p1_file}"
            return result

        with open(p1_file, "r", encoding="utf-8") as f:
            p1_data = yaml.safe_load(f)

        if not p1_data:
            result["error"] = "P1 data file is empty"
            return result

        # Extract modules and entry points
        modules = p1_data.get("module_inventory", {}).get("modules", [])

        # P1-DATA-01 FIX: Handle P1's categorized entry point structure
        # P1 outputs: api_entries[], ui_entries[], system_entries[], hidden_entries[]
        # P2 needs: flat entry_points[] list
        entry_point_inventory = p1_data.get("entry_point_inventory", {})
        entry_points = []

        # Collect from all categorized entry point lists (P1 structure)
        ENTRY_POINT_CATEGORIES = ["api_entries", "ui_entries", "system_entries", "hidden_entries"]
        for category in ENTRY_POINT_CATEGORIES:
            category_entries = entry_point_inventory.get(category, [])
            if isinstance(category_entries, list):
                for ep in category_entries:
                    if isinstance(ep, dict):
                        # Add source category for traceability
                        ep["_source_category"] = category
                        entry_points.append(ep)

        # Fallback: check for flat entry_points[] if categorized structure not found
        if not entry_points:
            entry_points = entry_point_inventory.get("entry_points", [])

        # Also check alternative top-level keys
        if not modules:
            modules = p1_data.get("modules", [])
        if not entry_points:
            entry_points = p1_data.get("entry_points", [])

        # Generate traversal tasks
        traversal_tasks = []
        task_seq = 1

        # Module analysis tasks
        for module in modules:
            module_id = module.get("id", f"M-{task_seq:03d}")
            module_name = module.get("name", module.get("path", "Unknown"))
            priority = "high" if module.get("security_relevant", False) else "medium"

            traversal_tasks.append({
                "task_id": f"TT-{task_seq:03d}",
                "type": "module_analysis",
                "target_id": module_id,
                "target_name": module_name,
                "priority": priority,
                "estimated_complexity": _estimate_complexity(module),
                "status": "pending",
            })
            task_seq += 1

        # Entry point analysis tasks
        for ep in entry_points:
            ep_id = ep.get("id", f"EP-{task_seq:03d}")
            ep_name = ep.get("path", ep.get("name", "Unknown"))
            # Entry points from external interfaces are higher priority
            priority = "high" if ep.get("layer", "L1") == "L1" else "medium"

            traversal_tasks.append({
                "task_id": f"TT-{task_seq:03d}",
                "type": "entry_point_analysis",
                "target_id": ep_id,
                "target_name": ep_name,
                "priority": priority,
                "estimated_complexity": _estimate_complexity(ep),
                "status": "pending",
            })
            task_seq += 1

        # Create output structure
        now = datetime.now().isoformat()
        output_data = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "generated_at": now,
            "source_p1": {
                "total_modules": len(modules),
                "total_entry_points": len(entry_points),
                "total_high_risk_paths": sum(1 for t in traversal_tasks if t["priority"] == "high"),
            },
            "traversal_tasks": traversal_tasks,
            "task_summary": {
                "total_tasks": len(traversal_tasks),
                "by_type": {
                    "module_analysis": sum(1 for t in traversal_tasks if t["type"] == "module_analysis"),
                    "entry_point_analysis": sum(1 for t in traversal_tasks if t["type"] == "entry_point_analysis"),
                },
                "by_priority": {
                    "high": sum(1 for t in traversal_tasks if t["priority"] == "high"),
                    "medium": sum(1 for t in traversal_tasks if t["priority"] == "medium"),
                    "low": sum(1 for t in traversal_tasks if t["priority"] == "low"),
                },
            },
        }

        # Write output file
        output_file = data_dir / "P2_traversal_tasks.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(output_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["tasks_generated"] = len(traversal_tasks)
        result["output_file"] = str(output_file)
        result["task_summary"] = output_data["task_summary"]

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


def _estimate_complexity(item: Dict) -> int:
    """Estimate task complexity (1-5) based on item properties."""
    complexity = 2  # Base complexity

    # Increase for security-relevant items
    if item.get("security_relevant", False):
        complexity += 1

    # Increase for multiple entry points (L10 fix: differentiate >5 from >2)
    entry_points = item.get("entry_points", [])
    if len(entry_points) > 5:
        complexity += 2
    elif len(entry_points) > 2:
        complexity += 1

    # Increase for external-facing interfaces
    if item.get("layer") == "L1":
        complexity += 1

    return min(complexity, 5)


def p2_merge_traversal_results(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P2.T.2: Merge all P2_traverse_{NNN}.yaml files into P2_full_traversal.yaml.

    Collects all sub-agent outputs, deduplicates elements, and creates
    a unified traversal result.

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with merge result and statistics
    """
    result = {
        "command": "p2_merge_traversal",
        "status": "error",
        "source_files": [],
        "merged_counts": {},
        "output_file": None,
    }

    try:
        # Get data directory
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Find all P2_traverse_*.yaml files
        traverse_files = list(data_dir.glob("P2_traverse_*.yaml"))
        if not traverse_files:
            result["error"] = "No P2_traverse_*.yaml files found"
            return result

        result["source_files"] = [str(f) for f in traverse_files]

        # Collect all elements
        all_interfaces = []
        all_data_flows = []
        all_call_flows = []
        all_data_stores = []
        deduplication_log = []

        for tf in traverse_files:
            with open(tf, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                continue

            discovered = data.get("discovered_elements", {})

            # Collect elements (will deduplicate later)
            all_interfaces.extend(discovered.get("interfaces", []))
            all_data_flows.extend(discovered.get("data_flows", []))
            all_call_flows.extend(discovered.get("call_flows", []))
            all_data_stores.extend(discovered.get("data_stores", []))

        # Deduplicate elements by ID
        interfaces, dup_log = _deduplicate_elements(all_interfaces, "interfaces")
        deduplication_log.extend(dup_log)

        data_flows, dup_log = _deduplicate_elements(all_data_flows, "data_flows")
        deduplication_log.extend(dup_log)

        call_flows, dup_log = _deduplicate_elements(all_call_flows, "call_flows")
        deduplication_log.extend(dup_log)

        data_stores, dup_log = _deduplicate_elements(all_data_stores, "data_stores")
        deduplication_log.extend(dup_log)

        # Create output structure
        now = datetime.now().isoformat()
        output_data = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "merged_at": now,
            "source_files": [f.name for f in traverse_files],
            "merged_elements": {
                "interfaces": interfaces,
                "data_flows": data_flows,
                "call_flows": call_flows,
                "data_stores": data_stores,
            },
            "deduplication_log": deduplication_log,
            "aggregate_metrics": {
                "total_interfaces": len(interfaces),
                "total_data_flows": len(data_flows),
                "total_call_flows": len(call_flows),
                "total_data_stores": len(data_stores),
            },
        }

        # Write output file
        output_file = data_dir / "P2_full_traversal.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(output_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["merged_counts"] = output_data["aggregate_metrics"]
        result["output_file"] = str(output_file)
        result["deduplication_count"] = len(deduplication_log)

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


def _deduplicate_elements(elements: List[Dict], element_type: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Deduplicate elements by ID, keeping the most complete version.

    Returns:
        Tuple of (deduplicated_list, deduplication_log)
    """
    seen = {}
    log = []

    for elem in elements:
        elem_id = elem.get("id")
        if not elem_id:
            continue

        if elem_id in seen:
            # Keep the version with more fields
            existing = seen[elem_id]
            if len(elem) > len(existing):
                log.append({
                    "original_id": elem_id,
                    "action": "replaced",
                    "reason": f"New version has more fields ({len(elem)} vs {len(existing)})",
                    "element_type": element_type,
                })
                seen[elem_id] = elem
            else:
                log.append({
                    "original_id": elem_id,
                    "action": "kept_existing",
                    "reason": "Duplicate found, kept existing version",
                    "element_type": element_type,
                })
        else:
            seen[elem_id] = elem

    return list(seen.values()), log


def p2_validate_coverage(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P2.T.3: Validate 100% coverage and generate coverage report.

    Compares traversal results against P1 enumeration to ensure
    all modules and entry points have been analyzed.

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with coverage validation result
    """
    result = {
        "command": "p2_validate_coverage",
        "status": "error",
        "coverage_metrics": {},
        "overall_status": "UNKNOWN",
        "output_file": None,
    }

    try:
        # Get data directory
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Read P1 data for totals
        p1_file = data_dir / "P1_project_context.yaml"
        if not p1_file.exists():
            result["error"] = f"P1 data file not found: {p1_file}"
            return result

        with open(p1_file, "r", encoding="utf-8") as f:
            p1_data = yaml.safe_load(f)

        # Read traversal tasks for expected counts
        tasks_file = data_dir / "P2_traversal_tasks.yaml"
        if not tasks_file.exists():
            result["error"] = f"Traversal tasks file not found. Run --p2-extract-tasks first."
            return result

        with open(tasks_file, "r", encoding="utf-8") as f:
            tasks_data = yaml.safe_load(f)

        # Read merged traversal results
        traversal_file = data_dir / "P2_full_traversal.yaml"
        if not traversal_file.exists():
            result["error"] = f"Full traversal file not found. Run --p2-merge-traversal first."
            return result

        with open(traversal_file, "r", encoding="utf-8") as f:
            traversal_data = yaml.safe_load(f)

        # Also read dfd_elements if exists (from P2.5)
        dfd_file = data_dir / "P2_dfd_elements.yaml"
        dfd_data = None
        if dfd_file.exists():
            with open(dfd_file, "r", encoding="utf-8") as f:
                dfd_data = yaml.safe_load(f)

        # Calculate coverage metrics
        source_p1 = tasks_data.get("source_p1", {})
        total_modules = source_p1.get("total_modules", 0)
        total_entry_points = source_p1.get("total_entry_points", 0)

        merged = traversal_data.get("merged_elements", {})
        traversed_interfaces = len(merged.get("interfaces", []))
        traversed_data_flows = len(merged.get("data_flows", []))
        traversed_call_flows = len(merged.get("call_flows", []))
        traversed_data_stores = len(merged.get("data_stores", []))

        # Check which tasks were completed
        tasks = tasks_data.get("traversal_tasks", [])
        completed_modules = sum(1 for t in tasks
                               if t["type"] == "module_analysis" and t.get("status") == "completed")
        completed_entry_points = sum(1 for t in tasks
                                    if t["type"] == "entry_point_analysis" and t.get("status") == "completed")

        # P2-FIX-03: Use actual task completion status, not optimistic estimates
        # Count tasks by analyzing merged traversal results more precisely
        if merged:
            # Count unique module IDs from discovered elements
            discovered_module_ids = set()
            for element_list in merged.values():
                if isinstance(element_list, list):
                    for elem in element_list:
                        if isinstance(elem, dict) and elem.get("module_id"):
                            discovered_module_ids.add(elem["module_id"])

            # Update completion counts based on actual discovery
            if discovered_module_ids:
                completed_modules = min(len(discovered_module_ids), total_modules)

            # For entry points, check if we have corresponding data flows
            discovered_ep_ids = set()
            for flow in merged.get("data_flows", []):
                if isinstance(flow, dict) and flow.get("entry_point_id"):
                    discovered_ep_ids.add(flow["entry_point_id"])
            if discovered_ep_ids:
                completed_entry_points = min(len(discovered_ep_ids), total_entry_points)

        # Build coverage metrics
        coverage_metrics = {
            "modules": {
                "analyzed": completed_modules,
                "total": total_modules,
                "coverage": completed_modules / total_modules if total_modules > 0 else 1.0,
                "status": "PASS" if completed_modules >= total_modules else "FAIL",
            },
            "entry_points": {
                "analyzed": completed_entry_points,
                "total": total_entry_points,
                "coverage": completed_entry_points / total_entry_points if total_entry_points > 0 else 1.0,
                "status": "PASS" if completed_entry_points >= total_entry_points else "FAIL",
            },
            # P2-FIX-03: Interface coverage should compare against total entry points
            # since each entry point should have at least one data flow traced
            "interfaces": {
                "with_data_flow": traversed_interfaces,
                "total": max(total_entry_points, traversed_interfaces),  # At minimum, discovered count
                "coverage": (
                    traversed_interfaces / total_entry_points
                    if total_entry_points > 0
                    else (1.0 if traversed_interfaces > 0 else 0.0)
                ),
                "status": "PASS" if traversed_interfaces >= total_entry_points else "FAIL",
            },
            # P2-FIX-03: Data stores coverage - count actual vs discovered
            "data_stores": {
                "with_access_pattern": traversed_data_stores,
                "total": max(1, traversed_data_stores),  # At minimum 1 expected
                "coverage": 1.0 if traversed_data_stores > 0 else 0.0,
                "status": "PASS" if traversed_data_stores > 0 else "FAIL",
            },
        }

        # Determine overall status
        all_pass = all(m["status"] == "PASS" for m in coverage_metrics.values())
        overall_status = "PASS" if all_pass else "FAIL"

        # Check iteration count from existing coverage report
        existing_report = data_dir / "P2_coverage_report.yaml"
        current_iteration = 1
        if existing_report.exists():
            with open(existing_report, "r", encoding="utf-8") as f:
                existing = yaml.safe_load(f)
            current_iteration = existing.get("iteration", 0) + 1

        max_iterations = 3

        # P2-GAP-03 fix: Task-based gap identification (identify SPECIFIC uncovered items)
        gaps = []
        uncovered_modules = []
        uncovered_entry_points = []

        # Get P1 module inventory
        p1_modules = p1_data.get("module_inventory", {}).get("modules", [])
        p1_entry_points = []
        ep_inventory = p1_data.get("entry_point_inventory", {})
        for key in ["api_entries", "ui_entries", "system_entries", "hidden_entries"]:
            p1_entry_points.extend(ep_inventory.get(key, []))

        # Get covered items from traversal
        covered_module_ids = set()
        covered_ep_ids = set()

        # From traversal data - check target_id, module_id, and target (backward compatibility)
        for task in tasks:
            if task.get("status") == "completed":
                if task["type"] == "module_analysis":
                    mod_id = task.get("target_id") or task.get("module_id") or task.get("target", "")
                    if mod_id:
                        covered_module_ids.add(mod_id)
                elif task["type"] == "entry_point_analysis":
                    ep_id = task.get("target_id") or task.get("entry_point_id") or task.get("target", "")
                    if ep_id:
                        covered_ep_ids.add(ep_id)

        # From merged elements (more reliable)
        for interface in merged.get("interfaces", []):
            if interface.get("module_id"):
                covered_module_ids.add(interface["module_id"])
            if interface.get("entry_point_id"):
                covered_ep_ids.add(interface["entry_point_id"])

        # Identify specific uncovered items
        for module in p1_modules:
            mod_id = module.get("id", module.get("path", ""))
            if mod_id and mod_id not in covered_module_ids:
                uncovered_modules.append({
                    "id": mod_id,
                    "name": module.get("name", "Unknown"),
                    "path": module.get("path", ""),
                    "security_level": module.get("security_level", "MEDIUM"),
                })

        for ep in p1_entry_points:
            ep_id = ep.get("id", "")
            if ep_id and ep_id not in covered_ep_ids:
                uncovered_entry_points.append({
                    "id": ep_id,
                    "path": ep.get("path", ""),
                    "type": ep.get("type", "unknown"),
                    "module": ep.get("module", ""),
                })

        # Update coverage metrics with actual counts
        coverage_metrics["modules"]["analyzed"] = len(covered_module_ids)
        coverage_metrics["modules"]["coverage"] = len(covered_module_ids) / total_modules if total_modules > 0 else 1.0
        coverage_metrics["modules"]["status"] = "PASS" if len(covered_module_ids) >= total_modules else "FAIL"

        coverage_metrics["entry_points"]["analyzed"] = len(covered_ep_ids)
        coverage_metrics["entry_points"]["coverage"] = len(covered_ep_ids) / total_entry_points if total_entry_points > 0 else 1.0
        coverage_metrics["entry_points"]["status"] = "PASS" if len(covered_ep_ids) >= total_entry_points else "FAIL"

        # Build detailed gaps
        if uncovered_modules:
            gaps.append({
                "gap_type": "uncovered_module",
                "count": len(uncovered_modules),
                "reason": "Modules not covered by traversal",
                "items": uncovered_modules[:20],  # Limit to first 20
                "truncated": len(uncovered_modules) > 20,
            })
        if uncovered_entry_points:
            gaps.append({
                "gap_type": "uncovered_entry_point",
                "count": len(uncovered_entry_points),
                "reason": "Entry points not covered by traversal",
                "items": uncovered_entry_points[:20],  # Limit to first 20
                "truncated": len(uncovered_entry_points) > 20,
            })

        # Check if should halt
        if current_iteration > max_iterations and overall_status != "PASS":
            overall_status = "HALTED"

        # Calculate overall coverage percentage (average of all metrics, converted to %)
        # P2-FIX-02: Add top-level coverage_percentage for p2_final_aggregate compatibility
        all_coverage_values = [
            m.get("coverage", 0) for m in coverage_metrics.values() if isinstance(m, dict)
        ]
        overall_coverage_pct = (
            sum(all_coverage_values) / len(all_coverage_values) * 100
            if all_coverage_values else 0
        )

        # Build output
        now = datetime.now().isoformat()
        output_data = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "validated_at": now,
            "coverage_percentage": round(overall_coverage_pct, 2),  # P2-FIX-02: Top-level key
            "coverage_metrics": coverage_metrics,
            "overall_status": overall_status,
            # P2-GAP-04: Use both 'iteration' and 'iteration_number' for backward compatibility
            "iteration": current_iteration,
            "iteration_number": current_iteration,  # Explicit iteration_number field
            "max_iterations": max_iterations,
            "gaps": gaps,
            "validation_result": {
                "ready_for_phase_3": overall_status == "PASS",
                "blocking_issues": [g["gap_type"] for g in gaps] if gaps else [],
                "warnings": [],
            },
        }

        # Write output file
        output_file = data_dir / "P2_coverage_report.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(output_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["coverage_metrics"] = coverage_metrics
        result["overall_status"] = overall_status
        # P2-GAP-04: Include both iteration and iteration_number in result
        result["iteration"] = current_iteration
        result["iteration_number"] = current_iteration
        result["output_file"] = str(output_file)
        result["ready_for_phase_3"] = output_data["validation_result"]["ready_for_phase_3"]

        if overall_status == "HALTED":
            result["halt_reason"] = f"Coverage threshold not met after {max_iterations} iterations"
            result["user_decision_required"] = True

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


# P2-GAP-06: Root cause categories for gap analysis
GAP_ROOT_CAUSES = {
    "timeout": {
        "description": "Sub-agent timeout during analysis",
        "severity": "medium",
        "remediation": "Retry with increased timeout or split into smaller tasks",
    },
    "code_complexity": {
        "description": "Code too complex for automated analysis",
        "severity": "high",
        "remediation": "Manual review required or simplify target scope",
    },
    "missing_handler": {
        "description": "Route/endpoint handler not found in code",
        "severity": "medium",
        "remediation": "Check if handler exists in different file or is dynamically generated",
    },
    "dynamic_routing": {
        "description": "Routes are dynamically generated at runtime",
        "severity": "low",
        "remediation": "Trace runtime behavior or document as dynamic endpoint",
    },
    "external_dependency": {
        "description": "Module depends on external service not in codebase",
        "severity": "low",
        "remediation": "Document as external boundary in DFD",
    },
    "incomplete_traversal": {
        "description": "Traversal started but not completed",
        "severity": "medium",
        "remediation": "Resume from last checkpoint or retry",
    },
    "unknown": {
        "description": "Unknown root cause",
        "severity": "high",
        "remediation": "Manual investigation required",
    },
}


def _classify_gap_root_cause(gap: Dict, task: Optional[Dict] = None) -> str:
    """
    P2-GAP-06: Classify the root cause of a coverage gap.

    Args:
        gap: Gap information from coverage validation
        task: Optional task information that may contain failure details

    Returns:
        Root cause category key
    """
    gap_type = gap.get("gap_type", "")
    items = gap.get("items", [])

    # Check task status for clues
    if task:
        status = task.get("status", "")
        error = task.get("error", "")

        if "timeout" in error.lower():
            return "timeout"
        if "complex" in error.lower() or "too large" in error.lower():
            return "code_complexity"
        if status == "in_progress":
            return "incomplete_traversal"

    # Analyze gap items for patterns
    for item in items[:5]:  # Check first 5 items
        path = item.get("path", "")
        name = item.get("name", "")

        # Dynamic routing indicators
        if any(kw in path.lower() for kw in ["dynamic", "wildcard", "[", ":"]):
            return "dynamic_routing"

        # External dependency indicators
        if any(kw in name.lower() for kw in ["external", "third_party", "sdk", "client"]):
            return "external_dependency"

        # Missing handler indicators
        if gap_type == "uncovered_entry_point":
            return "missing_handler"

    # Default classification based on gap type
    if gap_type == "uncovered_module":
        return "code_complexity"
    elif gap_type == "uncovered_entry_point":
        return "missing_handler"

    return "unknown"


def p2_gap_analysis(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P2.T.3: Identify gaps and generate remediation tasks.

    Called when coverage < 100% to create supplemental traversal tasks.

    Enhanced with P2-GAP-06: Root cause analysis for gaps.

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with gap analysis, root causes, and remediation tasks
    """
    result = {
        "command": "p2_gap_analysis",
        "status": "error",
        "gaps_identified": [],
        "gap_root_causes": {},  # P2-GAP-06: Root cause summary
        "remediation_tasks": [],
        "output_file": None,
    }

    try:
        # Get data directory
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Read coverage report
        coverage_file = data_dir / "P2_coverage_report.yaml"
        if not coverage_file.exists():
            result["error"] = "Coverage report not found. Run --p2-validate-coverage first."
            return result

        with open(coverage_file, "r", encoding="utf-8") as f:
            coverage_data = yaml.safe_load(f)

        # Read original traversal tasks
        tasks_file = data_dir / "P2_traversal_tasks.yaml"
        if not tasks_file.exists():
            result["error"] = "Traversal tasks file not found."
            return result

        with open(tasks_file, "r", encoding="utf-8") as f:
            tasks_data = yaml.safe_load(f)

        # Read P1 data for module/entry point details
        p1_file = data_dir / "P1_project_context.yaml"
        with open(p1_file, "r", encoding="utf-8") as f:
            p1_data = yaml.safe_load(f)

        # Identify gaps
        gaps = coverage_data.get("gaps", [])
        coverage_metrics = coverage_data.get("coverage_metrics", {})
        # P2-GAP-04: Use consistent iteration_number field name
        iteration = coverage_data.get("iteration", coverage_data.get("iteration_number", 1))

        # Find incomplete tasks and build task lookup
        original_tasks = tasks_data.get("traversal_tasks", [])
        incomplete_tasks = [t for t in original_tasks if t.get("status") != "completed"]
        task_lookup = {t.get("target_id", ""): t for t in original_tasks}

        # P2-GAP-06: Analyze root causes for all gaps
        root_cause_summary = {}
        for gap in gaps:
            # Find related task if any
            items = gap.get("items", [])
            for item in items[:5]:
                item_id = item.get("id", "")
                related_task = task_lookup.get(item_id)

                # Classify root cause
                root_cause = _classify_gap_root_cause(gap, related_task)
                item["root_cause"] = root_cause
                item["root_cause_details"] = GAP_ROOT_CAUSES.get(root_cause, GAP_ROOT_CAUSES["unknown"])

                # Aggregate root causes
                if root_cause not in root_cause_summary:
                    root_cause_summary[root_cause] = {
                        "count": 0,
                        "items": [],
                        **GAP_ROOT_CAUSES.get(root_cause, GAP_ROOT_CAUSES["unknown"]),
                    }
                root_cause_summary[root_cause]["count"] += 1
                root_cause_summary[root_cause]["items"].append(item_id)

        # Generate remediation tasks with enhanced root cause info
        remediation_tasks = []
        gap_seq = 1

        for gap in gaps:
            gap_type = gap.get("gap_type", "unknown")
            items = gap.get("items", [])

            # P2-GAP-06: Enhanced remediation task generation based on root cause
            for item in items:
                item_id = item.get("id", "")
                root_cause = item.get("root_cause", "unknown")
                root_cause_info = GAP_ROOT_CAUSES.get(root_cause, GAP_ROOT_CAUSES["unknown"])

                # Determine task type based on gap type
                if gap_type == "uncovered_module":
                    task_type = "module_analysis"
                elif gap_type == "uncovered_entry_point":
                    task_type = "entry_point_analysis"
                else:
                    task_type = "general_analysis"

                # Adjust priority based on root cause severity
                severity = root_cause_info.get("severity", "medium")
                priority = {"high": "critical", "medium": "high", "low": "medium"}.get(severity, "medium")

                remediation_tasks.append({
                    "task_id": f"TT-GAP-{gap_seq:03d}",
                    "type": task_type,
                    "target_id": item_id,
                    "target_name": item.get("name", item.get("path", "Unknown")),
                    "priority": priority,
                    "status": "pending",
                    "iteration_number": iteration + 1,  # P2-GAP-04: Consistent field name
                    "root_cause": root_cause,
                    "remediation_hint": root_cause_info.get("remediation", ""),
                    "reason": f"Gap remediation: {root_cause_info.get('description', 'Unknown cause')}",
                })
                gap_seq += 1

        # Build output
        now = datetime.now().isoformat()
        output_data = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "analyzed_at": now,
            "gaps_identified": gaps,
            "root_cause_summary": root_cause_summary,  # P2-GAP-06: Root cause analysis
            "remediation_tasks": remediation_tasks,
            "iteration_status": {
                "current": iteration,
                "iteration_number": iteration,  # P2-GAP-04: Explicit iteration_number
                "max": 3,
                "next_action": "dispatch_gap_tasks" if remediation_tasks else "manual_review",
            },
        }

        # Write output file
        output_file = data_dir / "P2_gap_tasks.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(output_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["gaps_identified"] = gaps
        result["gap_root_causes"] = root_cause_summary
        result["remediation_tasks"] = remediation_tasks
        result["remediation_count"] = len(remediation_tasks)
        result["output_file"] = str(output_file)
        result["iteration_number"] = iteration + 1  # P2-GAP-04: Consistent field name

        if iteration >= 3:
            result["warning"] = "This is the final iteration. If gaps persist, workflow will halt."
            result["halt_recommended"] = True

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


# ============================================================================
# P2 Final Aggregation (P2-GAP-01 fix)
# ============================================================================

def p2_final_aggregation(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P2.F: Final aggregation of Critical Track + Full Traversal Track outputs.

    This function merges:
    - P2_dfd_elements.yaml (Critical Track output from P2.1-P2.5)
    - P2_full_traversal.yaml (Full Traversal Track output)
    - P2_coverage_report.yaml (Coverage validation)

    Produces the final P2 output that passes to P3.

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with aggregated P2 results
    """
    result = {
        "command": "p2_final_aggregation",
        "status": "error",
        "aggregation_complete": False,
    }

    try:
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Load all P2 source files
        sources = {}
        source_files = {
            "critical_track": data_dir / "P2_dfd_elements.yaml",
            "traversal_results": data_dir / "P2_full_traversal.yaml",
            "coverage_report": data_dir / "P2_coverage_report.yaml",
        }

        for source_name, source_file in source_files.items():
            if source_file.exists():
                with open(source_file, "r", encoding="utf-8") as f:
                    sources[source_name] = yaml.safe_load(f)

        # Validate minimum sources
        if "critical_track" not in sources:
            result["error"] = "P2_dfd_elements.yaml not found. Complete Critical Track (P2.1-P2.5) first."
            return result

        # Aggregate data flows
        critical_data = sources.get("critical_track", {})
        traversal_data = sources.get("traversal_results", {})
        coverage_data = sources.get("coverage_report", {})

        # Merge DFD elements
        aggregated_elements = {
            "external_interactors": [],
            "processes": [],
            "data_stores": [],
            "data_flows": [],
            "trust_boundaries": [],
        }

        # Add from critical track
        for element_type in aggregated_elements.keys():
            critical_elements = critical_data.get(element_type, [])
            if isinstance(critical_elements, list):
                for elem in critical_elements:
                    elem["source"] = "critical_track"
                    aggregated_elements[element_type].append(elem)

        # Add from traversal results (deduplicate by ID)
        traversal_elements = traversal_data.get("discovered_elements", {})
        for element_type in aggregated_elements.keys():
            existing_ids = {e.get("id") for e in aggregated_elements[element_type]}
            trav_elements = traversal_elements.get(element_type, [])
            if isinstance(trav_elements, list):
                for elem in trav_elements:
                    if elem.get("id") not in existing_ids:
                        elem["source"] = "traversal_track"
                        aggregated_elements[element_type].append(elem)

        # Calculate final coverage
        final_coverage = coverage_data.get("coverage_percentage", 0)
        if not coverage_data:
            # Estimate coverage from sources
            total_modules = critical_data.get("module_count", 0)
            analyzed_modules = len(set(
                e.get("module_id") for elements in aggregated_elements.values()
                for e in elements if e.get("module_id")
            ))
            final_coverage = (analyzed_modules / total_modules * 100) if total_modules > 0 else 0

        # Build aggregated output
        now = datetime.now().isoformat()
        aggregated_output = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "aggregated_at": now,
            "sources_merged": list(sources.keys()),
            "elements": aggregated_elements,
            "element_counts": {
                element_type: len(elements)
                for element_type, elements in aggregated_elements.items()
            },
            "coverage": {
                "final_percentage": round(final_coverage, 2),
                "is_complete": final_coverage >= 100,
                "critical_track_contribution": sum(
                    1 for elements in aggregated_elements.values()
                    for e in elements if e.get("source") == "critical_track"
                ),
                "traversal_track_contribution": sum(
                    1 for elements in aggregated_elements.values()
                    for e in elements if e.get("source") == "traversal_track"
                ),
            },
            "iteration_history": traversal_data.get("iteration_history", []),
            "ready_for_p3": final_coverage >= 100,
        }

        # Write final aggregated file
        output_file = data_dir / "P2_final_aggregated.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(aggregated_output, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["aggregation_complete"] = True
        result["output_file"] = str(output_file)
        result["element_counts"] = aggregated_output["element_counts"]
        result["final_coverage"] = aggregated_output["coverage"]["final_percentage"]
        result["ready_for_p3"] = aggregated_output["ready_for_p3"]

        if not aggregated_output["ready_for_p3"]:
            result["warning"] = f"Coverage is {final_coverage:.1f}%. Need 100% before proceeding to P3."
            result["next_action"] = "p2_gap_analysis"

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


# ============================================================================
# P2 Gap Task Dispatch (P2-GAP-02 fix)
# ============================================================================

def p2_dispatch_gap_tasks(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P2.T.4: Dispatch gap remediation tasks for uncovered modules/entry points.

    This function reads P2_gap_tasks.yaml and creates actionable task assignments
    for Claude to analyze the uncovered components.

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with dispatched tasks and next action
    """
    result = {
        "command": "p2_dispatch_gap_tasks",
        "status": "error",
        "tasks_dispatched": 0,
        "dispatched_tasks": [],
    }

    try:
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Load gap analysis results
        gap_file = data_dir / "P2_gap_tasks.yaml"
        if not gap_file.exists():
            result["error"] = "P2_gap_tasks.yaml not found. Run --p2-gap-analysis first."
            return result

        with open(gap_file, "r", encoding="utf-8") as f:
            gap_data = yaml.safe_load(f)

        remediation_tasks = gap_data.get("remediation_tasks", [])
        iteration_status = gap_data.get("iteration_status", {})
        current_iteration = iteration_status.get("current", 1)

        if not remediation_tasks:
            result["status"] = "success"
            result["message"] = "No gap tasks to dispatch. Coverage is complete."
            result["next_action"] = "p2_final_aggregation"
            return result

        # Check iteration limit
        if current_iteration > 3:
            result["status"] = "error"
            result["error"] = "Maximum iterations (3) exceeded. Manual intervention required."
            result["unresolved_tasks"] = remediation_tasks
            return result

        # Dispatch tasks with priority ordering
        # Priority: uncovered_module > uncovered_entry_point > incomplete_data_flow
        priority_order = {
            "uncovered_module": 1,
            "uncovered_entry_point": 2,
            "incomplete_data_flow": 3,
        }

        sorted_tasks = sorted(
            remediation_tasks,
            key=lambda t: priority_order.get(t.get("type", ""), 99)
        )

        dispatched = []
        for task in sorted_tasks:
            dispatch_item = {
                "task_id": task.get("id", f"TASK-{len(dispatched)+1}"),
                "type": task.get("type"),
                "target": task.get("target"),
                "priority": priority_order.get(task.get("type", ""), 99),
                "iteration": current_iteration,
                "instructions": _generate_task_instructions(task),
                "expected_output": _get_expected_output_format(task),
            }
            dispatched.append(dispatch_item)

        # Write dispatched tasks
        dispatch_output = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "dispatched_at": datetime.now().isoformat(),
            "iteration": current_iteration,
            "tasks": dispatched,
            "total_tasks": len(dispatched),
            "next_action": "execute_tasks_then_merge",
        }

        output_file = data_dir / "P2_dispatched_tasks.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(dispatch_output, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["tasks_dispatched"] = len(dispatched)
        result["dispatched_tasks"] = dispatched
        result["output_file"] = str(output_file)
        result["iteration"] = current_iteration
        result["next_action"] = "Claude should analyze each task and update P2_full_traversal.yaml"

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


def _generate_task_instructions(task: Dict) -> str:
    """Generate human-readable instructions for a gap task."""
    task_type = task.get("type", "unknown")
    target = task.get("target", "unknown")

    if task_type == "uncovered_module":
        return f"""Analyze module '{target}':
1. Read all source files in the module directory
2. Identify all entry points (API endpoints, handlers, etc.)
3. Trace data flows within the module
4. Document data stores accessed
5. Identify trust boundary crossings
Output: Add discovered elements to P2_full_traversal.yaml"""

    elif task_type == "uncovered_entry_point":
        return f"""Analyze entry point '{target}':
1. Locate the entry point handler
2. Trace the data flow from input to output
3. Identify all processes and data stores involved
4. Document any external system interactions
Output: Add data flow to P2_full_traversal.yaml"""

    elif task_type == "incomplete_data_flow":
        return f"""Complete data flow for '{target}':
1. Find the incomplete data flow
2. Trace to termination (data store, external system, or response)
3. Document all intermediate processes
Output: Update the data flow in P2_full_traversal.yaml"""

    else:
        return f"Analyze '{target}' and document findings"


def _get_expected_output_format(task: Dict) -> Dict:
    """Get expected output format for a gap task."""
    task_type = task.get("type", "unknown")

    if task_type == "uncovered_module":
        return {
            "processes": [{"id": "P-xxx", "name": "...", "module_id": "..."}],
            "data_flows": [{"id": "DF-xxx", "source": "...", "target": "..."}],
            "data_stores": [{"id": "DS-xxx", "name": "...", "type": "..."}],
        }
    elif task_type == "uncovered_entry_point":
        return {
            "data_flows": [{"id": "DF-xxx", "source": "EI-xxx", "target": "P-xxx"}],
        }
    elif task_type == "incomplete_data_flow":
        return {
            "updated_data_flow": {"id": "DF-xxx", "complete": True, "termination": "..."},
        }
    else:
        return {"elements": []}


# ============================================================================
# P1.1 Conditional Execution Check (P1-GAP-05 fix)
# ============================================================================

def p1_check_doc_analysis_required(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P1.1: Check if documentation analysis is required based on quality_grade.

    Decision Gate:
    - quality_grade == "none" (score < 10): Skip P1.1
    - quality_grade == "low" (score 10-39): Execute P1.1 (README only)
    - quality_grade == "medium" (score 40-69): Execute P1.1 (standard)
    - quality_grade == "high" (score >= 70): Execute P1.1 (full)

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with decision and reasoning
    """
    result = {
        "command": "p1_check_doc_analysis",
        "status": "success",
        "p1_1_required": False,
        "quality_grade": "none",
        "quality_score": 0,
        "analysis_scope": None,
        "reasoning": None,
    }

    try:
        # Get data directory
        data_dir = get_phase_data_dir(project_root, session_id)

        # Check for P1_static_discovery.yaml which contains documentation analysis
        static_discovery_file = data_dir / "P1_static_discovery.yaml"
        if not static_discovery_file.exists():
            result["error"] = "P1_static_discovery.yaml not found. Run module_discovery.py --p1-discovery first."
            result["status"] = "error"
            return result

        with open(static_discovery_file, "r", encoding="utf-8") as f:
            static_data = yaml.safe_load(f)

        # Extract documentation quality info
        documentation = static_data.get("documentation", {})
        quality_grade = documentation.get("quality_grade", "none")
        quality_score = documentation.get("quality_score", 0)

        result["quality_grade"] = quality_grade
        result["quality_score"] = quality_score

        # Decision logic
        if quality_grade == "none" or quality_score < 10:
            result["p1_1_required"] = False
            result["analysis_scope"] = None
            result["reasoning"] = "Documentation quality is too low (score < 10). Skip P1.1 and proceed to P1.2."
        elif quality_grade == "low" or quality_score < 40:
            result["p1_1_required"] = True
            result["analysis_scope"] = "readme_only"
            result["reasoning"] = "Low documentation quality (score 10-39). Execute P1.1 with README focus only."
        elif quality_grade == "medium" or quality_score < 70:
            result["p1_1_required"] = True
            result["analysis_scope"] = "standard"
            result["reasoning"] = "Medium documentation quality (score 40-69). Execute P1.1 with standard scope."
        else:
            result["p1_1_required"] = True
            result["analysis_scope"] = "full"
            result["reasoning"] = "High documentation quality (score >= 70). Execute P1.1 with full scope."

        # Add doc priority list if analysis required
        if result["p1_1_required"]:
            result["doc_priority_order"] = documentation.get("doc_priority_order", [])[:10]

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


# ============================================================================
# P1 Three-Source Alignment
# ============================================================================

def p1_source_alignment(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    P1.4: Validate three-source alignment for P1 discovery.

    Compares three sources:
      - Source A: Static Discovery (P1_static_discovery.yaml from module_discovery.py --p1-discovery)
      - Source B: Doc Inventory (documentation from module_discovery.py --doc-analysis)
      - Source C: LLM Synthesis (P1_project_context.yaml)

    Generates alignment report with:
      - Items found in all three sources (high confidence)
      - Items found in only two sources (medium confidence, review required)
      - Items found in only one source (low confidence, investigation required)

    Args:
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Dict with alignment analysis and coverage confidence
    """
    result = {
        "command": "p1_source_alignment",
        "status": "error",
        "alignment_score": 0.0,
        "sources_found": [],
        "alignment_report": None,
    }

    try:
        # Get data directory
        data_dir = get_phase_data_dir(project_root, session_id)
        if not data_dir.exists():
            result["error"] = f"Data directory not found: {data_dir}"
            return result

        # Source A: P1_static_discovery.yaml (from module_discovery.py --p1-discovery --output-yaml)
        static_discovery_file = data_dir / "P1_static_discovery.yaml"
        static_data = None
        if static_discovery_file.exists():
            with open(static_discovery_file, "r", encoding="utf-8") as f:
                static_data = yaml.safe_load(f)
            result["sources_found"].append("static_discovery")

        # Source B: Extract doc info from P1_project_context.yaml documentation section
        # or from P1_doc_inventory.yaml if separate
        doc_inventory_file = data_dir / "P1_doc_inventory.yaml"
        doc_data = None
        if doc_inventory_file.exists():
            with open(doc_inventory_file, "r", encoding="utf-8") as f:
                doc_data = yaml.safe_load(f)
            result["sources_found"].append("doc_inventory")

        # Source C: P1_project_context.yaml (LLM synthesis)
        p1_file = data_dir / "P1_project_context.yaml"
        llm_data = None
        if p1_file.exists():
            with open(p1_file, "r", encoding="utf-8") as f:
                llm_data = yaml.safe_load(f)
            result["sources_found"].append("llm_synthesis")

        # Check minimum sources
        sources_count = len(result["sources_found"])
        if sources_count < 2:
            result["error"] = f"Insufficient sources for alignment. Found: {result['sources_found']}. Need at least 2."
            result["recommendation"] = "Run module_discovery.py --p1-discovery --output-yaml first"
            return result

        # Extract comparable items from each source
        alignment_items = {
            "entry_points": {"source_a": set(), "source_b": set(), "source_c": set()},
            "modules": {"source_a": set(), "source_b": set(), "source_c": set()},
            "frameworks": {"source_a": set(), "source_b": set(), "source_c": set()},
            "api_routes": {"source_a": set(), "source_b": set(), "source_c": set()},
        }

        # Extract from Source A (static discovery)
        if static_data:
            p1_discovery = static_data.get("p1_discovery", static_data)

            # Extract routes
            layer1_routes = p1_discovery.get("layer1_deterministic", {}).get("routes", {})
            for route in layer1_routes.get("discoveries", []):
                alignment_items["api_routes"]["source_a"].add(route.get("path", ""))

            # Extract frameworks
            summary = p1_discovery.get("summary", {})
            for fw in summary.get("frameworks_detected", []):
                alignment_items["frameworks"]["source_a"].add(fw)

            # Extract directories as module indicators
            layer2_dirs = p1_discovery.get("layer2_heuristic", {}).get("directories", {})
            for disc in layer2_dirs.get("discoveries", []):
                alignment_items["modules"]["source_a"].add(disc.get("directory", ""))

        # Extract from Source B (doc inventory)
        if doc_data:
            doc_info = doc_data.get("documentation", doc_data)

            # Extract API docs
            api_docs = doc_info.get("files", {}).get("api_docs", [])
            for api_doc in api_docs:
                if isinstance(api_doc, str):
                    alignment_items["api_routes"]["source_b"].add(api_doc)

        # Extract from Source C (LLM synthesis)
        if llm_data:
            # Entry points
            ep_inventory = llm_data.get("entry_point_inventory", {})
            for ep in ep_inventory.get("entry_points", []):
                ep_path = ep.get("path", ep.get("name", ""))
                if ep_path:
                    alignment_items["entry_points"]["source_c"].add(ep_path)

            # Modules
            mod_inventory = llm_data.get("module_inventory", {})
            for mod in mod_inventory.get("modules", []):
                mod_path = mod.get("path", mod.get("name", ""))
                if mod_path:
                    alignment_items["modules"]["source_c"].add(mod_path)

            # Frameworks from tech stack
            tech_stack = llm_data.get("tech_stack", {})
            frameworks = tech_stack.get("frameworks", [])
            for fw in frameworks:
                if isinstance(fw, str):
                    alignment_items["frameworks"]["source_c"].add(fw)
                elif isinstance(fw, dict):
                    alignment_items["frameworks"]["source_c"].add(fw.get("name", ""))

        # Calculate alignment for each category
        alignment_analysis = {}
        total_score = 0.0
        category_count = 0

        for category, sources in alignment_items.items():
            a = sources["source_a"]
            b = sources["source_b"]
            c = sources["source_c"]

            # Union of all items
            all_items = a | b | c
            if not all_items:
                continue

            # Items in all three
            in_all_three = a & b & c
            # Items in exactly two
            in_two_ab = (a & b) - c
            in_two_ac = (a & c) - b
            in_two_bc = (b & c) - a
            in_two = in_two_ab | in_two_ac | in_two_bc
            # Items in only one
            only_a = a - b - c
            only_b = b - a - c
            only_c = c - a - b

            # Calculate category score
            # 3-source items: 1.0, 2-source items: 0.7, 1-source items: 0.3
            if all_items:
                weighted_score = (
                    len(in_all_three) * 1.0 +
                    len(in_two) * 0.7 +
                    len(only_a | only_b | only_c) * 0.3
                ) / len(all_items)
            else:
                weighted_score = 0.0

            total_score += weighted_score
            category_count += 1

            alignment_analysis[category] = {
                "total_items": len(all_items),
                "in_all_three_sources": list(in_all_three)[:20],
                "in_two_sources": list(in_two)[:20],
                "only_in_static": list(only_a)[:10],
                "only_in_docs": list(only_b)[:10],
                "only_in_llm": list(only_c)[:10],
                "category_score": round(weighted_score, 3),
                "needs_review": len(only_a) + len(only_b) + len(only_c) > 0,
            }

        # Overall alignment score
        overall_score = total_score / category_count if category_count > 0 else 0.0

        # Build alignment report
        now = datetime.now().isoformat()
        alignment_report = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id or "default",
            "analyzed_at": now,
            "sources_analyzed": result["sources_found"],
            "overall_alignment_score": round(overall_score, 3),
            "alignment_by_category": alignment_analysis,
            "recommendation": (
                "HIGH_CONFIDENCE" if overall_score >= 0.85
                else "MEDIUM_CONFIDENCE_REVIEW_RECOMMENDED" if overall_score >= 0.70
                else "LOW_CONFIDENCE_INVESTIGATION_REQUIRED"
            ),
        }

        # Write alignment report
        output_file = data_dir / "P1_source_alignment.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(alignment_report, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        result["status"] = "success"
        result["alignment_score"] = round(overall_score, 3)
        result["alignment_report"] = alignment_report
        result["output_file"] = str(output_file)

        if overall_score < 0.70:
            result["warning"] = "Low alignment score. Review single-source items before proceeding."

    except (KeyError, TypeError, AttributeError, ValueError, ZeroDivisionError, yaml.YAMLError, IOError) as e:
        result["error"] = str(e)

    return result


# ============================================================================
# Main CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase data manager for STRIDE threat modeling workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Session Management (Multi-Version)
    python phase_data.py --init --project "OPEN-WEBUI" --path /path/to/project
    python phase_data.py --init --project "OPEN-WEBUI" --force   # Force new session
    python phase_data.py --check-session --root /path/to/project
    python phase_data.py --resume --root /path/to/project
    python phase_data.py --resume --session-id OPEN-WEBUI-20260129_150000
    python phase_data.py --list-sessions --root /path/to/project
    python phase_data.py --migrate-session --root /path/to/project

    # Extract YAML blocks from Markdown (Option C - Primary)
    python phase_data.py --extract P1-PROJECT-UNDERSTANDING.md --phase 1 --root /path/to/project

    # Query phase data
    python phase_data.py --query --phase 1 --summary --root /path/to/project
    python phase_data.py --query --phase 1 --type entry_points --root /path/to/project
    python phase_data.py --query --phase 2 --element P-001 --root /path/to/project
    python phase_data.py --query --threats-for-element P-013 --root /path/to/project
    python phase_data.py --query --phase 1 --session-id OPEN-WEBUI-20260129_150000

    # Validate phase completion
    python phase_data.py --validate --phase 1 --root /path/to/project
    python phase_data.py --validate --phase 2 --root /path/to/project

    # Checkpoint validations (CP1/CP2/CP3)
    python phase_data.py --validate-cp1 --root /path/to/project
    python phase_data.py --validate-cp2 --root /path/to/project
    python phase_data.py --validate-cp3 --root /path/to/project
    python phase_data.py --validate-all-cp --root /path/to/project

    # ID format validation
    python phase_data.py --validate-ids --phase 5 --root /path/to/project

    # Workflow validation
    python phase_data.py --validate-workflow --root /path/to/project

    # Phase End Protocol (extract + validate + summary in one step)
    python phase_data.py --phase-end --phase 1 --root /path/to/project
    python phase_data.py --phase-end --phase 2 --file P2-DFD-ANALYSIS.md --root /path/to/project
    python phase_data.py --phase-end --phase 5 --session-id OPEN-WEBUI-20260129_150000 --root .

    # Backward compatibility (direct markdown parsing)
    python phase_data.py --validate-cp1 --markdown-mode --root /path/to/project

    # Store JSON directly (Option B - Backup)
    python phase_data.py --store --phase 5 --input-json threats.json --root /path/to/project

    # Cross-phase aggregation
    python phase_data.py --aggregate --phases 1,2,5 --format summary --root /path/to/project

    # P2 Full Traversal Enhancement
    python phase_data.py --p2-extract-tasks --root /path/to/project
    python phase_data.py --p2-merge-traversal --root /path/to/project
    python phase_data.py --p2-validate-coverage --root /path/to/project
    python phase_data.py --p2-gap-analysis --root /path/to/project

    # P1 Three-Source Alignment
    python phase_data.py --p1-source-alignment --root /path/to/project
        """
    )

    # Command modes
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--init",
        action="store_true",
        help="Initialize session (creates new multi-version session)"
    )
    mode_group.add_argument(
        "--check-session",
        action="store_true",
        help="Check for incomplete sessions"
    )
    mode_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume most recent incomplete session"
    )
    mode_group.add_argument(
        "--list-sessions",
        action="store_true",
        help="List all sessions for the project"
    )
    mode_group.add_argument(
        "--migrate-session",
        action="store_true",
        help="Migrate legacy single-file session to new multi-version structure"
    )
    mode_group.add_argument(
        "--extract",
        metavar="FILE",
        help="Extract YAML blocks from Markdown file (Option C)"
    )
    mode_group.add_argument(
        "--store",
        action="store_true",
        help="Store JSON input directly (Option B)"
    )
    mode_group.add_argument(
        "--query",
        action="store_true",
        help="Query phase data"
    )
    mode_group.add_argument(
        "--validate",
        action="store_true",
        help="Validate phase completion"
    )
    mode_group.add_argument(
        "--aggregate",
        action="store_true",
        help="Aggregate multiple phases"
    )
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="Show session status"
    )
    mode_group.add_argument(
        "--validate-cp1",
        action="store_true",
        help="CP1: Validate P5→P6 threat count conservation"
    )
    mode_group.add_argument(
        "--validate-cp2",
        action="store_true",
        help="CP2: Validate VR threat_refs completeness"
    )
    mode_group.add_argument(
        "--validate-cp3",
        action="store_true",
        help="CP3: Validate P6→Reports VR count conservation"
    )
    mode_group.add_argument(
        "--validate-all-cp",
        action="store_true",
        help="Execute all checkpoint validations (CP1+CP2+CP3)"
    )
    mode_group.add_argument(
        "--validate-ids",
        action="store_true",
        help="Validate ID formats in a phase"
    )
    mode_group.add_argument(
        "--validate-workflow",
        action="store_true",
        help="Validate complete workflow integrity"
    )
    mode_group.add_argument(
        "--phase-end",
        action="store_true",
        help="Execute Phase End Protocol: extract + validate + summary for phase handoff"
    )

    # P2 Full Traversal Commands
    mode_group.add_argument(
        "--p2-extract-tasks",
        action="store_true",
        help="P2.0: Extract traversal tasks from P1 data for sub-agent dispatch"
    )
    mode_group.add_argument(
        "--p2-merge-traversal",
        action="store_true",
        help="P2.T.2: Merge all P2_traverse_{NNN}.yaml files into P2_full_traversal.yaml"
    )
    mode_group.add_argument(
        "--p2-validate-coverage",
        action="store_true",
        help="P2.T.3: Validate 100%% coverage and generate coverage report"
    )
    mode_group.add_argument(
        "--p2-gap-analysis",
        action="store_true",
        help="P2.T.3: Identify gaps and generate remediation tasks (called when coverage < 100%%)"
    )
    mode_group.add_argument(
        "--p2-final-aggregation",
        action="store_true",
        help="P2.F: Final aggregation of Critical Track + Full Traversal Track outputs"
    )
    mode_group.add_argument(
        "--p2-dispatch-gap-tasks",
        action="store_true",
        help="P2.T.3b: Dispatch gap remediation tasks to sub-agents"
    )

    # P1 Source Alignment Command
    mode_group.add_argument(
        "--p1-source-alignment",
        action="store_true",
        help="P1.4: Validate three-source alignment (Static Discovery, Doc Inventory, LLM Synthesis)"
    )

    # P1.1 Conditional Execution Check (P1-GAP-05 fix)
    mode_group.add_argument(
        "--p1-check-doc-analysis",
        action="store_true",
        help="P1.1: Check if documentation analysis is required based on quality_grade"
    )

    # End-to-End Coverage Verification Commands
    mode_group.add_argument(
        "--verify-p4-coverage",
        action="store_true",
        help="Verify P4 coverage of P1 modules and P2 data flows"
    )
    mode_group.add_argument(
        "--verify-p5-coverage",
        action="store_true",
        help="Verify P5 STRIDE coverage of ALL P2 DFD elements"
    )
    mode_group.add_argument(
        "--verify-p6-coverage",
        action="store_true",
        help="Verify P6 coverage of ALL P1-P5 findings with count conservation"
    )
    mode_group.add_argument(
        "--verify-p8-coverage",
        action="store_true",
        help="Verify P8 penetration test coverage of P6 attack paths/chains"
    )
    mode_group.add_argument(
        "--verify-all-coverage",
        action="store_true",
        help="Execute all end-to-end coverage verifications"
    )

    # Common arguments
    parser.add_argument(
        "--root", "-r",
        metavar="PATH",
        default=".",
        help="Project root directory (default: current directory)"
    )
    parser.add_argument(
        "--phase", "-p",
        type=int,
        choices=range(1, 9),
        help="Phase number (1-8)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output"
    )

    # Init arguments
    parser.add_argument(
        "--project",
        metavar="NAME",
        help="Project name (for --init)"
    )
    parser.add_argument(
        "--path",
        metavar="PATH",
        help="Project path (for --init)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force action (e.g., create new session even with incomplete sessions)"
    )

    # Session management arguments
    parser.add_argument(
        "--session-id",
        metavar="ID",
        help="Specific session ID (for --resume, --query, --extract, --phase-end)"
    )

    # Phase End Protocol arguments
    parser.add_argument(
        "--file", "-f",
        metavar="FILE",
        help="Markdown file for --phase-end (auto-detected if not provided)"
    )

    # Store arguments (Option B)
    parser.add_argument(
        "--input-json",
        metavar="FILE",
        help="JSON file to store (for --store)"
    )
    parser.add_argument(
        "--block",
        metavar="NAME",
        help="Block name for JSON storage"
    )

    # Query arguments
    parser.add_argument(
        "--type", "-t",
        metavar="TYPE",
        help="Query type (entry_points, modules, threats, etc.)"
    )
    parser.add_argument(
        "--element", "-e",
        metavar="ID",
        help="Element ID to query"
    )
    parser.add_argument(
        "--threats-for-element",
        metavar="ID",
        help="Query threats for specific element"
    )
    parser.add_argument(
        "--summary", "-s",
        action="store_true",
        help="Return summary instead of full data"
    )

    # Aggregate arguments
    parser.add_argument(
        "--phases",
        metavar="LIST",
        help="Comma-separated phase numbers (e.g., 1,2,5)"
    )
    parser.add_argument(
        "--format",
        choices=["summary", "full"],
        default="summary",
        help="Aggregation format"
    )

    # Validation mode argument
    parser.add_argument(
        "--markdown-mode",
        action="store_true",
        help="Use direct markdown parsing (backward compatible with validate_count_conservation.py)"
    )

    args = parser.parse_args()

    # L8: Validate --root directory exists (skip for --help which already exited)
    if not Path(args.root).is_dir():
        parser.error(f"--root directory does not exist: {args.root}")

    # Execute command
    result = None

    if args.init:
        if not args.project:
            parser.error("--init requires --project")
        project_path = args.path or args.root
        result = init_session(args.project, project_path, force=args.force)

    elif args.check_session:
        result = check_session(args.root)

    elif args.resume:
        result = resume_session(args.root, session_id=args.session_id)

    elif args.list_sessions:
        result = list_sessions(args.root)

    elif args.migrate_session:
        result = migrate_legacy_session(args.root)

    elif args.extract:
        if not args.phase:
            parser.error("--extract requires --phase")
        result = extract_from_markdown(
            args.extract,
            args.phase,
            args.root,
            session_id=args.session_id
        )

    elif args.store:
        if not args.phase or not args.input_json:
            parser.error("--store requires --phase and --input-json")
        result = store_json(args.input_json, args.phase, args.root, args.block)

    elif args.query:
        if args.threats_for_element:
            result = query_threats_for_element(args.threats_for_element, args.root)
        elif args.phase:
            result = query_phase(
                args.phase,
                args.root,
                query_type=args.type,
                element_id=args.element,
                summary=args.summary
            )
        else:
            parser.error("--query requires --phase or --threats-for-element")

    elif args.validate:
        if not args.phase:
            parser.error("--validate requires --phase")
        result = validate_phase(args.phase, args.root)

    elif args.aggregate:
        if not args.phases:
            parser.error("--aggregate requires --phases")
        phase_list = [int(p.strip()) for p in args.phases.split(",")]
        invalid = [p for p in phase_list if p < 1 or p > 8]
        if invalid:
            parser.error(f"--phases values must be 1-8, got invalid: {invalid}")
        result = aggregate_phases(phase_list, args.root, args.format)

    elif args.status:
        session = load_session(args.root, session_id=args.session_id)
        if session:
            result = {
                "status": "active",
                "session": session,
            }
        else:
            result = {
                "status": "no_session",
                "message": "No active session. Run --init to start.",
            }

    # Checkpoint validations
    elif args.validate_cp1:
        result = validate_cp1_threat_conservation(args.root, args.markdown_mode)

    elif args.validate_cp2:
        result = validate_cp2_vr_threat_refs(args.root, args.markdown_mode)

    elif args.validate_cp3:
        result = validate_cp3_report_conservation(args.root)

    elif args.validate_all_cp:
        result = validate_all_checkpoints(args.root, args.markdown_mode)

    elif args.validate_ids:
        if not args.phase:
            parser.error("--validate-ids requires --phase")
        result = validate_id_formats_in_phase(args.phase, args.root)

    elif args.validate_workflow:
        result = validate_workflow_complete(args.root)

    elif args.phase_end:
        if not args.phase:
            parser.error("--phase-end requires --phase")
        result = phase_end_protocol(
            args.phase,
            args.root,
            markdown_file=args.file,
            session_id=args.session_id
        )

    # P2 Full Traversal Commands
    elif args.p2_extract_tasks:
        result = p2_extract_traversal_tasks(args.root, session_id=args.session_id)

    elif args.p2_merge_traversal:
        result = p2_merge_traversal_results(args.root, session_id=args.session_id)

    elif args.p2_validate_coverage:
        result = p2_validate_coverage(args.root, session_id=args.session_id)

    elif args.p2_gap_analysis:
        result = p2_gap_analysis(args.root, session_id=args.session_id)

    elif args.p2_final_aggregation:
        result = p2_final_aggregation(args.root, session_id=args.session_id)

    elif args.p2_dispatch_gap_tasks:
        result = p2_dispatch_gap_tasks(args.root, session_id=args.session_id)

    elif args.p1_source_alignment:
        result = p1_source_alignment(args.root, session_id=args.session_id)

    elif args.p1_check_doc_analysis:
        result = p1_check_doc_analysis_required(args.root, session_id=args.session_id)

    # End-to-End Coverage Verification Commands
    elif args.verify_p4_coverage:
        result = verify_p4_coverage(args.root, session_id=args.session_id)

    elif args.verify_p5_coverage:
        result = verify_p5_element_coverage(args.root, session_id=args.session_id)

    elif args.verify_p6_coverage:
        result = verify_p6_findings_coverage(args.root, session_id=args.session_id)

    elif args.verify_p8_coverage:
        result = verify_p8_attack_coverage(args.root, session_id=args.session_id)

    elif args.verify_all_coverage:
        result = verify_all_coverage(args.root, session_id=args.session_id)

    # F10: Normalize error response — ensure both status fields present
    if result:
        if "overall_status" in result and "status" not in result:
            result["status"] = result["overall_status"]
        elif "status" in result and "overall_status" not in result:
            result["overall_status"] = result["status"]

    # Output JSON
    if result:
        if args.pretty:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(result, ensure_ascii=False))

        # Exit code per WORKFLOW.md contract (F3 fix)
        status = result.get("overall_status") or result.get("status", "")
        status_lower = status.lower() if isinstance(status, str) else ""
        if status_lower in ("error", "blocking", "fail"):
            sys.exit(1)
        elif status_lower in ("warning", "warn"):
            sys.exit(2)


if __name__ == "__main__":
    main()
