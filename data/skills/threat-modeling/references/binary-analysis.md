<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Binary Analysis & Reverse Engineering for Threat Modeling

On-demand reference for analyzing compiled binaries, firmware, kernel modules, and native code during threat modeling sessions.

**When to load**: When the threat model target includes compiled binaries (ELF/PE/Mach-O), firmware images, kernel modules, or when source code is unavailable for critical components. Primarily enhances P1 (binary module discovery), P5 (binary STRIDE analysis), and P6 (POC/attack path validation via decompilation).

---

## 1. Binary Analysis Tools (MCP + CLI)

### MCP-Integrated (direct tool calls)

| Tool | MCP Tools | Primary Capability |
|------|-----------|-------------------|
| **Ghidra** (pyghidra-mcp) | 18 headless tools | Decompilation to pseudo-C, semantic code search, call graphs, xrefs, symbol analysis |
| **Luoshu** (r2 backend) | `luoshu_auto_binary` | Fast binary recon: functions, imports, exports, sections into knowledge graph |

### CLI-Based (via Bash tool)

| Tool | Use Case | Output Format |
|------|----------|---------------|
| **Joern** | CPG taint analysis, 15 CWE vulnerability checks | Flatgraph + TSV findings |
| **GDB/pygdbmi** | Runtime analysis, crash debugging, stack traces | JSON (via MI interface) |
| **Valgrind** | Memory error detection (use-after-free, buffer overflow) | XML |
| **CAPA** | MITRE ATT&CK capability mapping | JSON |
| **strace/bpftrace** | System call tracing, kernel event monitoring | Text/JSON |
| **AFL++** | Coverage-guided fuzzing for vulnerability discovery | Crash corpus |
| **binwalk** | Firmware extraction | Extracted file tree |

---

## 2. Binary Module Discovery (P1 Enhancement)

### Entry Point Types for Binary Targets

Binary targets introduce entry point types beyond the source-code EP taxonomy:

| Entry Point Type | Description | Discovery Tool |
|-----------------|-------------|----------------|
| `binary_export` | Exported function symbols (shared library API) | Ghidra `list_exports` or `luoshu_auto_binary` |
| `elf_entry` | ELF entry point / `main` function | Ghidra `search_symbols_by_name(query="^main$")` |
| `ioctl_handler` | Kernel module ioctl dispatch | Ghidra `search_symbols_by_name(query="ioctl")` |
| `syscall_handler` | System call entry | Ghidra `search_code(query="syscall handler")` |
| `interrupt_handler` | Hardware interrupt service routine | Ghidra `search_symbols_by_name(query="IRQ\|irq_handler")` |
| `firmware_entry` | Firmware reset vector / boot entry | Ghidra `decompile_function(name_or_address="0x00000000")` |

### Binary Recon Workflow

```
1. luoshu_auto_binary(binary="<path>")
   → Imports functions/sections/imports/exports into Luoshu KG (seconds)

2. import_binary(binary_path="<path>")
   → Import into Ghidra for deep analysis

3. list_exports(binary_name="<name>", limit=50)
   → Public API surface (entry points)

4. list_imports(binary_name="<name>", query=".*")
   → External dependencies (attack surface indicators)

5. search_strings(binary_name="<name>", query="password\|key\|secret\|token")
   → Embedded credentials or sensitive strings
```

---

## 3. Decompilation & Program Logic Analysis (P2/P6 Enhancement)

### Understanding Binary Function Logic

```
decompile_function(
    binary_name="<name>",
    name_or_address="<func_or_addr>",
    include_callees=true,
    include_xrefs=true,
    include_strings=true
)
```

Returns pseudo-C with:
- Decompiled function body (readable C approximation)
- Callee list (functions called by this function)
- Cross-references (who calls this function)
- Referenced strings (embedded in the function)

### Call Graph for Attack Path Visualization

```
gen_callgraph(
    binary_name="<name>",
    function_name="<entry_point>",
    direction="calling",
    top_layers=3,
    bottom_layers=3
)
```

Returns MermaidJS diagram suitable for embedding in P2 DFD reports and P6 attack path diagrams.

### Semantic Code Search

```
search_code(
    binary_name="<name>",
    query="authentication check",
    search_mode="semantic",
    limit=10
)
```

Finds functions by behavior (not just name) using ChromaDB vector embeddings over decompiled pseudo-C. Useful for finding:
- Authentication/authorization logic
- Cryptographic operations
- Input validation routines
- Memory allocation patterns

---

## 4. Vulnerability Discovery (P5/P6 Enhancement)

### Automated CWE Detection (C/C++ via Joern)

```bash
# Parse and build CPG
joern-parse --language c /path/to/source

# Run 15 automated CWE checks
python -m luoshu.joern_queries.runner --cpg .luoshu/joern-work/cpg.bin --all
```

**15 CWE checks**: CWE-78 (command injection), CWE-89 (SQL injection), CWE-120/121/122 (buffer overflows), CWE-125/787 (out-of-bounds read/write), CWE-134 (format string), CWE-190 (integer overflow), CWE-367 (TOCTOU), CWE-401 (memory leak), CWE-415/416 (double-free/use-after-free), CWE-476 (null deref), CWE-798 (hardcoded credentials)

**Integration with P5**: Each CWE finding maps to a STRIDE threat:
- Buffer overflow (CWE-120/121/122/787) → Tampering, Elevation of Privilege
- Use-after-free (CWE-416) → Tampering, Denial of Service
- Command injection (CWE-78) → Tampering, Elevation of Privilege
- SQL injection (CWE-89) → Tampering, Information Disclosure
- Format string (CWE-134) → Information Disclosure, Tampering
- Hardcoded credentials (CWE-798) → Spoofing

### Memory Error Detection (Runtime)

```bash
valgrind --tool=memcheck --xml=yes --xml-file=memcheck.xml \
  --leak-check=full --track-origins=yes ./binary args
```

Detects: InvalidRead, InvalidWrite, UninitValue, Leak — with full stack traces and source locations.

### Attack Surface via Cross-References

```
# Find all callers of dangerous functions
list_xrefs(binary_name="<name>", name_or_address=["malloc", "free", "strcpy", "sprintf", "system"])

# Trace inbound call chain to entry point
luoshu_query_chain(symbol="<dangerous_func>", edge_kind="CALLS", direction="inbound", max_depth=5)
```

---

## 5. Firmware & Embedded Analysis

```bash
# 1. Extract firmware components
binwalk -e -M firmware.bin

# 2. Identify binaries
file _firmware.bin.extracted/*

# 3. Import key binaries into Ghidra
import_binary(binary_path="<extracted_binary>")

# 4. Analyze each binary's attack surface
list_exports(binary_name="<name>")
list_imports(binary_name="<name>")
decompile_function(binary_name="<name>", name_or_address="main")
```

---

## 6. Kernel Module Analysis

```bash
# Symbol analysis
readelf -s driver.ko | grep -E "FUNC|OBJECT"

# Function tracing (requires root + debug kernel)
echo 'driver_*' > /sys/kernel/debug/tracing/set_ftrace_filter
echo function_graph > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on

# eBPF event monitoring
bpftrace -e 'kprobe:driver_ioctl { printf("ioctl cmd=%d\n", arg1); }'
```

---

## 7. Phase Integration Summary

| Phase | Binary Analysis Enhancement |
|-------|----------------------------|
| **P1** | Binary module discovery via Ghidra exports/imports + Luoshu `auto_binary` |
| **P2** | Call graph generation via Ghidra `gen_callgraph` → DFD data flow mapping |
| **P3** | Trust boundary identification from import/export analysis (process boundaries) |
| **P5** | Joern CWE queries for automated threat evidence; Ghidra semantic search for vulnerability patterns |
| **P6** | Decompilation for POC design; memory error detection for attack validation; cross-reference for attack chain tracing |
| **P8** | MermaidJS call graphs from Ghidra `gen_callgraph` for report diagrams |

---

## 8. Limitations

1. **Ghidra decompilation** is heuristic — types and variable names are inferred, may be inaccurate
2. **Joern CWE queries** are sound but incomplete — they find common patterns, not all vulnerabilities
3. **Valgrind/AFL++** require the binary to be executable in the analysis environment
4. **Kernel debugging** requires `CONFIG_DEBUG_INFO=y` + unstripped `vmlinux`
5. **Dynamic analysis tools** (GDB, strace, bpftrace) are CLI-only — no MCP integration
6. **Ghidra startup** can take 10-60s for large binaries — plan for latency
