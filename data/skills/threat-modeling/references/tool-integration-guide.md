<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Tool Integration Guide for Threat Modeling

On-demand reference for MCP-based code analysis tools available during threat modeling sessions. Load this when a target project requires deep program analysis beyond manual code reading.

**Prerequisite**: Target repo must be indexed before querying. Always run `luoshu_status(repo="<target>")` first.

---

## 1. Tool Selection by Phase

| Phase Need | Primary Tool | MCP Call | Fallback |
|------------|-------------|----------|----------|
| **P1: Module/Architecture Discovery** | | | |
| System-level architecture | Luoshu | `luoshu_query_dfd(repo="<target>")` | Manual code reading |
| Module dependency tree | Luoshu | `luoshu_query_chain(symbol="<entry>", edge_kind="IMPORTS", max_depth=3)` | CGC `analyze_code_relationships(query_type="module_deps")` |
| Find entry points | Luoshu | `luoshu_query_search(text="route\|endpoint\|handler")` | `module_discovery.py --p1-discovery` |
| Full diagnostic on symbol | Luoshu | `luoshu_diagnose(symbol="<name>")` | — |
| **P2: DFD/CFD Analysis** | | | |
| DFD candidates (processes, stores, externals) | Luoshu | `luoshu_query_dfd(component="<name>")` | Manual identification |
| Control flow graph (per function) | Luoshu | `luoshu_query_flow(symbol="<func>", graph_kind="cfg")` | Joern CLI `joern-flow` |
| Data flow graph (per function) | Luoshu | `luoshu_query_flow(symbol="<func>", graph_kind="dfg")` | Joern CLI |
| Call chain tracing | Luoshu | `luoshu_query_chain(symbol="<func>", edge_kind="CALLS", max_depth=5)` | CGC `analyze_code_relationships(query_type="call_chain")` |
| Export DFD as Mermaid | Luoshu | `luoshu_export(format="mermaid", symbol="<func>")` | Manual diagram |
| **P4: Security Design Review** | | | |
| Automated security scan (source) | Luoshu | `luoshu_auto_codeql(languages=["python"], repo="<target>")` | ql-mcp `codeql_database_analyze` |
| Custom CodeQL query | ql-mcp | `codeql_query_run(database="<db>", query="<path>")` | — |
| SARIF alert analysis | ql-mcp | `sarif_list_rules(sarif="<path>")` | — |
| Dead code detection | CGC | `find_dead_code(repo_path="<target>")` | — |
| Complexity hotspots | CGC | `find_most_complex_functions(top_n=20)` | — |
| **P5: STRIDE Analysis** | | | |
| CWE vulnerability detection (C/C++) | Joern | `run_cwe_queries(cpg_path="<cpg>")` (15 CWE checks) | CodeQL security suites |
| Inter-procedural taint analysis | Joern | `joern` REPL: `snk.reachableByFlows(src).l` | — |
| Source-to-sink data flow | Luoshu | `luoshu_query_chain(symbol="<source>", direction="outbound", max_depth=5)` | Joern taint |
| **P6: Risk Validation / POC** | | | |
| Attack path call chain | Luoshu | `luoshu_query_chain(symbol="<entry>", edge_kind="CALLS", direction="outbound")` | — |
| Decompile binary function | Ghidra | `decompile_function(binary_name="<bin>", name_or_address="<func>", include_callees=true)` | — |
| Binary call graph | Ghidra | `gen_callgraph(binary_name="<bin>", function_name="<func>")` | — |
| Binary cross-references | Ghidra | `list_xrefs(binary_name="<bin>", name_or_address="<func>")` | — |
| Binary string search | Ghidra | `search_strings(binary_name="<bin>", query="password\|key\|token")` | — |
| Semantic binary code search | Ghidra | `search_code(binary_name="<bin>", query="authentication check", search_mode="semantic")` | — |
| Binary recon (fast) | Luoshu | `luoshu_auto_binary(binary="<path>")` | r2 CLI |
| Memory error detection | Valgrind | `valgrind --xml=yes --xml-file=report.xml --leak-check=full <binary>` (Bash) | — |
| **P8: Report Generation** | | | |
| Architecture Mermaid diagrams | Luoshu | `luoshu_export(format="mermaid")` | Manual |

---

## 2. Indexing (Required Before Queries)

```bash
# Step 0: Check if target is indexed
luoshu_status(repo="/path/to/target")

# Step 1: Index source code (languages: python, javascript, go, c)
luoshu_index(repo="/path/to/target", languages=["python"], parallel=4)

# Step 2 (optional): CGC graph-DB index for relationship queries
add_code_to_graph(path="/path/to/target")

# Step 3 (for binaries): Import into analysis tools
luoshu_auto_binary(binary="/path/to/binary")           # Fast recon via r2
import_binary(binary_path="/path/to/binary")            # Ghidra for decompilation
```

**Rule**: Always `luoshu_status` first. Querying an unindexed repo returns empty results silently.

---

## 3. Binary Analysis Pipeline (P6 Deep Validation)

For compiled targets requiring reverse engineering:

```
1. luoshu_auto_binary(binary="<path>")
   → Fast recon: functions, imports, exports into Luoshu KG

2. import_binary(binary_path="<path>")
   → Import into Ghidra project for decompilation

3. search_symbols_by_name(binary_name="<name>", query="<pattern>", functions_only=true)
   → Discover relevant functions

4. decompile_function(binary_name="<name>", name_or_address="<func>", include_callees=true, include_xrefs=true)
   → Decompile to pseudo-C with full context

5. gen_callgraph(binary_name="<name>", function_name="<func>", direction="calling")
   → MermaidJS call graph for report inclusion

6. list_xrefs(binary_name="<name>", name_or_address=["malloc", "free", "strcpy"])
   → Cross-reference analysis for dangerous functions
```

---

## 4. Joern CWE Detection Pipeline (P5 Automated Threat Evidence)

For C/C++ targets requiring automated vulnerability scanning:

```bash
# Parse source to CPG
joern-parse --language c /path/to/c-project

# Run all 15 CWE checks
python -m luoshu.joern_queries.runner --cpg .luoshu/joern-work/cpg.bin --all

# Or specific CWEs
python -m luoshu.joern_queries.runner --cpg .luoshu/joern-work/cpg.bin --cwe CWE-416 CWE-476 CWE-120

# Inter-procedural taint (manual via Joern REPL)
joern
joern> importCpg("workspace/repo/cpg.bin")
joern> def src = cpg.call.name("recv")
joern> def snk = cpg.call.name("memcpy")
joern> snk.reachableByFlows(src).l
```

**15 CWE checks available**: CWE-78, CWE-89, CWE-120, CWE-121, CWE-122, CWE-125, CWE-134, CWE-190, CWE-367, CWE-401, CWE-415, CWE-416, CWE-476, CWE-787, CWE-798

---

## 5. Tool Availability

These tools require MCP server configuration. Check availability:
- **Luoshu**: `luoshu_status` — if responsive, 14 MCP tools available
- **CGC**: `list_indexed_repositories` — if responsive, 24 MCP tools available
- **Ghidra**: `list_project_binaries` — if responsive, 18 MCP tools available
- **ql-mcp**: `codeql_resolve_languages` — if responsive, 65 MCP tools available
- **Joern**: CLI only — check `which joern-parse` via Bash

If a tool is unavailable, fall back to manual analysis as specified in the Fallback column above.

---

## 6. Key Limitations

1. **Luoshu `luoshu_query_flow` is intraprocedural only** — for cross-function data flow use Joern CLI
2. **DFD candidates are inferred** — `luoshu_query_dfd` results are heuristic. Always review before including in reports
3. **Joern has no MCP** — agent must use Bash tool for all Joern operations
4. **CodeQL needs compilation** — for C/C++/Java, CodeQL requires a build step (`--command 'make'`)
5. **Binary analysis tools** (Ghidra, r2) analyze compiled code — results may not match source exactly
6. **Large repos**: set `limit` parameters to 20-50 to avoid context overflow
